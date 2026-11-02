//! Recursive aggregation: one proof that all `NUM_BALLOTS` ballot STARKs verify.
//!
//! The aggregate is a Plonky3-recursion circuit that runs the `VoterAir` STARK verifier once
//! per ballot, then computes, from the ballots' public values:
//!
//! - equality of every ballot's eligibility root and election id,
//! - pairwise distinct nullifiers (no double vote inside the batch),
//! - the tally,
//! - `receipt_root`: a depth-3 Poseidon2 Merkle root over `receipt_leaf(nullifier_i, vote_i)`.
//!
//! Only [`AggregateStatement`] is public. A voter who holds their receipt path
//! ([`crate::receipts`]) checks their own `(nullifier, vote)` against `receipt_root`.
//!
//! The circuit is proven with a non-hiding FRI config ([`AggConfig`]): it only attests to values
//! that are already public, and an unsalted preprocessing commitment lets anyone rebuild the
//! verifier key ([`AggregateVerifier::derive`]) instead of trusting the aggregator's.

use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_circuit::ops::{Poseidon2PermCall, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{
    Circuit, CircuitBuilder, CircuitRunner, ExprId, NonPrimitiveOpId, StatementExport,
    StatementSchema,
};
use p3_circuit_prover::{
    AirVariant, BatchStarkProof, BatchStarkProver, CircuitVerifier, ConstraintProfile,
    StatementAirBuilder, StatementPreprocessor, StatementProver, TablePacking,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{
    FriProofTargets, InputProofTargets, MerkleCapTargets, RecExtensionValMmcs, RecValMmcs,
    Witness as FriWitness,
};
use p3_recursion::pcs::fri::{HidingFriProofTargets, RecValHidingMmcs};
use p3_recursion::pcs::{
    restore_fri_query_paths, restore_hiding_fri_query_paths, set_fri_mmcs_private_data,
};
use p3_recursion::{
    FriRecursionBackend, FriRecursionBackendForExt, FriRecursionConfig, FriVerifierParams,
    NativeFriParams, OpeningTranscript, PcsRecursionBackend, Poseidon2Config, RecursionInput,
    RecursiveAir, StarkVerifierInputsBuilder, VerificationError, merge_hiding_random_openings,
    observe_opened_values, verify_p3_uni_proof_circuit,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::air::{NUM_CANDIDATES, VoterAir, Witness, public_values, pv};
use crate::ballot::Ballot;
use crate::hash::{DIGEST, DOMAIN_RECEIPT, Digest, F, hash_leaf, nullifier, perm};
use crate::receipts::Receipts;
use crate::registry::{SignedRoot, random_secret};
use crate::stark::{
    Challenge, ChallengeMmcs, Challenger as LeafChallenger, Config, Pcs as LeafPcs, Proof, config,
    deserialize, fri_params, hiding_mmcs, plain_mmcs, prove_eligibility, verify_eligibility,
};
use crate::tree::{DEPTH, MerkleTree, NUM_LEAVES};

/// Ballots per aggregate: one per voter slot, so the receipt tree has the voter tree's shape.
pub const NUM_BALLOTS: usize = NUM_LEAVES;
/// Extension degree of the recursion circuit (same as the STARK challenge field).
const D: usize = 4;

/// Public statement layout of the aggregate proof.
pub mod agg_pv {
    use super::{DIGEST, NUM_CANDIDATES};
    pub const ELIGIBILITY_ROOT: usize = 0;
    pub const ELECTION_ID: usize = ELIGIBILITY_ROOT + DIGEST;
    pub const RECEIPT_ROOT: usize = ELECTION_ID + 1;
    pub const TALLY: usize = RECEIPT_ROOT + DIGEST;
    pub const LEN: usize = TALLY + NUM_CANDIDATES as usize;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateStatement {
    pub eligibility_root: Digest,
    pub election_id: u32,
    pub receipt_root: Digest,
    pub tally: [u32; NUM_CANDIDATES as usize],
}

impl AggregateStatement {
    /// What an honest aggregate of `entries` (in ballot order) must publish.
    pub fn compute(
        eligibility_root: &Digest,
        election_id: u32,
        entries: &[(Digest, u32); NUM_BALLOTS],
    ) -> Self {
        let mut tally = [0; NUM_CANDIDATES as usize];
        for &(_, vote) in entries {
            tally[vote as usize] += 1;
        }
        Self {
            eligibility_root: *eligibility_root,
            election_id,
            receipt_root: Receipts::new(entries).root(),
            tally,
        }
    }

    pub fn to_fields(&self) -> Vec<F> {
        let mut v = Vec::with_capacity(agg_pv::LEN);
        v.extend_from_slice(&self.eligibility_root);
        v.push(F::from_u32(self.election_id));
        v.extend_from_slice(&self.receipt_root);
        v.extend(self.tally.map(F::from_u32));
        v
    }

    /// Rejects wrong lengths and non-canonical values.
    pub fn from_u32s(v: &[u32]) -> Option<Self> {
        if v.len() != agg_pv::LEN || v.iter().any(|&x| x >= F::ORDER_U32) {
            return None;
        }
        let digest = |at: usize| -> Digest { core::array::from_fn(|j| F::from_u32(v[at + j])) };
        Some(Self {
            eligibility_root: digest(agg_pv::ELIGIBILITY_ROOT),
            election_id: v[agg_pv::ELECTION_ID],
            receipt_root: digest(agg_pv::RECEIPT_ROOT),
            tally: core::array::from_fn(|c| v[agg_pv::TALLY + c]),
        })
    }

    pub fn to_u32s(&self) -> Vec<u32> {
        self.to_fields()
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AggregateError {
    WrongCount(usize),
    MalformedProof(usize),
    InvalidChild(usize, String),
    DuplicateNullifier(usize, usize),
    /// The recursion circuit could not be built or its witness does not satisfy it.
    Circuit(String),
    Prove(String),
    Verify(String),
}

fn circuit_err(e: impl core::fmt::Debug) -> AggregateError {
    AggregateError::Circuit(format!("{e:?}"))
}

// ---------------------------------------------------------------------------------------------
// Input (leaf) config: lets the ballot STARKs from `crate::stark` be verified in-circuit.
// A BabyBear port of the upstream `koala_bear_d4_poseidon2_salted` built-in.

/// Poseidon2 permutation the recursive verifier uses for the challenger and Merkle hashing.
pub const POSEIDON2_CIRCUIT: Poseidon2Config = Poseidon2Config::BABY_BEAR_D4_W16;

/// FRI parameters of a ballot proof, in the two forms the recursion crate checks.
#[derive(Clone)]
pub struct LeafRecursionParams {
    native: NativeFriParams,
    verifier: FriVerifierParams,
}

impl LeafRecursionParams {
    pub(crate) fn new<M>(params: &FriParameters<M>) -> Self {
        Self {
            native: NativeFriParams::try_from_native::<F, _>(params).expect("valid FRI parameters"),
            verifier: FriVerifierParams::with_mmcs(
                params.log_blowup,
                params.log_final_poly_len,
                params.max_log_arity,
                params.commit_proof_of_work_bits,
                params.query_proof_of_work_bits,
                params.num_queries,
                POSEIDON2_CIRCUIT,
            ),
        }
    }
}

type LeafRecMmcs = RecValHidingMmcs<F, 8, 4, Hash, Compress, StdRng>;
type LeafInputProof = InputProofTargets<F, Challenge, LeafRecMmcs>;
type LeafOpeningProof = HidingFriProofTargets<
    F,
    Challenge,
    RecExtensionValMmcs<F, Challenge, 8, LeafRecMmcs>,
    LeafInputProof,
    FriWitness<F>,
>;

impl FriRecursionConfig for Config {
    type Commitment = MerkleCapTargets<F, 8>;
    type InputProof = LeafInputProof;
    type OpeningProof = LeafOpeningProof;
    type RawOpeningProof = <LeafPcs as p3_commit::Pcs<Challenge, LeafChallenger>>::Proof;

    const DIGEST_ELEMS: usize = 8;

    fn native_fri_validation_params(&self) -> Option<NativeFriParams> {
        Some(self.recursion.native)
    }

    fn with_fri_opening_proof<'a, A, T>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> T,
    ) -> T
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        enable_circuit_ops(circuit);
        Ok(())
    }

    fn pcs_verifier_params(&self) -> &FriVerifierParams {
        &self.recursion.verifier
    }

    fn set_fri_private_data(
        _config: &Self,
        runner: &mut CircuitRunner<'_, Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        // Verification only: these instances never commit, so their RNG is never drawn from.
        let input_hiding_mmcs = hiding_mmcs(StdRng::seed_from_u64(0));
        let fri_params = fri_params(ChallengeMmcs::new(hiding_mmcs(StdRng::seed_from_u64(0))));
        let OpeningTranscript {
            mut challenger,
            mut commitments_with_opening_points,
        } = transcript;
        merge_hiding_random_openings::<Self>(&mut commitments_with_opening_points, &opening_proof.0)
            .map_err(|_| "Failed to merge hiding FRI random openings")?;
        observe_opened_values::<Self>(
            &mut challenger,
            &commitments_with_opening_points,
            fri_params.batch_proof_of_work_bits,
        );
        let claims: Vec<_> = commitments_with_opening_points
            .into_iter()
            .map(Into::into)
            .collect();
        let query_paths = restore_hiding_fri_query_paths(
            &fri_params,
            &input_hiding_mmcs,
            &plain_mmcs(),
            &plain_mmcs(),
            &opening_proof.1,
            &mut challenger,
            &claims,
        )
        .map_err(|_| "Failed to restore salted FRI query paths")?;
        set_fri_mmcs_private_data::<F, Challenge, 8>(runner, op_ids, &query_paths, POSEIDON2_CIRCUIT)
    }
}

// ---------------------------------------------------------------------------------------------
// Output config: plain (non-hiding) FRI over the same Poseidon2/BabyBear primitives.

type Perm = p3_baby_bear::Poseidon2BabyBear<16>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type AggMmcs = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, Hash, Compress, 2, 8>;
type AggChallengeMmcs = ExtensionMmcs<F, Challenge, AggMmcs>;
type AggChallenger = DuplexChallenger<F, Perm, 16, 8>;
type AggPcs = TwoAdicFriPcs<F, Radix2DitParallel<F>, AggMmcs, AggChallengeMmcs>;
type AggRecMmcs = RecValMmcs<F, 8, Hash, Compress>;
type AggInputProof = InputProofTargets<F, Challenge, AggRecMmcs>;
type AggOpeningProof = FriProofTargets<
    F,
    Challenge,
    RecExtensionValMmcs<F, Challenge, 8, AggRecMmcs>,
    AggInputProof,
    FriWitness<F>,
>;

fn agg_mmcs() -> AggMmcs {
    AggMmcs::new(Hash::new(perm().clone()), Compress::new(perm().clone()), 0)
}

/// Blowup 8 (the circuit tables have higher constraint degree than `VoterAir`),
/// 40 queries + 16-bit grinding: ~136 conjectured bits.
fn agg_fri_params() -> FriParameters<AggChallengeMmcs> {
    FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 40,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 16,
        mmcs: AggChallengeMmcs::new(agg_mmcs()),
    }
}

#[derive(Clone)]
pub struct AggConfig {
    inner: StarkConfig<AggPcs, Challenge, AggChallenger>,
    native_fri_params: NativeFriParams,
    fri_verifier_params: FriVerifierParams,
}

impl AggConfig {
    pub fn new() -> Self {
        let params = agg_fri_params();
        let native_fri_params =
            NativeFriParams::try_from_native::<F, _>(&params).expect("valid FRI parameters");
        let fri_verifier_params = FriVerifierParams::with_mmcs(
            params.log_blowup,
            params.log_final_poly_len,
            params.max_log_arity,
            params.commit_proof_of_work_bits,
            params.query_proof_of_work_bits,
            params.num_queries,
            POSEIDON2_CIRCUIT,
        );
        let pcs = AggPcs::new(Radix2DitParallel::default(), agg_mmcs(), params);
        Self {
            inner: StarkConfig::new(pcs, AggChallenger::new(perm().clone())),
            native_fri_params,
            fri_verifier_params,
        }
    }
}

impl Default for AggConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for AggConfig {
    type Pcs = AggPcs;
    type Challenge = Challenge;
    type Challenger = AggChallenger;

    fn pcs(&self) -> &Self::Pcs {
        self.inner.pcs()
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.inner.initialise_challenger()
    }
}

/// Lets the aggregate itself be verified by a further recursion layer, and gives the backend
/// the table provers for proving under this config.
impl FriRecursionConfig for AggConfig {
    type Commitment = MerkleCapTargets<F, 8>;
    type InputProof = AggInputProof;
    type OpeningProof = AggOpeningProof;
    type RawOpeningProof = <AggPcs as p3_commit::Pcs<Challenge, AggChallenger>>::Proof;

    const DIGEST_ELEMS: usize = 8;

    fn native_fri_validation_params(&self) -> Option<NativeFriParams> {
        Some(self.native_fri_params)
    }

    fn with_fri_opening_proof<'a, A, T>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> T,
    ) -> T
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        enable_circuit_ops(circuit);
        Ok(())
    }

    fn pcs_verifier_params(&self) -> &FriVerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        _config: &Self,
        runner: &mut CircuitRunner<'_, Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let fri_params = agg_fri_params();
        let OpeningTranscript {
            mut challenger,
            commitments_with_opening_points,
        } = transcript;
        observe_opened_values::<Self>(
            &mut challenger,
            &commitments_with_opening_points,
            fri_params.batch_proof_of_work_bits,
        );
        let claims: Vec<_> = commitments_with_opening_points
            .into_iter()
            .map(Into::into)
            .collect();
        let query_paths = restore_fri_query_paths(
            &fri_params,
            &agg_mmcs(),
            &agg_mmcs(),
            opening_proof,
            &mut challenger,
            &claims,
        )
        .map_err(|_| "Failed to restore FRI query paths")?;
        set_fri_mmcs_private_data::<F, Challenge, 8>(
            runner,
            op_ids,
            &query_paths,
            POSEIDON2_CIRCUIT,
        )
    }
}

fn enable_circuit_ops(circuit: &mut CircuitBuilder<Challenge>) {
    circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm().clone(),
    );
    circuit.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, Challenge>);
    circuit.set_recompose_coeff_ctl_for_decompose_links(true);
}

// ---------------------------------------------------------------------------------------------
// Circuit.

type Backend = FriRecursionBackendForExt<D, 16, 8, p3_recursion::Poseidon2Config>;
type ChildInputs = StarkVerifierInputsBuilder<
    Config,
    <Config as FriRecursionConfig>::Commitment,
    <Config as FriRecursionConfig>::OpeningProof,
>;

fn backend() -> Backend {
    FriRecursionBackend::<16, 8, _>::new(POSEIDON2_CIRCUIT).for_extension_degree::<D>()
}

/// Allocated verifier inputs of one child proof.
struct ChildSlot {
    inputs: ChildInputs,
    op_ids: Vec<NonPrimitiveOpId>,
}

struct AggCircuit {
    circuit: Circuit<Challenge>,
    slots: Vec<ChildSlot>,
    schema: StatementSchema,
}

/// Base-field value of an extension target, constrained to have zero higher coefficients.
fn base_value(b: &mut CircuitBuilder<Challenge>, x: ExprId) -> Result<ExprId, AggregateError> {
    let coeffs = b
        .decompose_ext_to_base_coeffs_with_coeff_lookups::<BabyBear>(x)
        .map_err(circuit_err)?;
    for &c in &coeffs[1..] {
        b.assert_zero(c);
    }
    Ok(coeffs[0])
}

/// Pack 8 base values into the 2 extension limbs of a Poseidon2 rate (4 coefficients each).
fn limbs(
    b: &mut CircuitBuilder<Challenge>,
    vals: &[ExprId],
) -> Result<Vec<ExprId>, AggregateError> {
    vals.chunks(D)
        .map(|c| {
            b.recompose_base_coeffs_to_ext_with_coeff_lookups::<BabyBear>(c)
                .map_err(circuit_err)
        })
        .collect()
}

/// One width-16 Poseidon2 permutation over 4 extension limbs; returns the 8 base-field
/// outputs, matching the native `truncate(perm(state))` in `hash.rs`.
fn perm_digest(
    b: &mut CircuitBuilder<Challenge>,
    state: [ExprId; 4],
) -> Result<Vec<ExprId>, AggregateError> {
    let (_, outputs) = b
        .add_poseidon2_perm(&Poseidon2PermCall {
            config: POSEIDON2_CIRCUIT,
            new_start: true,
            merkle_path: false,
            mmcs_bit: None,
            mmcs_bit2: None,
            inputs: state.map(Some).to_vec(),
            out_ctl: vec![true, true],
            return_all_outputs: false,
            absorb_len: 0,
        })
        .map_err(circuit_err)?;
    let mut digest = Vec::with_capacity(DIGEST);
    for out in outputs.into_iter().take(2) {
        let limb = out.ok_or_else(|| circuit_err("missing Poseidon2 output"))?;
        digest.extend(
            b.decompose_ext_to_base_coeffs_with_coeff_lookups::<BabyBear>(limb)
                .map_err(circuit_err)?,
        );
    }
    Ok(digest)
}

/// Build the 8-to-1 circuit. Its shape depends only on the shape of `template`, never on its
/// values, so any `VoterAir` proof under [`Config`] yields the same circuit.
fn build_circuit(
    cfg: &Config,
    backend: &Backend,
    template: &Proof,
) -> Result<AggCircuit, AggregateError> {
    let air = VoterAir::default();
    let mut b = CircuitBuilder::<Challenge>::new();
    PcsRecursionBackend::<Config, VoterAir, D>::prepare_circuit(backend, cfg, &mut b)
        .map_err(circuit_err)?;

    // 1. Verify every child and read its public values as base-field targets.
    let mut slots = Vec::with_capacity(NUM_BALLOTS);
    let mut pvs: Vec<Vec<ExprId>> = Vec::with_capacity(NUM_BALLOTS);
    for _ in 0..NUM_BALLOTS {
        let inputs =
            ChildInputs::try_allocate(&mut b, template, None, pv::LEN).map_err(circuit_err)?;
        let op_ids = verify_p3_uni_proof_circuit::<
            VoterAir,
            Config,
            <Config as FriRecursionConfig>::Commitment,
            <Config as FriRecursionConfig>::InputProof,
            <Config as FriRecursionConfig>::OpeningProof,
            _,
            16,
            8,
        >(
            cfg,
            &air,
            &mut b,
            &inputs.proof_targets,
            &inputs.air_public_targets,
            &inputs.preprocessed_commit,
            cfg.pcs_verifier_params(),
            POSEIDON2_CIRCUIT,
        )
        .map_err(circuit_err)?;
        pvs.push(
            inputs
                .air_public_targets
                .iter()
                .map(|&t| base_value(&mut b, t))
                .collect::<Result<_, _>>()?,
        );
        slots.push(ChildSlot { inputs, op_ids });
    }

    // 2. Same eligibility root and election id everywhere.
    for child in &pvs[1..] {
        for j in 0..DIGEST {
            b.connect(child[pv::ROOT + j], pvs[0][pv::ROOT + j]);
        }
        b.connect(child[pv::ELECTION_ID], pvs[0][pv::ELECTION_ID]);
    }

    // 3. Receipt leaves; the nullifier limbs double as input to the distinctness check.
    let zero = b.define_const(Challenge::ZERO);
    let domain = b.define_const(Challenge::from_u32(DOMAIN_RECEIPT));
    let mut nf_limbs = Vec::with_capacity(NUM_BALLOTS);
    let mut level = Vec::with_capacity(NUM_BALLOTS);
    for child in &pvs {
        let nf = limbs(&mut b, &child[pv::NULLIFIER..pv::NULLIFIER + DIGEST])?;
        let tail = limbs(&mut b, &[child[pv::VOTE], domain, zero, zero])?;
        level.push(perm_digest(&mut b, [nf[0], nf[1], tail[0], zero])?);
        nf_limbs.push(nf);
    }

    // 4. Distinct nullifiers: d = Δlimb0 + w·Δlimb1 must be invertible for every pair.
    //    (The map F^8 -> EF has a 4-dimensional kernel, so a false collision needs a
    //    Poseidon2 output to hit a fixed subspace: ~2^-124 per pair.)
    let w = b.define_const(Challenge::from_basis_coefficients_fn(|i| {
        F::from_bool(i == 1)
    }));
    let one = b.define_const(Challenge::ONE);
    for i in 0..NUM_BALLOTS {
        for j in i + 1..NUM_BALLOTS {
            let d0 = b.sub(nf_limbs[i][0], nf_limbs[j][0]);
            let d1 = b.sub(nf_limbs[i][1], nf_limbs[j][1]);
            let wd1 = b.mul(w, d1);
            let d = b.add(d0, wd1);
            let inv = b.div(one, d);
            let check = b.mul(d, inv);
            b.connect(check, one);
        }
    }

    // 5. Receipt root: same pairing as `MerkleTree::new`.
    for _ in 0..DEPTH {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let l = limbs(&mut b, &pair[0])?;
            let r = limbs(&mut b, &pair[1])?;
            next.push(perm_digest(&mut b, [l[0], l[1], r[0], r[1]])?);
        }
        level = next;
    }
    let receipt_root = level.pop().expect("tree has a root");

    // 6. Tally. Each child's AIR already pins vote ∈ {0,1,2}; these are its indicator polynomials.
    let two = b.define_const(Challenge::TWO);
    let half = b.define_const(Challenge::TWO.inverse());
    let mut tally = [zero; NUM_CANDIDATES as usize];
    for child in &pvs {
        let v = child[pv::VOTE];
        let v_1 = b.sub(v, one);
        let v_2 = b.sub(v, two);
        let two_v = b.sub(two, v);
        let p0 = b.mul(v_1, v_2);
        let is0 = b.mul(p0, half);
        let is1 = b.mul(v, two_v);
        let p2 = b.mul(v, v_1);
        let is2 = b.mul(p2, half);
        for (acc, ind) in tally.iter_mut().zip([is0, is1, is2]) {
            *acc = b.add(*acc, ind);
        }
    }

    // 7. Public statement, in `agg_pv` order.
    let mut exports = Vec::with_capacity(agg_pv::LEN);
    exports.extend(
        pvs[0][pv::ROOT..pv::ROOT + DIGEST]
            .iter()
            .map(|&e| StatementExport::Base(e)),
    );
    exports.push(StatementExport::Base(pvs[0][pv::ELECTION_ID]));
    exports.extend(receipt_root.iter().map(|&e| StatementExport::Base(e)));
    exports.extend(tally.iter().map(|&e| StatementExport::Base(e)));
    let schema = b
        .set_statement_exports::<BabyBear>(&exports)
        .map_err(circuit_err)?;
    debug_assert_eq!(schema.base_len(), agg_pv::LEN);

    let circuit = b.build().map_err(circuit_err)?;
    Ok(AggCircuit {
        circuit,
        slots,
        schema,
    })
}

/// Commit to the circuit relation once; returns the batch prover over [`AggConfig`].
fn prepare(
    agg: &AggCircuit,
    backend: &Backend,
) -> Result<p3_circuit_prover::PreparedCircuitProver<AggConfig>, AggregateError> {
    let mut prover = BatchStarkProver::new(AggConfig::new())
        .with_table_packing(TablePacking::new(1, 4))
        .with_alu_variant(AirVariant::Baseline);
    for p in PcsRecursionBackend::<AggConfig, VoterAir, D>::non_primitive_provers(backend, D) {
        prover.register_table_prover(p);
    }
    prover.register_table_prover(Box::new(StatementProver::<D>::new(agg.schema.clone())));
    let mut preprocessors =
        PcsRecursionBackend::<AggConfig, VoterAir, D>::non_primitive_preprocessors(backend);
    preprocessors.push(Box::new(StatementPreprocessor::new(agg.schema.clone())));
    let mut air_builders =
        PcsRecursionBackend::<AggConfig, VoterAir, D>::non_primitive_air_builders(backend);
    air_builders.push(Box::new(StatementAirBuilder::<D>::new(agg.schema.clone())));
    prover
        .prepare_circuit::<Challenge, D>(
            &agg.circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .map_err(|e| AggregateError::Prove(format!("{e:?}")))
}

// ---------------------------------------------------------------------------------------------
// Public API.

pub type AggProof = BatchStarkProof<AggConfig>;

/// Everything the aggregator publishes or hands out.
pub struct AggregateBundle {
    pub proof: AggProof,
    pub statement: AggregateStatement,
    /// Kept by the aggregator to hand each voter their path; not part of the proof.
    pub receipts: Receipts,
}

/// Aggregator side: native pre-checks, then [`aggregate_unchecked`].
///
/// `ballots` must be exactly `NUM_BALLOTS` ballots for the election in `signed`.
pub fn aggregate(ballots: &[Ballot], signed: &SignedRoot) -> Result<AggregateBundle, AggregateError> {
    aggregate_for_root(ballots, &signed.root, signed.election_id)
}

/// Like [`aggregate`], for a caller that only has the (already trusted) root and election id,
/// e.g. the native aggregator service. The registrar signature over `root` is checked by
/// whoever compares `statement.eligibility_root` with the signed root.
pub fn aggregate_for_root(
    ballots: &[Ballot],
    root: &Digest,
    election_id: u32,
) -> Result<AggregateBundle, AggregateError> {
    if ballots.len() != NUM_BALLOTS {
        return Err(AggregateError::WrongCount(ballots.len()));
    }
    let mut children = Vec::with_capacity(NUM_BALLOTS);
    for (i, ballot) in ballots.iter().enumerate() {
        if let Some(j) = ballots[..i]
            .iter()
            .position(|b| b.nullifier == ballot.nullifier)
        {
            return Err(AggregateError::DuplicateNullifier(j, i));
        }
        if ballot.vote >= NUM_CANDIDATES {
            return Err(AggregateError::InvalidChild(i, "vote out of range".into()));
        }
        let proof = deserialize(&ballot.proof).ok_or(AggregateError::MalformedProof(i))?;
        let pis = public_values(root, &ballot.nullifier, election_id, ballot.vote);
        verify_eligibility(&proof, &pis).map_err(|e| AggregateError::InvalidChild(i, e))?;
        children.push((proof, pis));
    }
    aggregate_unchecked(&children)
}

/// Prove the aggregate of `(proof, public values)` pairs without native checks.
///
/// Exposed so tests can show the *circuit* rejects bad children; use [`aggregate`].
#[doc(hidden)]
pub fn aggregate_unchecked(
    children: &[(Proof, Vec<F>)],
) -> Result<AggregateBundle, AggregateError> {
    if children.len() != NUM_BALLOTS {
        return Err(AggregateError::WrongCount(children.len()));
    }
    let cfg = config();
    let backend = backend();
    let agg = build_circuit(&cfg, &backend, &children[0].0)?;

    let mut public = Vec::new();
    let mut private = Vec::new();
    for (i, (slot, (proof, pis))) in agg.slots.iter().zip(children).enumerate() {
        let bad = |e: VerificationError| AggregateError::InvalidChild(i, format!("{e:?}"));
        public.extend(
            slot.inputs
                .try_pack_public_values(pis, proof, &None)
                .map_err(bad)?,
        );
        private.extend(slot.inputs.try_pack_private_values(proof).map_err(bad)?);
    }
    let traces = {
        let mut runner = agg.circuit.runner();
        runner.set_public_inputs(&public).map_err(circuit_err)?;
        runner.set_private_inputs(&private).map_err(circuit_err)?;
        for (i, (slot, (proof, pis))) in agg.slots.iter().zip(children).enumerate() {
            let input = RecursionInput::UniStark {
                proof,
                air: &VoterAir::default(),
                public_inputs: pis.clone(),
                preprocessed_commit: None,
            };
            PcsRecursionBackend::<Config, VoterAir, D>::set_private_data(
                &backend,
                &cfg,
                &mut runner,
                &slot.op_ids,
                &input,
            )
            .map_err(|e| AggregateError::InvalidChild(i, e.to_string()))?;
        }
        runner.run().map_err(circuit_err)?
    };

    let entries: [(Digest, u32); NUM_BALLOTS] = core::array::from_fn(|i| {
        let pis = &children[i].1;
        let nf: Digest = pis[pv::NULLIFIER..pv::NULLIFIER + DIGEST]
            .try_into()
            .unwrap();
        (nf, pis[pv::VOTE].as_canonical_u32())
    });
    let root: Digest = children[0].1[pv::ROOT..pv::ROOT + DIGEST]
        .try_into()
        .unwrap();
    let election_id = children[0].1[pv::ELECTION_ID].as_canonical_u32();
    let statement = AggregateStatement::compute(&root, election_id, &entries);

    let proof = prepare(&agg, &backend)?
        .prove(&traces)
        .map_err(|e| AggregateError::Prove(format!("{e:?}")))?;
    Ok(AggregateBundle {
        proof,
        statement,
        receipts: Receipts::new(&entries),
    })
}

/// Verifier key for aggregate proofs: the committed circuit relation.
pub struct AggregateVerifier(CircuitVerifier<AggConfig>);

impl AggregateVerifier {
    /// Rebuild the key from scratch. Proves one throwaway ballot (random voter, random tree)
    /// only to learn the child proof shape; the result does not depend on it.
    pub fn derive() -> Result<Self, AggregateError> {
        let secret = random_secret();
        let leaves: [Digest; NUM_LEAVES] = core::array::from_fn(|i| {
            if i == 0 {
                hash_leaf(&secret)
            } else {
                hash_leaf(&random_secret())
            }
        });
        let tree = MerkleTree::new(leaves);
        let witness = Witness {
            secret,
            path: tree.path(0),
            election_id: 0,
        };
        let pis = public_values(&tree.root(), &nullifier(&secret, 0), 0, 0);
        let template = prove_eligibility(&witness, &pis).map_err(AggregateError::Prove)?;
        Self::from_template(&template)
    }

    pub fn from_template(template: &Proof) -> Result<Self, AggregateError> {
        let backend = backend();
        let agg = build_circuit(&config(), &backend, template)?;
        Ok(Self(prepare(&agg, &backend)?.verifier()))
    }

    pub fn verify(
        &self,
        proof: &AggProof,
        statement: &AggregateStatement,
    ) -> Result<(), AggregateError> {
        self.0
            .verify(proof, &statement.to_fields())
            .map_err(|e| AggregateError::Verify(format!("{e:?}")))
    }
}

pub fn serialize_agg(proof: &AggProof) -> Vec<u8> {
    postcard::to_allocvec(proof).expect("aggregate proof serialization")
}

pub fn deserialize_agg(bytes: &[u8]) -> Option<AggProof> {
    postcard::from_bytes(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{compress, receipt_leaf};

    /// The in-circuit Poseidon2 gadget must agree with native `receipt_leaf` and `compress`.
    #[test]
    fn in_circuit_poseidon2_matches_native() {
        assert!(
            run_hash_circuit(2, 2).is_ok(),
            "in-circuit hash differs from native"
        );
        // Sanity: the check has teeth.
        assert!(run_hash_circuit(2, 1).is_err());
    }

    /// Circuit hashes `vote`, compares against the native hash of `expected_vote`.
    fn run_hash_circuit(vote: u32, expected_vote: u32) -> Result<(), String> {
        let nf = random_secret();
        let other = random_secret();

        let mut b = CircuitBuilder::<Challenge>::new();
        enable_circuit_ops(&mut b);
        let pi: Vec<ExprId> = (0..DIGEST * 2 + 1).map(|_| b.public_input()).collect();
        let base: Vec<ExprId> = pi.iter().map(|&t| base_value(&mut b, t).unwrap()).collect();
        let zero = b.define_const(Challenge::ZERO);
        let domain = b.define_const(Challenge::from_u32(DOMAIN_RECEIPT));
        let n = limbs(&mut b, &base[..DIGEST]).unwrap();
        let tail = limbs(&mut b, &[base[2 * DIGEST], domain, zero, zero]).unwrap();
        let leaf = perm_digest(&mut b, [n[0], n[1], tail[0], zero]).unwrap();
        let o = limbs(&mut b, &base[DIGEST..2 * DIGEST]).unwrap();
        let l = limbs(&mut b, &leaf).unwrap();
        let node = perm_digest(&mut b, [l[0], l[1], o[0], o[1]]).unwrap();
        let expected_leaf = receipt_leaf(&nf, expected_vote);
        let expected_node = compress(&expected_leaf, &other);
        for j in 0..DIGEST {
            let c = b.define_const(Challenge::from(expected_node[j]));
            b.connect(node[j], c);
            let c = b.define_const(Challenge::from(expected_leaf[j]));
            b.connect(leaf[j], c);
        }
        let circuit = b.build().unwrap();

        let mut inputs: Vec<Challenge> = nf
            .iter()
            .chain(&other)
            .map(|&x| Challenge::from(x))
            .collect();
        inputs.push(Challenge::from_u32(vote));
        let mut runner = circuit.runner();
        runner.set_public_inputs(&inputs).unwrap();
        runner.run().map(|_| ()).map_err(|e| format!("{e:?}"))
    }
}
