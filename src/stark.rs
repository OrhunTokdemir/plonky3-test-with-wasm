//! Zero-knowledge STARK configuration (Plonky3 uni-stark + hiding FRI) and prove/verify helpers.
//!
//! Everything is hash-based (Poseidon2 over BabyBear), so there are no elliptic-curve or
//! factoring assumptions anywhere in the proof system.
//!
//! With the `aggregation` feature, [`Config`] can also be verified inside a Plonky3-recursion
//! circuit (see `crate::aggregate`). Without it (the wasm build) no recursion code is compiled.

use p3_baby_bear::Poseidon2BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::air::{VoterAir, Witness, generate_trace};
use crate::hash::{F, perm};

type Perm = Poseidon2BabyBear<16>;
pub(crate) type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub(crate) type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
/// Salted (hiding) Merkle commitments: 4 salt elements per leaf.
pub(crate) type ValMmcs = MerkleTreeHidingMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    Hash,
    Compress,
    StdRng,
    2,
    8,
    4,
>;
/// Unsalted twin of `ValMmcs`, used only to rebuild Merkle paths for the recursive verifier.
#[cfg(feature = "aggregation")]
pub(crate) type PlainMmcs = p3_merkle_tree::MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, Hash, Compress, 2, 8>;
/// Degree-4 extension: ~124-bit challenge space.
pub type Challenge = BinomialExtensionField<F, 4>;
pub(crate) type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
pub(crate) type Challenger = DuplexChallenger<F, Perm, 16, 8>;
type Dft = Radix2DitParallel<F>;
pub(crate) type Pcs = HidingFriPcs<F, Dft, ValMmcs, ChallengeMmcs, StdRng>;
type Inner = StarkConfig<Pcs, Challenge, Challenger>;
pub type Proof = p3_uni_stark::Proof<Config>;

/// Random codewords mixed into the committed traces (must be >= extension degree).
const NUM_RANDOM_CODEWORDS: usize = 4;
/// Merkle cap height of every commitment (0 = a single root).
const CAP_HEIGHT: usize = 0;

/// FRI parameters: blowup 8, 38 queries, 16-bit query grinding (~130 conjectured bits),
/// folding arity 8. Few queries and few folding rounds keep the recursive verifier circuit small;
/// batch grinding stays off because the recursive verifier does not support it.
pub fn fri_params<M>(mmcs: M) -> FriParameters<M> {
    FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 3,
        num_queries: 38,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 16,
        mmcs,
    }
}

fn os_rng() -> StdRng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness unavailable");
    StdRng::from_seed(seed)
}

pub(crate) fn hiding_mmcs(rng: StdRng) -> ValMmcs {
    ValMmcs::new(Hash::new(perm().clone()), Compress::new(perm().clone()), CAP_HEIGHT, rng)
}

#[cfg(feature = "aggregation")]
pub(crate) fn plain_mmcs() -> PlainMmcs {
    PlainMmcs::new(Hash::new(perm().clone()), Compress::new(perm().clone()), CAP_HEIGHT)
}

/// STARK config, plus (with `aggregation`) the FRI parameters the recursive verifier needs.
#[derive(Clone)]
pub struct Config {
    inner: Inner,
    #[cfg(feature = "aggregation")]
    pub(crate) recursion: crate::aggregate::LeafRecursionParams,
}

impl StarkGenericConfig for Config {
    type Pcs = Pcs;
    type Challenge = Challenge;
    type Challenger = Challenger;

    fn pcs(&self) -> &Self::Pcs {
        self.inner.pcs()
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.inner.initialise_challenger()
    }
}

/// Build a config. Hiding salts and masks are drawn from fresh OS randomness;
/// predictable seeds would let an observer strip the masks and break zero knowledge.
/// Trace commitments, FRI commitments and random codewords each get their own RNG.
pub fn config() -> Config {
    let params = fri_params(ChallengeMmcs::new(hiding_mmcs(os_rng())));
    #[cfg(feature = "aggregation")]
    let recursion = crate::aggregate::LeafRecursionParams::new(&params);
    let pcs = Pcs::new(
        Dft::default(),
        hiding_mmcs(os_rng()),
        params,
        NUM_RANDOM_CODEWORDS,
        os_rng(),
    );
    Config {
        inner: Inner::new(pcs, Challenger::new(perm().clone())),
        #[cfg(feature = "aggregation")]
        recursion,
    }
}

pub fn prove_eligibility(witness: &Witness, public_values: &[F]) -> Result<Proof, String> {
    let trace = generate_trace(witness);
    prove(&config(), &VoterAir::default(), trace, public_values).map_err(|e| format!("{e:?}"))
}

pub fn verify_eligibility(proof: &Proof, public_values: &[F]) -> Result<(), String> {
    verify(&config(), &VoterAir::default(), proof, public_values).map_err(|e| format!("{e:?}"))
}

pub fn serialize(proof: &Proof) -> Vec<u8> {
    postcard::to_allocvec(proof).expect("proof serialization")
}

pub fn deserialize(bytes: &[u8]) -> Option<Proof> {
    postcard::from_bytes(bytes).ok()
}
