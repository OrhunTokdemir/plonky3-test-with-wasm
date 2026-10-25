//! Zero-knowledge STARK configuration (Plonky3 uni-stark + hiding FRI) and prove/verify helpers.
//!
//! Everything is hash-based (Poseidon2 over BabyBear), so there are no elliptic-curve or
//! factoring assumptions anywhere in the proof system.

use p3_baby_bear::Poseidon2BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::air::{VoterAir, Witness, generate_trace};
use crate::hash::{F, perm};

type Perm = Poseidon2BabyBear<16>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
/// Salted (hiding) Merkle commitments: 4 salt elements per leaf.
type ValMmcs = MerkleTreeHidingMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    Hash,
    Compress,
    StdRng,
    2,
    8,
    4,
>;
/// Degree-4 extension: ~124-bit challenge space.
type Challenge = BinomialExtensionField<F, 4>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm, 16, 8>;
type Dft = Radix2DitParallel<F>;
type Pcs = HidingFriPcs<F, Dft, ValMmcs, ChallengeMmcs, StdRng>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub type Proof = p3_uni_stark::Proof<Config>;

/// Random codewords mixed into the committed traces (must be >= extension degree).
const NUM_RANDOM_CODEWORDS: usize = 4;

/// FRI parameters: blowup 4, 100 queries, 16-bit query grinding + 10-bit batch grinding.
pub fn fri_params(mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
    FriParameters::new_benchmark_zk(mmcs)
}

fn os_rng() -> StdRng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness unavailable");
    StdRng::from_seed(seed)
}

/// Build a config. Hiding salts and masks are drawn from fresh OS randomness;
/// predictable seeds would let an observer strip the masks and break zero knowledge.
pub fn config() -> Config {
    let hash = Hash::new(perm().clone());
    let compress = Compress::new(perm().clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0, os_rng());
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let pcs = Pcs::new(
        Dft::default(),
        val_mmcs,
        fri_params(challenge_mmcs),
        NUM_RANDOM_CODEWORDS,
        os_rng(),
    );
    Config::new(pcs, Challenger::new(perm().clone()))
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
