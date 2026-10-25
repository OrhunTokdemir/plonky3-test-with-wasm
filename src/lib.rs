//! Proof of concept: private, post-quantum voter-eligibility proofs.
//!
//! - 8 voters (2^3 Merkle tree), leaves are `Poseidon2(secret)`.
//! - A zero-knowledge Plonky3 STARK proves "I know a secret whose leaf is in the tree with this
//!   root", and outputs a nullifier `Poseidon2(secret, election_id)` to stop double voting.
//! - The vote is a public input bound to the proof.
//! - The registrar signs `(election_id, root)` with ML-DSA-65 (FIPS 204).
//!
//! NOT AUDITED. Post-quantum security of the STARK rests on Poseidon2 collision resistance with
//! 248-bit digests (~124-bit classical, lower against quantum collision search) and the
//! degree-4 extension field (~124-bit challenge space). Zero knowledge relies on Plonky3's
//! hiding FRI PCS seeded from OS randomness.

pub mod air;
pub mod ballot;
pub mod hash;
pub mod registry;
pub mod stark;
pub mod tree;
