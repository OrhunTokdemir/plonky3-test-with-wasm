//! Native Poseidon2 hashing over BabyBear (width 16).
//!
//! Every hash here is a single Poseidon2 permutation truncated to 8 elements, which is
//! exactly what one row of the AIR computes. That keeps native and in-circuit values identical.

use std::sync::OnceLock;

use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;

pub type F = BabyBear;
pub const WIDTH: usize = 16;
pub const DIGEST: usize = 8;
pub type Digest = [F; DIGEST];

/// Domain-separation tags placed in the capacity half of the state.
pub const DOMAIN_LEAF: u32 = 1;
pub const DOMAIN_NULLIFIER: u32 = 2;
pub const DOMAIN_RECEIPT: u32 = 3;

pub fn perm() -> &'static Poseidon2BabyBear<WIDTH> {
    static PERM: OnceLock<Poseidon2BabyBear<WIDTH>> = OnceLock::new();
    PERM.get_or_init(default_babybear_poseidon2_16)
}

fn truncate(state: [F; WIDTH]) -> Digest {
    state[..DIGEST].try_into().unwrap()
}

pub fn leaf_input(secret: &Digest) -> [F; WIDTH] {
    let mut s = [F::ZERO; WIDTH];
    s[..DIGEST].copy_from_slice(secret);
    s[DIGEST] = F::from_u32(DOMAIN_LEAF);
    s
}

pub fn compress_input(left: &Digest, right: &Digest) -> [F; WIDTH] {
    let mut s = [F::ZERO; WIDTH];
    s[..DIGEST].copy_from_slice(left);
    s[DIGEST..].copy_from_slice(right);
    s
}

pub fn nullifier_input(secret: &Digest, election_id: u32) -> [F; WIDTH] {
    let mut s = [F::ZERO; WIDTH];
    s[..DIGEST].copy_from_slice(secret);
    s[DIGEST] = F::from_u32(election_id);
    s[DIGEST + 1] = F::from_u32(DOMAIN_NULLIFIER);
    s
}

pub fn receipt_input(nullifier: &Digest, vote: u32) -> [F; WIDTH] {
    let mut s = [F::ZERO; WIDTH];
    s[..DIGEST].copy_from_slice(nullifier);
    s[DIGEST] = F::from_u32(vote);
    s[DIGEST + 1] = F::from_u32(DOMAIN_RECEIPT);
    s
}

pub fn hash_leaf(secret: &Digest) -> Digest {
    truncate(perm().permute(leaf_input(secret)))
}

pub fn compress(left: &Digest, right: &Digest) -> Digest {
    truncate(perm().permute(compress_input(left, right)))
}

pub fn nullifier(secret: &Digest, election_id: u32) -> Digest {
    truncate(perm().permute(nullifier_input(secret, election_id)))
}

/// Leaf of the receipt tree published by an aggregate proof: `H(nullifier ‖ vote ‖ DOMAIN_RECEIPT)`.
pub fn receipt_leaf(nullifier: &Digest, vote: u32) -> Digest {
    truncate(perm().permute(receipt_input(nullifier, vote)))
}
