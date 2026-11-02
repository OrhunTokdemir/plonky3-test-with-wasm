//! Receipt tree: lets each voter check their own ballot against an aggregate proof.
//!
//! The aggregate proof publishes `receipt_root`, the root of a depth-3 Merkle tree whose leaf `i`
//! is `receipt_leaf(nullifier_i, vote_i)` (in ballot order). The aggregator hands each voter
//! the authentication path for their leaf. The voter recomputes the leaf from their own
//! nullifier and vote, so they learn nothing about other ballots beyond sibling hashes.

use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::hash::{DIGEST, Digest, F, receipt_leaf};
use crate::tree::{DEPTH, MerklePath, MerkleTree, NUM_LEAVES, root_from_path};

/// Flat `u32` length of an encoded [`MerklePath`]: siblings then direction bits.
pub const PATH_U32S: usize = DEPTH * DIGEST + DEPTH;

pub struct Receipts {
    entries: Vec<(Digest, u32)>,
    tree: MerkleTree,
}

impl Receipts {
    /// `entries[i] = (nullifier, vote)` of the `i`-th aggregated ballot.
    pub fn new(entries: &[(Digest, u32); NUM_LEAVES]) -> Self {
        let leaves = entries.map(|(nf, vote)| receipt_leaf(&nf, vote));
        Self {
            entries: entries.to_vec(),
            tree: MerkleTree::new(leaves),
        }
    }

    pub fn root(&self) -> Digest {
        self.tree.root()
    }

    pub fn index_of(&self, nullifier: &Digest) -> Option<usize> {
        self.entries.iter().position(|(nf, _)| nf == nullifier)
    }

    pub fn path(&self, index: usize) -> MerklePath {
        self.tree.path(index)
    }
}

/// Voter side: is `(nullifier, vote)` committed under `receipt_root`?
pub fn verify_receipt(
    nullifier: &Digest,
    vote: u32,
    path: &MerklePath,
    receipt_root: &Digest,
) -> bool {
    root_from_path(&receipt_leaf(nullifier, vote), path) == *receipt_root
}

pub fn encode_path(path: &MerklePath) -> Vec<u32> {
    let mut out: Vec<u32> = path
        .siblings
        .iter()
        .flat_map(|s| s.map(|x| x.as_canonical_u32()))
        .collect();
    out.extend(path.bits.map(u32::from));
    out
}

/// Rejects wrong lengths, non-canonical field elements and non-boolean bits.
pub fn decode_path(v: &[u32]) -> Option<MerklePath> {
    if v.len() != PATH_U32S || v.iter().any(|&x| x >= F::ORDER_U32) {
        return None;
    }
    let (sib, bits) = v.split_at(DEPTH * DIGEST);
    if bits.iter().any(|&b| b > 1) {
        return None;
    }
    Some(MerklePath {
        siblings: core::array::from_fn(|k| {
            core::array::from_fn(|j| F::from_u32(sib[k * DIGEST + j]))
        }),
        bits: core::array::from_fn(|k| bits[k] == 1),
    })
}
