//! Fixed-depth (2^3 = 8 leaves) Poseidon2 Merkle tree of voter commitments.

use crate::hash::{Digest, compress};

pub const DEPTH: usize = 3;
pub const NUM_LEAVES: usize = 1 << DEPTH;

/// Authentication path for one leaf, ordered from the leaf level up.
#[derive(Clone, Debug)]
pub struct MerklePath {
    pub siblings: [Digest; DEPTH],
    /// `bits[k] == true` means the running node is the *right* child at level `k`.
    pub bits: [bool; DEPTH],
}

pub struct MerkleTree {
    /// `levels[0]` are the leaves, `levels[DEPTH]` holds only the root.
    levels: Vec<Vec<Digest>>,
}

impl MerkleTree {
    pub fn new(leaves: [Digest; NUM_LEAVES]) -> Self {
        let mut levels = vec![leaves.to_vec()];
        for _ in 0..DEPTH {
            let prev = levels.last().unwrap();
            let next = prev.chunks(2).map(|p| compress(&p[0], &p[1])).collect();
            levels.push(next);
        }
        Self { levels }
    }

    pub fn root(&self) -> Digest {
        self.levels[DEPTH][0]
    }

    pub fn leaf(&self, index: usize) -> Digest {
        self.levels[0][index]
    }

    pub fn path(&self, index: usize) -> MerklePath {
        assert!(index < NUM_LEAVES);
        let mut siblings = [[Default::default(); 8]; DEPTH];
        let mut bits = [false; DEPTH];
        for k in 0..DEPTH {
            let i = index >> k;
            siblings[k] = self.levels[k][i ^ 1];
            bits[k] = i & 1 == 1;
        }
        MerklePath { siblings, bits }
    }
}

/// Recompute the root from a leaf and its path (native reference for the AIR).
pub fn root_from_path(leaf: &Digest, path: &MerklePath) -> Digest {
    let mut node = *leaf;
    for k in 0..DEPTH {
        node = if path.bits[k] {
            compress(&path.siblings[k], &node)
        } else {
            compress(&node, &path.siblings[k])
        };
    }
    node
}
