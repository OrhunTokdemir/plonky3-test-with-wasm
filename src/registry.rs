//! Registrar: builds the voter tree and signs `(election_id, root)` with ML-DSA-65 (FIPS 204).

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{Generate, MlDsa65, Signature, SigningKey, VerifyingKey};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::hash::{DIGEST, Digest, F, hash_leaf};
use crate::tree::{MerkleTree, NUM_LEAVES};

const ROOT_DOMAIN: &[u8] = b"voter-stark/signed-root/v1";

#[derive(Clone)]
pub struct SignedRoot {
    pub election_id: u32,
    pub root: Digest,
    pub signature: Signature<MlDsa65>,
}

fn root_message(election_id: u32, root: &Digest) -> Vec<u8> {
    let mut m = ROOT_DOMAIN.to_vec();
    m.extend_from_slice(&election_id.to_le_bytes());
    for x in root {
        m.extend_from_slice(&x.as_canonical_u32().to_le_bytes());
    }
    m
}

impl SignedRoot {
    pub fn verify(&self, vk: &VerifyingKey<MlDsa65>) -> bool {
        vk.verify(&root_message(self.election_id, &self.root), &self.signature)
            .is_ok()
    }
}

/// A voter's private credential.
#[derive(Clone)]
pub struct Voter {
    pub index: usize,
    pub secret: Digest,
}

/// Uniformly random secret of 8 BabyBear elements (~248 bits).
pub fn random_secret() -> Digest {
    core::array::from_fn(|_| loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("OS randomness unavailable");
        let x = u32::from_le_bytes(b) & 0x7fff_ffff;
        if x < F::ORDER_U32 {
            break F::from_u32(x);
        }
    })
}

pub struct Registrar {
    signing_key: SigningKey<MlDsa65>,
}

impl Registrar {
    pub fn new() -> Self {
        Self {
            signing_key: SigningKey::<MlDsa65>::generate(),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        self.signing_key.verifying_key()
    }

    /// Register `NUM_LEAVES` voters: each gets a secret, the tree stores only `H(secret)`.
    pub fn register(&self, election_id: u32) -> (Vec<Voter>, MerkleTree, SignedRoot) {
        let voters: Vec<Voter> = (0..NUM_LEAVES)
            .map(|index| Voter {
                index,
                secret: random_secret(),
            })
            .collect();
        let leaves: [Digest; NUM_LEAVES] = core::array::from_fn(|i| hash_leaf(&voters[i].secret));
        let tree = MerkleTree::new(leaves);
        let root = tree.root();
        let signature = self.signing_key.sign(&root_message(election_id, &root));
        let signed = SignedRoot {
            election_id,
            root,
            signature,
        };
        (voters, tree, signed)
    }
}

impl Default for Registrar {
    fn default() -> Self {
        Self::new()
    }
}

pub fn digest_hex(d: &Digest) -> String {
    d.iter()
        .take(DIGEST / 2)
        .map(|x| format!("{:08x}", x.as_canonical_u32()))
        .collect::<String>()
        + "…"
}
