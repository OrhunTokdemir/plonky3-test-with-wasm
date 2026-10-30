//! wasm-bindgen wrapper around `voter_stark` for in-browser benchmarking.
//!
//! `Election` is the registrar + ballot box (lives in one coordinator worker).
//! `prove_ballot` is stateless so any number of workers can prove in parallel.
//! Timing is done in JS with `performance.now()`; `std::time::Instant` panics on wasm32.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use voter_stark::air::{NUM_CANDIDATES, Witness, public_values};
use voter_stark::ballot::{Ballot, BallotBox};
use voter_stark::hash::{DIGEST, Digest, F, hash_leaf, nullifier};
use voter_stark::registry::{Registrar, SignedRoot, Voter};
use voter_stark::stark::{prove_eligibility, serialize};
use voter_stark::tree::{MerkleTree, NUM_LEAVES};
use wasm_bindgen::prelude::*;

const ELECTION_ID: u32 = 2026;

#[wasm_bindgen]
pub struct Election {
    voters: Vec<Voter>,
    signed: SignedRoot,
    ballot_box: BallotBox,
}

#[wasm_bindgen]
impl Election {
    /// ML-DSA-65 keygen, register 8 voters, sign the root, open the ballot box.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Election, JsError> {
        let registrar = Registrar::new();
        let (voters, _tree, signed) = registrar.register(ELECTION_ID);
        let ballot_box = BallotBox::new(signed.clone(), &registrar.verifying_key())
            .map_err(|e| JsError::new(&format!("{e:?}")))?;
        Ok(Election {
            voters,
            signed,
            ballot_box,
        })
    }

    /// All voter secrets, flattened (NUM_LEAVES x DIGEST). Handed to prover workers.
    pub fn secrets(&self) -> Vec<u32> {
        self.voters
            .iter()
            .flat_map(|v| v.secret.map(|x| x.as_canonical_u32()))
            .collect()
    }

    pub fn election_id(&self) -> u32 {
        self.signed.election_id
    }

    /// Verify and record a ballot. Returns `Ok(())` or the `BallotError` as text.
    pub fn submit(&mut self, nullifier: &[u32], vote: u32, proof: &[u8]) -> Result<String, JsError> {
        let ballot = Ballot {
            nullifier: to_digest(nullifier)?,
            vote,
            proof: proof.to_vec(),
        };
        Ok(format!("{:?}", self.ballot_box.submit(&ballot)))
    }

    pub fn tally(&self) -> Vec<u32> {
        self.ballot_box.tally.to_vec()
    }
}

#[wasm_bindgen]
pub struct ProvedBallot {
    nullifier: Vec<u32>,
    proof: Vec<u8>,
}

#[wasm_bindgen]
impl ProvedBallot {
    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> Vec<u32> {
        self.nullifier.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> Vec<u8> {
        self.proof.clone()
    }
}

/// Voter side: rebuild the tree from the secrets and prove eligibility for voter `index`.
#[wasm_bindgen]
pub fn prove_ballot(
    secrets: &[u32],
    election_id: u32,
    index: usize,
    vote: u32,
) -> Result<ProvedBallot, JsError> {
    if secrets.len() != NUM_LEAVES * DIGEST || index >= NUM_LEAVES {
        return Err(JsError::new("bad secrets length or voter index"));
    }
    let secrets: Vec<Digest> = secrets
        .chunks(DIGEST)
        .map(to_digest)
        .collect::<Result<_, _>>()?;
    let leaves: [Digest; NUM_LEAVES] = core::array::from_fn(|i| hash_leaf(&secrets[i]));
    let tree = MerkleTree::new(leaves);
    let secret = secrets[index];
    let nf = nullifier(&secret, election_id);
    let witness = Witness {
        secret,
        path: tree.path(index),
        election_id,
    };
    let pis = public_values(&tree.root(), &nf, election_id, vote);
    let proof = prove_eligibility(&witness, &pis).map_err(|e| JsError::new(&e))?;
    Ok(ProvedBallot {
        nullifier: nf.map(|x| x.as_canonical_u32()).to_vec(),
        proof: serialize(&proof),
    })
}

#[wasm_bindgen]
pub fn num_voters() -> usize {
    NUM_LEAVES
}

#[wasm_bindgen]
pub fn num_candidates() -> u32 {
    NUM_CANDIDATES
}

fn to_digest(v: &[u32]) -> Result<Digest, JsError> {
    let v: [u32; DIGEST] = v
        .try_into()
        .map_err(|_| JsError::new("digest must be 8 u32s"))?;
    if v.iter().any(|&x| x >= F::ORDER_U32) {
        return Err(JsError::new("non-canonical field element"));
    }
    Ok(v.map(F::from_u32))
}
