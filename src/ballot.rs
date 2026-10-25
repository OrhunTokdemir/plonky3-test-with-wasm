//! Ballot box: accepts a ballot only if the root is registrar-signed, the STARK verifies,
//! and the nullifier has not been seen before.

use std::collections::HashSet;

use ml_dsa::{MlDsa65, VerifyingKey};
use p3_field::PrimeField32;

use crate::air::{NUM_CANDIDATES, Witness, public_values};
use crate::hash::{Digest, nullifier};
use crate::registry::{SignedRoot, Voter};
use crate::stark::{deserialize, prove_eligibility, serialize, verify_eligibility};
use crate::tree::MerkleTree;

/// What a voter submits. Contains no identity, leaf or path.
#[derive(Clone)]
pub struct Ballot {
    pub nullifier: Digest,
    pub vote: u32,
    pub proof: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BallotError {
    BadRootSignature,
    InvalidVote,
    MalformedProof,
    InvalidProof(String),
    DoubleVote,
}

/// Voter side: build the private witness from the tree path and prove.
pub fn cast_ballot(
    voter: &Voter,
    tree: &MerkleTree,
    signed: &SignedRoot,
    vote: u32,
) -> Result<Ballot, String> {
    let witness = Witness {
        secret: voter.secret,
        path: tree.path(voter.index),
        election_id: signed.election_id,
    };
    let nf = nullifier(&voter.secret, signed.election_id);
    let pis = public_values(&signed.root, &nf, signed.election_id, vote);
    let proof = prove_eligibility(&witness, &pis)?;
    Ok(Ballot {
        nullifier: nf,
        vote,
        proof: serialize(&proof),
    })
}

pub struct BallotBox {
    signed: SignedRoot,
    spent: HashSet<[u32; 8]>,
    pub tally: [u32; NUM_CANDIDATES as usize],
}

impl BallotBox {
    pub fn new(signed: SignedRoot, registrar_vk: &VerifyingKey<MlDsa65>) -> Result<Self, BallotError> {
        if !signed.verify(registrar_vk) {
            return Err(BallotError::BadRootSignature);
        }
        Ok(Self {
            signed,
            spent: HashSet::new(),
            tally: [0; NUM_CANDIDATES as usize],
        })
    }

    /// Verify a ballot without recording it.
    pub fn check(&self, ballot: &Ballot) -> Result<(), BallotError> {
        if ballot.vote >= NUM_CANDIDATES {
            return Err(BallotError::InvalidVote);
        }
        if self.spent.contains(&key(&ballot.nullifier)) {
            return Err(BallotError::DoubleVote);
        }
        let proof = deserialize(&ballot.proof).ok_or(BallotError::MalformedProof)?;
        let pis = public_values(
            &self.signed.root,
            &ballot.nullifier,
            self.signed.election_id,
            ballot.vote,
        );
        verify_eligibility(&proof, &pis).map_err(BallotError::InvalidProof)
    }

    pub fn submit(&mut self, ballot: &Ballot) -> Result<(), BallotError> {
        self.check(ballot)?;
        self.spent.insert(key(&ballot.nullifier));
        self.tally[ballot.vote as usize] += 1;
        Ok(())
    }
}

fn key(d: &Digest) -> [u32; 8] {
    d.map(|x| x.as_canonical_u32())
}
