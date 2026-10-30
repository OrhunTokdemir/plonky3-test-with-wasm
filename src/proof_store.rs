//! Portable binary ballot files: `proofs/<nullifier-hex>.bin`.
//!
//! Layout: `MAGIC` followed by the postcard encoding of [`ProofFile`]. The proof itself is the
//! same postcard bytes that [`crate::stark::serialize`] produces, so the file is barely larger
//! than the raw proof.
//!
//! A file carries everything a remote verifier needs except the registrar's verifying key, which
//! must be pinned out-of-band (taking it from the file would let anyone sign their own root).
//! Files are named by nullifier, never by voter index, so they don't link a ballot to a voter.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ml_dsa::{MlDsa65, Signature, VerifyingKey};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};

use crate::ballot::{Ballot, BallotBox, BallotError};
use crate::hash::{Digest, F};
use crate::registry::SignedRoot;
use crate::stark::{deserialize, serialize};

pub const FORMAT_VERSION: u32 = 2;
const MAGIC: &[u8; 4] = b"VSTK";

#[derive(Serialize, Deserialize)]
pub struct ProofFile {
    pub version: u32,
    pub election_id: u32,
    pub root: [u32; 8],
    /// ML-DSA-65 encoded signature over `(election_id, root)`.
    pub root_signature: Vec<u8>,
    pub nullifier: [u32; 8],
    pub vote: u32,
    /// Postcard-encoded STARK proof.
    pub proof: Vec<u8>,
}

impl ProofFile {
    pub fn new(signed: &SignedRoot, ballot: &Ballot) -> Result<Self, BallotError> {
        let proof = deserialize(&ballot.proof).ok_or(BallotError::MalformedProof)?;
        Ok(Self {
            version: FORMAT_VERSION,
            election_id: signed.election_id,
            root: to_u32s(&signed.root),
            root_signature: signed.signature.encode().to_vec(),
            nullifier: to_u32s(&ballot.nullifier),
            vote: ballot.vote,
            proof: serialize(&proof),
        })
    }

    pub fn signed_root(&self) -> Result<SignedRoot, BallotError> {
        let signature = Signature::<MlDsa65>::try_from(self.root_signature.as_slice())
            .map_err(|_| BallotError::BadRootSignature)?;
        Ok(SignedRoot {
            election_id: self.election_id,
            root: from_u32s(&self.root).ok_or(BallotError::MalformedProof)?,
            signature,
        })
    }

    pub fn ballot(&self) -> Result<Ballot, BallotError> {
        let proof = deserialize(&self.proof).ok_or(BallotError::MalformedProof)?;
        Ok(Ballot {
            nullifier: from_u32s(&self.nullifier).ok_or(BallotError::MalformedProof)?,
            vote: self.vote,
            proof: serialize(&proof),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_extend(self, MAGIC.to_vec()).expect("proof file serialization")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BallotError> {
        let body = bytes.strip_prefix(MAGIC).ok_or(BallotError::MalformedProof)?;
        let (file, rest): (Self, _) =
            postcard::take_from_bytes(body).map_err(|_| BallotError::MalformedProof)?;
        if !rest.is_empty() || file.version != FORMAT_VERSION {
            return Err(BallotError::MalformedProof);
        }
        Ok(file)
    }
}

/// Standalone check for another device: root signed by the pinned registrar key, valid STARK.
/// Double voting is not checked here; the receiver keeps its own nullifier set.
pub fn verify_file(file: &ProofFile, registrar_vk: &VerifyingKey<MlDsa65>) -> Result<(), BallotError> {
    BallotBox::new(file.signed_root()?, registrar_vk)?.check(&file.ballot()?)
}

pub fn save(dir: impl AsRef<Path>, signed: &SignedRoot, ballot: &Ballot) -> io::Result<PathBuf> {
    let file = ProofFile::new(signed, ballot)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    fs::create_dir_all(&dir)?;
    let path = dir
        .as_ref()
        .join(format!("{}.bin", to_hex_u32s(&file.nullifier)));
    fs::write(&path, file.to_bytes())?;
    Ok(path)
}

pub fn load(path: impl AsRef<Path>) -> Result<ProofFile, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    ProofFile::from_bytes(&bytes).map_err(|e| format!("{e:?}"))
}

fn to_u32s(d: &Digest) -> [u32; 8] {
    d.map(|x| x.as_canonical_u32())
}

/// Rejects non-canonical values so every digest has exactly one encoding.
fn from_u32s(v: &[u32; 8]) -> Option<Digest> {
    if v.iter().any(|&x| x >= F::ORDER_U32) {
        return None;
    }
    Some(v.map(F::from_u32))
}

fn to_hex_u32s(v: &[u32; 8]) -> String {
    v.iter().map(|x| format!("{x:08x}")).collect()
}
