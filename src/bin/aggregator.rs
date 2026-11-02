//! Native aggregator service: one JSON request on stdin, one JSON response on stdout.
//!
//! Recursive aggregation is too heavy for wasm, so the web app's API route
//! (`web/app/api/aggregate/route.ts`) runs this binary. It aggregates the browser's 8 ballots,
//! verifies the aggregate with an independently derived key, saves the proof under `proofs/`, and
//! returns the public statement plus every ballot's receipt path. The browser then lets each
//! voter check their own receipt in wasm.
//!
//! Request:  `{ root: [u32; 8], electionId, ballots: [{ nullifier: [u32; 8], vote, proof: [u8] }] }`
//! Response: `{ ok, error?, aggregateMs, deriveMs, verifyMs, verify, proofBytes, proofFile,
//!              statement: [u32; 20], receipts: [[u32; 27]; 8] }` (`receipts[i]` is ballot `i`'s path)
//!
//! Progress goes to stderr.

use std::io::Read;
use std::time::Instant;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};
use voter_stark::aggregate::{AggregateVerifier, aggregate_for_root, serialize_agg};
use voter_stark::ballot::Ballot;
use voter_stark::hash::{Digest, F};
use voter_stark::receipts::encode_path;

const PROOF_DIR: &str = "proofs";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    root: [u32; 8],
    election_id: u32,
    ballots: Vec<BallotIn>,
}

#[derive(Deserialize)]
struct BallotIn {
    nullifier: [u32; 8],
    vote: u32,
    proof: Vec<u8>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    aggregate_ms: f64,
    derive_ms: f64,
    verify_ms: f64,
    verify: String,
    proof_bytes: usize,
    proof_file: String,
    statement: Vec<u32>,
    receipts: Vec<Vec<u32>>,
}

fn main() {
    let response = run().unwrap_or_else(|error| Response {
        error: Some(error),
        ..Default::default()
    });
    println!("{}", serde_json::to_string(&response).expect("response serialization"));
}

fn run() -> Result<Response, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let req: Request = serde_json::from_str(&input).map_err(|e| format!("bad request: {e}"))?;
    let root = digest(&req.root).ok_or("non-canonical root")?;
    let ballots = req
        .ballots
        .into_iter()
        .map(|b| {
            Ok(Ballot {
                nullifier: digest(&b.nullifier).ok_or("non-canonical nullifier")?,
                vote: b.vote,
                proof: b.proof,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    eprintln!("aggregating {} ballots…", ballots.len());
    let t = Instant::now();
    let bundle = aggregate_for_root(&ballots, &root, req.election_id).map_err(|e| format!("{e:?}"))?;
    let aggregate_ms = ms(t);

    eprintln!("deriving verifier key…");
    let t = Instant::now();
    let verifier = AggregateVerifier::derive().map_err(|e| format!("{e:?}"))?;
    let derive_ms = ms(t);
    let t = Instant::now();
    let verify = format!("{:?}", verifier.verify(&bundle.proof, &bundle.statement));
    let verify_ms = ms(t);

    let bytes = serialize_agg(&bundle.proof);
    let hex: String = bundle
        .statement
        .receipt_root
        .iter()
        .map(|x| format!("{:08x}", x.as_canonical_u32()))
        .collect();
    let proof_file = format!("{PROOF_DIR}/aggregate-{hex}.bin");
    std::fs::create_dir_all(PROOF_DIR).map_err(|e| e.to_string())?;
    std::fs::write(&proof_file, &bytes).map_err(|e| e.to_string())?;
    eprintln!("done: {verify}, saved {proof_file}");

    Ok(Response {
        ok: true,
        error: None,
        aggregate_ms,
        derive_ms,
        verify_ms,
        verify,
        proof_bytes: bytes.len(),
        proof_file,
        statement: bundle.statement.to_u32s(),
        receipts: (0..ballots.len())
            .map(|i| encode_path(&bundle.receipts.path(i)))
            .collect(),
    })
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

/// Rejects non-canonical values so every digest has exactly one encoding.
fn digest(v: &[u32; 8]) -> Option<Digest> {
    if v.iter().any(|&x| x >= F::ORDER_U32) {
        return None;
    }
    Some(v.map(F::from_u32))
}
