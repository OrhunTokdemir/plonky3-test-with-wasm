use std::time::Instant;

use voter_stark::air::{NUM_COLS, NUM_CANDIDATES, TRACE_ROWS};
use voter_stark::ballot::{BallotBox, cast_ballot};
use voter_stark::proof_store;
use voter_stark::registry::{Registrar, digest_hex};
use voter_stark::tree::NUM_LEAVES;

const ELECTION_ID: u32 = 2026;
const PROOF_DIR: &str = "proofs";

fn main() {
    println!("== Registration ==");
    let registrar = Registrar::new();
    let (voters, tree, signed) = registrar.register(ELECTION_ID);
    for v in &voters {
        println!("  leaf[{}] = {}", v.index, digest_hex(&tree.leaf(v.index)));
    }
    println!("  root     = {}", digest_hex(&signed.root));
    println!(
        "  root signed with ML-DSA-65 ({} byte signature)",
        signed.signature.encode().len()
    );

    let mut ballot_box =
        BallotBox::new(signed.clone(), &registrar.verifying_key()).expect("root signature valid");

    println!("\n== Voting ({NUM_LEAVES} voters, trace {TRACE_ROWS}x{NUM_COLS}) ==");
    let mut ballots = Vec::new();
    let mut saved = Vec::new();
    for v in &voters {
        let vote = (v.index as u32) % NUM_CANDIDATES;
        let t = Instant::now();
        let ballot = cast_ballot(v, &tree, &signed, vote).expect("proving failed");
        let prove_ms = t.elapsed().as_millis();

        let t = Instant::now();
        let result = ballot_box.submit(&ballot);
        let verify_ms = t.elapsed().as_millis();
        println!(
            "  voter {} -> vote {} | nullifier {} | proof {} KiB | prove {} ms | verify {} ms | {:?}",
            v.index,
            vote,
            digest_hex(&ballot.nullifier),
            ballot.proof.len() / 1024,
            prove_ms,
            verify_ms,
            result
        );
        assert!(result.is_ok());
        let path = proof_store::save(PROOF_DIR, &signed, &ballot).expect("saving proof");
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        println!("    saved {} ({} KiB on disk)", path.display(), size / 1024);
        ballots.push(ballot);
        saved.push(path);
    }

    println!("\n== Attacks ==");
    println!("  replaying voter 0's ballot: {:?}", ballot_box.submit(&ballots[0]));
    let fresh = cast_ballot(&voters[1], &tree, &signed, 2).expect("proving failed");
    println!("  voter 1 votes again (new proof): {:?}", ballot_box.submit(&fresh));

    println!("\n== Re-verify stored proof ==");
    let path = &saved[0];
    let file = proof_store::load(path).expect("loading proof");
    let t = Instant::now();
    let result = proof_store::verify_file(&file, &registrar.verifying_key());
    println!(
        "  {} -> {:?} ({} ms)",
        path.display(),
        result,
        t.elapsed().as_millis()
    );

    #[cfg(feature = "aggregation")]
    aggregate_demo(&ballot_box, &signed, &voters);

    println!("\n== Tally ==");
    for (c, n) in ballot_box.tally.iter().enumerate() {
        println!("  candidate {c}: {n}");
    }
}

/// Recursive 8 -> 1 aggregation plus each voter's receipt self-check.
#[cfg(feature = "aggregation")]
fn aggregate_demo(
    ballot_box: &voter_stark::ballot::BallotBox,
    signed: &voter_stark::registry::SignedRoot,
    voters: &[voter_stark::registry::Voter],
) {
    use voter_stark::aggregate::{AggregateVerifier, aggregate, serialize_agg};
    use voter_stark::hash::nullifier;
    use voter_stark::receipts::verify_receipt;

    println!("\n== Recursive aggregation ({NUM_LEAVES} proofs -> 1) ==");
    let t = Instant::now();
    let bundle = aggregate(ballot_box.accepted(), signed).expect("aggregation failed");
    println!(
        "  aggregate proof {} KiB in {} ms",
        serialize_agg(&bundle.proof).len() / 1024,
        t.elapsed().as_millis()
    );
    let st = &bundle.statement;
    println!("  receipt root = {} | tally {:?}", digest_hex(&st.receipt_root), st.tally);
    let t = Instant::now();
    let verifier = AggregateVerifier::derive().expect("verifier key");
    println!("  auditor derives verifier key: {} ms", t.elapsed().as_millis());
    let t = Instant::now();
    let result = verifier.verify(&bundle.proof, st);
    println!("  auditor verifies aggregate: {:?} ({} ms)", result, t.elapsed().as_millis());
    assert!(result.is_ok());
    assert_eq!(st.tally, ballot_box.tally);
    for v in voters {
        let nf = nullifier(&v.secret, ELECTION_ID);
        let path = bundle.receipts.path(bundle.receipts.index_of(&nf).expect("ballot included"));
        let vote = (v.index as u32) % NUM_CANDIDATES;
        println!(
            "  voter {} checks own receipt (vote {}): {} | claiming vote {} instead: {}",
            v.index,
            vote,
            verify_receipt(&nf, vote, &path, &st.receipt_root),
            (vote + 1) % NUM_CANDIDATES,
            verify_receipt(&nf, (vote + 1) % NUM_CANDIDATES, &path, &st.receipt_root),
        );
    }
}
