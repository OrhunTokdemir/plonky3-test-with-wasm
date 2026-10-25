use std::time::Instant;

use voter_stark::air::{NUM_COLS, NUM_CANDIDATES, TRACE_ROWS};
use voter_stark::ballot::{BallotBox, cast_ballot};
use voter_stark::registry::{Registrar, digest_hex};
use voter_stark::tree::NUM_LEAVES;

const ELECTION_ID: u32 = 2026;

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
        ballots.push(ballot);
    }

    println!("\n== Attacks ==");
    println!("  replaying voter 0's ballot: {:?}", ballot_box.submit(&ballots[0]));
    let fresh = cast_ballot(&voters[1], &tree, &signed, 2).expect("proving failed");
    println!("  voter 1 votes again (new proof): {:?}", ballot_box.submit(&fresh));

    println!("\n== Tally ==");
    for (c, n) in ballot_box.tally.iter().enumerate() {
        println!("  candidate {c}: {n}");
    }
}
