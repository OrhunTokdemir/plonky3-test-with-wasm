//! Recursive aggregation of ballot proofs and per-voter receipt checks.
//!
//! Aggregating is expensive (one STARK verifier circuit per ballot), so all tests share one
//! honest aggregate, and every circuit build/run is serialized through `HEAVY` to bound memory.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, OnceLock};

use p3_field::PrimeCharacteristicRing;
use voter_stark::aggregate::{
    AggregateBundle, AggregateError, AggregateStatement, AggregateVerifier, NUM_BALLOTS, aggregate,
    aggregate_unchecked, deserialize_agg, serialize_agg,
};
use voter_stark::air::{Witness, public_values};
use voter_stark::ballot::{Ballot, BallotBox, BallotError, cast_ballot};
use voter_stark::hash::{F, nullifier};
use voter_stark::receipts::{decode_path, encode_path, verify_receipt};
use voter_stark::registry::{Registrar, SignedRoot, Voter};
use voter_stark::stark::{Proof, deserialize, prove_eligibility};
use voter_stark::tree::MerkleTree;

const EID: u32 = 7;

static HEAVY: Mutex<()> = Mutex::new(());

struct Election {
    voters: Vec<Voter>,
    tree: MerkleTree,
    signed: SignedRoot,
    ballot_box: BallotBox,
}

fn election() -> Election {
    let reg = Registrar::new();
    let (voters, tree, signed) = reg.register(EID);
    let ballot_box = BallotBox::new(signed.clone(), &reg.verifying_key()).unwrap();
    Election {
        voters,
        tree,
        signed,
        ballot_box,
    }
}

/// Every voter casts `index % 3` and the ballot box accepts it.
fn voted() -> Election {
    let mut e = election();
    for v in &e.voters {
        let ballot = cast_ballot(v, &e.tree, &e.signed, v.index as u32 % 3).unwrap();
        e.ballot_box.submit(&ballot).unwrap();
    }
    e
}

struct Fixture {
    e: Election,
    bundle: AggregateBundle,
    /// Derived independently from a throwaway proof, not from the aggregator.
    verifier: AggregateVerifier,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let _g = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
        let e = voted();
        let bundle = aggregate(e.ballot_box.accepted(), &e.signed).expect("honest aggregate");
        let verifier = AggregateVerifier::derive().expect("verifier key");
        Fixture {
            e,
            bundle,
            verifier,
        }
    })
}

fn children(ballots: &[Ballot], signed: &SignedRoot) -> Vec<(Proof, Vec<F>)> {
    ballots
        .iter()
        .map(|b| {
            let pis = public_values(&signed.root, &b.nullifier, signed.election_id, b.vote);
            (deserialize(&b.proof).unwrap(), pis)
        })
        .collect()
}

/// The circuit itself must reject: no proof comes out (error or panic in debug builds).
fn circuit_rejects(children: &[(Proof, Vec<F>)]) -> bool {
    let _g = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    match catch_unwind(AssertUnwindSafe(|| aggregate_unchecked(children))) {
        Ok(Ok(_)) => false,
        Ok(Err(e)) => {
            eprintln!("circuit rejected: {:.200}", format!("{e:?}"));
            true
        }
        Err(_) => true,
    }
}

#[test]
fn honest_aggregate_verifies_with_independent_key() {
    let f = fixture();
    let st = &f.bundle.statement;
    assert_eq!(f.verifier.verify(&f.bundle.proof, st), Ok(()));
    assert_eq!(st.eligibility_root, f.e.signed.root);
    assert_eq!(st.election_id, EID);
    assert_eq!(st.tally, f.e.ballot_box.tally);
    let entries = core::array::from_fn(|i| {
        let b = &f.e.ballot_box.accepted()[i];
        (b.nullifier, b.vote)
    });
    assert_eq!(
        *st,
        AggregateStatement::compute(&f.e.signed.root, EID, &entries)
    );
}

#[test]
fn every_voter_receipt_verifies() {
    let f = fixture();
    let root = f.bundle.statement.receipt_root;
    for v in &f.e.voters {
        // Voter side: recompute own nullifier, ask the aggregator for the path.
        let nf = nullifier(&v.secret, EID);
        let index = f.bundle.receipts.index_of(&nf).expect("ballot included");
        let path = f.bundle.receipts.path(index);
        assert!(
            verify_receipt(&nf, v.index as u32 % 3, &path, &root),
            "voter {}",
            v.index
        );
        // The wasm encoding round-trips.
        assert_eq!(
            decode_path(&encode_path(&path)).map(|p| p.bits),
            Some(path.bits)
        );
    }
}

#[test]
fn tampered_vote_or_nullifier_receipt_rejected() {
    let f = fixture();
    let root = f.bundle.statement.receipt_root;
    let v = &f.e.voters[3];
    let nf = nullifier(&v.secret, EID);
    let path = f
        .bundle
        .receipts
        .path(f.bundle.receipts.index_of(&nf).unwrap());
    let vote = v.index as u32 % 3;
    assert!(verify_receipt(&nf, vote, &path, &root));
    assert!(!verify_receipt(&nf, (vote + 1) % 3, &path, &root));
    let mut other_nf = nf;
    other_nf[5] += F::ONE;
    assert!(!verify_receipt(&other_nf, vote, &path, &root));
}

#[test]
fn tampered_receipt_path_rejected() {
    let f = fixture();
    let root = f.bundle.statement.receipt_root;
    let v = &f.e.voters[5];
    let nf = nullifier(&v.secret, EID);
    let vote = v.index as u32 % 3;
    let path = f
        .bundle
        .receipts
        .path(f.bundle.receipts.index_of(&nf).unwrap());

    let mut bad = path.clone();
    bad.siblings[1][0] += F::ONE;
    assert!(!verify_receipt(&nf, vote, &bad, &root));
    let mut bad = path.clone();
    bad.bits[2] = !bad.bits[2];
    assert!(!verify_receipt(&nf, vote, &bad, &root));
    let someone_else = f
        .bundle
        .receipts
        .path(f.bundle.receipts.index_of(&nf).unwrap() ^ 1);
    assert!(!verify_receipt(&nf, vote, &someone_else, &root));
    assert!(decode_path(&[0; 3]).is_none());
}

#[test]
fn wrong_statement_rejected() {
    let f = fixture();
    let ok = &f.bundle.statement;
    let mut cases = Vec::new();
    let mut s = ok.clone();
    s.receipt_root[0] += F::ONE;
    cases.push(("receipt_root", s));
    let mut s = ok.clone();
    // Same total, different per-candidate counts ([3, 3, 2] -> [2, 3, 3]).
    s.tally = [s.tally[2], s.tally[0], s.tally[1]];
    assert_ne!(s.tally, ok.tally);
    cases.push(("tally rotated", s));
    let mut s = ok.clone();
    s.tally[0] += 1;
    cases.push(("tally inflated", s));
    let mut s = ok.clone();
    s.eligibility_root[7] += F::ONE;
    cases.push(("eligibility_root", s));
    let mut s = ok.clone();
    s.election_id += 1;
    cases.push(("election_id", s));
    for (what, s) in cases {
        assert!(f.verifier.verify(&f.bundle.proof, &s).is_err(), "{what}");
    }
}

#[test]
fn tampered_aggregate_proof_rejected() {
    let f = fixture();
    let bytes = serialize_agg(&f.bundle.proof);
    // The STARK itself (commitments, openings, FRI) is serialized first. The remaining fields
    // are shape metadata that `CircuitVerifier` re-derives from its own key, so flip bytes in
    // the STARK part.
    let stark_len = postcard::to_allocvec(&f.bundle.proof.proof).unwrap().len();
    let mut rejected = 0;
    for pos in [
        stark_len / 5,
        stark_len / 2,
        4 * stark_len / 5,
        stark_len - 20,
    ] {
        let mut bad = bytes.clone();
        bad[pos] ^= 1;
        match deserialize_agg(&bad) {
            None => rejected += 1,
            Some(p) => {
                if f.verifier.verify(&p, &f.bundle.statement).is_err() {
                    rejected += 1;
                }
            }
        }
    }
    assert_eq!(rejected, 4);
    assert!(deserialize_agg(b"not a proof").is_none());
}

#[test]
fn aggregate_proof_round_trips() {
    let f = fixture();
    let bytes = serialize_agg(&f.bundle.proof);
    eprintln!("aggregate proof: {} KiB", bytes.len() / 1024);
    let p = deserialize_agg(&bytes).unwrap();
    assert_eq!(f.verifier.verify(&p, &f.bundle.statement), Ok(()));
}

#[test]
fn wrong_ballot_count_rejected() {
    let f = fixture();
    let seven = &f.e.ballot_box.accepted()[..NUM_BALLOTS - 1];
    assert!(matches!(
        aggregate(seven, &f.e.signed),
        Err(AggregateError::WrongCount(7))
    ));
}

#[test]
fn invalid_child_rejected() {
    let f = fixture();
    let mut ballots = f.e.ballot_box.accepted().to_vec();
    // Claim a different vote than the one proven.
    ballots[4].vote = (ballots[4].vote + 1) % 3;
    assert!(matches!(
        aggregate(&ballots, &f.e.signed),
        Err(AggregateError::InvalidChild(4, _))
    ));
    assert!(circuit_rejects(&children(&ballots, &f.e.signed)));
}

#[test]
fn mixed_elections_rejected() {
    let f = fixture();
    // Valid ballot for another election (different registrar, tree and root).
    let other = voted();
    let mut ballots = f.e.ballot_box.accepted().to_vec();
    ballots[6] = other.ballot_box.accepted()[6].clone();
    assert!(matches!(
        aggregate(&ballots, &f.e.signed),
        Err(AggregateError::InvalidChild(6, _))
    ));
    // Each child honestly verifies against its own root, but the circuit demands equal roots.
    let mut kids = children(f.e.ballot_box.accepted(), &f.e.signed);
    kids[6] = children(&other.ballot_box.accepted()[6..7], &other.signed).remove(0);
    assert!(circuit_rejects(&kids));
}

#[test]
fn duplicate_nullifier_rejected() {
    let f = fixture();
    let v = &f.e.voters[2];
    // The ballot box already refuses a second ballot from the same voter.
    let again = cast_ballot(v, &f.e.tree, &f.e.signed, 0).unwrap();
    assert_eq!(f.e.ballot_box.check(&again), Err(BallotError::DoubleVote));

    // A malicious aggregator bypassing the ballot box: voter 2 appears twice, voter 3 not at all.
    let mut ballots = f.e.ballot_box.accepted().to_vec();
    ballots[3] = again;
    assert_eq!(
        aggregate(&ballots, &f.e.signed).err(),
        Some(AggregateError::DuplicateNullifier(2, 3))
    );
    assert!(circuit_rejects(&children(&ballots, &f.e.signed)));
}

#[test]
fn verifier_key_does_not_depend_on_template() {
    // A key built from some unrelated eligibility proof accepts the real aggregate too.
    let f = fixture();
    let _g = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let other = election();
    let v = &other.voters[1];
    let w = Witness {
        secret: v.secret,
        path: other.tree.path(1),
        election_id: 99,
    };
    let pis = public_values(&other.signed.root, &nullifier(&v.secret, 99), 99, 2);
    let template = prove_eligibility(&w, &pis).unwrap();
    let key = AggregateVerifier::from_template(&template).unwrap();
    assert_eq!(key.verify(&f.bundle.proof, &f.bundle.statement), Ok(()));
}
