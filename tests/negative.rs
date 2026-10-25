use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_air::check_all_constraints;
use p3_field::PrimeCharacteristicRing;
use voter_stark::air::{
    NUM_COLS, NUM_SELECTORS, VoterAir, Witness, generate_trace, public_values,
};
use voter_stark::ballot::{BallotBox, BallotError, cast_ballot};
use voter_stark::hash::{F, nullifier};
use voter_stark::registry::{Registrar, SignedRoot, Voter, random_secret};
use voter_stark::stark::{prove_eligibility, verify_eligibility};
use voter_stark::tree::{MerkleTree, root_from_path};

const EID: u32 = 7;

fn setup() -> (Registrar, Vec<Voter>, MerkleTree, SignedRoot) {
    let reg = Registrar::new();
    let (voters, tree, signed) = reg.register(EID);
    (reg, voters, tree, signed)
}

fn witness(v: &Voter, tree: &MerkleTree) -> Witness {
    Witness {
        secret: v.secret,
        path: tree.path(v.index),
        election_id: EID,
    }
}

fn constraints_hold(w: &Witness, pis: &[F]) -> bool {
    check_all_constraints(&VoterAir::default(), &generate_trace(w), pis, Some(1)).is_ok()
}

/// A cheating prover runs the full STARK pipeline. In debug builds Plonky3 panics on an
/// unsatisfied trace; in release it emits a proof that must fail verification.
fn stark_accepts(w: &Witness, pis: &[F]) -> bool {
    match catch_unwind(AssertUnwindSafe(|| prove_eligibility(w, pis))) {
        Ok(Ok(proof)) => verify_eligibility(&proof, pis).is_ok(),
        _ => false,
    }
}

#[test]
fn native_tree_and_paths_agree() {
    let (_, voters, tree, _) = setup();
    for v in &voters {
        assert_eq!(root_from_path(&tree.leaf(v.index), &tree.path(v.index)), tree.root());
    }
}

#[test]
fn honest_traces_satisfy_constraints() {
    let (_, voters, tree, signed) = setup();
    for v in &voters {
        let pis = public_values(&signed.root, &nullifier(&v.secret, EID), EID, 1);
        assert!(constraints_hold(&witness(v, &tree), &pis), "voter {}", v.index);
    }
}

#[test]
fn honest_ballot_accepted() {
    let (reg, voters, tree, signed) = setup();
    let mut bb = BallotBox::new(signed.clone(), &reg.verifying_key()).unwrap();
    let ballot = cast_ballot(&voters[5], &tree, &signed, 2).unwrap();
    assert_eq!(bb.submit(&ballot), Ok(()));
    assert_eq!(bb.tally, [0, 0, 1]);
}

#[test]
fn non_member_secret_rejected() {
    let (_, voters, tree, signed) = setup();
    let outsider = Voter {
        index: 3,
        secret: random_secret(),
    };
    let w = witness(&outsider, &tree);
    let pis = public_values(&signed.root, &nullifier(&outsider.secret, EID), EID, 0);
    assert!(!constraints_hold(&w, &pis));
    assert!(!stark_accepts(&w, &pis));
    // Sanity: the real voter at that index is accepted by the constraints.
    let real = public_values(&signed.root, &nullifier(&voters[3].secret, EID), EID, 0);
    assert!(constraints_hold(&witness(&voters[3], &tree), &real));
}

#[test]
fn wrong_root_rejected() {
    let (_, voters, tree, signed) = setup();
    let v = &voters[2];
    let nf = nullifier(&v.secret, EID);
    let proof = prove_eligibility(&witness(v, &tree), &public_values(&signed.root, &nf, EID, 0))
        .unwrap();
    let mut other_root = signed.root;
    other_root[0] += F::ONE;
    assert!(verify_eligibility(&proof, &public_values(&other_root, &nf, EID, 0)).is_err());
}

#[test]
fn flipped_direction_bit_rejected() {
    let (_, voters, tree, signed) = setup();
    let v = &voters[6];
    let mut w = witness(v, &tree);
    w.path.bits[1] = !w.path.bits[1];
    let pis = public_values(&signed.root, &nullifier(&v.secret, EID), EID, 0);
    assert!(!constraints_hold(&w, &pis));
    assert!(!stark_accepts(&w, &pis));
}

#[test]
fn forged_nullifier_or_election_rejected() {
    let (_, voters, tree, signed) = setup();
    let v = &voters[1];
    let w = witness(v, &tree);
    // A nullifier from another secret (e.g. to vote twice) does not match the trace.
    let pis = public_values(&signed.root, &nullifier(&random_secret(), EID), EID, 0);
    assert!(!constraints_hold(&w, &pis));
    // A nullifier for a different election does not fit this election's statement.
    let pis = public_values(&signed.root, &nullifier(&v.secret, EID + 1), EID, 0);
    assert!(!constraints_hold(&w, &pis));
}

#[test]
fn shifted_row_selectors_rejected() {
    let (_, voters, tree, signed) = setup();
    let v = &voters[0];
    let pis = public_values(&signed.root, &nullifier(&v.secret, EID), EID, 0);
    let mut trace = generate_trace(&witness(v, &tree));
    // Try to skip the leaf-hash row by clearing sel[0] on row 0.
    trace.values[NUM_COLS - NUM_SELECTORS] = F::ZERO;
    assert!(!check_all_constraints(&VoterAir::default(), &trace, &pis, Some(1)).is_ok());
}

#[test]
fn out_of_range_vote_rejected() {
    let (reg, voters, tree, signed) = setup();
    let v = &voters[4];
    let pis = public_values(&signed.root, &nullifier(&v.secret, EID), EID, 3);
    assert!(!constraints_hold(&witness(v, &tree), &pis));
    let bb = BallotBox::new(signed.clone(), &reg.verifying_key()).unwrap();
    let mut ballot = cast_ballot(v, &tree, &signed, 0).unwrap();
    ballot.vote = 3;
    assert_eq!(bb.check(&ballot), Err(BallotError::InvalidVote));
}

#[test]
fn changed_vote_rejected() {
    let (reg, voters, tree, signed) = setup();
    let bb = BallotBox::new(signed.clone(), &reg.verifying_key()).unwrap();
    let mut ballot = cast_ballot(&voters[0], &tree, &signed, 0).unwrap();
    ballot.vote = 1;
    assert!(matches!(bb.check(&ballot), Err(BallotError::InvalidProof(_))));
}

#[test]
fn tampered_proof_bytes_rejected() {
    let (reg, voters, tree, signed) = setup();
    let bb = BallotBox::new(signed.clone(), &reg.verifying_key()).unwrap();
    let ballot = cast_ballot(&voters[7], &tree, &signed, 1).unwrap();
    for pos in [ballot.proof.len() / 3, ballot.proof.len() / 2, ballot.proof.len() - 10] {
        let mut bad = ballot.clone();
        bad.proof[pos] ^= 0x01;
        let res = bb.check(&bad);
        assert!(
            matches!(res, Err(BallotError::MalformedProof | BallotError::InvalidProof(_))),
            "byte {pos}: {res:?}"
        );
    }
    assert_eq!(bb.check(&ballot), Ok(()));
}

#[test]
fn reused_nullifier_rejected() {
    let (reg, voters, tree, signed) = setup();
    let mut bb = BallotBox::new(signed.clone(), &reg.verifying_key()).unwrap();
    let first = cast_ballot(&voters[2], &tree, &signed, 0).unwrap();
    assert_eq!(bb.submit(&first), Ok(()));
    assert_eq!(bb.submit(&first), Err(BallotError::DoubleVote));
    let second = cast_ballot(&voters[2], &tree, &signed, 1).unwrap();
    assert_eq!(bb.submit(&second), Err(BallotError::DoubleVote));
    assert_eq!(bb.tally, [1, 0, 0]);
}

#[test]
fn bad_root_signature_rejected() {
    let (reg, _, _, signed) = setup();
    // Root signed by an impostor registrar.
    let impostor = Registrar::new();
    let (_, _, fake) = impostor.register(EID);
    assert!(matches!(
        BallotBox::new(fake, &reg.verifying_key()),
        Err(BallotError::BadRootSignature)
    ));
    // Genuine signature, but root swapped.
    let mut swapped = signed.clone();
    swapped.root[3] += F::ONE;
    assert!(matches!(
        BallotBox::new(swapped, &reg.verifying_key()),
        Err(BallotError::BadRootSignature)
    ));
    assert!(BallotBox::new(signed, &reg.verifying_key()).is_ok());
}

#[test]
fn proofs_are_randomized() {
    // Zero-knowledge sanity check: proving the same statement twice gives different proofs.
    let (_, voters, tree, signed) = setup();
    let a = cast_ballot(&voters[0], &tree, &signed, 0).unwrap();
    let b = cast_ballot(&voters[0], &tree, &signed, 0).unwrap();
    assert_eq!(a.nullifier, b.nullifier);
    assert_ne!(a.proof, b.proof);
}
