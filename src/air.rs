//! `VoterAir`: proves knowledge of a secret whose leaf `H(secret)` sits in a depth-3 Merkle tree,
//! and that the public nullifier is `H(secret, election_id)`.
//!
//! One Poseidon2 permutation per row (columns reused from `p3-poseidon2-air`) plus extra columns:
//!
//! | row | role                                  | Poseidon2 input                    |
//! |-----|---------------------------------------|------------------------------------|
//! | 0   | leaf = H(secret)                      | secret ‖ DOMAIN_LEAF ‖ 0…          |
//! | 1-3 | Merkle level k                        | bit ? sibling ‖ prev : prev ‖ sibling |
//! | 4   | nullifier = H(secret, election_id)    | secret ‖ election_id ‖ DOMAIN_NULLIFIER ‖ 0… |
//! | 5.. | padding (unconstrained permutations)  | zeros                              |
//!
//! Row roles come from a shift-register of selector columns, pinned by a first-row constraint,
//! so the prover cannot move them.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL, BABYBEAR_S_BOX_DEGREE, GenericPoseidon2LinearLayersBabyBear,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows, num_cols};
use p3_uni_stark::SubAirBuilder;

use crate::hash::{
    DIGEST, DOMAIN_LEAF, DOMAIN_NULLIFIER, Digest, F, WIDTH, compress_input, leaf_input,
    nullifier_input,
};
use crate::tree::{DEPTH, MerklePath};

pub const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE;
pub const SBOX_REGISTERS: usize = 1;
pub const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
pub const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;

/// Trace height. Rows beyond 5 are padding: the hiding PCS needs
/// `height >= 2 * (num_queries + 4 * opening_points)`, i.e. >= 92 with 38 queries.
pub const LOG_TRACE_ROWS: usize = 8;
pub const TRACE_ROWS: usize = 1 << LOG_TRACE_ROWS;

/// Number of candidates; the vote public value must be in `0..NUM_CANDIDATES`.
pub const NUM_CANDIDATES: u32 = 3;

pub const ROW_NULLIFIER: usize = DEPTH + 1;
pub const NUM_SELECTORS: usize = ROW_NULLIFIER + 1;

pub type P2Air = Poseidon2Air<
    F,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;
type P2Cols<T> =
    Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;
const P2_COLS: usize = num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

#[repr(C)]
pub struct VoterCols<T> {
    pub p2: P2Cols<T>,
    /// Voter secret, held constant over all rows.
    pub secret: [T; DIGEST],
    /// Merkle sibling used on this row (rows 1-3).
    pub sibling: [T; DIGEST],
    /// Direction bit for this row (rows 1-3): 1 = running node is the right child.
    pub bit: T,
    /// One-hot row role: `sel[r] == 1` exactly on row `r`, for r in 0..=4.
    pub sel: [T; NUM_SELECTORS],
}

pub const NUM_COLS: usize = core::mem::size_of::<VoterCols<u8>>();

impl<T> Borrow<VoterCols<T>> for [T] {
    fn borrow(&self) -> &VoterCols<T> {
        debug_assert_eq!(self.len(), NUM_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to::<VoterCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty());

        &cols[0]
    }
}

impl<T> VoterCols<T> {
    fn output(&self) -> &[T] {
        &self.p2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[..DIGEST]
    }
}

/// Public values layout.
pub mod pv {
    use super::DIGEST;
    pub const ROOT: usize = 0;
    pub const NULLIFIER: usize = ROOT + DIGEST;
    pub const ELECTION_ID: usize = NULLIFIER + DIGEST;
    pub const VOTE: usize = ELECTION_ID + 1;
    pub const LEN: usize = VOTE + 1;
}

pub fn public_values(root: &Digest, nullifier: &Digest, election_id: u32, vote: u32) -> Vec<F> {
    let mut v = Vec::with_capacity(pv::LEN);
    v.extend_from_slice(root);
    v.extend_from_slice(nullifier);
    v.push(F::from_u32(election_id));
    v.push(F::from_u32(vote));
    v
}

pub struct VoterAir {
    p2: P2Air,
}

impl Default for VoterAir {
    fn default() -> Self {
        Self {
            p2: Poseidon2Air::new(round_constants()),
        }
    }
}

fn round_constants() -> RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    // Same constants as `default_babybear_poseidon2_16`, used natively in `hash.rs`.
    RoundConstants::new(
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        BABYBEAR_POSEIDON2_RC_16_INTERNAL,
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

impl BaseAir<F> for VoterAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn num_public_values(&self) -> usize {
        pv::LEN
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for VoterAir {
    fn eval(&self, builder: &mut AB) {
        // Every row is a valid Poseidon2 permutation.
        let mut sub = SubAirBuilder::<AB, P2Air, AB::Var>::new(builder, 0..P2_COLS);
        self.p2.eval(&mut sub);

        let main = builder.main();
        let local: &VoterCols<AB::Var> = main.current_slice().borrow();
        let next: &VoterCols<AB::Var> = main.next_slice().borrow();
        let pis: Vec<AB::Expr> = builder.public_values().iter().map(|&p| p.into()).collect();

        // Selector shift register: row 0 = e_0, and each row shifts the one-hot right by one.
        {
            let mut first = builder.when_first_row();
            first.assert_one(local.sel[0]);
            for r in 1..NUM_SELECTORS {
                first.assert_zero(local.sel[r]);
            }
        }
        {
            let mut t = builder.when_transition();
            t.assert_zero(next.sel[0]);
            for r in 1..NUM_SELECTORS {
                t.assert_eq(next.sel[r], local.sel[r - 1]);
            }
            // The secret is the same on every row.
            for j in 0..DIGEST {
                t.assert_eq(next.secret[j], local.secret[j]);
            }
        }
        builder.assert_bool(local.bit);

        // Row 0: leaf = H(secret ‖ DOMAIN_LEAF ‖ 0…).
        {
            let mut b = builder.when(local.sel[0]);
            for j in 0..DIGEST {
                b.assert_eq(local.p2.inputs[j], local.secret[j]);
            }
            b.assert_eq(local.p2.inputs[DIGEST], AB::Expr::from_u32(DOMAIN_LEAF));
            for j in DIGEST + 1..WIDTH {
                b.assert_zero(local.p2.inputs[j]);
            }
        }

        // Rows 1..=DEPTH: next.input = bit ? sibling ‖ prev : prev ‖ sibling, prev = local output.
        // Not guarded by `is_transition`: on the wrap-around (last row -> row 0) the next-row
        // selectors are all zero, so the constraint holds trivially and stays degree 3.
        let is_level: AB::Expr = (1..=DEPTH).map(|r| next.sel[r].into()).sum();
        let bit: AB::Expr = next.bit.into();
        let prev = local.output();
        {
            let mut b = builder.when(is_level);
            for j in 0..DIGEST {
                let p: AB::Expr = prev[j].into();
                let s: AB::Expr = next.sibling[j].into();
                b.assert_eq(next.p2.inputs[j], p.clone() + bit.clone() * (s.clone() - p.clone()));
                b.assert_eq(next.p2.inputs[DIGEST + j], s.clone() + bit.clone() * (p - s));
            }
        }

        // Row DEPTH output is the public root.
        {
            let mut b = builder.when(local.sel[DEPTH]);
            for j in 0..DIGEST {
                b.assert_eq(local.output()[j], pis[pv::ROOT + j].clone());
            }
        }

        // Row 4: nullifier = H(secret ‖ election_id ‖ DOMAIN_NULLIFIER ‖ 0…).
        {
            let mut b = builder.when(local.sel[ROW_NULLIFIER]);
            for j in 0..DIGEST {
                b.assert_eq(local.p2.inputs[j], local.secret[j]);
                b.assert_eq(local.output()[j], pis[pv::NULLIFIER + j].clone());
            }
            b.assert_eq(local.p2.inputs[DIGEST], pis[pv::ELECTION_ID].clone());
            b.assert_eq(
                local.p2.inputs[DIGEST + 1],
                AB::Expr::from_u32(DOMAIN_NULLIFIER),
            );
            for j in DIGEST + 2..WIDTH {
                b.assert_zero(local.p2.inputs[j]);
            }
        }

        // The vote is part of the statement and must be a valid candidate index.
        // (It is also absorbed into the Fiat-Shamir transcript as a public value.)
        let vote = pis[pv::VOTE].clone();
        let range_check = (0..NUM_CANDIDATES)
            .map(|c| vote.clone() - AB::Expr::from_u32(c))
            .product::<AB::Expr>();
        builder.when_first_row().assert_zero(range_check);
    }
}

/// Private witness for one voter.
pub struct Witness {
    pub secret: Digest,
    pub path: MerklePath,
    pub election_id: u32,
}

/// Build the execution trace. This does not check that the witness is valid:
/// an invalid witness simply yields a trace that violates the constraints.
pub fn generate_trace(w: &Witness) -> RowMajorMatrix<F> {
    use crate::hash::compress;

    let mut inputs = vec![[F::ZERO; WIDTH]; TRACE_ROWS];
    inputs[0] = leaf_input(&w.secret);
    let mut node = crate::hash::hash_leaf(&w.secret);
    for k in 0..DEPTH {
        let sib = &w.path.siblings[k];
        let (l, r) = if w.path.bits[k] { (sib, &node) } else { (&node, sib) };
        inputs[k + 1] = compress_input(l, r);
        node = compress(l, r);
    }
    inputs[ROW_NULLIFIER] = nullifier_input(&w.secret, w.election_id);

    let p2_trace = generate_trace_rows::<
        F,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &round_constants(), 0);
    debug_assert_eq!(p2_trace.width, P2_COLS);

    let mut values = Vec::with_capacity(TRACE_ROWS * NUM_COLS);
    for (row, p2_row) in p2_trace.values.chunks_exact(P2_COLS).enumerate() {
        values.extend_from_slice(p2_row);
        values.extend_from_slice(&w.secret);
        if (1..=DEPTH).contains(&row) {
            values.extend_from_slice(&w.path.siblings[row - 1]);
            values.push(F::from_bool(w.path.bits[row - 1]));
        } else {
            values.extend_from_slice(&[F::ZERO; DIGEST]);
            values.push(F::ZERO);
        }
        for r in 0..NUM_SELECTORS {
            values.push(F::from_bool(r == row));
        }
    }
    RowMajorMatrix::new(values, NUM_COLS)
}
