# voter_stark

Proof of concept: **private, post-quantum voter-eligibility proofs** with zero-knowledge STARKs
([Plonky3](https://github.com/Plonky3/Plonky3)), generated and verified **in the browser via
WebAssembly**, plus **recursive aggregation** of all ballot proofs into one proof that every voter
can check their own vote against.

> **NOT AUDITED.** Research code. Do not use for real elections.

- 8 registered voters (depth-3 Poseidon2 Merkle tree); a leaf is `H(secret)`.
- A voter proves "I know a secret whose leaf is in the tree with this root" and publishes a
  nullifier `H(secret, election_id)` (stops double voting) plus their vote. The proof reveals
  nothing else.
- The registrar signs `(election_id, root)` with **ML-DSA-65** (FIPS 204).
- Everything is hash-based (Poseidon2 over BabyBear, FRI): no elliptic curves or factoring.
- A native **aggregator** verifies all 8 ballot STARKs *inside a recursive circuit*
  ([Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion)) and outputs one proof of
  `(eligibility_root, election_id, receipt_root, tally)`. Each voter gets a Merkle receipt path
  and checks **only their own** `(nullifier, vote)` against `receipt_root`.

## Architecture

```
 browser (web/, Next.js)                                         native Rust
 ───────────────────────────────────────────────                 ─────────────────────────────
 prover workers (wasm)  ──ballots──▶ coordinator worker (wasm)
   prove_ballot()                     Election: registrar +
                                      ballot box (verify each,
                                      reject double votes, tally)
        │ Aggregate phase
        └── POST /api/aggregate ─────▶ app/api/aggregate/route.ts ──stdin JSON──▶ target/release/aggregator
                                                                                   aggregate 8 → 1 (recursive)
                                                                                   derive verifier key, verify
                                       ◀──── statement + 8 receipt paths ──────── save proofs/aggregate-*.bin
 voter-device worker (wasm)
   verify_receipt(own nullifier, own vote, own path, receipt_root)  → ✓ / ✗
```

Recursive aggregation runs natively because it is far too heavy for wasm. Compiling the
recursion crates for wasm takes more than 35 minutes, and aggregation peaks around 2.3 GB of
memory. Ballot proving and verifying and the receipt checks stay in the browser.

| Path | What |
|---|---|
| `src/air.rs` | `VoterAir`: one Poseidon2 permutation per row (leaf, 3 Merkle levels, nullifier), vote range check, public-value layout `pv` |
| `src/stark.rs` | ZK uni-stark config (hiding FRI, salted Merkle), `prove_eligibility` / `verify_eligibility` |
| `src/hash.rs`, `src/tree.rs` | Native Poseidon2 hashes (leaf, compress, nullifier, receipt leaf) and the Merkle tree |
| `src/registry.rs`, `src/ballot.rs` | Registrar (ML-DSA-65 signed root), `BallotBox` (verify, nullifier set, tally) |
| `src/proof_store.rs` | Portable ballot files `proofs/<nullifier>.bin` |
| `src/receipts.rs` | Receipt tree, `verify_receipt`, path encoding for wasm/JSON |
| `src/aggregate.rs` | *(feature `aggregation`)* recursion configs, the 8→1 circuit, `aggregate`, `AggregateVerifier` |
| `src/bin/aggregator.rs` | *(feature `aggregation`)* JSON stdin→stdout aggregator used by the web app |
| `src/main.rs` | CLI demo: register, vote, attacks, stored proof, aggregation, receipts, tally |
| `tests/negative.rs` | Soundness and negative tests for ballots (15) |
| `tests/aggregation.rs` | Aggregation and receipt tests (12) |
| `wasm/` | wasm-bindgen wrapper (`Election`, `prove_ballot`, `verify_receipt`), built without `aggregation` |
| `web/` | Next.js benchmark UI, Web Workers (`public/worker.js`), aggregation API route |

### Public statements

| Proof | Public values |
|---|---|
| Ballot (`air::pv`) | `root[8], nullifier[8], election_id, vote` |
| Aggregate (`aggregate::agg_pv`) | `eligibility_root[8], election_id, receipt_root[8], tally[3]` |

The receipt leaf is `Poseidon2(nullifier ‖ vote ‖ 3 ‖ 0…)[..8]`. Internal nodes reuse the voter
tree's `compress`. Inside the aggregation circuit:

- every ballot STARK is verified;
- all roots and election ids must be equal;
- nullifiers must be pairwise distinct;
- the tally is summed from the votes;
- `receipt_root` is recomputed from the ballots.

## Quick start

Prerequisites: stable Rust, `rustup target add wasm32-unknown-unknown`,
[wasm-pack](https://github.com/wasm-bindgen/wasm-pack), Node.js.

```bash
# Rust: CLI demo and tests (always --release; recursion is unusable in debug)
cargo run --release
cargo test --release                      # aggregation tests take about 3 minutes
cargo test --release --test negative      # fast ballot tests only

# Browser
cd web
npm install
npm run wasm          # build wasm into public/pkg (about 40 s)
npm run aggregator    # build the native aggregator binary (target/release/aggregator)
npm run dev           # open http://localhost:3000 and click Run
```

The page runs:
1. a sequential phase;
2. a parallel proving phase;
3. the Aggregate phase, which calls the native aggregator (about 2 minutes) and then
   self-checks each voter's receipt in wasm.

### Cargo feature `aggregation`

On by default. It pulls in Plonky3-recursion (pinned git rev `3a69ba6`) and the
`aggregator` binary. `wasm/` depends on `voter_stark` with `default-features = false`, so no
recursion code reaches the browser build.

## Measured numbers

Measured on the development machine, single-threaded native unless noted:

| | |
|---|---|
| Ballot proof | about 117 KiB, prove 0.5–0.9 s, verify about 8 ms |
| Aggregate 8 → 1 | 106–150 s, about 2.3 GB peak RSS, about 330–340 KiB |
| Derive the aggregate verifier key from scratch | 22–30 s |
| Verify the aggregate | about 20 ms |
| wasm bundle | 819 KiB |

## Security notes and limitations

- **Ballot proofs:** zero-knowledge via hiding FRI with salted Merkle commitments. Every
  config draws fresh OS randomness.
- **FRI parameters:** blowup 8, 38 queries and 16-bit query grinding, about 130 conjectured
  bits. These are chosen to keep the recursive verifier circuit small. Batch grinding is 0
  because the recursive verifier does not support it.
- **Challenge field:** the degree-4 extension, a ~124-bit challenge space.
- **Aggregate proof is not hiding.** It only attests to values that are already public. An
  unsalted preprocessing commitment lets anyone rebuild the verifier key
  (`AggregateVerifier::derive`) instead of trusting the aggregator.
- **The aggregator trusts the root it is given.** Auditors must compare
  `statement.eligibility_root` with the registrar-signed root.
- **Receipt privacy:** a receipt path reveals sibling hashes. With only 3 candidates a sibling
  leaf's vote can be brute-forced from a known nullifier. Nullifiers and votes are public per
  ballot anyway.
- **Invalid-child test gap:** a ballot whose vote was changed after proving is rejected while
  the aggregator rebuilds its FRI query paths, before the circuit runs. Duplicate nullifiers and
  mixed elections are rejected inside the circuit.
- **Fixed batch size:** 8 ballots per aggregate.
- **Dev tooling:** tools that `LD_PRELOAD` a Node addon into `next dev`, such as the Console
  Ninja extension, would crash the native child process. The API route strips `LD_PRELOAD`.

## License

MIT, see [`License`](License).
