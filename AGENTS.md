# AGENTS.md

Context for AI coding agents working in this repo. Read `README.md` for the full picture.

## What this is

A proof of concept for zero-knowledge, post-quantum voter-eligibility proofs. It uses Plonky3
uni-stark with hiding FRI and Poseidon2 over BabyBear, plus an ML-DSA-65 signed root.

- Ballots are proven and verified **in the browser** (wasm, Web Workers).
- 8 ballot proofs are **recursively aggregated natively** into one proof.
- Each voter checks their own `(nullifier, vote)` against the aggregate's `receipt_root` using a
  Merkle receipt path.

**Current focus:** recursive aggregation and per-voter receipt verification, and their
browser integration.

## Map

- `src/air.rs`: `VoterAir`, trace generation, ballot public-value layout `pv`.
- `src/stark.rs`: the leaf (ballot) STARK `Config` and `fri_params`. It holds the
  recursion-only `LeafRecursionParams` behind `#[cfg(feature = "aggregation")]`.
- `src/aggregate.rs` *(feature `aggregation`)*:
  - `FriRecursionConfig for Config`, a BabyBear port of upstream `koala_bear_d4_poseidon2_salted`;
  - the non-hiding output config `AggConfig`;
  - the 8→1 circuit `build_circuit`, with statement layout `agg_pv`;
  - `aggregate`, `aggregate_for_root`, `aggregate_unchecked` (test-only), `AggregateVerifier`.
- `src/receipts.rs`: receipt tree, `verify_receipt`, `encode_path`/`decode_path` (27 u32s).
- `src/hash.rs`: native Poseidon2. Every hash is one width-16 permutation truncated to 8.
- `src/bin/aggregator.rs`: JSON stdin→stdout service used by `web/app/api/aggregate/route.ts`.
- `wasm/src/lib.rs`: wasm-bindgen API (`Election`, `prove_ballot`, `verify_receipt`).
- `web/public/worker.js`: worker commands `ping`, `setup`, `prove`, `submit`, `tally`,
  `checkReceipt`.
- `web/app/page.tsx`: benchmark UI (Sequential, Parallel, Aggregate).
- `tests/negative.rs`: 15 ballot tests. `tests/aggregation.rs`: 12 aggregation tests (they share
  one aggregate and serialize heavy work through a mutex).

## Commands

```bash
cargo test --release --test negative       # fast (~3 s)
cargo test --release --test aggregation    # slow (~3 min, ~2.3 GB RAM)
cargo test --release                       # everything
cargo test --release --no-default-features # library without recursion (what wasm uses)
cargo run --release                        # CLI demo incl. aggregation
cd web && npm run wasm                     # wasm-pack build into web/public/pkg
cd web && npm run aggregator               # cargo build --release --bin aggregator
cd web && npm run dev
```

Always build and test with `--release`; recursion is unusably slow in debug.

## Rules and invariants

- **Don't change `tests/negative.rs` semantics.** Existing tests must keep passing.
- **Native and in-circuit hashing must match.** The circuit's Poseidon2 (`perm_digest` in
  `aggregate.rs`) must equal `hash.rs`. `in_circuit_poseidon2_matches_native` guards this.
- **Leaf FRI params must keep `batch_proof_of_work_bits = 0`.** The recursive verifier rejects
  batch grinding. Changing leaf FRI params changes the circuit size: re-measure time and memory.
- **No recursion crates in wasm.** Aggregation code lives only behind
  `#[cfg(feature = "aggregation")]`. Never add `p3-recursion`, `p3-circuit*` or `p3-batch-stark`
  to `wasm/`; they make the wasm build take more than 35 minutes. Check with
  `cd wasm && cargo tree --target wasm32-unknown-unknown | grep p3-recursion` (must be empty).
- **Keep versions pinned.** All `p3-*` crates are `=0.9.0-rc.2`. Plonky3-recursion is pinned to
  git rev `3a69ba61f713c8400b14eb3d8f0e52caa13512c7`. Upgrade them together.
- **`AggConfig` must stay non-hiding.** With a salted preprocessing commitment,
  `AggregateVerifier::derive` could not reproduce the verifier key.
- **Fresh randomness per config.** Every config draws fresh OS randomness (`config()` in
  `stark.rs`). Never reuse seeds for hiding.
- **Reject non-canonical input.** All `u32` inputs from JS/JSON must be checked `< F::ORDER_U32`
  before becoming field elements.
- **Don't commit or push unless the user asks.**

## Web notes

- Read `web/AGENTS.md`: this Next.js version has breaking changes, so check
  `web/node_modules/next/dist/docs/` before using Next-specific APIs.
- API contract: `POST /api/aggregate` with
  `{ root, electionId, ballots: [{ nullifier, vote, proof }] }`. It returns
  `{ ok, aggregateMs, deriveMs, verifyMs, verify, proofBytes, proofFile, statement[20], receipts[8][27] }`.
- The route strips `LD_PRELOAD` before spawning the native binary. Editor extensions inject Node
  addons that crash it.
- `web/public/pkg/` is generated; never edit it by hand.

## Known gaps and next ideas

- There is no test where a forged child proof reaches the in-circuit verifier. Today the
  invalid-child case fails earlier, in FRI path reconstruction.
- The batch size is fixed at 8 ballots (it matches the voter-tree depth).
- Native aggregation is single-threaded. An optional `parallel` feature, which needs
  `p3-circuit-prover/parallel`, could speed it up.
- 2→1 tree aggregation needs a small fork of Plonky3-recursion, because the custom-statement APIs
  are `pub(crate)`.
