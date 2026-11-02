"use client";

import { useEffect, useState } from "react";

// All proving/verifying happens in browser Web Workers (public/worker.js) running the wasm.
// Next.js only serves static files.

const NUM_VOTERS = 8;
const NUM_CANDIDATES = 3;

type Reply = { ok: boolean; ms: number; error?: string; [k: string]: any };

function spawn(): Worker {
  return new Worker("/worker.js", { type: "module" });
}

let nextId = 0;
function call(w: Worker, msg: object, transfer: Transferable[] = []): Promise<Reply> {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const onMsg = (e: MessageEvent<Reply & { id: number }>) => {
      if (e.data.id !== id) return;
      w.removeEventListener("message", onMsg);
      e.data.ok ? resolve(e.data) : reject(new Error(e.data.error));
    };
    w.addEventListener("message", onMsg);
    w.postMessage({ id, ...msg }, transfer);
  });
}

type Row = { voter: number; worker: number; vote: number; proveMs: number; verifyMs: number; kib: number; result: string };
type Ballots = Record<number, { nullifier: Uint32Array; proof: Uint8Array; vote: number }>;
type Phase = {
  name: string;
  threads: number;
  setupMs: number;
  wallMs: number;
  rows: Row[];
  attacks: [string, string][];
  tally: number[];
  ballots: Ballots;
  electionId: number;
  root: number[];
};

/** Setup an election, prove all voters on `threads` workers (job queue), verify each on the coordinator. */
async function runPhase(name: string, threads: number, coord: Worker, onUpdate: (p: Phase) => void): Promise<Phase> {
  const provers = Array.from({ length: threads }, spawn);
  await Promise.all(provers.map((w) => call(w, { cmd: "ping" }))); // wasm compiled before timing

  const setup = await call(coord, { cmd: "setup" });
  const { secrets, electionId, root } = setup;
  const ballots: Ballots = {};
  const phase: Phase = { name, threads, setupMs: setup.ms, wallMs: 0, rows: [], attacks: [], tally: [], ballots, electionId, root };

  let next = 0;
  const t0 = performance.now();
  await Promise.all(
    provers.map(async (w, wi) => {
      while (next < NUM_VOTERS) {
        const voter = next++;
        const vote = voter % NUM_CANDIDATES;
        const p = await call(w, { cmd: "prove", secrets, electionId, index: voter, vote });
        ballots[voter] = { nullifier: p.nullifier, proof: p.proof, vote };
        const v = await call(coord, { cmd: "submit", nullifier: p.nullifier, vote, proof: p.proof });
        phase.rows.push({ voter, worker: wi, vote, proveMs: p.ms, verifyMs: v.ms, kib: p.proof.length / 1024, result: v.result });
        phase.wallMs = performance.now() - t0;
        onUpdate({ ...phase, rows: [...phase.rows] });
      }
    }),
  );
  phase.wallMs = performance.now() - t0;

  const b0 = ballots[0];
  const replay = await call(coord, { cmd: "submit", ...b0 });
  phase.attacks.push(["replay voter 0 ballot", replay.result]);
  const again = await call(provers[0], { cmd: "prove", secrets, electionId, index: 1, vote: 2 });
  const dbl = await call(coord, { cmd: "submit", nullifier: again.nullifier, vote: 2, proof: again.proof });
  phase.attacks.push(["voter 1 votes again (new proof)", dbl.result]);
  phase.tally = (await call(coord, { cmd: "tally" })).tally;

  provers.forEach((w) => w.terminate());
  onUpdate({ ...phase });
  return phase;
}

// Aggregate statement layout (see `agg_pv` in src/aggregate.rs).
const RECEIPT_ROOT = 9;
const TALLY = 17;

type ReceiptRow = { voter: number; vote: number; ms: number; ok: boolean };
type Agg = {
  roundTripMs: number;
  aggregateMs: number;
  kib: number;
  proofFile: string;
  statement: number[];
  ballotBoxTally: number[];
  deriveMs: number;
  verifyMs: number;
  verify: string;
  receipts: ReceiptRow[];
  tamper?: boolean;
};

/**
 * Recursive aggregation is too heavy for wasm, so the 8 accepted ballots go to the native Rust
 * aggregator (`/api/aggregate` -> target/release/aggregator). It proves the aggregate, verifies it
 * with an independently derived key, and returns the statement plus each ballot's receipt path.
 * Each voter then checks only their own (nullifier, vote) against the receipt root, in wasm.
 */
async function runAggregate(phase: Phase, onUpdate: (a: Agg) => void): Promise<Agg> {
  const ballots = Array.from({ length: NUM_VOTERS }, (_, voter) => {
    const b = phase.ballots[voter];
    return { nullifier: Array.from(b.nullifier), vote: b.vote, proof: Array.from(b.proof) };
  });
  const t0 = performance.now();
  const res = await fetch("/api/aggregate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ root: phase.root, electionId: phase.electionId, ballots }),
  });
  const out = await res.json();
  if (!out.ok) throw new Error(`native aggregator: ${out.error}`);
  const statement: number[] = out.statement;
  const agg: Agg = {
    roundTripMs: performance.now() - t0, aggregateMs: out.aggregateMs, kib: out.proofBytes / 1024, proofFile: out.proofFile,
    statement, ballotBoxTally: phase.tally, deriveMs: out.deriveMs, verifyMs: out.verifyMs, verify: out.verify, receipts: [],
  };
  onUpdate({ ...agg });

  // Voter device: a fresh worker holding only the voter's own data and the public statement.
  const voterDevice = spawn();
  try {
    await call(voterDevice, { cmd: "ping" });
    const receiptRoot = statement.slice(RECEIPT_ROOT, RECEIPT_ROOT + 8);
    for (let voter = 0; voter < NUM_VOTERS; voter++) {
      const { nullifier, vote } = phase.ballots[voter];
      const r = await call(voterDevice, { cmd: "checkReceipt", nullifier, vote, path: out.receipts[voter], receiptRoot });
      agg.receipts.push({ voter, vote, ms: r.ms, ok: r.ok });
      onUpdate({ ...agg, receipts: [...agg.receipts] });
    }
    const b0 = phase.ballots[0];
    const forged = await call(voterDevice, {
      cmd: "checkReceipt", nullifier: b0.nullifier, vote: (b0.vote + 1) % NUM_CANDIDATES, path: out.receipts[0], receiptRoot,
    });
    agg.tamper = forged.ok;
  } finally {
    voterDevice.terminate();
  }
  onUpdate({ ...agg });
  return agg;
}

const fmt = (x: number) => x.toFixed(1);
const hex = (xs: number[]) => xs.slice(0, 4).map((x) => x.toString(16).padStart(8, "0")).join("") + "…";

function stats(xs: number[]) {
  if (!xs.length) return "-";
  const avg = xs.reduce((a, b) => a + b, 0) / xs.length;
  return `avg ${fmt(avg)} / min ${fmt(Math.min(...xs))} / max ${fmt(Math.max(...xs))} ms`;
}

function PhaseView({ p }: { p: Phase }) {
  const rows = [...p.rows].sort((a, b) => a.voter - b.voter);
  return (
    <section>
      <h3>
        {p.name} — {p.threads} worker{p.threads > 1 ? "s" : ""}
      </h3>
      <div>setup (ML-DSA keygen + register + sign): {fmt(p.setupMs)} ms</div>
      <div>prove: {stats(rows.map((r) => r.proveMs))}</div>
      <div>verify: {stats(rows.map((r) => r.verifyMs))}</div>
      <div>
        wall time for {rows.length} ballots: <b>{fmt(p.wallMs)} ms</b> ({fmt((rows.length / p.wallMs) * 1000)} proofs/s)
      </div>
      <table>
        <thead>
          <tr>
            <th>voter</th><th>worker</th><th>vote</th><th>prove ms</th><th>verify ms</th><th>proof KiB</th><th>result</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.voter}>
              <td>{r.voter}</td><td>{r.worker}</td><td>{r.vote}</td><td>{fmt(r.proveMs)}</td>
              <td>{fmt(r.verifyMs)}</td><td>{fmt(r.kib)}</td><td>{r.result}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {p.attacks.map(([k, v]) => (
        <div key={k}>{k}: {v}</div>
      ))}
      {p.tally.length > 0 && <div>tally: {p.tally.map((n, c) => `c${c}=${n}`).join("  ")}</div>}
    </section>
  );
}

function AggView({ a }: { a: Agg }) {
  const tally = a.statement.slice(TALLY, TALLY + NUM_CANDIDATES);
  return (
    <section>
      <h3>Recursive aggregation — 8 ballot proofs → 1 proof (native Rust aggregator)</h3>
      <div>
        native aggregate (verify 8 STARKs in-circuit + prove): <b>{fmt(a.aggregateMs)} ms</b>, proof {fmt(a.kib)} KiB → {a.proofFile}
      </div>
      <div>eligibility root: {hex(a.statement.slice(0, 8))} · election: {a.statement[8]}</div>
      <div>receipt root: {hex(a.statement.slice(RECEIPT_ROOT, RECEIPT_ROOT + 8))}</div>
      <div>
        tally in proof: {tally.map((n, c) => `c${c}=${n}`).join("  ")} · ballot box: {a.ballotBoxTally.map((n, c) => `c${c}=${n}`).join("  ")}
      </div>
      <div>native auditor: derive verifier key {fmt(a.deriveMs)} ms · verify {fmt(a.verifyMs)} ms → {a.verify}</div>
      <div>request round trip (incl. upload, aggregate, derive, verify): {fmt(a.roundTripMs)} ms</div>
      <table>
        <thead>
          <tr><th>voter</th><th>vote</th><th>wasm self-check ms</th><th>receipt in aggregate</th></tr>
        </thead>
        <tbody>
          {a.receipts.map((r) => (
            <tr key={r.voter}>
              <td>{r.voter}</td><td>{r.vote}</td><td>{fmt(r.ms)}</td><td>{r.ok ? "✓" : "✗"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {a.tamper !== undefined && <div>voter 0 claims a different vote with the same path: {a.tamper ? "✓ (BUG)" : "✗ rejected"}</div>}
    </section>
  );
}

export default function Home() {
  const [threads, setThreads] = useState(4);
  const [maxThreads, setMaxThreads] = useState(8);
  const [running, setRunning] = useState(false);
  const [phases, setPhases] = useState<Phase[]>([]);
  const [agg, setAgg] = useState<Agg | null>(null);
  const [aggStatus, setAggStatus] = useState("");
  const [error, setError] = useState("");
  const [wasmKiB, setWasmKiB] = useState<number | null>(null);

  useEffect(() => {
    const hc = navigator.hardwareConcurrency || 4;
    setMaxThreads(hc);
    setThreads(Math.min(hc, NUM_VOTERS));
    fetch("/pkg/voter_stark_wasm_bg.wasm")
      .then((r) => r.arrayBuffer())
      .then((b) => setWasmKiB(b.byteLength / 1024))
      .catch(() => {});
  }, []);

  async function run() {
    setRunning(true);
    setError("");
    setPhases([]);
    setAgg(null);
    const coord = spawn();
    try {
      await call(coord, { cmd: "ping" });
      const show = (i: number) => (p: Phase) =>
        setPhases((ps) => {
          const c = [...ps];
          c[i] = p;
          return c;
        });
      await runPhase("Sequential", 1, coord, show(0));
      const parallel = await runPhase("Parallel", threads, coord, show(1));
      setAggStatus("aggregating 8 proofs with the native Rust aggregator (takes a few minutes)…");
      await runAggregate(parallel, setAgg);
    } catch (e) {
      setError(String(e));
    } finally {
      coord.terminate();
      setAggStatus("");
      setRunning(false);
    }
  }

  return (
    <main>
      <h2>voter_stark — Plonky3 WASM benchmark (client-side)</h2>
      <div>
        {NUM_VOTERS} voters, Poseidon2/BabyBear STARK, hiding FRI. wasm: {wasmKiB ? `${fmt(wasmKiB)} KiB` : "…"} · cores:{" "}
        {maxThreads}
      </div>
      <p>
        parallel workers{" "}
        <input
          type="number"
          min={1}
          max={NUM_VOTERS}
          value={threads}
          disabled={running}
          onChange={(e) => setThreads(Math.max(1, Math.min(NUM_VOTERS, Number(e.target.value) || 1)))}
        />{" "}
        <button onClick={run} disabled={running}>
          {running ? "running…" : "Run"}
        </button>
      </p>
      {error && <p className="err">{error}</p>}
      {phases.map((p) => p && <PhaseView key={p.name} p={p} />)}
      {aggStatus && !agg && <p>{aggStatus}</p>}
      {agg && <AggView a={agg} />}
    </main>
  );
}
