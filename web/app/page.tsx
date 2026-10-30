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
type Phase = {
  name: string;
  threads: number;
  setupMs: number;
  wallMs: number;
  rows: Row[];
  attacks: [string, string][];
  tally: number[];
};

/** Setup an election, prove all voters on `threads` workers (job queue), verify each on the coordinator. */
async function runPhase(name: string, threads: number, coord: Worker, onUpdate: (p: Phase) => void): Promise<Phase> {
  const provers = Array.from({ length: threads }, spawn);
  await Promise.all(provers.map((w) => call(w, { cmd: "ping" }))); // wasm compiled before timing

  const setup = await call(coord, { cmd: "setup" });
  const { secrets, electionId } = setup;
  const phase: Phase = { name, threads, setupMs: setup.ms, wallMs: 0, rows: [], attacks: [], tally: [] };
  const ballots: Record<number, { nullifier: Uint32Array; proof: Uint8Array; vote: number }> = {};

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

const fmt = (x: number) => x.toFixed(1);

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

export default function Home() {
  const [threads, setThreads] = useState(4);
  const [maxThreads, setMaxThreads] = useState(8);
  const [running, setRunning] = useState(false);
  const [phases, setPhases] = useState<Phase[]>([]);
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
      await runPhase("Parallel", threads, coord, show(1));
    } catch (e) {
      setError(String(e));
    } finally {
      coord.terminate();
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
    </main>
  );
}
