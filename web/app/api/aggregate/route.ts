// Recursive aggregation is too heavy for wasm, so it runs natively: this route pipes the
// browser's ballots into the Rust `aggregator` binary (src/bin/aggregator.rs) and returns its
// JSON (aggregate statement, timings, and every ballot's receipt path).
// Build the binary first with `npm run aggregator`.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

export const runtime = "nodejs";

const REPO = path.resolve(process.cwd(), "..");
const BIN = path.join(REPO, "target", "release", process.platform === "win32" ? "aggregator.exe" : "aggregator");

export async function POST(request: Request) {
  if (!existsSync(BIN)) {
    return Response.json({ ok: false, error: `native aggregator not built: run \`npm run aggregator\` (expected ${BIN})` }, { status: 500 });
  }
  const body = await request.text();
  const { code, stdout, stderr } = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    // Dev tooling (e.g. editor extensions) can LD_PRELOAD Node addons into the dev server;
    // they must not leak into the native binary, which would fail to load them.
    const { LD_PRELOAD: _ld, DYLD_INSERT_LIBRARIES: _dyld, ...env } = process.env;
    const child = spawn(BIN, [], { cwd: REPO, env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(body);
  });
  try {
    const out = JSON.parse(stdout);
    return Response.json(out, { status: out.ok ? 200 : 400 });
  } catch {
    return Response.json({ ok: false, error: `aggregator exited with ${code}: ${stderr.slice(-2000)}` }, { status: 500 });
  }
}
