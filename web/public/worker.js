// Module worker: loads the wasm once, then runs commands from the page.
// Each worker has its own wasm instance; timings use performance.now() around the wasm call only.
import init, { Election, prove_ballot } from "/pkg/voter_stark_wasm.js";

const ready = init();
let election = null;

self.onmessage = async ({ data: msg }) => {
  try {
    await ready;
    let out = {};
    let transfer = [];
    const t0 = performance.now();
    switch (msg.cmd) {
      case "ping":
        break;
      case "setup":
        election = new Election();
        out = { secrets: election.secrets(), electionId: election.election_id() };
        break;
      case "prove": {
        const b = prove_ballot(msg.secrets, msg.electionId, msg.index, msg.vote);
        out = { nullifier: b.nullifier, proof: b.proof };
        b.free();
        transfer = [out.proof.buffer];
        break;
      }
      case "submit":
        out = { result: election.submit(msg.nullifier, msg.vote, msg.proof) };
        break;
      case "tally":
        out = { tally: Array.from(election.tally()) };
        break;
      default:
        throw new Error(`unknown cmd ${msg.cmd}`);
    }
    const ms = performance.now() - t0;
    self.postMessage({ id: msg.id, ok: true, ms, ...out }, transfer);
  } catch (e) {
    self.postMessage({ id: msg.id, ok: false, error: String(e) });
  }
};
