// Child process helper for replay-ledger-xproc.test.ts (NOT a test file).
//   decide <inputs.json>   uses FACTORY_REPLAY_DIR (guard markers in <dir>, decision ledger in <dir>/decisions)
// prints one JSON line: {decision, receipt_digest, decision_digest, replay, consumed}
import { readFileSync } from "node:fs";
import { decideIdempotent, replayStoresFromEnv } from "../replay-ledger.ts";
import type { ReplayStore } from "../replay-store.ts";

const [mode, arg] = process.argv.slice(2);
const stores = replayStoresFromEnv();
if (mode !== "decide" || stores === null || arg === undefined) {
  console.log("BAD-MODE");
  process.exitCode = 2;
} else {
  const i = JSON.parse(readFileSync(arg, "utf8")) as { root: string; repository: string; envelope: unknown; receipt: unknown; rastik: never; toepara: never; signatures?: never };
  let consumed = 0;
  const guard: ReplayStore = { consume: (d) => { const ok = stores.guard.consume(d); if (ok) consumed++; return ok; } };
  const r = await decideIdempotent({ envelope: i.envelope, receipt: i.receipt, rastik: i.rastik, toepara: i.toepara, signatures: i.signatures }, { root: i.root, repository: i.repository, rerun: new Map(), guard }, stores.ledger, { waitMs: Number(process.env.LEDGER_WAIT_MS ?? 5000), pollMs: 10 });
  console.log(JSON.stringify({ decision: r.decision.decision, receipt_digest: r.receipt.receipt_digest, decision_digest: r.decision.decision_digest, replay: r.idempotent_replay, consumed, reasons: r.decision.reasons.slice(0, 3) }));
}
