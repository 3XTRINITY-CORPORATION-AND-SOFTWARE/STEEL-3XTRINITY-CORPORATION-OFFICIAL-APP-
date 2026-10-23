// Child process helper for replay-persistent.test.ts (NOT a test file). Modes:
//   consume <dir> <digest>        -> prints TRUE | FALSE
//   gate <dir> <inputs.json>      -> prints the Cerberus decision value
import { readFileSync } from "node:fs";
import { cerberusDecide } from "../cerberus-gate.ts";
import { FileReplayGuard } from "../replay-store.ts";

const [mode, dir, arg] = process.argv.slice(2);
if (mode === "consume") {
  console.log(new FileReplayGuard(dir).consume(arg) ? "TRUE" : "FALSE");
} else if (mode === "gate") {
  const i = JSON.parse(readFileSync(arg, "utf8")) as { root: string; repository: string; envelope: unknown; receipt: unknown; rastik: never; toepara: never };
  const g = await cerberusDecide(
    { envelope: i.envelope, receipt: i.receipt, rastik: i.rastik, toepara: i.toepara },
    { root: i.root, repository: i.repository, rerun: new Map(), guard: new FileReplayGuard(dir) },
  );
  console.log(`${g.decision.decision} ${g.adapter_reasons.join(",")}`);
} else {
  console.log("BAD-MODE");
  process.exitCode = 2;
}
