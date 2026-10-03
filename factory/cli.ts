import { readFileSync, writeFileSync } from "node:fs";
import { ReplayGuard } from "../kratt/evidence.ts";
import { CAPABILITIES } from "./capabilities.ts";
import { repoSlug } from "./git.ts";
import { GoliathStandIn, makeDispatcher, selfCheckFinalReceipt, type ClosedLoopReceipt } from "./loop.ts";
import { resolve } from "node:path";
import { buildJsonSchema } from "./protocol/types.ts";
import { buildInitialRegistry, countRegistry, validateRegistryShape, validateInitialRegistry, type Registry } from "./registry.ts";

/**
 * npm run factory -- init      write the initial (all SLEEP, 0 tasks) registry + empty queue/receipts/matrix + protocol schema
 * npm run factory -- validate  validate the committed registry (shape + counts); exit 1 on any violation
 * npm run factory -- status    print honest counts
 * npm run factory -- run-loop   execute the real closed loops at the current HEAD and append their receipts
 *                               (registry, queue + transition log, receipts are rewritten; HEAD must have a clean scope)
 */
const root = resolve(import.meta.dirname);
const file = (n: string) => resolve(root, n);
const write = (n: string, v: unknown) => writeFileSync(file(n), JSON.stringify(v, null, 2) + "\n");

const cmd = process.argv[2];
if (cmd === "init") {
  write("factory-registry.json", buildInitialRegistry());
  const existing = (() => {
    try {
      return JSON.parse(readFileSync(file("factory-registry.json"), "utf8")) as Registry;
    } catch {
      return null;
    }
  })();
  if (existing && countRegistry(existing).executed_tasks > 0 && !process.argv.includes("--force")) {
    console.error("refusing to reset a registry that records executed tasks (receipts would be orphaned); pass --force to wipe");
    process.exit(1);
  }
  write("factory-registry.json", buildInitialRegistry(CAPABILITIES));
  write("factory-queue.json", { queue_version: 1, tasks: [], transitions: [] });
  write("factory-receipts.json", { receipts_version: 1, closed_loops: [] });
  write("factory-matrix.json", { matrix_version: 1, note: "no factory evidence connected to scripts/matrix250 yet", slots: [] });
  writeFileSync(file("protocol/protocol.schema.json"), JSON.stringify(buildJsonSchema(), null, 2) + "\n");
  console.log("factory: initial files written");
} else if (cmd === "validate" || cmd === "status") {
  const reg = JSON.parse(readFileSync(file("factory-registry.json"), "utf8")) as Registry;
  const shape = validateRegistryShape(reg);
  const shape = validateRegistryShape(reg, CAPABILITIES);
  if (cmd === "status") {
    console.log(JSON.stringify({ shape_violations: shape.length, ...countRegistry(reg) }, null, 2));
    process.exit(shape.length ? 1 : 0);
  }
  const init = validateInitialRegistry(reg);
  const init = validateInitialRegistry(reg, CAPABILITIES);
  if (shape.length) {
    console.error(`registry shape violations:\n${shape.join("\n")}`);
    process.exit(1);
  }
  console.log(`registry shape ok; initial-state invariants ${init.length === 0 ? "hold" : `do not hold (${init.length}; expected after real tasks ran)`}`);
} else {
  console.error("usage: factory <init|validate|status>");
} else if (cmd === "run-loop") {
  const repoRoot = resolve(root, "..");
  const repository = process.env.GITHUB_REPOSITORY ?? repoSlug(repoRoot);
  if (!repository) {
    console.error("cannot determine repository slug (origin url / GITHUB_REPOSITORY)");
    process.exit(2);
  }
  const clock = () => new Date().toISOString();
  const reg = JSON.parse(readFileSync(file("factory-registry.json"), "utf8")) as Registry;
  const shape = validateRegistryShape(reg, CAPABILITIES);
  if (shape.length) {
    console.error(`registry invalid for the capability map:\n${shape.join("\n")}`);
    process.exit(1);
  }
  const queueDoc = JSON.parse(readFileSync(file("factory-queue.json"), "utf8"));
  const receiptsDoc = JSON.parse(readFileSync(file("factory-receipts.json"), "utf8"));
  const d = makeDispatcher(clock, reg);
  d.restore(queueDoc.tasks, queueDoc.transitions);
  const stand = new GoliathStandIn({ root: repoRoot, repository, dispatcher: d, guard: new ReplayGuard(), clock });
  const branch = process.env.FACTORY_BRANCH ?? "factory/closed-loop-v1";
  const envs = [
    stand.issueEnvelope({ action: "hash-files", branch, scope: ["cerberus/core/decide.ts", "cerberus/core/normalize.ts", "cerberus/policy/policy.ts", "cerberus/artifact-trust/artifact-trust.ts"] }),
    stand.issueEnvelope({ action: "run-test", branch, scope: ["cerberus/tests/decide.test.ts"] }),
  ];
  const out: ClosedLoopReceipt[] = [];
  for (const e of envs) {
    const r = await stand.submit(e);
    const bad = selfCheckFinalReceipt(r);
    console.log(`${e.task_id}: ${r.final_decision} (toepara=${r.toepara?.verdict.verdict ?? "none"}, rastik cases=${r.rastik?.cases_executed ?? 0}, confirmed findings=${r.rastik?.findings.filter((f) => f.status === "CONFIRMED").length ?? 0}) selfcheck=${bad.length ? bad.join(",") : "ok"}`);
    out.push(r);
  }
  const wd = d.watchdog();
  if (wd.length) {
    console.error(`watchdog violations: ${wd.join("; ")}`);
    process.exit(1);
  }
  write("factory-registry.json", d.registry);
  write("factory-queue.json", { queue_version: 1, tasks: d.queue, transitions: d.log });
  write("factory-receipts.json", { receipts_version: 1, closed_loops: [...receiptsDoc.closed_loops, ...out] });
  console.log(JSON.stringify(d.counts()));
} else {
  console.error("usage: factory <init|validate|status|run-loop>");
  process.exit(2);
}
