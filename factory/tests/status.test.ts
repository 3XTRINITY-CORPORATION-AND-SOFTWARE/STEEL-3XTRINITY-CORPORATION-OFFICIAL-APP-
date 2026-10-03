import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dispatcher } from "../dispatcher.ts";
import { digestOf } from "../protocol/types.ts";
import { WORKER_STATES, buildInitialRegistry, countRegistry } from "../registry.ts";
import { DECISIONS, TASK_STATUSES, summarizeStatus } from "../status.ts";
import { envelope, fixedClock } from "./fixtures.ts";

const FACTORY_DIR = resolve(import.meta.dirname, "..");

// ---- fixtures: hand-built documents with hand-computed expectations -------------------------
type Doc = Record<string, any>;
const task = (task_id: string, status: string, agent_id = "FORGE-026"): Doc => ({ task_id, agent_id, status, envelope_digest: "0".repeat(64) });
const queueDoc = (...tasks: Doc[]): Doc => ({ queue_version: 1, tasks });
const registry = (patch: Record<string, Partial<Doc>> = {}): Doc => {
  const r = buildInitialRegistry() as unknown as Doc;
  for (const w of r.workers) Object.assign(w, patch[w.id] ?? {});
  return r;
};
const receipt = (task_id: string, final_decision: string, extra: Doc = {}): Doc => {
  const body = { receipt_kind: "closed-loop/v1", protocol_version: 1, task_id, final_decision, stages: [], ...extra };
  return { ...body, final_digest: digestOf(body) };
};
const receiptsDoc = (...closed_loops: Doc[]): Doc => ({ receipts_version: 1, closed_loops });

// 7 tasks: QUEUED 2, ACTIVE 1, DONE 3, BLOCKED 1. Workers: ACTIVE 1 (holds t-act), others SLEEP; ledgers 3 done / 1 failed.
const QUEUE = queueDoc(
  task("t-q1", "QUEUED"), task("t-q2", "QUEUED"), task("t-act", "ACTIVE", "FORGE-027"),
  task("t-d1", "DONE"), task("t-d2", "DONE", "FORGE-028"), task("t-d3", "DONE", "FORGE-028"), task("t-b1", "BLOCKED", "FORGE-029"),
);
const REG = () => registry({
  "FORGE-026": { completed_tasks: 1 },
  "FORGE-027": { state: "ACTIVE", current_task: "t-act" },
  "FORGE-028": { completed_tasks: 2 },
  "FORGE-029": { failed_tasks: 1 },
});
const REC = () => receiptsDoc(receipt("t-d1", "ADMIT"), receipt("t-d2", "DENY"), receipt("t-d3", "QUARANTINE"));
const clean = () => summarizeStatus(QUEUE, REG(), REC());

test("counts by TaskStatus / WorkerState / decision are exact on a hand-built consistent state, ok=true, no anomalies", () => {
  const s = clean();
  assert.deepEqual(s.anomalies, []);
  assert.equal(s.ok, true);
  assert.deepEqual(s.tasks, { seen: 7, counted: 7, rejected: 0, by_status: { QUEUED: 2, ACTIVE: 1, DONE: 3, BLOCKED: 1 } });
  assert.deepEqual(s.workers.by_state, { SLEEP: 149, READY: 0, ACTIVE: 1, VERIFY: 0, DONE: 0, BLOCKED: 0 });
  assert.deepEqual([s.workers.seen, s.workers.counted, s.workers.rejected], [150, 150, 0]);
  assert.deepEqual(s.receipts.by_decision, { ADMIT: 1, DENY: 1, QUARANTINE: 1 });
  assert.deepEqual(s.ledger, { registry_completed_tasks: 3, registry_failed_tasks: 1 });
});

test("an empty factory reports zeros, last=null and ok=true (nothing fabricated)", () => {
  const s = summarizeStatus(queueDoc(), buildInitialRegistry(), receiptsDoc());
  assert.deepEqual(s.tasks.by_status, { QUEUED: 0, ACTIVE: 0, DONE: 0, BLOCKED: 0 });
  assert.deepEqual(s.receipts, { seen: 0, counted: 0, rejected: 0, by_decision: { ADMIT: 0, DENY: 0, QUARANTINE: 0 }, last: null });
  assert.deepEqual(s.workers.by_state, { SLEEP: 150, READY: 0, ACTIVE: 0, VERIFY: 0, DONE: 0, BLOCKED: 0 });
  assert.equal(s.ok, true);
});

test("last receipt digest is the LAST element's own digest, not the first or an older one", () => {
  const s = clean();
  assert.deepEqual(s.receipts.last, { task_id: "t-d3", final_decision: "QUARANTINE", final_digest: (REC().closed_loops[2] as Doc).final_digest });
  assert.notEqual(s.receipts.last?.final_digest, (REC().closed_loops[0] as Doc).final_digest);
});

test("a tampered receipt (digest no longer matches its body) is not counted, ok=false, and never shown as last", () => {
  const rec = REC();
  rec.closed_loops[2].final_decision = "ADMIT"; // body edited after sealing
  const s = summarizeStatus(QUEUE, REG(), rec);
  assert.equal(s.ok, false);
  assert.ok(s.anomalies.includes("receipt[2]:digest-mismatch"));
  assert.ok(s.anomalies.includes("last-receipt-invalid"));
  assert.deepEqual(s.receipts.by_decision, { ADMIT: 1, DENY: 1, QUARANTINE: 0 });
  assert.equal(s.receipts.counted, 2);
  assert.equal(s.receipts.rejected, 1);
  assert.equal(s.receipts.last, null, "an older valid receipt must not be presented as the latest");
});

test("a receipt with a forged-format digest, unknown decision, wrong kind or no task id is rejected, never counted", () => {
  const good = receipt("t-d1", "ADMIT");
  const cases: Array<[string, Doc, string]> = [
    ["bad-digest-format", { ...good, final_digest: "XYZ" }, "receipt[0]:bad-digest-format"],
    ["illegal-decision", receipt("t-d1", "PROCEED"), "receipt[0]:illegal-decision"],
    ["wrong kind", { ...good, receipt_kind: "other" }, "receipt[0]:malformed"],
    ["no task id", receipt("", "ADMIT"), "receipt[0]:no-task-id"],
  ];
  for (const [name, r, code] of cases) {
    const s = summarizeStatus(QUEUE, REG(), receiptsDoc(r));
    assert.equal(s.ok, false, name);
    assert.ok(s.anomalies.includes(code), `${name}: ${s.anomalies.join(",")}`);
    assert.deepEqual(s.receipts.by_decision, { ADMIT: 0, DENY: 0, QUARANTINE: 0 }, name);
    assert.equal(s.receipts.last, null, name);
  }
});

test("a duplicate receipt for one task is counted once (no inflation)", () => {
  const s = summarizeStatus(QUEUE, REG(), receiptsDoc(receipt("t-d1", "ADMIT"), receipt("t-d1", "ADMIT", { stages: [{ x: 1 }] })));
  assert.equal(s.receipts.counted, 1);
  assert.equal(s.receipts.by_decision.ADMIT, 1);
  assert.ok(s.anomalies.includes("receipt[1]:duplicate-receipt-task"));
  assert.equal(s.ok, false);
});

test("a receipt for a task that is not in the queue is rejected as orphaned", () => {
  const s = summarizeStatus(QUEUE, REG(), receiptsDoc(receipt("ghost", "ADMIT")));
  assert.ok(s.anomalies.includes("receipt[0]:task-not-in-queue"));
  assert.equal(s.receipts.counted, 0);
  assert.equal(s.ok, false);
});

test("tasks with an unknown status, malformed shape or duplicate id are not counted", () => {
  const q = queueDoc(task("a", "DONE"), task("b", "RUNNING"), task("a", "QUEUED"), { task_id: "c" }, "junk" as any, task("", "DONE"));
  const s = summarizeStatus(q, registry({ "FORGE-026": { completed_tasks: 1 } }), receiptsDoc());
  assert.deepEqual(s.tasks.by_status, { QUEUED: 0, ACTIVE: 0, DONE: 1, BLOCKED: 0 });
  assert.deepEqual([s.tasks.seen, s.tasks.counted, s.tasks.rejected], [6, 1, 5]);
  for (const code of ["task[1]:b:illegal-status", "task[2]:a:duplicate-task-id", "task[3]:malformed", "task[4]:malformed", "task[5]:malformed"]) assert.ok(s.anomalies.includes(code), code);
  assert.equal(s.ok, false);
});

test("workers with an illegal state, duplicate id or invalid counters are not counted or summed", () => {
  const r = registry();
  r.workers[0].state = "FLYING";
  r.workers[1].id = r.workers[2].id; // duplicate id
  r.workers[3].completed_tasks = -4;
  r.workers[4].failed_tasks = 1.5;
  r.workers[5].completed_tasks = Number.NaN;
  r.workers[6] = null;
  const s = summarizeStatus(queueDoc(), r, receiptsDoc());
  assert.equal(s.workers.counted, 144);
  assert.equal(s.workers.rejected, 6);
  assert.equal(s.workers.by_state.SLEEP, 144);
  assert.deepEqual(s.ledger, { registry_completed_tasks: 0, registry_failed_tasks: 0 });
  for (const code of ["worker[0]:FORGE-001:illegal-state", "worker[2]:FORGE-003:duplicate-worker-id", "worker[3]:FORGE-004:invalid-task-counters", "worker[4]:FORGE-005:invalid-task-counters", "worker[5]:FORGE-006:invalid-task-counters", "worker[6]:malformed"]) assert.ok(s.anomalies.includes(code), `${code} in ${s.anomalies.slice(0, 8).join(",")}`);
  assert.equal(s.ok, false);
});

test("not-a-document inputs fail closed: zero counts, ok=false, one named anomaly each, no throw", () => {
  for (const bad of [null, undefined, 7, "x", [], {}, { tasks: "no" }]) {
    const s = summarizeStatus(bad, bad, bad);
    assert.equal(s.ok, false);
    assert.equal(s.tasks.counted + s.workers.counted + s.receipts.counted, 0);
    assert.equal(s.receipts.last, null);
    assert.equal(s.anomalies.filter((a) => /^(queue|registry|receipts):/.test(a)).length, 3, JSON.stringify(bad));
  }
});

test("inflated worker ledger (completed/failed above what the queue records) is flagged, not silently reported as clean", () => {
  const inflated = REG();
  inflated.workers[0].completed_tasks = 5; // queue has 3 DONE in total
  const s = summarizeStatus(QUEUE, inflated, REC());
  assert.ok(s.anomalies.includes("ledger-mismatch:registry-completed=8:queue-DONE=3"));
  assert.equal(s.ok, false);
  const f = REG();
  f.workers[28].failed_tasks = 0; // queue has 1 BLOCKED but no worker failure recorded
  const s2 = summarizeStatus(QUEUE, f, REC());
  assert.ok(s2.anomalies.includes("ledger-mismatch:registry-failed=0:queue-BLOCKED=1"));
  assert.equal(s2.ok, false);
});

test("state/task consistency: sleeping-with-task, awake-without-task, unqueued held task, phantom ACTIVE task and double holder are all flagged", () => {
  const a = REG();
  a.workers[0].current_task = "t-q1"; // FORGE-001 SLEEP holding a task
  assert.ok(summarizeStatus(QUEUE, a, REC()).anomalies.includes("FORGE-001:sleeping-with-task"));
  const b = REG();
  b.workers[0].state = "READY"; // awake without a task
  assert.ok(summarizeStatus(QUEUE, b, REC()).anomalies.includes("FORGE-001:awake-without-task"));
  const c = REG();
  c.workers[26].current_task = "nope"; // FORGE-027 holds a task that is not queued
  assert.ok(summarizeStatus(QUEUE, c, REC()).anomalies.includes("FORGE-027:holds-unqueued-task:nope"));
  const d = REG();
  d.workers[26].state = "SLEEP";
  d.workers[26].current_task = null; // t-act is ACTIVE in the queue but nobody holds it
  assert.ok(summarizeStatus(QUEUE, d, REC()).anomalies.includes("t-act:active-task-not-held"));
  const e = REG();
  e.workers[0].state = "READY";
  e.workers[0].current_task = "t-act"; // two holders
  assert.ok(summarizeStatus(QUEUE, e, REC()).anomalies.some((x) => x.startsWith("t-act:held-by-two-workers")));
  for (const m of [a, b, c, d, e]) assert.equal(summarizeStatus(QUEUE, m, REC()).ok, false);
});

test("ok is derived from anomalies: false iff at least one anomaly (never a constant)", () => {
  const good = clean();
  assert.equal(good.ok, good.anomalies.length === 0);
  const bad = summarizeStatus(QUEUE, REG(), receiptsDoc(receipt("ghost", "DENY")));
  assert.equal(bad.ok, bad.anomalies.length === 0);
  assert.notEqual(good.ok, bad.ok);
});

test("read-only: deep-frozen inputs are accepted, unchanged, and the result shares no state with them", () => {
  const deepFreeze = <T>(o: T): T => {
    if (typeof o === "object" && o !== null) for (const v of Object.values(o)) deepFreeze(v);
    return Object.freeze(o);
  };
  const q = deepFreeze(structuredClone(QUEUE)), r = deepFreeze(REG()), c = deepFreeze(REC());
  const before = JSON.stringify([q, r, c]);
  const s = summarizeStatus(q, r, c);
  assert.equal(JSON.stringify([q, r, c]), before);
  s.tasks.by_status.DONE = 999;
  s.anomalies.push("x");
  assert.equal(summarizeStatus(q, r, c).tasks.by_status.DONE, 3);
  assert.deepEqual(summarizeStatus(q, r, c), clean(), "pure: same input, same output");
});

test("the module has no IO, clock or randomness and is NOT wired into cli.ts", () => {
  const src = readFileSync(resolve(FACTORY_DIR, "status.ts"), "utf8");
  assert.doesNotMatch(src, /node:(fs|child_process|net|http|https|os|path)|\bfetch\(|\bDate\b|Math\.random|process\.|\brequire\(|writeFile|readFile/);
  assert.doesNotMatch(readFileSync(resolve(FACTORY_DIR, "cli.ts"), "utf8"), /status\.ts|summarizeStatus/);
});

test("the enumerations used for counting equal the real ones (registry WORKER_STATES; dispatcher TaskStatus incl. a live run; protocol decisions)", () => {
  assert.deepEqual(Object.keys(clean().workers.by_state), [...WORKER_STATES]);
  assert.deepEqual([...TASK_STATUSES], ["QUEUED", "ACTIVE", "DONE", "BLOCKED"]);
  assert.deepEqual([...DECISIONS], ["ADMIT", "DENY", "QUARANTINE"]);
  assert.deepEqual(Object.keys(clean().receipts.by_decision), [...DECISIONS]);
});

test("against a LIVE Dispatcher (real transitions): QUEUED/ACTIVE/DONE/BLOCKED counts equal the dispatcher's own, and the registry ledgers reconcile", async () => {
  const d = new Dispatcher(buildInitialRegistry(), { clock: fixedClock() });
  const mk = (id: string, agent: string) => d.enqueue(envelope({ task_id: id, agent_id: agent }));
  for (const [id, agent] of [["l-done", "FORGE-026"], ["l-blocked", "FORGE-027"], ["l-active", "FORGE-028"], ["l-queued", "FORGE-029"]] as const) mk(id, agent);
  await d.run("l-done", () => ({ ok: true, evidence: "ev:1" }));
  await d.run("l-blocked", () => ({ ok: false, evidence: null, note: "boom" }));
  d.transition("FORGE-028", "READY", { task_id: "l-active" });
  d.transition("FORGE-028", "ACTIVE", { task_id: "l-active" });
  const s = summarizeStatus({ queue_version: 1, tasks: d.queue }, d.registry, receiptsDoc());
  assert.deepEqual(s.anomalies, []);
  assert.deepEqual(s.tasks.by_status, { QUEUED: 1, ACTIVE: 1, DONE: 1, BLOCKED: 1 });
  assert.deepEqual(s.workers.by_state, { SLEEP: 149, READY: 0, ACTIVE: 1, VERIFY: 0, DONE: 0, BLOCKED: 0 });
  const c = countRegistry(d.registry);
  assert.deepEqual(s.workers.by_state, c.by_state);
  assert.deepEqual(s.ledger, { registry_completed_tasks: c.executed_tasks, registry_failed_tasks: c.failed_tasks });
  assert.equal(s.ok, true);
  assert.deepEqual(d.watchdog(), [], "the dispatcher's own watchdog agrees the state is consistent");
});

test("the committed factory files: status equals an independent recount, the real receipts verify, and last = the final receipt", () => {
  const read = (f: string) => JSON.parse(readFileSync(resolve(FACTORY_DIR, f), "utf8")) as Doc;
  const q = read("factory-queue.json"), r = read("factory-registry.json"), rc = read("factory-receipts.json");
  const s = summarizeStatus(q, r, rc);
  const tally = <T extends string>(items: any[], key: string, keys: readonly T[]) => Object.fromEntries(keys.map((k) => [k, items.filter((i) => i[key] === k).length]));
  assert.deepEqual(s.tasks.by_status, tally(q.tasks, "status", TASK_STATUSES));
  assert.deepEqual(s.workers.by_state, tally(r.workers, "state", WORKER_STATES));
  assert.deepEqual(s.receipts.by_decision, tally(rc.closed_loops, "final_decision", DECISIONS));
  assert.equal(s.tasks.seen, q.tasks.length);
  assert.equal(s.receipts.last?.final_digest, rc.closed_loops.at(-1).final_digest);
  assert.deepEqual(s.anomalies, [], "committed factory state must be self-consistent");
  assert.equal(s.ok, true);
});
