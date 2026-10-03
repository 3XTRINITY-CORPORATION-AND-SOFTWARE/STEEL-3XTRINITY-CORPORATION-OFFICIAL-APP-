import test from "node:test";
import assert from "node:assert/strict";
import { DispatchError, Dispatcher, LEGAL_TRANSITIONS } from "../dispatcher.ts";
import { WORKER_STATES, buildInitialRegistry, validateInitialRegistry, type WorkerState } from "../registry.ts";
import { envelope, fixedClock } from "./fixtures.ts";

const mk = (handlers: string[] = []) => new Dispatcher(buildInitialRegistry({ "FORGE-026": ["kratt:hash-files"] }), { clock: fixedClock(), handlers });
const code = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    return e instanceof DispatchError ? e.code : `other:${String(e)}`;
  }
  return "no-throw";
};

test("legal path SLEEP -> READY -> ACTIVE -> VERIFY -> DONE -> SLEEP records every step and counts one completed task", () => {
  const d = mk();
  d.enqueue(envelope());
  const id = "FORGE-026";
  d.transition(id, "READY", { task_id: "t-001" });
  d.transition(id, "ACTIVE", { task_id: "t-001" });
  d.transition(id, "VERIFY", { task_id: "t-001" });
  d.transition(id, "DONE", { task_id: "t-001", evidence: "receipt:t-001" });
  d.transition(id, "SLEEP", { task_id: "t-001" });
  const w = d.worker(id);
  assert.equal(w.state, "SLEEP");
  assert.equal(w.current_task, null);
  assert.equal(w.completed_tasks, 1);
  assert.deepEqual(w.evidence, ["receipt:t-001"]);
  assert.deepEqual(d.log.map((r) => `${r.from}->${r.to}`), ["SLEEP->READY", "READY->ACTIVE", "ACTIVE->VERIFY", "VERIFY->DONE", "DONE->SLEEP"]);
  assert.ok(d.log.every((r) => r.accepted && r.task_id === "t-001"));
  assert.deepEqual(d.log.map((r) => r.seq), [1, 2, 3, 4, 5]);
  assert.deepEqual(d.watchdog(), []);
});

test("failure path ACTIVE -> BLOCKED -> SLEEP counts a failed task, never a completed one", () => {
  const d = mk();
  d.enqueue(envelope());
  d.transition("FORGE-026", "READY", { task_id: "t-001" });
  d.transition("FORGE-026", "ACTIVE", { task_id: "t-001" });
  d.transition("FORGE-026", "BLOCKED", { task_id: "t-001", reason: "scope file missing" });
  d.transition("FORGE-026", "SLEEP", { task_id: "t-001" });
  const w = d.worker("FORGE-026");
  assert.equal(w.completed_tasks, 0);
  assert.equal(w.failed_tasks, 1);
  assert.equal(w.state, "SLEEP");
  assert.equal(d.queue[0]?.status, "BLOCKED");
  assert.equal(code(() => d.transition("FORGE-026", "READY", { task_id: "t-001" })), "task-not-queued", "a blocked task cannot be silently re-run");
});

test("EVERY illegal (from,to) pair is rejected, logged as rejected, and leaves the worker unchanged", () => {
  let illegal = 0;
  for (const from of WORKER_STATES) {
    for (const to of WORKER_STATES) {
      if ((LEGAL_TRANSITIONS[from] as readonly WorkerState[]).includes(to)) continue;
      illegal++;
      const d = mk();
      d.enqueue(envelope());
      const w = d.worker("FORGE-026");
      w.state = from;
      w.current_task = from === "SLEEP" ? null : "t-001";
      const before = JSON.stringify(w);
      const c = code(() => d.transition("FORGE-026", to, { task_id: "t-001", reason: "r", evidence: "e" }));
      assert.equal(c, `illegal-transition:${from}->${to}`, `${from}->${to}`);
      assert.equal(JSON.stringify(w), before, `${from}->${to} mutated the worker`);
      assert.equal(d.log.length, 1);
      assert.equal(d.log[0]?.accepted, false);
    }
  }
  assert.equal(illegal, 36 - 8); // 6x6 pairs minus the 8 legal edges
});

test("no task, no wake: SLEEP -> READY needs a queued task owned by that worker", () => {
  const d = mk();
  d.enqueue(envelope());
  assert.equal(code(() => d.transition("FORGE-026", "READY")), "no-task-no-wake");
  assert.equal(code(() => d.transition("FORGE-026", "READY", { task_id: "nope" })), "unknown-task");
  assert.equal(code(() => d.transition("FORGE-027", "READY", { task_id: "t-001" })), "task-owner-mismatch");
  assert.equal(code(() => d.transition("NOPE-001", "READY", { task_id: "t-001" })), "unknown-worker");
  assert.equal(d.worker("FORGE-026").state, "SLEEP");
  assert.equal(d.counts().sleeping, 150);
});

test("later edges must name the held task; DONE needs evidence; BLOCKED needs a reason", () => {
  const d = mk();
  d.enqueue(envelope());
  d.enqueue(envelope({ task_id: "t-002" }));
  d.transition("FORGE-026", "READY", { task_id: "t-001" });
  assert.equal(code(() => d.transition("FORGE-026", "ACTIVE", { task_id: "t-002" })), "task-mismatch");
  d.transition("FORGE-026", "ACTIVE", { task_id: "t-001" });
  assert.equal(code(() => d.transition("FORGE-026", "BLOCKED", { task_id: "t-001" })), "blocked-requires-reason");
  d.transition("FORGE-026", "VERIFY", { task_id: "t-001" });
  assert.equal(code(() => d.transition("FORGE-026", "DONE", { task_id: "t-001" })), "done-requires-evidence");
  assert.equal(d.worker("FORGE-026").completed_tasks, 0, "no evidence, no completion");
});

test("enqueue: duplicate task_id, ownerless tasks, factory mismatch and invalid envelopes are rejected", () => {
  const d = mk();
  d.enqueue(envelope());
  assert.equal(code(() => d.enqueue(envelope())), "duplicate-task");
  assert.equal(code(() => d.enqueue(envelope({ task_id: "t-9", agent_id: "FORGE-999" }))), "task-without-owner");
  assert.ok(code(() => d.enqueue(envelope({ task_id: "t-8", factory: "SERPENT" }))).startsWith("envelope-invalid:"));
  assert.ok(code(() => d.enqueue({ ...envelope({ task_id: "t-7" }), protocol_version: 2 })).includes("protocol-incompatible-major:2"));
  assert.ok(code(() => d.enqueue({})).startsWith("envelope-invalid:"));
  assert.equal(d.queue.length, 1);
});

test("watchdog: duplicate holders, ownerless tasks, awake-without-task and sleeping-with-task are all detected", () => {
  const d = mk();
  d.enqueue(envelope());
  assert.deepEqual(d.watchdog(), []);
  d.worker("FORGE-001").state = "ACTIVE";
  assert.ok(d.watchdog().includes("FORGE-001:awake-without-task"));
  d.worker("FORGE-001").state = "SLEEP";
  d.worker("FORGE-002").current_task = "t-001";
  assert.ok(d.watchdog().includes("FORGE-002:sleeping-with-task"));
  assert.ok(d.watchdog().some((x) => x.startsWith("FORGE-002:holds-task-owned-by-FORGE-026")));
  d.worker("FORGE-026").current_task = "t-001";
  assert.ok(d.watchdog().some((x) => x.startsWith("duplicate-task-holder:t-001")));
  d.worker("FORGE-002").current_task = null;
  d.worker("FORGE-026").current_task = null;
  d.queue[0]!.agent_id = "FORGE-404";
  assert.ok(d.watchdog().includes("task-without-owner:t-001"));
  d.queue[0]!.agent_id = "FORGE-026";
  d.queue.push({ ...d.queue[0]! });
  assert.ok(d.watchdog().includes("duplicate-task:t-001"));
});

test("run(): success walks the full machine; failure and thrown work end BLOCKED -> SLEEP; unavailable capability is refused before any transition", async () => {
  const d = mk(["FORGE-026:kratt:hash-files"]);
  d.enqueue(envelope());
  d.enqueue(envelope({ task_id: "t-002" }));
  d.enqueue(envelope({ task_id: "t-003" }));
  const ok = await d.run("t-001", () => ({ ok: true, evidence: "ev:1" }), { capability: "kratt:hash-files" });
  assert.equal(ok?.ok, true);
  assert.equal(await d.run("t-002", () => ({ ok: false, evidence: null, note: "nope" })).then((r) => r?.ok), false);
  assert.equal(await d.run("t-003", () => { throw new Error("boom"); }), null);
  const w = d.worker("FORGE-026");
  assert.equal(w.completed_tasks, 1);
  assert.equal(w.failed_tasks, 2);
  assert.equal(w.state, "SLEEP");
  assert.deepEqual(d.watchdog(), []);
  d.enqueue(envelope({ task_id: "t-004" }));
  const before = d.log.length;
  await assert.rejects(d.run("t-004", () => ({ ok: true, evidence: "x" }), { capability: "kratt:run-test" }), /capability-not-available/);
  assert.equal(d.log.length, before, "no transition logged for a refused capability");
});

test("AVAILABLE counts only workers whose capability has a registered handler; with none it is 0", () => {
  assert.equal(mk().counts().available, 0);
  assert.equal(mk().counts().with_capabilities, 1);
  assert.equal(mk(["FORGE-026:kratt:hash-files"]).counts().available, 1);
  assert.equal(mk(["FORGE-027:kratt:hash-files"]).counts().available, 0, "handler for a worker that does not declare it");
});

test("a fresh dispatcher registry satisfies the init invariants (150 sleeping, 0 active, 0 completed)", () => {
  const d = new Dispatcher(buildInitialRegistry());
  assert.deepEqual(validateInitialRegistry(d.registry), []);
  const c = d.counts();
  assert.deepEqual([c.defined, c.sleeping, c.active, c.executed_tasks, c.available], [150, 150, 0, 0, 0]);
});
