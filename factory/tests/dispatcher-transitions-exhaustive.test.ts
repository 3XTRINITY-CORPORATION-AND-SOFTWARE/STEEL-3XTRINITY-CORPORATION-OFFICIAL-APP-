import test from "node:test";
import assert from "node:assert/strict";
import { Dispatcher, DispatchError, LEGAL_TRANSITIONS, type QueueEntry } from "../dispatcher.ts";
import { WORKER_STATES, buildInitialRegistry, type WorkerState } from "../registry.ts";
import { envelope, fixedClock } from "./fixtures.ts";

/**
 * A-020: exhaustive state-machine test. The reference machine below is an independent literal copy of the
 * documented design (dispatcher.ts header). It is compared against the real dispatcher for
 *   (1) all 6x6 = 36 (from,to) pairs, including side effects and logging,
 *   (2) every sequence of up to 4 transition attempts (6+36+216+1296 = 1554 walks) from SLEEP.
 */
const AGENT = "FORGE-026";
const TASK = "t-001";
const DOCUMENTED: Record<WorkerState, WorkerState[]> = {
  SLEEP: ["READY"],
  READY: ["ACTIVE"],
  ACTIVE: ["VERIFY", "BLOCKED"],
  VERIFY: ["DONE", "BLOCKED"],
  DONE: ["SLEEP"],
  BLOCKED: ["SLEEP"],
};
const legal = (from: WorkerState, to: WorkerState) => DOCUMENTED[from].includes(to);
const QUEUE_STATUS_FOR: Record<WorkerState, QueueEntry["status"]> = { SLEEP: "QUEUED", READY: "QUEUED", ACTIVE: "ACTIVE", VERIFY: "ACTIVE", DONE: "DONE", BLOCKED: "BLOCKED" };

function fresh() {
  const d = new Dispatcher(buildInitialRegistry({ [AGENT]: ["kratt:hash-files"] }), { clock: fixedClock() });
  d.enqueue(envelope());
  return d;
}
/** Put the worker into `from` in a state the watchdog accepts (SLEEP has no task, every other state holds TASK). */
function placed(from: WorkerState) {
  const d = fresh();
  const w = d.worker(AGENT);
  w.state = from;
  w.current_task = from === "SLEEP" ? null : TASK;
  d.queue[0]!.status = QUEUE_STATUS_FOR[from];
  assert.deepEqual(d.watchdog(), [], `precondition ${from}`);
  return d;
}
const attempt = (d: Dispatcher, to: WorkerState) => {
  try {
    d.transition(AGENT, to, { task_id: TASK, reason: "r", evidence: "e" });
    return "ok";
  } catch (e) {
    return e instanceof DispatchError ? e.code : `other:${String(e)}`;
  }
};
const snapshot = (d: Dispatcher) => JSON.stringify({ w: d.worker(AGENT), q: d.queue.map((q) => [q.task_id, q.status]), all: d.registry.workers.filter((w) => w.id !== AGENT).map((w) => [w.state, w.current_task, w.completed_tasks, w.failed_tasks]) });

test("LEGAL_TRANSITIONS equals the documented machine exactly: 8 edges, no self-loops, no dead ends, everything reachable from SLEEP", () => {
  assert.deepEqual(Object.keys(LEGAL_TRANSITIONS).sort(), [...WORKER_STATES].sort());
  for (const s of WORKER_STATES) assert.deepEqual([...LEGAL_TRANSITIONS[s]].sort(), [...DOCUMENTED[s]].sort(), s);
  assert.equal(WORKER_STATES.reduce((n, s) => n + LEGAL_TRANSITIONS[s].length, 0), 8);
  for (const s of WORKER_STATES) {
    assert.ok(!LEGAL_TRANSITIONS[s].includes(s), `${s} -> ${s} must not be legal`);
    assert.ok(LEGAL_TRANSITIONS[s].length >= 1, `${s} is not a dead end`);
  }
  const seen = new Set<WorkerState>(["SLEEP"]);
  const frontier: WorkerState[] = ["SLEEP"];
  while (frontier.length) {
    for (const n of LEGAL_TRANSITIONS[frontier.shift() as WorkerState]) {
      if (seen.has(n)) continue;
      seen.add(n);
      frontier.push(n);
    }
  }
  assert.deepEqual([...seen].sort(), [...WORKER_STATES].sort());
});

test("all 36 (from,to) pairs: exactly the 8 legal ones are accepted; the 28 others are rejected as illegal-transition:<from>-><to> and change NOTHING", () => {
  let accepted = 0;
  let rejected = 0;
  for (const from of WORKER_STATES) {
    for (const to of WORKER_STATES) {
      const d = placed(from);
      const before = snapshot(d);
      const out = attempt(d, to);
      if (legal(from, to)) {
        accepted++;
        assert.equal(out, "ok", `${from}->${to}`);
        assert.equal(d.worker(AGENT).state, to, `${from}->${to} moved the worker`);
      } else {
        rejected++;
        assert.equal(out, `illegal-transition:${from}->${to}`, `${from}->${to}`);
        assert.equal(snapshot(d), before, `${from}->${to}: a rejected attempt mutated state`);
      }
      assert.deepEqual(d.watchdog(), [], `${from}->${to}: watchdog clean afterwards`);
    }
  }
  assert.deepEqual([accepted, rejected], [8, 28]);
});

test("every one of the 36 attempts is logged exactly once, accepted or not, with seq, agent, from, to, task and a reason", () => {
  for (const from of WORKER_STATES) {
    for (const to of WORKER_STATES) {
      const d = placed(from);
      const out = attempt(d, to);
      assert.equal(d.log.length, 1, `${from}->${to} log length`);
      const rec = d.log[0]!;
      assert.equal(rec.seq, 1);
      assert.equal(rec.agent_id, AGENT);
      assert.equal(rec.from, from);
      assert.equal(rec.to, to);
      assert.equal(rec.task_id, TASK, "task context is recorded");
      assert.equal(rec.accepted, out === "ok", `${from}->${to} accepted flag`);
      assert.equal(rec.reason, out === "ok" ? "r" : out, `${from}->${to} reason`);
      assert.match(rec.at, /^2026-10-03T00:00:00\.000Z$/);
    }
  }
});

test("accepted edges have exactly their documented side effects (and no others)", () => {
  // SLEEP -> READY binds the task
  let d = placed("SLEEP");
  attempt(d, "READY");
  assert.equal(d.worker(AGENT).current_task, TASK);
  assert.equal(d.queue[0]!.status, "QUEUED", "READY does not start the task");
  // READY -> ACTIVE starts it
  d = placed("READY");
  attempt(d, "ACTIVE");
  assert.equal(d.queue[0]!.status, "ACTIVE");
  // ACTIVE -> VERIFY: no counters
  d = placed("ACTIVE");
  attempt(d, "VERIFY");
  assert.deepEqual([d.worker(AGENT).completed_tasks, d.worker(AGENT).failed_tasks, d.queue[0]!.status], [0, 0, "ACTIVE"]);
  // VERIFY -> DONE counts one completion, records evidence, closes the task
  d = placed("VERIFY");
  attempt(d, "DONE");
  assert.deepEqual([d.worker(AGENT).completed_tasks, d.worker(AGENT).failed_tasks, d.worker(AGENT).evidence, d.queue[0]!.status], [1, 0, ["e"], "DONE"]);
  // ACTIVE -> BLOCKED and VERIFY -> BLOCKED count one failure, never a completion
  for (const from of ["ACTIVE", "VERIFY"] as const) {
    d = placed(from);
    attempt(d, "BLOCKED");
    assert.deepEqual([d.worker(AGENT).completed_tasks, d.worker(AGENT).failed_tasks, d.worker(AGENT).evidence, d.queue[0]!.status], [0, 1, [], "BLOCKED"], from);
  }
  // DONE -> SLEEP and BLOCKED -> SLEEP release the task; counters untouched
  for (const from of ["DONE", "BLOCKED"] as const) {
    d = placed(from);
    const c = [d.worker(AGENT).completed_tasks, d.worker(AGENT).failed_tasks];
    attempt(d, "SLEEP");
    assert.equal(d.worker(AGENT).current_task, null, from);
    assert.deepEqual([d.worker(AGENT).completed_tasks, d.worker(AGENT).failed_tasks], c, from);
    assert.equal(d.queue[0]!.status, QUEUE_STATUS_FOR[from], "task status is final and not rewritten by SLEEP");
  }
});

test("a legal edge is still refused when its precondition is missing (log says accepted:false, state unchanged)", () => {
  const cases: [string, WorkerState, WorkerState, Parameters<Dispatcher["transition"]>[2], string][] = [
    ["wake without task id", "SLEEP", "READY", {}, "no-task-no-wake"],
    ["wake with unknown task", "SLEEP", "READY", { task_id: "nope" }, "unknown-task"],
    ["DONE without evidence", "VERIFY", "DONE", { task_id: TASK }, "done-requires-evidence"],
    ["DONE with empty evidence string", "VERIFY", "DONE", { task_id: TASK, evidence: "" }, "done-requires-evidence"],
    ["BLOCKED without reason (from ACTIVE)", "ACTIVE", "BLOCKED", { task_id: TASK }, "blocked-requires-reason"],
    ["BLOCKED without reason (from VERIFY)", "VERIFY", "BLOCKED", { task_id: TASK }, "blocked-requires-reason"],
    ["BLOCKED with empty reason", "ACTIVE", "BLOCKED", { task_id: TASK, reason: "" }, "blocked-requires-reason"],
    ["edge names a different task than the worker holds", "READY", "ACTIVE", { task_id: "t-other" }, "task-mismatch"],
  ];
  for (const [label, from, to, ctx, want] of cases) {
    const d = placed(from);
    const before = snapshot(d);
    let code = "no-throw";
    try {
      d.transition(AGENT, to, ctx);
    } catch (e) {
      code = e instanceof DispatchError ? e.code : String(e);
    }
    assert.equal(code, want, label);
    assert.equal(snapshot(d), before, `${label}: mutated state`);
    assert.equal(d.log.length, 1, `${label}: logged`);
    assert.equal(d.log[0]!.accepted, false, label);
    assert.equal(d.log[0]!.reason, want, label);
  }
});

test("a task that already ran cannot be re-woken by a legal SLEEP -> READY (task-not-queued), for both DONE and BLOCKED outcomes", () => {
  for (const end of ["DONE", "BLOCKED"] as const) {
    const d = placed(end);
    attempt(d, "SLEEP");
    assert.equal(attempt(d, "READY"), "task-not-queued", end);
    assert.equal(d.worker(AGENT).state, "SLEEP", end);
  }
});

test("unknown target states are rejected (unknown-state) and logged, including look-alikes, case variants and non-strings", () => {
  for (const bogus of ["sleep", "SLEEP ", "ASLEEP", "", "DONE\n", "READY\0", "IDLE", "constructor", "__proto__"]) {
    const d = placed("SLEEP");
    const before = snapshot(d);
    assert.equal(attempt(d, bogus as WorkerState), "unknown-state", JSON.stringify(bogus));
    assert.equal(snapshot(d), before);
    assert.equal(d.log.length, 1);
    assert.equal(d.log[0]!.accepted, false);
  }
  for (const bogus of [undefined, null, 1, {}, ["READY"]]) {
    const d = placed("SLEEP");
    assert.equal(attempt(d, bogus as unknown as WorkerState), "unknown-state");
    assert.equal(d.worker(AGENT).state, "SLEEP");
  }
});

test("EXHAUSTIVE WALKS: all 1554 sequences of 1..4 attempts from SLEEP behave exactly like the reference machine (state, accept/reject, log length, counters)", () => {
  const states = [...WORKER_STATES];
  let walks = 0;
  let acceptedSteps = 0;
  const go = (seq: WorkerState[]) => {
    // reference
    let ref: WorkerState = "SLEEP";
    let refDone = 0;
    let refBlocked = 0;
    const expect: boolean[] = [];
    for (const to of seq) {
      if (legal(ref, to)) {
        expect.push(true);
        if (to === "DONE") refDone++;
        if (to === "BLOCKED") refBlocked++;
        ref = to;
      } else expect.push(false);
    }
    // real
    const d = fresh();
    const got: boolean[] = [];
    for (const to of seq) got.push(attempt(d, to) === "ok");
    const w = d.worker(AGENT);
    const label = seq.join(">");
    assert.deepEqual(got, expect, label);
    assert.equal(w.state, ref, label);
    assert.equal(w.completed_tasks, refDone, label);
    assert.equal(w.failed_tasks, refBlocked, label);
    assert.equal(d.log.length, seq.length, `${label}: one log record per attempt`);
    assert.deepEqual(d.log.map((r) => r.accepted), expect, label);
    assert.deepEqual(d.log.map((r) => r.seq), seq.map((_, i) => i + 1), label);
    assert.deepEqual(d.watchdog(), [], label);
    walks++;
    acceptedSteps += expect.filter(Boolean).length;
  };
  const rec = (seq: WorkerState[], depth: number) => {
    if (seq.length > 0) go(seq);
    if (depth === 0) return;
    for (const s of states) rec([...seq, s], depth - 1);
  };
  rec([], 4);
  assert.equal(walks, 6 + 36 + 216 + 1296);
  assert.ok(acceptedSteps > 0);
});

test("the only way to a completed task is the full legal path with evidence: no 1..4-step walk from SLEEP skipping a state ever increments completed_tasks", () => {
  const skip: WorkerState[][] = [["DONE"], ["VERIFY", "DONE"], ["ACTIVE", "VERIFY", "DONE"], ["READY", "VERIFY", "DONE"], ["READY", "DONE"], ["READY", "ACTIVE", "DONE"]];
  for (const seq of skip) {
    const d = fresh();
    for (const to of seq) attempt(d, to);
    assert.equal(d.worker(AGENT).completed_tasks, 0, seq.join(">"));
    assert.deepEqual(d.worker(AGENT).evidence, []);
  }
  const d = fresh();
  for (const to of ["READY", "ACTIVE", "VERIFY", "DONE"] as const) assert.equal(attempt(d, to), "ok");
  assert.equal(d.worker(AGENT).completed_tasks, 1);
});

test("other workers are never touched by any of the 36 attempts (isolation)", () => {
  for (const from of WORKER_STATES) {
    for (const to of WORKER_STATES) {
      const d = placed(from);
      const others = () => JSON.stringify(d.registry.workers.filter((w) => w.id !== AGENT));
      const before = others();
      attempt(d, to);
      assert.equal(others(), before, `${from}->${to}`);
    }
  }
});

test("a worker cannot wake on, or act on, a task owned by another worker (task-owner-mismatch / task-mismatch), and both workers stay untouched", () => {
  const d = fresh();
  const other = d.registry.workers.find((w) => w.id !== AGENT && w.factory === d.worker(AGENT).factory);
  assert.ok(other, "a sibling worker in the same factory exists");
  const snap = () => JSON.stringify([d.worker(AGENT), other, d.queue.map((q) => [q.task_id, q.status])]);
  const before = snap();
  assert.throws(() => d.transition(other.id, "READY", { task_id: TASK }), (e) => e instanceof DispatchError && e.code === "task-owner-mismatch");
  assert.equal(snap(), before, "owner mismatch changes nothing");
  const last = d.log[d.log.length - 1]!;
  assert.deepEqual([last.agent_id, last.accepted, last.reason], [other.id, false, "task-owner-mismatch"]);

  // Owner proceeds legitimately; the sibling, parked in a non-SLEEP state on a different task, cannot name TASK.
  d.transition(AGENT, "READY", { task_id: TASK });
  other.state = "ACTIVE";
  other.current_task = "some-other-task";
  const mid = snap();
  assert.throws(() => d.transition(other.id, "VERIFY", { task_id: TASK }), (e) => e instanceof DispatchError && e.code === "task-mismatch");
  assert.equal(snap(), mid, "task mismatch changes nothing");
  assert.equal(d.log[d.log.length - 1]!.accepted, false);
});
