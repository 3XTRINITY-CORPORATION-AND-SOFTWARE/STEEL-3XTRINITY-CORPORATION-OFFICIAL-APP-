import { digestOf } from "./protocol/types.ts";
import type { CerberusDecisionValue } from "./protocol/types.ts";
import type { TaskStatus } from "./dispatcher.ts";
import { WORKER_STATES, type WorkerState } from "./registry.ts";

/**
 * Read-only operator status (F-020). A pure function of three already-parsed documents:
 *   queue    = factory-queue.json    { tasks: QueueEntry[] }
 *   registry = factory-registry.json { workers: Worker[] }
 *   receipts = factory-receipts.json { closed_loops: ClosedLoopReceipt[] }
 *
 * No IO, no clock, no mutation of its inputs, and NOT wired into cli.ts.
 *
 * Counting rule (no inflation): an item is counted only if it is well-formed. Every malformed,
 * duplicate or unverifiable item is excluded from the counts, is tallied under `rejected`, and is
 * named in `anomalies`. `ok` is true only when there is no anomaly - an operator must never read a
 * clean-looking count off a document that failed its own checks (fail-closed, never fail-open).
 */

export const TASK_STATUSES = ["QUEUED", "ACTIVE", "DONE", "BLOCKED"] as const satisfies readonly TaskStatus[];
// Compile-time exhaustiveness: adding a TaskStatus without listing it above fails typecheck.
type MissingTaskStatus = Exclude<TaskStatus, (typeof TASK_STATUSES)[number]>;
const taskStatusesExhaustive: MissingTaskStatus extends never ? true : never = true;
void taskStatusesExhaustive;

export const DECISIONS = ["ADMIT", "DENY", "QUARANTINE"] as const satisfies readonly CerberusDecisionValue[];
type Decision = (typeof DECISIONS)[number];

export interface StatusSummary {
  /** true only when `anomalies` is empty. */
  ok: boolean;
  tasks: { seen: number; counted: number; rejected: number; by_status: Record<TaskStatus, number> };
  workers: { seen: number; counted: number; rejected: number; by_state: Record<WorkerState, number> };
  receipts: {
    seen: number;
    counted: number;
    rejected: number;
    by_decision: Record<Decision, number>;
    /**
     * The LAST receipt in the document, and only if it is itself valid (recomputed digest matches).
     * If the last receipt is invalid this is null (an older valid receipt is never shown as "latest").
     */
    last: { task_id: string; final_decision: Decision; final_digest: string } | null;
  };
  /** Sums over counted workers, cross-checked against the queue (see anomalies). */
  ledger: { registry_completed_tasks: number; registry_failed_tasks: number };
  anomalies: string[];
}

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const isStr = (x: unknown): x is string => typeof x === "string" && x.length > 0;
const isCount = (x: unknown): x is number => typeof x === "number" && Number.isSafeInteger(x) && x >= 0;
const SHA256 = /^[0-9a-f]{64}$/;
const zero = <K extends string>(keys: readonly K[]) => Object.fromEntries(keys.map((k) => [k, 0])) as Record<K, number>;
const has = <T extends string>(list: readonly T[], x: unknown): x is T => typeof x === "string" && (list as readonly string[]).includes(x);

function listOf(doc: unknown, field: string, label: string, anomalies: string[]): unknown[] {
  if (!isObj(doc)) {
    anomalies.push(`${label}:not-an-object`);
    return [];
  }
  const v = doc[field];
  if (!Array.isArray(v)) {
    anomalies.push(`${label}:${field}-not-array`);
    return [];
  }
  return v;
}

export function summarizeStatus(queue: unknown, registry: unknown, receipts: unknown): StatusSummary {
  const anomalies: string[] = [];
  const rawTasks = listOf(queue, "tasks", "queue", anomalies);
  const rawWorkers = listOf(registry, "workers", "registry", anomalies);
  const rawReceipts = listOf(receipts, "closed_loops", "receipts", anomalies);

  // ---- queue: counts by TaskStatus -------------------------------------------------------
  const by_status = zero(TASK_STATUSES);
  const taskIds = new Map<string, TaskStatus>();
  let tasksRejected = 0;
  rawTasks.forEach((t, i) => {
    if (!isObj(t) || !isStr(t.task_id) || !isStr(t.agent_id)) {
      tasksRejected++;
      return void anomalies.push(`task[${i}]:malformed`);
    }
    if (!has(TASK_STATUSES, t.status)) {
      tasksRejected++;
      return void anomalies.push(`task[${i}]:${t.task_id}:illegal-status`);
    }
    if (taskIds.has(t.task_id)) {
      tasksRejected++;
      return void anomalies.push(`task[${i}]:${t.task_id}:duplicate-task-id`);
    }
    taskIds.set(t.task_id, t.status);
    by_status[t.status]++;
  });

  // ---- registry: counts by WorkerState ---------------------------------------------------
  const by_state = zero(WORKER_STATES);
  const workerIds = new Set<string>();
  const held = new Map<string, string>(); // task_id -> worker id
  let workersRejected = 0;
  let completed = 0;
  let failed = 0;
  rawWorkers.forEach((w, i) => {
    if (!isObj(w) || !isStr(w.id)) {
      workersRejected++;
      return void anomalies.push(`worker[${i}]:malformed`);
    }
    if (!has(WORKER_STATES, w.state)) {
      workersRejected++;
      return void anomalies.push(`worker[${i}]:${w.id}:illegal-state`);
    }
    if (workerIds.has(w.id)) {
      workersRejected++;
      return void anomalies.push(`worker[${i}]:${w.id}:duplicate-worker-id`);
    }
    if (!isCount(w.completed_tasks) || !isCount(w.failed_tasks)) {
      workersRejected++;
      return void anomalies.push(`worker[${i}]:${w.id}:invalid-task-counters`);
    }
    workerIds.add(w.id);
    by_state[w.state]++;
    completed += w.completed_tasks;
    failed += w.failed_tasks;
    const cur = w.current_task ?? null;
    if (cur !== null && !isStr(cur)) return void anomalies.push(`${w.id}:current-task-malformed`);
    if (w.state === "SLEEP" && cur !== null) anomalies.push(`${w.id}:sleeping-with-task`);
    if (w.state !== "SLEEP" && cur === null) anomalies.push(`${w.id}:awake-without-task`);
    if (cur !== null) {
      if (held.has(cur)) anomalies.push(`${cur}:held-by-two-workers:${held.get(cur)},${w.id}`);
      held.set(cur, w.id);
      if (!taskIds.has(cur)) anomalies.push(`${w.id}:holds-unqueued-task:${cur}`);
    }
  });
  // an ACTIVE queue entry nobody holds is a phantom in-flight task
  for (const [id, st] of taskIds) if (st === "ACTIVE" && !held.has(id)) anomalies.push(`${id}:active-task-not-held`);
  // registry ledgers vs queue: a worker ledger above the queue's own record is inflation
  if (completed !== by_status.DONE) anomalies.push(`ledger-mismatch:registry-completed=${completed}:queue-DONE=${by_status.DONE}`);
  if (failed !== by_status.BLOCKED) anomalies.push(`ledger-mismatch:registry-failed=${failed}:queue-BLOCKED=${by_status.BLOCKED}`);

  // ---- receipts: validated, digest recomputed, counted once ------------------------------
  const by_decision = zero(DECISIONS);
  const receiptTasks = new Set<string>();
  let receiptsRejected = 0;
  let last: StatusSummary["receipts"]["last"] = null;
  rawReceipts.forEach((r, i) => {
    const isLast = i === rawReceipts.length - 1;
    const bad = (code: string) => {
      receiptsRejected++;
      anomalies.push(`receipt[${i}]:${code}`);
      if (isLast) anomalies.push("last-receipt-invalid");
    };
    if (!isObj(r) || r.receipt_kind !== "closed-loop/v1") return bad("malformed");
    if (!isStr(r.task_id)) return bad("no-task-id");
    if (!has(DECISIONS, r.final_decision)) return bad("illegal-decision");
    if (typeof r.final_digest !== "string" || !SHA256.test(r.final_digest)) return bad("bad-digest-format");
    let recomputed: string;
    try {
      const { final_digest: _drop, ...body } = r;
      recomputed = digestOf(body);
    } catch {
      return bad("undigestable");
    }
    if (recomputed !== r.final_digest) return bad("digest-mismatch");
    if (receiptTasks.has(r.task_id)) return bad("duplicate-receipt-task");
    if (!taskIds.has(r.task_id)) return bad("task-not-in-queue");
    receiptTasks.add(r.task_id);
    by_decision[r.final_decision]++;
    if (isLast) last = { task_id: r.task_id, final_decision: r.final_decision, final_digest: r.final_digest };
  });

  return {
    ok: anomalies.length === 0,
    tasks: { seen: rawTasks.length, counted: rawTasks.length - tasksRejected, rejected: tasksRejected, by_status },
    workers: { seen: rawWorkers.length, counted: rawWorkers.length - workersRejected, rejected: workersRejected, by_state },
    receipts: { seen: rawReceipts.length, counted: rawReceipts.length - receiptsRejected, rejected: receiptsRejected, by_decision, last },
    ledger: { registry_completed_tasks: completed, registry_failed_tasks: failed },
    anomalies,
  };
}
