import { digestOf, validateEnvelope, type TaskEnvelope } from "./protocol/types.ts";
import { countRegistry, WORKER_STATES, type Registry, type RegistryCounts, type Worker, type WorkerState } from "./registry.ts";

/**
 * Worker state machine + dispatcher (the "ARCHIDECT" mechanical core).
 *
 *   SLEEP -> READY -> ACTIVE -> VERIFY -> DONE -> SLEEP        (task completed)
 *                       ACTIVE -> BLOCKED -> SLEEP             (task failed)
 *   Additional legal edges (not in the original brief, added so the machine is closed):
 *     DONE -> SLEEP      a finished worker returns to its default state;
 *     VERIFY -> BLOCKED  verification failed.
 * Every other edge is illegal and rejected. Every attempt, accepted or rejected, is
 * appended to the transition log. No task => the worker stays SLEEP.
 */
export const LEGAL_TRANSITIONS: Readonly<Record<WorkerState, readonly WorkerState[]>> = {
  SLEEP: ["READY"],
  READY: ["ACTIVE"],
  ACTIVE: ["VERIFY", "BLOCKED"],
  VERIFY: ["DONE", "BLOCKED"],
  DONE: ["SLEEP"],
  BLOCKED: ["SLEEP"],
};

export class DispatchError extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export interface TransitionRecord {
  seq: number;
  at: string;
  agent_id: string;
  from: WorkerState;
  to: WorkerState;
  task_id: string | null;
  accepted: boolean;
  reason: string;
}

export type TaskStatus = "QUEUED" | "ACTIVE" | "DONE" | "BLOCKED";
export interface QueueEntry {
  task_id: string;
  agent_id: string;
  status: TaskStatus;
  envelope_digest: string;
  envelope: TaskEnvelope;
}

export interface WorkOutcome {
  ok: boolean;
  /** Reference to the evidence the work produced (required for DONE). */
  evidence: string | null;
  note?: string;
}

export interface DispatcherOptions {
  clock?: () => string;
  /** "agent_id:capability" pairs that have real handler code. Used for AVAILABLE accounting. */
  handlers?: readonly string[];
}

export class Dispatcher {
  readonly registry: Registry;
  readonly log: TransitionRecord[] = [];
  readonly queue: QueueEntry[] = [];
  #clock: () => string;
  #handlers: Set<string>;
  #byId = new Map<string, Worker>();

  constructor(registry: Registry, opts: DispatcherOptions = {}) {
    this.registry = registry;
    this.#clock = opts.clock ?? (() => new Date().toISOString());
    this.#handlers = new Set(opts.handlers ?? []);
    for (const w of registry.workers) this.#byId.set(w.id, w);
  }

  /** Reload persisted queue + transition log (the registry itself is passed to the constructor). */
  restore(queue: QueueEntry[], log: TransitionRecord[]): void {
    this.queue.push(...queue);
    this.log.push(...log);
  }

  worker(id: string): Worker {
    const w = this.#byId.get(id);
    if (!w) throw new DispatchError("unknown-worker");
    return w;
  }

  /** Admit a task: strict envelope validation, known owner in the right factory, no duplicate task_id. */
  enqueue(raw: unknown): QueueEntry {
    const v = validateEnvelope(raw);
    if (!v.ok) throw new DispatchError(`envelope-invalid:${v.reason}`);
    const e = v.value;
    const w = this.#byId.get(e.agent_id);
    if (!w) throw new DispatchError("task-without-owner");
    if (w.factory !== e.factory) throw new DispatchError("owner-factory-mismatch");
    if (this.queue.some((q) => q.task_id === e.task_id)) throw new DispatchError("duplicate-task");
    const entry: QueueEntry = {
      task_id: e.task_id,
      agent_id: e.agent_id,
      status: "QUEUED",
      envelope_digest: digestOf(e),
      envelope: Object.freeze(structuredClone(e)) as TaskEnvelope,
    };
    this.queue.push(entry);
    return entry;
  }

  #entry(taskId: string): QueueEntry {
    const q = this.queue.find((x) => x.task_id === taskId);
    if (!q) throw new DispatchError("unknown-task");
    return q;
  }

  /**
   * Move one worker along one edge. `taskId` is mandatory for SLEEP->READY (it binds the
   * worker to a queued task it owns); later edges must name the task the worker holds.
   */
  transition(agentId: string, to: WorkerState, ctx: { task_id?: string; reason?: string; evidence?: string } = {}): Worker {
    const w = this.worker(agentId);
    const from = w.state;
    const reject = (code: string): never => {
      this.#record(w, from, to, ctx.task_id ?? w.current_task, false, code);
      throw new DispatchError(code);
    };
    if (!(WORKER_STATES as readonly string[]).includes(to)) return reject("unknown-state");
    if (!LEGAL_TRANSITIONS[from].includes(to)) return reject(`illegal-transition:${from}->${to}`);
    if (from === "SLEEP") {
      if (!ctx.task_id) return reject("no-task-no-wake");
      const q = this.queue.find((x) => x.task_id === ctx.task_id);
      if (!q) return reject("unknown-task");
      if (q.agent_id !== w.id) return reject("task-owner-mismatch");
      if (q.status !== "QUEUED") return reject("task-not-queued");
      w.current_task = q.task_id;
    } else if (ctx.task_id !== undefined && ctx.task_id !== w.current_task) {
      return reject("task-mismatch");
    }
    const q = w.current_task ? this.queue.find((x) => x.task_id === w.current_task) : undefined;
    if (to === "ACTIVE" && q) q.status = "ACTIVE";
    if ((to === "BLOCKED") && !ctx.reason) return reject("blocked-requires-reason");
    if (to === "DONE") {
      if (!ctx.evidence) return reject("done-requires-evidence");
      w.evidence.push(ctx.evidence);
      w.completed_tasks++;
      if (q) q.status = "DONE";
    }
    if (to === "BLOCKED") {
      w.failed_tasks++;
      if (q) q.status = "BLOCKED";
    }
    w.state = to;
    this.#record(w, from, to, w.current_task, true, ctx.reason ?? "ok");
    if (to === "SLEEP") w.current_task = null;
    return w;
  }

  #record(w: Worker, from: WorkerState, to: WorkerState, task: string | null, accepted: boolean, reason: string) {
    this.log.push({ seq: this.log.length + 1, at: this.#clock(), agent_id: w.id, from, to, task_id: task, accepted, reason });
  }

  /**
   * Run one queued task through the whole machine. `work` is the only place real work
   * happens. A thrown error or `ok:false` ends in BLOCKED -> SLEEP; success ends in
   * ACTIVE -> VERIFY -> DONE -> SLEEP with the evidence reference recorded on the worker.
   */
  async run<T extends WorkOutcome>(
    taskId: string,
    work: (e: TaskEnvelope) => Promise<T> | T,
    opts: { capability?: string } = {},
  ): Promise<T | null> {
    const q = this.#entry(taskId);
    const id = q.agent_id;
    if (opts.capability !== undefined) {
      const cap = opts.capability;
      if (!this.worker(id).capabilities.includes(cap) || !this.#handlers.has(`${id}:${cap}`))
        throw new DispatchError(`capability-not-available:${id}:${cap}`);
    }
    this.transition(id, "READY", { task_id: taskId });
    this.transition(id, "ACTIVE", { task_id: taskId });
    let out: T | null = null;
    try {
      out = await work(q.envelope);
    } catch (e) {
      this.transition(id, "BLOCKED", { task_id: taskId, reason: `work-threw:${e instanceof Error ? e.message.slice(0, 120) : "unknown"}` });
      this.transition(id, "SLEEP", { task_id: taskId, reason: "blocked-return-to-sleep" });
      return null;
    }
    if (!out.ok) {
      this.transition(id, "BLOCKED", { task_id: taskId, reason: out.note ?? "work-reported-failure" });
      this.transition(id, "SLEEP", { task_id: taskId, reason: "blocked-return-to-sleep" });
      return out;
    }
    this.transition(id, "VERIFY", { task_id: taskId });
    if (!out.evidence) {
      this.transition(id, "BLOCKED", { task_id: taskId, reason: "verify-failed:no-evidence-reference" });
      this.transition(id, "SLEEP", { task_id: taskId, reason: "blocked-return-to-sleep" });
      return out;
    }
    this.transition(id, "DONE", { task_id: taskId, evidence: out.evidence });
    this.transition(id, "SLEEP", { task_id: taskId, reason: "done-return-to-sleep" });
    return out;
  }

  /** Consistency watchdog. Empty list = no violation. */
  watchdog(): string[] {
    const v: string[] = [];
    const seen = new Map<string, string>();
    for (const w of this.registry.workers) {
      if (w.state === "SLEEP" && w.current_task !== null) v.push(`${w.id}:sleeping-with-task`);
      if (w.state !== "SLEEP" && w.current_task === null) v.push(`${w.id}:awake-without-task`);
      if (w.current_task !== null) {
        const prev = seen.get(w.current_task);
        if (prev) v.push(`duplicate-task-holder:${w.current_task}:${prev},${w.id}`);
        seen.set(w.current_task, w.id);
        const q = this.queue.find((x) => x.task_id === w.current_task);
        if (!q) v.push(`${w.id}:holds-unqueued-task:${w.current_task}`);
        else if (q.agent_id !== w.id) v.push(`${w.id}:holds-task-owned-by-${q.agent_id}`);
      }
    }
    const ids = new Set<string>();
    for (const q of this.queue) {
      if (ids.has(q.task_id)) v.push(`duplicate-task:${q.task_id}`);
      ids.add(q.task_id);
      if (!this.#byId.has(q.agent_id)) v.push(`task-without-owner:${q.task_id}`);
      if (q.status === "ACTIVE" && this.#byId.get(q.agent_id)?.current_task !== q.task_id) v.push(`active-task-not-held:${q.task_id}`);
    }
    return v;
  }

  /** Workers with >=1 capability whose "id:capability" pair has registered handler code. */
  available(): string[] {
    return this.registry.workers
      .filter((w) => w.capabilities.some((c) => this.#handlers.has(`${w.id}:${c}`)))
      .map((w) => w.id);
  }

  counts(): RegistryCounts & { available: number } {
    return { ...countRegistry(this.registry), available: this.available().length };
  }
}
