import { FACTORIES, FACTORY_FIRST, ROLES, agentId, type FactoryName } from "./roles.ts";

/** Worker states. Default is SLEEP. */
export const WORKER_STATES = ["SLEEP", "READY", "ACTIVE", "VERIFY", "DONE", "BLOCKED"] as const;
export type WorkerState = (typeof WORKER_STATES)[number];

export interface Worker {
  id: string; // e.g. "FORGE-026"
  number: number; // 1..150
  factory: FactoryName;
  role: string;
  state: WorkerState;
  /** Only capabilities with real handler code behind them (see factory/capabilities.ts). */
  capabilities: string[];
  current_task: string | null;
  completed_tasks: number;
  failed_tasks: number;
  evidence: string[];
}

export interface Registry {
  registry_version: 1;
  workers: Worker[];
}

/** agent id -> capabilities that have executable handlers. Empty until a handler exists. */
export type CapabilityMap = Readonly<Record<string, readonly string[]>>;

export function buildInitialRegistry(capabilities: CapabilityMap = {}): Registry {
  const workers: Worker[] = [];
  for (const factory of FACTORIES) {
    ROLES[factory].forEach((role, i) => {
      const number = FACTORY_FIRST[factory] + i;
      const id = agentId(factory, number);
      workers.push({
        id,
        number,
        factory,
        role,
        state: "SLEEP",
        capabilities: [...(capabilities[id] ?? [])],
        current_task: null,
        completed_tasks: 0,
        failed_tasks: 0,
        evidence: [],
      });
    });
  }
  return { registry_version: 1, workers };
}

export interface RegistryCounts {
  defined: number;
  forge: number;
  serpent: number;
  citadel: number;
  by_state: Record<WorkerState, number>;
  active: number;
  sleeping: number;
  blocked: number;
  /** Workers with >=1 capability. The dispatcher cross-checks this against registered handlers. */
  with_capabilities: number;
  executed_tasks: number;
  failed_tasks: number;
}

export function countRegistry(reg: Registry): RegistryCounts {
  const by_state = Object.fromEntries(WORKER_STATES.map((s) => [s, 0])) as Record<WorkerState, number>;
  let executed = 0;
  let failed = 0;
  let caps = 0;
  for (const w of reg.workers) {
    by_state[w.state]++;
    executed += w.completed_tasks;
    failed += w.failed_tasks;
    if (w.capabilities.length > 0) caps++;
  }
  const f = (n: FactoryName) => reg.workers.filter((w) => w.factory === n).length;
  return {
    defined: reg.workers.length,
    forge: f("FORGE"),
    serpent: f("SERPENT"),
    citadel: f("CITADEL"),
    by_state,
    active: by_state.ACTIVE,
    sleeping: by_state.SLEEP,
    blocked: by_state.BLOCKED,
    with_capabilities: caps,
    executed_tasks: executed,
    failed_tasks: failed,
  };
}

/** Structural checks shared by init and snapshot validation. Returns violations (empty = ok). */
export function validateRegistryShape(reg: unknown, capabilities: CapabilityMap = {}): string[] {
  const v: string[] = [];
  if (typeof reg !== "object" || reg === null) return ["registry-not-object"];
  const r = reg as Partial<Registry>;
  if (r.registry_version !== 1) v.push("registry_version-not-1");
  if (!Array.isArray(r.workers)) return [...v, "workers-not-array"];
  const expected = buildInitialRegistry(capabilities).workers;
  if (r.workers.length !== expected.length) v.push(`workers-count:${r.workers.length}`);
  const ids = new Set<string>();
  r.workers.forEach((w, i) => {
    const e = expected[i];
    if (!e || typeof w !== "object" || w === null) return void v.push(`worker[${i}]-invalid`);
    if (Object.keys(w).sort().join(",") !== Object.keys(e).sort().join(",")) v.push(`${e.id}:keys`);
    if (w.id !== e.id) v.push(`${e.id}:id-mismatch(${String(w.id)})`);
    if (ids.has(w.id)) v.push(`${w.id}:duplicate-id`);
    ids.add(w.id);
    if (w.number !== e.number || w.factory !== e.factory || w.role !== e.role) v.push(`${e.id}:identity-mismatch`);
    if (!WORKER_STATES.includes(w.state)) v.push(`${e.id}:illegal-state`);
    if (JSON.stringify(w.capabilities) !== JSON.stringify(e.capabilities)) v.push(`${e.id}:capabilities-mismatch`);
    if (!Number.isSafeInteger(w.completed_tasks) || w.completed_tasks < 0) v.push(`${e.id}:completed_tasks-invalid`);
    if (!Number.isSafeInteger(w.failed_tasks) || w.failed_tasks < 0) v.push(`${e.id}:failed_tasks-invalid`);
    if (!Array.isArray(w.evidence)) v.push(`${e.id}:evidence-not-array`);
    if (w.state === "SLEEP" && w.current_task !== null) v.push(`${e.id}:sleeping-with-task`);
    if (w.state !== "SLEEP" && w.current_task === null) v.push(`${e.id}:awake-without-task`);
  });
  return v;
}

/** Init invariants: DEFINED 150 (50/50/50), ACTIVE 0, SLEEPING 150, zero completed/failed tasks, no evidence. */
export function validateInitialRegistry(reg: unknown, capabilities: CapabilityMap = {}): string[] {
  const v = validateRegistryShape(reg, capabilities);
  if (v.length > 0 || typeof reg !== "object" || reg === null) return v;
  const r = reg as Registry;
  const c = countRegistry(r);
  if (c.defined !== 150) v.push(`DEFINED!=150:${c.defined}`);
  if (c.forge !== 50) v.push(`FORGE!=50:${c.forge}`);
  if (c.serpent !== 50) v.push(`SERPENT!=50:${c.serpent}`);
  if (c.citadel !== 50) v.push(`CITADEL!=50:${c.citadel}`);
  if (c.active !== 0) v.push(`ACTIVE!=0:${c.active}`);
  if (c.sleeping !== 150) v.push(`SLEEPING!=150:${c.sleeping}`);
  for (const w of r.workers) {
    if (w.completed_tasks !== 0) v.push(`${w.id}:completed_tasks!=0`);
    if (w.failed_tasks !== 0) v.push(`${w.id}:failed_tasks!=0`);
    if (w.current_task !== null) v.push(`${w.id}:current_task!=null`);
    if (w.evidence.length !== 0) v.push(`${w.id}:evidence-not-empty`);
  }
  return v;
}
