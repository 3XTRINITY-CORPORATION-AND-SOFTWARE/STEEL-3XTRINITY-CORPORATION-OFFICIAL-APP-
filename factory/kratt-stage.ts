import { executeTask } from "../kratt/actions.ts";
import { produceEvidence } from "../kratt/evidence.ts";
import { KRATT_ACTIONS, validateTask, type KrattAction, type KrattTask } from "../kratt/task.ts";
import type { ActionReceipt, TaskEnvelope } from "./protocol/types.ts";

/**
 * Thin adapter from the factory protocol to the existing KRATT pipeline. No new action
 * logic: validation is `kratt/task.ts`, execution is `kratt/actions.ts`, evidence is
 * `kratt/evidence.ts`. KRATT does NOT verify its own output: the receipt it emits is
 * always `UNVERIFIED`; only TÖEPÄRA (factory/toepara.ts) may change that judgement.
 */
export type Mapped = { ok: true; task: Readonly<KrattTask>; action: KrattAction } | { ok: false; reason: string };

/** The single KRATT action an envelope authorises, mapped onto a closed KRATT task. Pure; used by KRATT and by TÖEPÄRA. */
export function envelopeToKrattTask(e: TaskEnvelope): Mapped {
  const actions = e.allowed_actions.filter((a) => (KRATT_ACTIONS as readonly string[]).includes(a));
  if (actions.length !== 1 || e.allowed_actions.length !== 1) return { ok: false, reason: "envelope-must-allow-exactly-one-kratt-action" };
  const action = actions[0] as KrattAction;
  if (e.forbidden_actions.includes(action)) return { ok: false, reason: "action-forbidden" };
  let raw: unknown;
  switch (action) {
    case "hash-files":
      raw = { taskId: e.task_id, action, files: [...e.scope] };
      break;
    case "validate-manifest":
      if (e.scope.length !== 1) return { ok: false, reason: "validate-manifest-needs-exactly-one-scope-path" };
      raw = { taskId: e.task_id, action, manifest: e.scope[0] };
      break;
    case "run-test":
      if (e.scope.length !== 1) return { ok: false, reason: "run-test-needs-exactly-one-scope-path" };
      raw = {
        taskId: e.task_id,
        action,
        testFile: e.scope[0],
        timeoutMs: Math.min(e.resource_budget.max_wall_ms, 60_000),
        maxOutputBytes: e.resource_budget.max_output_bytes,
      };
      break;
  }
  const v = validateTask(raw);
  return v.ok ? { ok: true, task: v.task, action } : { ok: false, reason: `kratt-task-invalid:${v.reason}` };
}

export async function runKrattStage(
  e: TaskEnvelope,
  root: string,
  clock: () => string,
): Promise<{ ok: true; receipt: ActionReceipt } | { ok: false; reason: string }> {
  const m = envelopeToKrattTask(e);
  if (!m.ok) return m;
  const result = await executeTask(root, m.task);
  const evidence = produceEvidence(m.task, result);
  const receipt: ActionReceipt = {
    task_id: e.task_id,
    agent_id: e.agent_id,
    repository: e.repository,
    base_sha: e.base_sha,
    action: m.action,
    scope: [...e.scope],
    result: {
      ok: evidence.exitCode === 0 && evidence.failure === null,
      exit_code: evidence.exitCode,
      checks: { ...evidence.checks },
      failure: evidence.failure,
    },
    evidence: JSON.parse(JSON.stringify(evidence)) as Record<string, unknown>,
    verification_state: "UNVERIFIED",
    timestamp: clock(),
    protocol_version: 1,
  };
  return { ok: true, receipt };
}
