import { malformedInputReceipt, type RecoveryReceipt } from "../cerberus/core/decide.ts";
import { decideWithAdapters, type VerdictAdapter } from "../cerberus/integrations/verdict-adapters.ts";
import { executeTask, type ActionOptions } from "./actions.ts";
import {
  createToeparaAdapter,
  evidenceToArtifact,
  produceEvidence,
  type ReplayGuard,
  type ToeparaEvidence,
} from "./evidence.ts";
import { validateTask, type KrattTask } from "./task.ts";

/**
 * KRATT pipeline:
 *   task -> validateTask (closed schema) -> allow-listed bounded execution
 *        -> TÖEPÄRA evidence (verdict computed from facts)
 *        -> Cerberus decideWithAdapters (policy + TÖEPÄRA + Trust Gate + artifact trust)
 *
 * Cerberus is the only authority on the outcome. KRATT never returns PROCEED itself, the
 * Trust Gate adapter is a mandatory parameter (no default), and the caller can't supply
 * a verdict string (decideWithAdapters ignores caller verdict fields).
 */
export interface KrattDeps extends ActionOptions {
  root: string;
  /** Real Trust Gate client when one exists; tests pass a stub. Mandatory by design. */
  trustGate: VerdictAdapter;
  guard: ReplayGuard;
}

export interface KrattOutcome {
  task: Readonly<KrattTask> | null;
  evidence: ToeparaEvidence | null;
  /** Why TÖEPÄRA did not admit (diagnostic; null if admitted or never reached). */
  toeparaReason: string | null;
  receipt: RecoveryReceipt;
}

/** Cerberus action for every KRATT execution: read-only verification => "detect". */
export const CERBERUS_ACTION = "detect";

/** Feed already-produced evidence through TÖEPÄRA validation + Cerberus (also used for replay/tamper tests). */
export function gateArtifact(
  artifact: { name: string; content: string; sha256: string },
  deps: Pick<KrattDeps, "trustGate" | "guard">,
): { toeparaReason: string | null; receipt: RecoveryReceipt } {
  const toepara = createToeparaAdapter(deps.guard);
  const receipt = decideWithAdapters(
    { action: CERBERUS_ACTION, artifact },
    { toepara, trustGate: deps.trustGate },
  );
  return { toeparaReason: toepara.lastReason, receipt };
}

export async function runKrattTask(raw: unknown, deps: KrattDeps): Promise<KrattOutcome> {
  try {
    const v = validateTask(raw);
    if (!v.ok) {
      return {
        task: null,
        evidence: null,
        toeparaReason: null,
        receipt: malformedInputReceipt(`kratt-task-invalid:${v.reason}`, "adapter"),
      };
    }
    const result = await executeTask(deps.root, v.task, { allowedTestDirs: deps.allowedTestDirs });
    const evidence = produceEvidence(v.task, result);
    const g = gateArtifact(evidenceToArtifact(evidence), deps);
    return { task: v.task, evidence, toeparaReason: g.toeparaReason, receipt: g.receipt };
  } catch {
    return { task: null, evidence: null, toeparaReason: null, receipt: malformedInputReceipt("kratt-internal-error", "adapter") };
  }
}
