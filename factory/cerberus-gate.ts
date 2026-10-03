import { canonicalize, malformedInputReceipt, verifyReceipt, type RecoveryReceipt } from "../cerberus/core/decide.ts";
import type { NormalizedInput } from "../cerberus/core/normalize.ts";
import { sha256Hex } from "../cerberus/artifact-trust/artifact-trust.ts";
import { decideWithAdapters, type VerdictAdapter } from "../cerberus/integrations/verdict-adapters.ts";
import { KRATT_ACTIONS } from "../kratt/task.ts";
import { ReplayGuard } from "../kratt/evidence.ts";
import { toeparaVerify, type ToeparaCtx, type ToeparaResult } from "./toepara.ts";
import {
  PROTOCOL_VERSION,
  digestOf,
  validateEnvelope,
  validateEvidenceBundle,
  type CerberusDecision,
  type TaskEnvelope,
} from "./protocol/types.ts";
import { isUnresolvedHigh, type RastikRun } from "./rastik-types.ts";

/**
 * CERBERUS stage for the closed loop. Reuses `cerberus/core/decide.ts` (receipt, digests,
 * fail-closed pipeline) through `decideWithAdapters` and changes ONE thing: where the two
 * upstream verdicts come from.
 *
 *  - TÖEPÄRA verdict: NOT a string the caller passes. The adapter parses the bundle that
 *    reaches Cerberus and re-runs the full independent verification (`toeparaVerify`, which
 *    recomputes from git); "ADMITTED" only if that re-run is VERIFIED, produces a
 *    byte-identical bundle, and the bundle digest has not been presented before (replay guard).
 *  - Trust Gate verdict: computed by `localPolicyTrustGate` from the envelope and receipt
 *    (read-only action set, merge/deploy forbidden, repository match). This is a LOCAL POLICY,
 *    not the real Trust Gate, which does not exist in this repo.
 *
 * Mapping to the protocol decision: Cerberus FAIL_CLOSED => DENY; PROCEED with an unresolved
 * CONFIRMED high/critical RÄSTIK finding => QUARANTINE; PROCEED otherwise => ADMIT.
 * The decision is a pure function of its inputs (no clock, no randomness), so identical
 * inputs and a fresh replay guard give byte-identical results.
 */
export const CERBERUS_ACTION = "detect";

export interface CerberusCtx extends ToeparaCtx {
  guard: ReplayGuard;
}

export interface GateInput {
  envelope: unknown;
  receipt: unknown;
  rastik: RastikRun | null;
  toepara: ToeparaResult;
}

export interface GateOutput {
  decision: CerberusDecision;
  cerberus_receipt: RecoveryReceipt;
  /** Diagnostics from the adapters (also reflected coarsely in the receipt). */
  adapter_reasons: string[];
}

export function localPolicyTrustGate(envelope: TaskEnvelope, receipt: unknown, repository: string, sink: string[]): VerdictAdapter {
  return {
    name: "local-policy-trust-gate(NOT the real Trust Gate)",
    verdict() {
      const why: string[] = [];
      const action = typeof receipt === "object" && receipt !== null ? (receipt as { action?: unknown }).action : undefined;
      if (envelope.repository !== repository) why.push("policy:repository-mismatch");
      if (!envelope.allowed_actions.every((a) => (KRATT_ACTIONS as readonly string[]).includes(a))) why.push("policy:non-kratt-action-allowed");
      for (const must of ["merge", "deploy"]) if (!envelope.forbidden_actions.includes(must)) why.push(`policy:${must}-not-forbidden`);
      if (typeof action !== "string" || !envelope.allowed_actions.includes(action)) why.push("policy:receipt-action-not-allowed");
      sink.push(...why);
      return why.length === 0 ? "AUTHORIZED" : "DENIED";
    },
  };
}

/**
 * Cerberus adapters are synchronous; independent verification (which may re-execute a test)
 * is async. So the recomputation happens first, and the adapter only accepts the artifact if
 * it is byte-identical to the freshly recomputed bundle AND the recomputation is VERIFIED.
 * The caller's `input.toepara` is used for nothing but diagnostics: a lying caller changes nothing.
 */
export async function cerberusDecide(input: GateInput, ctx: CerberusCtx): Promise<GateOutput> {
  const adapterReasons: string[] = [];
  const ev = validateEnvelope(input.envelope);
  const taskId = ev.ok ? ev.value.task_id : "invalid-task-id";
  const fresh = await toeparaVerify(input.envelope, input.receipt, input.rastik, ctx);
  const freshBundle = fresh.bundle;
  const content = canonicalize(input.toepara.bundle ?? { bundle: null });
  const artifact = { name: `factory-bundle-${taskId}.json`, content, sha256: sha256Hex(content) };

  const toepara: VerdictAdapter = {
    name: "factory-toepara-recompute",
    verdict(snapshot: Readonly<NormalizedInput>) {
      const reject = (r: string) => {
        adapterReasons.push(r);
        return "REJECTED";
      };
      const a = snapshot.artifact;
      if (a === null || a.content === null) return reject("bundle-missing");
      let parsed: unknown;
      try {
        parsed = JSON.parse(a.content);
      } catch {
        return reject("bundle-not-json");
      }
      const b = validateEvidenceBundle(parsed);
      if (!b.ok) return reject(`bundle-invalid:${b.reason}`);
      if (b.value.bundle_digest !== freshBundle?.bundle_digest) return reject("bundle-digest-differs-from-recomputed");
      if (fresh.verdict.verdict !== "VERIFIED" || freshBundle === null) return reject(`toepara-recompute-${fresh.verdict.verdict.toLowerCase()}:${fresh.verdict.reasons[0] ?? "no-reason"}`);
      if (canonicalize(freshBundle) !== a.content) return reject("bundle-differs-from-recomputed");
      if (!ctx.guard.consume(freshBundle.bundle_digest)) return reject("replayed-bundle");
      return "ADMITTED";
    },
  };
  const trustGate: VerdictAdapter = ev.ok
    ? localPolicyTrustGate(ev.value, input.receipt, ctx.repository, adapterReasons)
    : { name: "local-policy-trust-gate(NOT the real Trust Gate)", verdict: () => (adapterReasons.push("policy:envelope-invalid"), "DENIED") };

  const rc = decideWithAdapters({ action: CERBERUS_ACTION, artifact }, { toepara, trustGate });
  const unresolved = (input.rastik?.findings ?? []).filter(isUnresolvedHigh).map((f) => f.finding_id);
  let decision: CerberusDecision["decision"];
  const reasons: string[] = [...rc.reasons, ...adapterReasons];
  if (rc.decision !== "PROCEED") decision = "DENY";
  else if (unresolved.length > 0) {
    decision = "QUARANTINE";
    reasons.push("unresolved-confirmed-high-rastik-finding");
  } else decision = "ADMIT";

  const body = {
    protocol_version: PROTOCOL_VERSION,
    task_id: taskId,
    decision,
    reasons: [...new Set(reasons)].map((r) => r.slice(0, 300)).slice(0, 64),
    toepara_evidence_digest: fresh.verdict.evidence_digest,
    cerberus_receipt_digest: rc.receiptDigest,
    unresolved_high_findings: unresolved,
  };
  return {
    decision: { ...body, decision_digest: digestOf(body) } as CerberusDecision,
    cerberus_receipt: rc,
    adapter_reasons: adapterReasons,
  };
}

/** DENY for a task that never produced a receipt (stale base, bad envelope, unavailable capability). */
export function denyWithoutReceipt(taskId: string, reason: string): GateOutput {
  const rc = malformedInputReceipt(`factory:${reason}`.slice(0, 200), "adapter");
  const body = {
    protocol_version: PROTOCOL_VERSION,
    task_id: /^[a-z0-9][a-z0-9-]{0,63}$/.test(taskId) ? taskId : "invalid-task-id",
    decision: "DENY" as const,
    reasons: [reason.slice(0, 300), ...rc.reasons],
    toepara_evidence_digest: digestOf({ no_receipt: reason }),
    cerberus_receipt_digest: rc.receiptDigest,
    unresolved_high_findings: [] as string[],
  };
  return { decision: { ...body, decision_digest: digestOf(body) }, cerberus_receipt: rc, adapter_reasons: [] };
}

export { verifyReceipt };
