import { canonicalize, malformedInputReceipt, verifyReceipt, type RecoveryReceipt } from "../cerberus/core/decide.ts";
import type { NormalizedInput } from "../cerberus/core/normalize.ts";
import { sha256Hex } from "../cerberus/artifact-trust/artifact-trust.ts";
import { decideWithAdapters, type VerdictAdapter } from "../cerberus/integrations/verdict-adapters.ts";
import { noSigningProvider, bundleSubject, rastikSubject, signatureStatus, type ArtifactSignatures, type SignatureReport, type SigningPolicy } from "./signing.ts";
import type { ReplayStore } from "./replay-store.ts";
import { DEFAULT_TRUST_TIMEOUT_MS, policyViolations, resolveTrustGate, stubPolicyTrustGate, type AsyncTrustGate, type TrustGateRequest } from "./trust-gate.ts";
import { toeparaVerify, type ToeparaCtx, type ToeparaResult } from "./toepara.ts";
import {
  PROTOCOL_VERSION,
  digestOf,
  validateEnvelope,
  validateEvidenceBundle,
  type CerberusDecision,
  type EvidenceBundle,
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
  /** One-time-use store: kratt `ReplayGuard` (in-memory) or `FileReplayGuard` (persistent, cross-process). */
  guard: ReplayStore;
  /** Async Trust Gate (default: the local stub policy). Denied on timeout/throw/malformed verdict. */
  trustGate?: AsyncTrustGate;
  trustGateTimeoutMs?: number;
  /** Evidence authentication policy. Absent => no provider, nothing required (statuses are UNSIGNED). */
  signing?: SigningPolicy;
}

export interface GateInput {
  envelope: unknown;
  receipt: unknown;
  rastik: RastikRun | null;
  toepara: ToeparaResult;
  /** Signatures presented for the TÖEPÄRA bundle and the RÄSTIK report. Verified against subjects CERBERUS recomputes. */
  signatures?: ArtifactSignatures;
}

export interface GateOutput {
  decision: CerberusDecision;
  cerberus_receipt: RecoveryReceipt;
  /** Diagnostics from the adapters (also reflected coarsely in the receipt). */
  adapter_reasons: string[];
  /** Authentication status of the evidence (UNSIGNED unless a provider verified a signature). */
  signature_status: SignatureReport;
}

/**
 * Identity of "this action, on this base, with this KRATT evidence" for the replay guard. It deliberately excludes
 * everything an attacker can vary without changing the work: the receipt timestamp (and so the receipt digest and the
 * bundle digest), the RÄSTIK report and the signatures. Consuming bundle_digest let a re-stamped copy of an
 * already-admitted receipt through (RÄSTIK finding).
 */
export function replayKey(b: Pick<EvidenceBundle, "task_id" | "action" | "base_sha" | "kratt_evidence_digest">): string {
  return digestOf({ task_id: b.task_id, action: b.action, base_sha: b.base_sha, kratt_evidence_digest: b.kratt_evidence_digest });
}

/** agent_id claimed by a (possibly hostile) receipt; null when unreadable so the producer check fails closed. */
function producerOf(receipt: unknown): string | null {
  try {
    const a = typeof receipt === "object" && receipt !== null ? (receipt as { agent_id?: unknown }).agent_id : undefined;
    return typeof a === "string" ? a : null;
  } catch {
    return null;
  }
}

export function localPolicyTrustGate(envelope: TaskEnvelope, receipt: unknown, repository: string, sink: string[]): VerdictAdapter {
  return {
    name: "local-policy-trust-gate(NOT the real Trust Gate)",
    verdict() {
      const action = typeof receipt === "object" && receipt !== null ? (receipt as { action?: unknown }).action : undefined;
      const why = policyViolations(envelope, action, repository, producerOf(receipt));
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

  let signingBlock: string | null = null; // set before the pipeline runs; checked BEFORE the replay guard so a rejected bundle is not burned
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
      if (signingBlock !== null) return reject(signingBlock);
      if (!ctx.guard.consume(replayKey(freshBundle))) return reject("replayed-bundle");
      return "ADMITTED";
    },
  };
  // Trust Gate: resolved asynchronously BEFORE the synchronous Cerberus pipeline (deny on timeout/throw/malformed).
  let gateVerdict: "AUTHORIZED" | "DENIED";
  if (!ev.ok) {
    adapterReasons.push("policy:envelope-invalid");
    gateVerdict = "DENIED";
  } else {
    const action = typeof input.receipt === "object" && input.receipt !== null ? (input.receipt as { action?: unknown }).action : undefined;
    const req: TrustGateRequest = Object.freeze({
      task_id: ev.value.task_id,
      repository: ev.value.repository,
      action: typeof action === "string" ? action : null,
      producer_agent_id: producerOf(input.receipt),
      envelope: structuredClone(ev.value),
      host_repository: ctx.repository,
    });
    const res = await resolveTrustGate(ctx.trustGate ?? stubPolicyTrustGate, req, ctx.trustGateTimeoutMs ?? DEFAULT_TRUST_TIMEOUT_MS);
    // Defense in depth: the local policy ALWAYS applies, even when an external gate says AUTHORIZED.
    const local = policyViolations(ev.value, action, ctx.repository, producerOf(input.receipt));
    gateVerdict = res.verdict === "AUTHORIZED" && local.length === 0 ? "AUTHORIZED" : "DENIED";
    adapterReasons.push(...res.reasons, ...local);
  }
  const trustGate: VerdictAdapter = { name: "async-trust-gate-resolved", verdict: () => gateVerdict };

  // Evidence authentication (statuses are always computed; they only gate the decision when required).
  const sp = ctx.signing ?? { provider: noSigningProvider, required: false };
  const signature_status: SignatureReport = {
    bundle: freshBundle === null ? "UNSIGNED" : await signatureStatus(sp.provider, "evidence-bundle", bundleSubject(freshBundle), input.signatures?.bundle),
    rastik:
      input.rastik === null
        ? "NOT_APPLICABLE"
        : await signatureStatus(sp.provider, "rastik-report", rastikSubject(input.rastik), input.signatures?.rastik),
  };
  const signingDenied = sp.required && (signature_status.bundle !== "SIGNED" || (signature_status.rastik !== "SIGNED" && signature_status.rastik !== "NOT_APPLICABLE"));
  if (signingDenied) signingBlock = "evidence-authentication-required-not-satisfied";
  if (sp.required) {
    if (signature_status.bundle !== "SIGNED") adapterReasons.push(`signature:evidence-bundle:${signature_status.bundle}`);
    if (signature_status.rastik !== "SIGNED" && signature_status.rastik !== "NOT_APPLICABLE") adapterReasons.push(`signature:rastik-report:${signature_status.rastik}`);
  }

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
    signature_status,
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
  return { decision: { ...body, decision_digest: digestOf(body) }, cerberus_receipt: rc, adapter_reasons: [], signature_status: { bundle: "UNSIGNED", rastik: "NOT_APPLICABLE" } };
}

export { verifyReceipt };
