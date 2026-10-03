import type { RecoveryReceipt } from "../cerberus/core/decide.ts";
import { verifyReceipt } from "../cerberus/core/decide.ts";
import { buildDecisionReceipt, digestJson, type DecisionReceipt, type DecisionRequest, type EvidenceName } from "../cerberus/receipts/decision-receipt.ts";
import type { GateInput, GateOutput } from "./cerberus-gate.ts";
import { validateEnvelope, type CerberusDecision } from "./protocol/types.ts";

/**
 * Builds the evidence-bound decision receipt (cerberus/receipts/decision-receipt.ts) for one CERBERUS gate run.
 * Nothing here is trusted from the caller: the receipt digest of the Cerberus pipeline is re-verified, and the
 * caller-supplied TÖEPÄRA result only counts if its evidence digest equals the digest CERBERUS recomputed.
 */
type Ref = { state: "PRESENT" | "MISSING" | "UNKNOWN" | "NOT_APPLICABLE"; digest?: string };
const present = (v: unknown): Ref => {
  try {
    return { state: "PRESENT", digest: digestJson(v) };
  } catch {
    return { state: "UNKNOWN" };
  }
};

function rastikRequired(envelope: unknown): boolean {
  const e = validateEnvelope(envelope);
  return e.ok && e.value.required_evidence.includes("rastik_findings");
}

export function evidenceRefs(input: GateInput, out: GateOutput | null): Partial<Record<EvidenceName, Ref>> {
  const refs: Partial<Record<EvidenceName, Ref>> = {};
  try {
    refs.envelope = validateEnvelope(input.envelope).ok ? present(input.envelope) : { state: "UNKNOWN" };
    refs.action_receipt = typeof input.receipt === "object" && input.receipt !== null ? present(input.receipt) : { state: "MISSING" };
    const bundle = input.toepara?.bundle ?? null;
    refs.evidence_bundle = bundle === null ? { state: "MISSING" } : present(bundle);
    refs.rastik_report = input.rastik === null || input.rastik === undefined ? (rastikRequired(input.envelope) ? { state: "MISSING" } : { state: "NOT_APPLICABLE" }) : present(input.rastik);
    if (out !== null) {
      const rc: RecoveryReceipt = out.cerberus_receipt;
      refs.cerberus_receipt = verifyReceipt(rc) && rc.receiptDigest === out.decision.cerberus_receipt_digest ? present(rc) : { state: "UNKNOWN" };
      // The TÖEPÄRA evidence digest that CERBERUS recomputed must be the one the presented TÖEPÄRA result claims.
      refs.toepara_evidence = input.toepara?.verdict?.evidence_digest === out.decision.toepara_evidence_digest ? present(input.toepara.verdict) : { state: "UNKNOWN" };
    }
  } catch {
    /* anything unreadable stays absent => MISSING */
  }
  return refs;
}

/** Decision receipt for a completed gate run (ADMIT / DENY / QUARANTINE alike). */
export function decisionReceiptForGate(input: GateInput, out: GateOutput): DecisionReceipt {
  let toeparaVerdict: unknown = "UNKNOWN";
  try {
    toeparaVerdict = input.toepara?.verdict?.verdict;
  } catch {
    /* UNKNOWN */
  }
  const req: DecisionRequest = {
    task_id: out.decision.task_id,
    proposed: out.decision.decision,
    reasons: out.decision.reasons,
    evidence: evidenceRefs(input, out),
    toepara_verdict: toeparaVerdict,
    cerberus_decision: out.cerberus_receipt.decision,
    stages: out.cerberus_receipt.stages,
  };
  return buildDecisionReceipt(req);
}

/** A DENY decision receipt for a request the gate never ran on (ledger fault, hostile input, pending/incomplete idempotency). */
export function denyDecisionReceipt(input: GateInput | null, taskId: string, reasons: string[]): DecisionReceipt {
  return buildDecisionReceipt({
    task_id: taskId,
    proposed: "DENY",
    reasons,
    evidence: input === null ? {} : evidenceRefs(input, null),
    toepara_verdict: "UNKNOWN",
    cerberus_decision: "FAIL_CLOSED",
    stages: {},
  });
}

export type { CerberusDecision };
