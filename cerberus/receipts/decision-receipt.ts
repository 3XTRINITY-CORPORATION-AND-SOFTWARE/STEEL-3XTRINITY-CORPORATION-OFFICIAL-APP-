import { createHash } from "node:crypto";
import { canonicalize } from "../core/decide.ts";

/**
 * Decision receipt (decision-receipt/v1): a sealed record of ONE admission decision and of exactly which
 * evidence it was made on. Pure and dependency-free (apart from canonicalize), so it is usable by any caller.
 *
 * Evidence binding: every piece of evidence is referenced by the SHA-256 of its canonical JSON, and the
 * references are themselves hashed (`evidence_binding_digest`) and sealed into `receipt_digest`. Changing any
 * bound evidence, any reason or the decision changes the digest; `bindEvidence` re-hashes presented evidence
 * against the references.
 *
 * Fail closed (the whole point of this module):
 *   - ADMIT and QUARANTINE (the two outcomes that let work proceed) are only ever issued when EVERY required
 *     evidence item is exactly PRESENT with a well-formed digest, the TÖEPÄRA verdict is exactly "VERIFIED",
 *     the Cerberus decision is exactly "PROCEED" and every pipeline stage is exactly "PASS".
 *   - MISSING, UNKNOWN, NOT_IMPLEMENTED, NOT_EVALUATED, FAIL, lowercase variants, padded strings, non-strings:
 *     none of them is PASS. A request for ADMIT/QUARANTINE on such evidence is DOWNGRADED to DENY with a reason
 *     (`proposed_decision` keeps what was asked for, so the downgrade is visible and auditable).
 *   - Anything unexpected while building (hostile objects, throwing getters) => DENY.
 *
 * NOT here: authentication. A decision receipt is hashed, not signed (`authentication: "UNSIGNED"`).
 */
export const DECISION_RECEIPT_VERSION = "decision-receipt/v1";

export type DecisionValue = "ADMIT" | "DENY" | "QUARANTINE";
export const EVIDENCE_NAMES = ["envelope", "action_receipt", "toepara_evidence", "evidence_bundle", "rastik_report", "cerberus_receipt"] as const;
export type EvidenceName = (typeof EVIDENCE_NAMES)[number];
export type EvidenceState = "PRESENT" | "MISSING" | "UNKNOWN" | "NOT_IMPLEMENTED" | "NOT_APPLICABLE";
const STATES: readonly EvidenceState[] = ["PRESENT", "MISSING", "UNKNOWN", "NOT_IMPLEMENTED", "NOT_APPLICABLE"];
export const STAGE_NAMES = ["input", "policy", "toepara", "trustGate", "artifactTrust"] as const;

export interface EvidenceRef {
  state: EvidenceState;
  /** SHA-256 hex of the canonical JSON of the evidence; non-null iff state is PRESENT. */
  digest: string | null;
}

export interface DecisionReceipt {
  version: typeof DECISION_RECEIPT_VERSION;
  task_id: string;
  decision: DecisionValue;
  /** What the caller asked for. Differs from `decision` only when the request was downgraded to DENY. */
  proposed_decision: DecisionValue | "INVALID";
  reasons: string[];
  evidence: Record<EvidenceName, EvidenceRef>;
  evidence_binding_digest: string;
  /** The facts ADMIT/QUARANTINE were checked against (normalised to strings; anything unexpected is "UNKNOWN"). */
  basis: { toepara_verdict: string; cerberus_decision: string; stages: Record<(typeof STAGE_NAMES)[number], string> };
  authentication: "UNSIGNED";
  receipt_digest: string;
}

const HEX64 = /^[0-9a-f]{64}$/;
const TASK_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const digestJson = (v: unknown): string => createHash("sha256").update(canonicalize(v), "utf8").digest("hex");
const exact = (v: unknown): string => (typeof v === "string" && v.length <= 64 && /^[A-Za-z0-9_:-]*$/.test(v) ? v : "UNKNOWN");

/** ADMIT/QUARANTINE need these PRESENT. rastik_report may alternatively be NOT_APPLICABLE (the envelope did not require it). */
const REQUIRED_PRESENT: readonly EvidenceName[] = ["envelope", "action_receipt", "toepara_evidence", "evidence_bundle", "cerberus_receipt"];

export interface DecisionRequest {
  task_id: unknown;
  proposed: unknown;
  reasons?: unknown;
  evidence: Partial<Record<EvidenceName, { state?: unknown; digest?: unknown } | undefined>>;
  toepara_verdict: unknown;
  cerberus_decision: unknown;
  stages: unknown;
}

function normaliseRef(r: { state?: unknown; digest?: unknown } | undefined): EvidenceRef {
  if (r === undefined) return { state: "MISSING", digest: null };
  const state = (STATES as readonly unknown[]).includes(r.state) ? (r.state as EvidenceState) : "UNKNOWN";
  if (state === "PRESENT") return typeof r.digest === "string" && HEX64.test(r.digest) ? { state, digest: r.digest } : { state: "UNKNOWN", digest: null };
  return { state, digest: null };
}

function seal(body: Omit<DecisionReceipt, "receipt_digest">): DecisionReceipt {
  return { ...body, receipt_digest: digestJson(body) };
}

/** Why the evidence/basis would NOT justify letting work proceed. Empty list <=> ADMIT/QUARANTINE is justified. */
function proceedBlockers(evidence: Record<EvidenceName, EvidenceRef>, basis: DecisionReceipt["basis"]): string[] {
  const why: string[] = [];
  for (const n of REQUIRED_PRESENT) if (evidence[n].state !== "PRESENT") why.push(`evidence-${n.replaceAll("_", "-")}-${evidence[n].state.toLowerCase().replaceAll("_", "-")}`);
  const rr = evidence.rastik_report.state;
  if (rr !== "PRESENT" && rr !== "NOT_APPLICABLE") why.push(`evidence-rastik-report-${rr.toLowerCase().replaceAll("_", "-")}`);
  if (basis.toepara_verdict !== "VERIFIED") why.push(`toepara-verdict-not-verified:${basis.toepara_verdict}`);
  if (basis.cerberus_decision !== "PROCEED") why.push(`cerberus-decision-not-proceed:${basis.cerberus_decision}`);
  for (const s of STAGE_NAMES) if (basis.stages[s] !== "PASS") why.push(`stage-not-pass:${s}:${basis.stages[s]}`);
  return why;
}

export function buildDecisionReceipt(req: DecisionRequest): DecisionReceipt {
  try {
    const task_id = typeof req.task_id === "string" && TASK_ID.test(req.task_id) ? req.task_id : "invalid-task-id";
    const reasons: string[] = [];
    if (task_id === "invalid-task-id") reasons.push("task-id-invalid");
    const evidence = Object.fromEntries(EVIDENCE_NAMES.map((n) => [n, normaliseRef(req.evidence?.[n])])) as Record<EvidenceName, EvidenceRef>;
    const stagesIn = typeof req.stages === "object" && req.stages !== null ? (req.stages as Record<string, unknown>) : {};
    const basis: DecisionReceipt["basis"] = {
      toepara_verdict: exact(req.toepara_verdict),
      cerberus_decision: exact(req.cerberus_decision),
      stages: Object.fromEntries(STAGE_NAMES.map((s) => [s, exact(stagesIn[s])])) as DecisionReceipt["basis"]["stages"],
    };
    const proposedOk = req.proposed === "ADMIT" || req.proposed === "DENY" || req.proposed === "QUARANTINE";
    const proposed: DecisionReceipt["proposed_decision"] = proposedOk ? (req.proposed as DecisionValue) : "INVALID";
    if (Array.isArray(req.reasons)) for (const r of req.reasons) if (typeof r === "string" && reasons.length < 64) reasons.push(r.slice(0, 300));
    let decision: DecisionValue = "DENY";
    if (!proposedOk) reasons.push("proposed-decision-invalid");
    else if (proposed === "DENY") decision = "DENY";
    else {
      const blockers = proceedBlockers(evidence, basis);
      if (blockers.length === 0 && task_id !== "invalid-task-id") decision = req.proposed as DecisionValue;
      else reasons.push(...blockers.slice(0, 32), "downgraded-to-deny");
    }
    if (decision === "DENY" && reasons.length === 0) reasons.push("denied");
    const unique = [...new Set(reasons)].slice(0, 64);
    return seal({ version: DECISION_RECEIPT_VERSION, task_id, decision, proposed_decision: proposed, reasons: unique, evidence, evidence_binding_digest: digestJson(evidence), basis, authentication: "UNSIGNED" });
  } catch {
    const evidence = Object.fromEntries(EVIDENCE_NAMES.map((n) => [n, { state: "UNKNOWN", digest: null }])) as Record<EvidenceName, EvidenceRef>;
    const stages = Object.fromEntries(STAGE_NAMES.map((s) => [s, "UNKNOWN"])) as DecisionReceipt["basis"]["stages"];
    return seal({ version: DECISION_RECEIPT_VERSION, task_id: "invalid-task-id", decision: "DENY", proposed_decision: "INVALID", reasons: ["internal-error"], evidence, evidence_binding_digest: digestJson(evidence), basis: { toepara_verdict: "UNKNOWN", cerberus_decision: "UNKNOWN", stages }, authentication: "UNSIGNED" });
  }
}

export interface VerifyResult {
  ok: boolean;
  problems: string[];
}

const RECEIPT_KEYS = ["authentication", "basis", "decision", "evidence", "evidence_binding_digest", "proposed_decision", "reasons", "receipt_digest", "task_id", "version"];

/**
 * Re-derive everything a receipt claims: closed shape, digests, and the ADMIT/QUARANTINE invariants. A receipt that
 * was edited (decision flipped to ADMIT, evidence swapped, a stage rewritten to PASS) fails here.
 */
export function verifyDecisionReceipt(x: unknown): VerifyResult {
  const problems: string[] = [];
  try {
    if (typeof x !== "object" || x === null || Array.isArray(x)) return { ok: false, problems: ["not-an-object"] };
    const r = x as Record<string, unknown>;
    if (Object.keys(r).sort().join(",") !== RECEIPT_KEYS.join(",")) problems.push("unexpected-or-missing-keys");
    if (r.version !== DECISION_RECEIPT_VERSION) problems.push("version");
    if (r.authentication !== "UNSIGNED") problems.push("authentication");
    if (typeof r.task_id !== "string" || !TASK_ID.test(r.task_id)) problems.push("task-id");
    if (r.decision !== "ADMIT" && r.decision !== "DENY" && r.decision !== "QUARANTINE") problems.push("decision");
    if (!Array.isArray(r.reasons) || !r.reasons.every((s) => typeof s === "string")) problems.push("reasons");
    const ev = r.evidence as Record<string, EvidenceRef> | null;
    if (typeof ev !== "object" || ev === null || Object.keys(ev).sort().join(",") !== [...EVIDENCE_NAMES].sort().join(",")) problems.push("evidence-keys");
    else {
      for (const n of EVIDENCE_NAMES) {
        const e = ev[n];
        const okRef = typeof e === "object" && e !== null && (STATES as readonly unknown[]).includes(e.state) && (e.state === "PRESENT" ? typeof e.digest === "string" && HEX64.test(e.digest) : e.digest === null);
        if (!okRef) problems.push(`evidence-ref:${n}`);
      }
      if (r.evidence_binding_digest !== digestJson(ev)) problems.push("evidence-binding-digest");
    }
    const b = r.basis as DecisionReceipt["basis"] | null;
    const basisOk = typeof b === "object" && b !== null && typeof b.stages === "object" && b.stages !== null;
    if (!basisOk) problems.push("basis");
    if (problems.length === 0 && (r.decision === "ADMIT" || r.decision === "QUARANTINE")) {
      const blockers = proceedBlockers(ev as unknown as Record<EvidenceName, EvidenceRef>, b as DecisionReceipt["basis"]);
      for (const w of blockers) problems.push(`proceed-invariant:${w}`);
      if (r.proposed_decision !== r.decision) problems.push("proposed-differs-from-decision");
    }
    if (r.decision === "DENY" && Array.isArray(r.reasons) && r.reasons.length === 0) problems.push("deny-without-reason");
    const { receipt_digest, ...body } = r;
    if (typeof receipt_digest !== "string" || receipt_digest !== digestJson(body)) problems.push("receipt-digest");
  } catch {
    problems.push("internal-error");
  }
  return { ok: problems.length === 0, problems };
}

/**
 * Evidence binding check: re-hash the evidence objects you hold and compare with the receipt's references.
 * `complete` additionally requires that every PRESENT reference is supplied (no silent partial verification).
 */
export function bindEvidence(receipt: DecisionReceipt, actual: Partial<Record<EvidenceName, unknown>>, opts: { complete?: boolean } = {}): VerifyResult {
  const problems: string[] = [];
  try {
    for (const n of EVIDENCE_NAMES) {
      const ref = receipt.evidence[n];
      const supplied = Object.prototype.hasOwnProperty.call(actual, n);
      if (supplied) {
        if (ref.state !== "PRESENT") problems.push(`bound-${n}-is-${ref.state.toLowerCase()}-but-evidence-supplied`);
        else if (digestJson(actual[n]) !== ref.digest) problems.push(`evidence-mismatch:${n}`);
      } else if (opts.complete && ref.state === "PRESENT") problems.push(`evidence-not-supplied:${n}`);
    }
  } catch {
    problems.push("internal-error");
  }
  return { ok: problems.length === 0, problems };
}
