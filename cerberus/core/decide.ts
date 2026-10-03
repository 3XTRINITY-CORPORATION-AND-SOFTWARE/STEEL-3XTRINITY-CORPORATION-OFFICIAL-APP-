import { createHash } from "node:crypto";
import { artifactTrustFailure, sha256Hex } from "../artifact-trust/artifact-trust.ts";
import { isAllowedAction } from "../policy/policy.ts";
import { normalizeInput, type NormalizedInput } from "./normalize.ts";

/**
 * Cerberus v1 slice (all upstream systems are caller-supplied / stubbed):
 *   INPUT -> POLICY -> TÖEPÄRA -> TRUST GATE -> ARTIFACT TRUST -> DECISION -> RECOVERY RECEIPT
 *
 * Invariants (each covered by cerberus/tests):
 *  - Every stage is always evaluated (no short-circuit) so the receipt lists every failure.
 *  - PROCEED only if all five stages are PASS; the decision is derived from the stage
 *    results, not from a separate flag, so no stage can be skipped.
 *  - Missing / malformed / hostile input => FAIL_CLOSED. `decide` never throws.
 *  - The digest and the decision are computed from the same immutable snapshot, so the
 *    same normalized input always yields a byte-identical receipt.
 *  - Cerberus never produces its own authorization: TÖEPÄRA and Trust Gate verdicts are
 *    required inputs and only the exact strings "ADMITTED" / "AUTHORIZED" pass.
 *
 * LIMITATION: in `decide(input)` the TÖEPÄRA / Trust Gate verdicts are plain strings
 * supplied by the caller. Cerberus cannot verify they came from the real systems; see
 * ../integrations/verdict-adapters.ts for the (stubbed) seam.
 */
export interface CerberusInput {
  action: string;
  toepara: string; // must be "ADMITTED"
  trustGate: string; // must be "AUTHORIZED"
  artifact: { name: string; content: string; /** declared lowercase hex SHA-256 */ sha256: string };
}

export type Decision = "PROCEED" | "FAIL_CLOSED";
export type StageResult = "PASS" | "FAIL" | "NOT_EVALUATED";
export type VerdictSource = "caller-supplied" | "adapter";

export const RECEIPT_VERSION = "cerberus-receipt/v1";

export interface RecoveryReceipt {
  version: typeof RECEIPT_VERSION;
  decision: Decision;
  reasons: string[];
  verdictSource: VerdictSource;
  stages: {
    input: StageResult;
    policy: StageResult;
    toepara: StageResult;
    trustGate: StageResult;
    artifactTrust: StageResult;
  };
  /** The exact values the decision was made on (from the normalized snapshot). */
  evidence: {
    action: string | null;
    toepara: string | null;
    trustGate: string | null;
    artifact: { name: string | null; declaredSha256: string | null; computedSha256: string | null } | null;
  };
  /** SHA-256 of the canonical normalized input (all four decision fields, incl. artifact content). */
  inputDigest: string;
  /** SHA-256 of the canonical receipt body (every field above). */
  receiptDigest: string;
}

/** Canonical JSON: keys sorted at every level, so insertion order never matters. */
export function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalize(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

const digest = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

type ReceiptBody = Omit<RecoveryReceipt, "receiptDigest">;

function seal(body: ReceiptBody): RecoveryReceipt {
  return { ...body, receiptDigest: digest(canonicalize(body)) };
}

/** Recompute the receipt digest; false if any field was altered after sealing. */
export function verifyReceipt(receipt: unknown): boolean {
  try {
    if (typeof receipt !== "object" || receipt === null) return false;
    const { receiptDigest, ...body } = receipt as Record<string, unknown>;
    return typeof receiptDigest === "string" && receiptDigest === digest(canonicalize(body));
  } catch {
    return false;
  }
}

/** Pure evaluation of a snapshot. Exposed for the adapter seam; prefer `decide`. */
export function evaluate(
  snapshot: Readonly<NormalizedInput>,
  verdictSource: VerdictSource,
): RecoveryReceipt {
  const reasons: string[] = [];
  const stage = (ok: boolean, reason: string | null): StageResult => {
    if (!ok && reason) reasons.push(reason);
    return ok ? "PASS" : "FAIL";
  };

  const policy = stage(isAllowedAction(snapshot.action), "policy-action-denied");
  const toepara = stage(snapshot.toepara === "ADMITTED", "toepara-not-admitted");
  const trustGate = stage(snapshot.trustGate === "AUTHORIZED", "trust-gate-not-authorized");
  const trustFailure = artifactTrustFailure(snapshot.artifact);
  const artifactTrust = stage(trustFailure === null, trustFailure);

  const stages = { input: "PASS" as StageResult, policy, toepara, trustGate, artifactTrust };
  const decision: Decision = Object.values(stages).every((s) => s === "PASS") ? "PROCEED" : "FAIL_CLOSED";

  const a = snapshot.artifact;
  return seal({
    version: RECEIPT_VERSION,
    decision,
    reasons,
    verdictSource,
    stages,
    evidence: {
      action: snapshot.action,
      toepara: snapshot.toepara,
      trustGate: snapshot.trustGate,
      artifact: a && {
        name: a.name,
        declaredSha256: a.sha256,
        computedSha256: a.content === null ? null : sha256Hex(a.content),
      },
    },
    inputDigest: digest(canonicalize(snapshot)),
  });
}

/** Receipt for input that could not even be normalized. Always FAIL_CLOSED. */
export function malformedInputReceipt(reason: string, verdictSource: VerdictSource): RecoveryReceipt {
  return seal({
    version: RECEIPT_VERSION,
    decision: "FAIL_CLOSED",
    reasons: [reason],
    verdictSource,
    stages: {
      input: "FAIL",
      policy: "NOT_EVALUATED",
      toepara: "NOT_EVALUATED",
      trustGate: "NOT_EVALUATED",
      artifactTrust: "NOT_EVALUATED",
    },
    evidence: { action: null, toepara: null, trustGate: null, artifact: null },
    inputDigest: digest(canonicalize({ malformed: reason })),
  });
}

export function decide(input: unknown): RecoveryReceipt {
  try {
    const n = normalizeInput(input);
    return n.ok ? evaluate(n.value, "caller-supplied") : malformedInputReceipt(n.reason, "caller-supplied");
  } catch {
    // Defence in depth: nothing may escape as an exception that a caller could treat as "not denied".
    return malformedInputReceipt("internal-error", "caller-supplied");
  }
}
