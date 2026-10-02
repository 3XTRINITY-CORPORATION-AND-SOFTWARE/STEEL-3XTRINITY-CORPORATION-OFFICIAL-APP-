import { createHash } from "node:crypto";
import { artifactTrustFailure, type ArtifactEvidence } from "../artifact-trust/artifact-trust.ts";
import { isAllowedAction } from "../policy/policy.ts";

/**
 * Cerberus v0 vertical slice:
 *   INPUT -> POLICY CHECK -> ARTIFACT TRUST CHECK -> DECISION -> RECOVERY RECEIPT
 *
 * Cerberus never produces its own authorization. Upstream TÖEPÄRA and Trust Gate
 * verdicts are REQUIRED inputs; anything other than the exact admitted values fails closed.
 */
export interface CerberusInput {
  action: string;
  toepara: string; // must be "ADMITTED"
  trustGate: string; // must be "AUTHORIZED"
  artifact: ArtifactEvidence;
}

export type Decision = "PROCEED" | "FAIL_CLOSED";

export interface RecoveryReceipt {
  decision: Decision;
  reasons: string[];
  inputDigest: string;
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

export function decide(input: unknown): RecoveryReceipt {
  const reasons: string[] = [];
  const i = (typeof input === "object" && input !== null ? input : {}) as Partial<CerberusInput>;

  // 1. policy
  if (!isAllowedAction(i.action)) reasons.push("policy-action-denied");
  // 2. upstream gates (never bypassed)
  if (i.toepara !== "ADMITTED") reasons.push("toepara-not-admitted");
  if (i.trustGate !== "AUTHORIZED") reasons.push("trust-gate-not-authorized");
  // 3. artifact trust
  const trust = artifactTrustFailure(i.artifact);
  if (trust) reasons.push(trust);

  const decision: Decision = reasons.length === 0 ? "PROCEED" : "FAIL_CLOSED";
  const inputDigest = digest(canonicalize(input ?? null));
  const body = { decision, reasons, inputDigest };
  return { ...body, receiptDigest: digest(canonicalize(body)) };
}
