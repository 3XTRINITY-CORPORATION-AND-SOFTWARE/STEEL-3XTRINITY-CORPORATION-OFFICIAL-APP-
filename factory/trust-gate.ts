import { KRATT_ACTIONS } from "../kratt/task.ts";
import type { TaskEnvelope } from "./protocol/types.ts";

/**
 * Asynchronous Trust Gate interface (Promise-based) so a real remote Trust Gate can later be plugged in.
 * Only a STUB implementation exists in this repo (`stubPolicyTrustGate`); no real Trust Gate service exists.
 *
 * Fail-closed contract enforced by `resolveTrustGate`, whatever the gate does:
 *   - rejects, throws synchronously, or never settles within `timeoutMs`  => DENIED
 *   - resolves with anything other than the exact string "AUTHORIZED"/"DENIED" (including objects,
 *     lowercase, whitespace-padded, null, undefined, "ADMITTED", "PROCEED")        => DENIED
 *   - a late answer after a timeout is ignored.
 */
export type TrustVerdict = "AUTHORIZED" | "DENIED";

export interface TrustGateRequest {
  readonly task_id: string;
  readonly repository: string;
  readonly action: string | null;
  readonly envelope: Readonly<TaskEnvelope>;
  /** The host-configured repository the installation verifies for. */
  readonly host_repository: string;
}

export interface AsyncTrustGate {
  readonly name: string;
  evaluate(req: TrustGateRequest): Promise<unknown>;
}

export interface TrustResolution {
  verdict: TrustVerdict;
  /** Why it was DENIED (diagnostics); empty for AUTHORIZED. */
  reasons: string[];
}

export const DEFAULT_TRUST_TIMEOUT_MS = 2000;
export const MAX_TRUST_TIMEOUT_MS = 60_000;

export async function resolveTrustGate(gate: AsyncTrustGate, req: TrustGateRequest, timeoutMs: number = DEFAULT_TRUST_TIMEOUT_MS): Promise<TrustResolution> {
  const deny = (r: string): TrustResolution => ({ verdict: "DENIED", reasons: [r] });
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TRUST_TIMEOUT_MS) return deny("trust-gate:invalid-timeout");
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<{ timedOut: true }>((resolve) => {
    timer = setTimeout(() => resolve({ timedOut: true }), timeoutMs);
  });
  try {
    const call = (async () => ({ timedOut: false as const, value: await gate.evaluate(req) }))();
    const r = await Promise.race([call, timeout]);
    if (r.timedOut) return deny("trust-gate:timeout");
    if (r.value === "AUTHORIZED") return { verdict: "AUTHORIZED", reasons: [] };
    if (r.value === "DENIED") return deny("trust-gate:denied");
    return deny("trust-gate:malformed-verdict");
  } catch {
    return deny("trust-gate:threw");
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Local policy shared by the stub (and by the sync adapter in cerberus-gate). Returns the reasons it would DENY for. */
export function policyViolations(envelope: Readonly<TaskEnvelope>, action: unknown, hostRepository: string): string[] {
  const why: string[] = [];
  if (envelope.repository !== hostRepository) why.push("policy:repository-mismatch");
  if (!envelope.allowed_actions.every((a) => (KRATT_ACTIONS as readonly string[]).includes(a))) why.push("policy:non-kratt-action-allowed");
  for (const must of ["merge", "deploy"]) if (!envelope.forbidden_actions.includes(must)) why.push(`policy:${must}-not-forbidden`);
  if (typeof action !== "string" || !envelope.allowed_actions.includes(action)) why.push("policy:receipt-action-not-allowed");
  return why;
}

/** STUB: a local policy dressed as an async gate. It is NOT the real Trust Gate. */
export const stubPolicyTrustGate: AsyncTrustGate = {
  name: "stub-policy-trust-gate(NOT the real Trust Gate)",
  async evaluate(req) {
    return policyViolations(req.envelope, req.action, req.host_repository).length === 0 ? "AUTHORIZED" : "DENIED";
  },
};
