import type { AttackClass } from "./capabilities.ts";
import { digestOf, type RastikFinding } from "./protocol/types.ts";

export interface AttackRecord {
  attack_id: string;
  class: AttackClass;
  agent_id: string;
  case_id: string;
  hypothesis: string;
  /** REPELLED: the mutated receipt was not admitted. SUCCEEDED: it was admitted (a defect). */
  outcome: "REPELLED" | "SUCCEEDED";
  /** For SUCCEEDED: did an independent second run reproduce it (=> CONFIRMED finding)? Otherwise null. */
  reproduced: boolean | null;
}

export interface ProbeSummary {
  probes: number;
  cases_executed: number;
  confirmed_findings: number;
  probe_errors: number;
  evidence_digest: string | null;
}

/** Everything RÄSTIK reports about one exact action receipt. Integrity-hashed, not signed. */
export interface RastikRun {
  target_receipt_digest: string;
  cases_executed: number;
  attacks: AttackRecord[];
  findings: RastikFinding[];
  probe: ProbeSummary;
  evidence_digest: string;
}

export function rastikEvidenceDigest(run: Omit<RastikRun, "evidence_digest">): string {
  return digestOf({
    target_receipt_digest: run.target_receipt_digest,
    cases_executed: run.cases_executed,
    attacks: run.attacks,
    findings: run.findings,
    probe: run.probe,
  });
}

export const isUnresolvedHigh = (f: RastikFinding): boolean =>
  f.status === "CONFIRMED" && (f.severity === "high" || f.severity === "critical");
