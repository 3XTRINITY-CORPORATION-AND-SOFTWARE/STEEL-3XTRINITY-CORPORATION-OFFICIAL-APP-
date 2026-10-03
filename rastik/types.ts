export type Category =
  | "invalid-input"
  | "boundary"
  | "non-finite"
  | "fail-open"
  | "evidence-bypass"
  | "stale-import";

export interface Finding {
  id: string;
  category: Category;
  /** Always CONFIRMED: a violation is only reported after an independent re-run reproduced it. */
  status: "CONFIRMED";
  risk: string;
  reproduction: string;
  affectedComponent: string;
  smallestFix: string;
  regressionTest: string;
}

/** One expectation that did not hold. `recheck` must return true if it still does. */
export interface Violation {
  caseId: string;
  expected: string;
  observed: string;
  reproduction: string;
  recheck: () => boolean | Promise<boolean>;
}

export interface ProbeOutcome {
  cases: number;
  violations: Violation[];
}

export interface ProbeContext {
  root: string;
  /** Changed files (repo-relative, POSIX) the probe was selected for. */
  files: string[];
}

export interface Probe {
  id: string;
  category: Category;
  component: string;
  smallestFix: string;
  /** Selects the probe for a change set. */
  applies: (files: string[]) => boolean;
  run: (ctx: ProbeContext) => Promise<ProbeOutcome>;
}

export interface ProbeResult {
  probe: string;
  category: Category;
  component: string;
  cases: number;
  /** Violations that did not reproduce on re-run (reported, never counted as findings). */
  unconfirmed: number;
  error: string | null;
}
