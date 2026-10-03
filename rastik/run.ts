import { createHash } from "node:crypto";
import { canonicalize } from "../cerberus/core/decide.ts";
import { allProbes } from "./probes.ts";
import type { Finding, Probe, ProbeResult } from "./types.ts";

/**
 * RÄSTIK execution stage: changed files -> select applicable adversarial probes ->
 * run them against the real code -> re-run every violation once -> CONFIRMED findings.
 * A probe that throws is reported as an error and fails the run (never counted as a pass).
 * Zero applicable probes is reported as zero executed cases, not as a pass.
 */
export interface RastikEvidence {
  version: "rastik-evidence/v1";
  base: string | null;
  head: string | null;
  changedFiles: string[];
  probes: ProbeResult[];
  findingIds: string[];
  evidenceDigest: string;
}

export interface RastikReport {
  findings: Finding[];
  probes: ProbeResult[];
  casesExecuted: number;
  evidence: RastikEvidence;
}

const slug = (s: string) => s.replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);

export function selectProbes(files: string[], probes: Probe[], all: boolean): Probe[] {
  return all ? probes : probes.filter((p) => p.applies(files));
}

export async function runRastik(opts: {
  root: string;
  files: string[];
  base?: string | null;
  head?: string | null;
  all?: boolean;
  probes?: Probe[];
}): Promise<RastikReport> {
  const selected = selectProbes(opts.files, opts.probes ?? allProbes(), opts.all === true);
  const findings: Finding[] = [];
  const results: ProbeResult[] = [];
  for (const p of selected) {
    let cases = 0;
    let unconfirmed = 0;
    let error: string | null = null;
    try {
      const out = await p.run({ root: opts.root, files: opts.files });
      cases = out.cases;
      for (const v of out.violations) {
        let again = false;
        try {
          again = await v.recheck();
        } catch {
          again = true; // throwing on re-run is still a violation of a total guard
        }
        if (!again) {
          unconfirmed++;
          continue;
        }
        findings.push({
          id: `RASTIK-${p.id}-${slug(v.caseId)}`,
          category: p.category,
          status: "CONFIRMED",
          risk: `${p.category}: expected "${v.expected}" but observed "${v.observed}"`,
          reproduction: v.reproduction,
          affectedComponent: p.component,
          smallestFix: p.smallestFix,
          regressionTest: `test(${JSON.stringify(`RASTIK ${p.id}: ${v.caseId}`)}, () => { /* expected: ${v.expected} */ /* repro: ${v.reproduction.replace(/\*\//g, "* /")} */ });`,
        });
      }
    } catch (e) {
      error = `probe-threw:${String(e instanceof Error ? e.message : e).slice(0, 200)}`;
    }
    results.push({ probe: p.id, category: p.category, component: p.component, cases, unconfirmed, error });
  }
  const body = {
    version: "rastik-evidence/v1" as const,
    base: opts.base ?? null,
    head: opts.head ?? null,
    changedFiles: opts.files,
    probes: results,
    findingIds: findings.map((f) => f.id),
  };
  const evidenceDigest = createHash("sha256").update(canonicalize(body), "utf8").digest("hex");
  return {
    findings,
    probes: results,
    casesExecuted: results.reduce((n, r) => n + r.cases, 0),
    evidence: { ...body, evidenceDigest },
  };
}

export function renderReport(r: RastikReport): string {
  const lines = [
    `RASTIK: ${r.probes.length} probes, ${r.casesExecuted} cases executed, ${r.findings.length} CONFIRMED findings, ${r.probes.filter((p) => p.error).length} probe errors`,
  ];
  for (const p of r.probes)
    lines.push(`  - ${p.probe} [${p.category}] cases=${p.cases} unconfirmed=${p.unconfirmed}${p.error ? ` ERROR=${p.error}` : ""}`);
  for (const f of r.findings)
    lines.push("", `FINDING ${f.id}`, `  RISK: ${f.risk}`, `  REPRODUCTION: ${f.reproduction}`, `  AFFECTED COMPONENT: ${f.affectedComponent}`, `  SMALLEST FIX: ${f.smallestFix}`, `  REGRESSION TEST: ${f.regressionTest}`);
  lines.push("", `EVIDENCE rastik-evidence/v1 digest=${r.evidence.evidenceDigest}`);
  return lines.join("\n");
}

export const hasFailures = (r: RastikReport): boolean => r.findings.length > 0 || r.probes.some((p) => p.error !== null);
