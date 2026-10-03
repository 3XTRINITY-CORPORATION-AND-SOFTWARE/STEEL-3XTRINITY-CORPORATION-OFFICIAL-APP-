import { canonicalize } from "../cerberus/core/decide.ts";
import { sha256Hex } from "../cerberus/artifact-trust/artifact-trust.ts";
import { KRATT_ACTIONS } from "../kratt/task.ts";
import { ReplayGuard } from "../kratt/evidence.ts";
import { runRastik } from "../rastik/run.ts";
import { ATTACK_AGENT, type AttackClass } from "./capabilities.ts";
import { cerberusDecide } from "./cerberus-gate.ts";
import { commitExists } from "./git.ts";
import { digestOf, type ActionReceipt, type RastikFinding, type Severity, type TaskEnvelope } from "./protocol/types.ts";
import { rastikEvidenceDigest, type AttackRecord, type ProbeSummary, type RastikRun } from "./rastik-types.ts";
import { toeparaVerify, type ToeparaCtx } from "./toepara.ts";
import { spawnSync } from "node:child_process";

/**
 * RÄSTIK stage against ONE exact action receipt.
 *
 * Hypothesis for every case: "this mutated receipt (or sequence) gets ADMITted". A case that
 * is not admitted is REPELLED (no finding). One that is admitted is re-run in a fresh session:
 * reproduced => CONFIRMED finding (with a regression-test skeleton and smallest fix), otherwise
 * UNCONFIRMED. The target under attack is injectable so tests can prove the battery really
 * detects a weak verifier (mutation check) instead of only ever reporting "all repelled".
 */
export type AttackTarget = (candidate: unknown, envelope: unknown, guard: ReplayGuard) => Promise<boolean>;

interface Case {
  id: string;
  hypothesis: string;
  fix: string;
  /** Candidate sequence; acceptance of the LAST one is the hypothesis. */
  build: (g: ActionReceipt, e: TaskEnvelope) => { seq: unknown[]; envelope?: unknown } | null;
}

const clone = <T>(v: T): T => structuredClone(v);
const flip = (hex: string) => (hex[0] === "0" ? "1" : "0") + hex.slice(1);
type Mut = (g: Record<string, any>) => void;
const mutate = (g: ActionReceipt, f: Mut): unknown => {
  const c = clone(g) as unknown as Record<string, unknown>;
  f(c as Record<string, any>);
  return c;
};
const one = (g: ActionReceipt, f: Mut) => ({ seq: [mutate(g, f)] });

/** Recompute KRATT's evidenceDigest after a mutation, i.e. a self-consistent forgery. */
function reseal(ev: Record<string, unknown>): void {
  const { evidenceDigest: _d, ...body } = ev;
  void _d;
  ev.evidenceDigest = sha256Hex(canonicalize(body));
}

const CASES: Record<AttackClass, Case[]> = {
  "invalid-input": [
    { id: "null-receipt", hypothesis: "null is admitted as a receipt", fix: "Reject non-object receipts before any other check.", build: () => ({ seq: [null] }) },
    { id: "string-receipt", hypothesis: "the string ADMITTED is admitted", fix: "Schema-validate the receipt (closed ActionReceipt spec).", build: () => ({ seq: ["ADMITTED"] }) },
    { id: "array-receipt", hypothesis: "an array is admitted", fix: "Reject arrays at the schema layer.", build: () => ({ seq: [[]] }) },
    { id: "empty-object", hypothesis: "{} is admitted", fix: "Required keys must be present.", build: () => ({ seq: [{}] }) },
    { id: "scope-traversal", hypothesis: "scope ../../etc/passwd is admitted", fix: "REL_PATH allow-list for scope entries.", build: (g) => one(g, (c) => { c.scope = ["../../etc/passwd"]; }) },
    { id: "task-id-injection", hypothesis: "task_id '../../x' is admitted", fix: "TASK_ID allow-list pattern.", build: (g) => one(g, (c) => { c.task_id = "../../x"; }) },
    { id: "trust-field-injection", hypothesis: "an extra top-level trust field is accepted", fix: "Closed key set; unknown keys reject.", build: (g) => one(g, (c) => { c.trust = "ADMITTED"; }) },
  ],
  boundary: [
    { id: "scope-65-entries", hypothesis: "65 scope entries (limit 64) are admitted", fix: "Enforce maxItems on scope.", build: (g) => one(g, (c) => { c.scope = Array.from({ length: 65 }, (_, i) => `f${i}.ts`); }) },
    { id: "task-id-65-chars", hypothesis: "a 65 character task_id is admitted", fix: "Enforce TASK_ID length.", build: (g) => one(g, (c) => { c.task_id = "a".repeat(65); }) },
    { id: "empty-timestamp", hypothesis: "an empty timestamp is admitted", fix: "ISO-8601 UTC pattern on timestamp.", build: (g) => one(g, (c) => { c.timestamp = ""; }) },
    { id: "checks-pass-2-pow-53", hypothesis: "checks.pass = 2^53 is admitted", fix: "Safe-integer bounds on counters.", build: (g) => one(g, (c) => { c.result.checks.pass = 2 ** 53; }) },
    { id: "exit-code-256", hypothesis: "exit_code 256 is admitted", fix: "Bound exit_code to -1..255.", build: (g) => one(g, (c) => { c.result.exit_code = 256; }) },
    { id: "artifact-bytes-negative", hypothesis: "artifact bytes = -1 is admitted", fix: "Evidence parser requires non-negative safe integers.", build: (g) => one(g, (c) => { c.evidence.artifacts[0].bytes = -1; }) },
    { id: "checks-pass-zero-ok-true", hypothesis: "ok=true with zero passed checks is admitted", fix: "Require pass >= 1 for a success claim.", build: (g) => one(g, (c) => { c.result.checks.pass = 0; }) },
  ],
  "missing-evidence": [
    { id: "evidence-deleted", hypothesis: "a receipt without evidence is admitted", fix: "Missing evidence => INSUFFICIENT_EVIDENCE.", build: (g) => one(g, (c) => { delete c.evidence; }) },
    { id: "result-deleted", hypothesis: "a receipt without result is admitted", fix: "Missing result => INSUFFICIENT_EVIDENCE.", build: (g) => one(g, (c) => { delete c.result; }) },
    { id: "evidence-empty-object", hypothesis: "evidence {} is admitted", fix: "Empty evidence is missing evidence.", build: (g) => one(g, (c) => { c.evidence = {}; }) },
    { id: "evidence-null", hypothesis: "evidence null is admitted", fix: "Schema requires an object.", build: (g) => one(g, (c) => { c.evidence = null; }) },
    { id: "artifacts-emptied", hypothesis: "evidence with its artifact list emptied is admitted", fix: "Artifacts must equal scope; digest must verify.", build: (g) => one(g, (c) => { c.evidence.artifacts = []; }) },
  ],
  "tampered-evidence": [
    { id: "artifact-sha-flipped", hypothesis: "a flipped artifact digest (evidenceDigest untouched) is admitted", fix: "Recompute evidenceDigest in parseEvidence.", build: (g) => one(g, (c) => { c.evidence.artifacts[0].sha256 = flip(c.evidence.artifacts[0].sha256); }) },
    { id: "checks-inflated", hypothesis: "inflated check counts are admitted", fix: "Digest covers checks; receipt result must match evidence.", build: (g) => one(g, (c) => { c.evidence.checks.pass += 1; }) },
    { id: "evidence-digest-swapped", hypothesis: "a swapped evidenceDigest is admitted", fix: "Recompute and compare evidenceDigest.", build: (g) => one(g, (c) => { c.evidence.evidenceDigest = flip(c.evidence.evidenceDigest); }) },
    {
      id: "self-consistent-forgery-wrong-source-digest",
      hypothesis: "evidence whose artifact digest is wrong but whose evidenceDigest was recomputed (self-consistent) is admitted",
      fix: "Recompute artifact digests from git at base_sha; never trust the producer's digest.",
      build: (g) => one(g, (c) => { c.evidence.artifacts[0].sha256 = flip(c.evidence.artifacts[0].sha256); reseal(c.evidence); }),
    },
    {
      id: "self-consistent-forgery-wrong-task",
      hypothesis: "self-consistent evidence bound to a different task digest is admitted",
      fix: "Re-derive taskDigest from the envelope.",
      build: (g) => one(g, (c) => { c.evidence.taskDigest = flip(c.evidence.taskDigest); reseal(c.evidence); }),
    },
  ],
  "unauthorized-action": [
    { id: "action-deploy", hypothesis: "action 'deploy' is admitted", fix: "Action must be in envelope.allowed_actions.", build: (g) => one(g, (c) => { c.action = "deploy"; }) },
    { id: "action-merge", hypothesis: "action 'merge' is admitted", fix: "Action must be in envelope.allowed_actions and not forbidden.", build: (g) => one(g, (c) => { c.action = "merge"; }) },
    {
      id: "kratt-action-not-in-envelope",
      hypothesis: "a KRATT action the envelope did not allow is admitted",
      fix: "Compare receipt.action against envelope.allowed_actions exactly.",
      build: (g, e) => {
        const other = KRATT_ACTIONS.find((a) => !e.allowed_actions.includes(a));
        return other ? one(g, (c) => { c.action = other; }) : null;
      },
    },
    { id: "agent-spoof", hypothesis: "a receipt claiming a different agent is admitted", fix: "receipt.agent_id must equal the envelope owner.", build: (g) => one(g, (c) => { c.agent_id = "CITADEL-111"; }) },
    {
      id: "repository-spoof",
      hypothesis: "a receipt and envelope for another repository are admitted",
      fix: "Repository is host-configured; mismatch rejects.",
      build: (g, e) => ({ seq: [mutate(g, (c) => { c.repository = "evil/other-repo"; })], envelope: { ...clone(e), repository: "evil/other-repo" } }),
    },
  ],
  "stale-base-sha": [
    { id: "base-sha-zero-both", hypothesis: "base_sha 000..0 in receipt and envelope is admitted", fix: "base_sha must be an existing commit equal to HEAD.", build: (g, e) => ({ seq: [mutate(g, (c) => { c.base_sha = "0".repeat(40); })], envelope: { ...clone(e), base_sha: "0".repeat(40) } }) },
    { id: "receipt-base-sha-differs", hypothesis: "a receipt whose base_sha differs from the envelope is admitted", fix: "receipt.base_sha must equal envelope.base_sha.", build: (g) => one(g, (c) => { c.base_sha = "1".repeat(40); }) },
    {
      id: "base-sha-parent-commit",
      hypothesis: "a real but stale commit (HEAD~1) as base_sha in receipt and envelope is admitted",
      fix: "base_sha must equal the current HEAD.",
      build: (g, e) => {
        const p = parentSha(g.base_sha);
        return p ? { seq: [mutate(g, (c) => { c.base_sha = p; })], envelope: { ...clone(e), base_sha: p } } : null;
      },
    },
  ],
  "malformed-receipt": [
    { id: "protocol-version-2", hypothesis: "protocol_version 2 is admitted", fix: "Reject incompatible major.", build: (g) => one(g, (c) => { c.protocol_version = 2; }) },
    { id: "self-verified-by-kratt", hypothesis: "a KRATT receipt claiming VERIFIED is admitted", fix: "Only TÖEPÄRA may verify; KRATT receipts must be UNVERIFIED.", build: (g) => one(g, (c) => { c.verification_state = "VERIFIED"; }) },
    { id: "state-trusted", hypothesis: "verification_state TRUSTED is admitted", fix: "Closed enum.", build: (g) => one(g, (c) => { c.verification_state = "TRUSTED"; }) },
    { id: "result-ok-string", hypothesis: "result.ok = 'true' (string) is admitted", fix: "Type-check result.ok.", build: (g) => one(g, (c) => { c.result.ok = "true"; }) },
    { id: "evidence-array", hypothesis: "evidence as an array is admitted", fix: "evidence must be a plain object.", build: (g) => one(g, (c) => { c.evidence = [c.evidence]; }) },
    { id: "failure-number", hypothesis: "result.failure = 0 is admitted", fix: "failure is null or text.", build: (g) => one(g, (c) => { c.result.failure = 0; }) },
    { id: "result-contradicts-evidence", hypothesis: "result.checks differing from the evidence are admitted", fix: "Receipt result must equal the evidence facts.", build: (g) => one(g, (c) => { c.result.checks.pass = c.result.checks.pass + 1; }) },
  ],
  replay: [
    { id: "same-receipt-twice", hypothesis: "the identical valid receipt is admitted a second time", fix: "Consume the bundle digest in a replay guard; deny on second sight.", build: (g) => ({ seq: [clone(g), clone(g)] }) },
  ],
};

let parentCache: Map<string, string | null> = new Map();
let parentRoot = "";
export function configureParentLookup(root: string): void {
  parentRoot = root;
  parentCache = new Map();
}
function parentSha(sha: string): string | null {
  if (parentCache.has(sha)) return parentCache.get(sha) ?? null;
  const r = spawnSync("git", ["rev-parse", "--verify", `${sha}~1^{commit}`], { cwd: parentRoot, shell: false, encoding: "utf8", env: { PATH: process.env.PATH ?? "" } });
  const s = r.status === 0 ? r.stdout.trim() : "";
  const v = /^[0-9a-f]{40}$/.test(s) && commitExists(parentRoot, s) ? s : null;
  parentCache.set(sha, v);
  return v;
}

const SEVERITY: Record<AttackClass, Severity> = {
  "invalid-input": "high",
  boundary: "medium",
  "missing-evidence": "high",
  "tampered-evidence": "critical",
  "unauthorized-action": "critical",
  "stale-base-sha": "high",
  "malformed-receipt": "high",
  replay: "high",
};

export function regressionTestSkeleton(cls: AttackClass, c: Case): string {
  return [
    `test(${JSON.stringify(`RASTIK ${cls}/${c.id}: must not be ADMITted`)}, async () => {`,
    `  // hypothesis: ${c.hypothesis}`,
    `  // build the good receipt for the fixture task, apply the "${c.id}" mutation from factory/rastik-attacks.ts,`,
    `  // submit it to toeparaVerify + cerberusDecide and assert decision !== "ADMIT".`,
    `});`,
  ].join("\n");
}

export interface AttackDeps {
  target: AttackTarget;
}

export async function runAttackClass(
  cls: AttackClass,
  good: ActionReceipt,
  envelope: TaskEnvelope,
  deps: AttackDeps,
): Promise<{ records: AttackRecord[]; findings: RastikFinding[]; control_admitted: boolean }> {
  const records: AttackRecord[] = [];
  const findings: RastikFinding[] = [];
  const receiptDigest = digestOf(good);
  const attempt = async (seq: unknown[], env: unknown): Promise<boolean> => {
    const guard = new ReplayGuard();
    let last = false;
    for (const cand of seq) {
      try {
        last = await deps.target(cand, env, guard);
      } catch {
        last = false; // a throwing verifier is fail-closed; not a bypass
      }
    }
    return last;
  };
  // Control: the unmutated receipt must be admitted, otherwise "everything was repelled" proves nothing.
  const control_admitted = await attempt([clone(good)], clone(envelope));
  if (!control_admitted) return { records, findings, control_admitted };
  for (const c of CASES[cls]) {
    const built = c.build(clone(good), clone(envelope));
    if (built === null) continue; // case not applicable (e.g. no parent commit in a shallow clone): not counted
    const env = built.envelope ?? clone(envelope);
    const accepted = await attempt(built.seq, env);
    const attack_id = `${cls}/${c.id}`;
    if (!accepted) {
      records.push({ attack_id, class: cls, agent_id: ATTACK_AGENT[cls], case_id: c.id, hypothesis: c.hypothesis, outcome: "REPELLED", reproduced: null });
      continue;
    }
    const again = await attempt(built.seq, env);
    records.push({ attack_id, class: cls, agent_id: ATTACK_AGENT[cls], case_id: c.id, hypothesis: c.hypothesis, outcome: "SUCCEEDED", reproduced: again });
    findings.push({
      finding_id: `RASTIK-RCPT-${cls}-${c.id}`,
      target: `factory receipt verification (toeparaVerify + cerberusDecide), task ${envelope.task_id}`,
      hypothesis: c.hypothesis,
      reproduction: `Take the genuine receipt (digest ${receiptDigest}), apply mutation "${c.id}" (factory/rastik-attacks.ts, class ${cls}); the verifier ADMITted it${again ? " on two independent runs" : " once, but not on the re-run"}.`,
      severity: SEVERITY[cls],
      status: again ? "CONFIRMED" : "UNCONFIRMED",
      evidence: { attack_id, receipt_digest: receiptDigest, admitted_on_rerun: again },
      regression_test: regressionTestSkeleton(cls, c),
      proposed_smallest_fix: c.fix,
    });
  }
  return { records, findings, control_admitted };
}

/** The real verification path the attacks are aimed at. */
export function realAttackTarget(base: ToeparaCtx): AttackTarget {
  return async (candidate, envelope, guard) => {
    const env = (typeof envelope === "object" && envelope !== null ? { ...(envelope as object), required_evidence: ["source_digests"] } : envelope) as unknown;
    const t = await toeparaVerify(env, candidate, null, base);
    if (t.verdict.verdict !== "VERIFIED") return false;
    const g = await cerberusDecide({ envelope: env, receipt: candidate, rastik: null, toepara: t }, { ...base, guard });
    return g.decision.decision === "ADMIT";
  };
}

export function caseCount(cls: AttackClass): number {
  return CASES[cls].length;
}

/** Existing RÄSTIK probes selected by the receipt's scope (real code, real cases). */
export async function runProbes(root: string, scope: string[], base: string): Promise<ProbeSummary & { findings: RastikFinding[] }> {
  const rep = await runRastik({ root, files: scope, base, head: base });
  return {
    probes: rep.probes.length,
    cases_executed: rep.casesExecuted,
    confirmed_findings: rep.findings.length,
    probe_errors: rep.probes.filter((p) => p.error !== null).length,
    evidence_digest: rep.evidence.evidenceDigest,
    findings: rep.findings.map(fromProbeFinding),
  };
}

/** Thin adapter: rastik/types.ts Finding -> protocol RastikFinding (no duplicate type). */
export function fromProbeFinding(f: { id: string; category: string; risk: string; reproduction: string; affectedComponent: string; smallestFix: string; regressionTest: string }): RastikFinding {
  const cut = (s: string, n: number) => (s.length === 0 ? "-" : s.slice(0, n)).replace(/[\u0000-\u001f\u007f]/g, " "); // eslint-disable-line no-control-regex
  const cutMl = (s: string, n: number) => (s.length === 0 ? "-" : s.slice(0, n)).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " "); // eslint-disable-line no-control-regex
  return {
    finding_id: cut(f.id, 200),
    target: cut(f.affectedComponent, 300),
    hypothesis: cut(f.risk, 500),
    reproduction: cut(f.reproduction, 2000),
    severity: "high",
    status: "CONFIRMED",
    evidence: { category: f.category },
    regression_test: cutMl(f.regressionTest, 4000),
    proposed_smallest_fix: cut(f.smallestFix, 1000),
  };
}

export function assembleRun(receipt: ActionReceipt, attacks: AttackRecord[], findings: RastikFinding[], probe: ProbeSummary): RastikRun {
  const body = {
    target_receipt_digest: digestOf(receipt),
    cases_executed: attacks.length + probe.cases_executed,
    attacks,
    findings,
    probe,
  };
  return { ...body, evidence_digest: rastikEvidenceDigest(body) };
}
