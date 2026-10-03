import { canonicalize } from "../cerberus/core/decide.ts";
import { sha256Hex } from "../cerberus/artifact-trust/artifact-trust.ts";
import { KRATT_ACTIONS } from "../kratt/task.ts";
import { ReplayGuard, computeVerdict } from "../kratt/evidence.ts";
import { runRastik } from "../rastik/run.ts";
import { ATTACK_AGENT, ATTACK_CLASSES as ATTACK_CLASSES_LIST, type AttackClass } from "./capabilities.ts";
import { cerberusDecide } from "./cerberus-gate.ts";
import { blobDigest, commitExists } from "./git.ts";
import { digestOf, type ActionReceipt, type RastikFinding, type Severity, type TaskEnvelope } from "./protocol/types.ts";
import { rastikEvidenceDigest, type AttackRecord, type ProbeSummary, type RastikRun } from "./rastik-types.ts";
import { toeparaVerify, type ToeparaCtx } from "./toepara.ts";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

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
  /**
   * Set when the attack is KNOWN to succeed against the current verifier because of a defect in a
   * file RÄSTIK does not own. Such cases are excluded from the default loop battery (so the genuine
   * loop is not quarantined by a defect that is already reported) and only run with
   * `includeOpenDefects: true`. Removing the flag is the "defect fixed" step: the case then guards
   * the fix. They are NEVER skipped by weakening a gate; the verifier still evaluates them.
   */
  openDefect?: { component: string };
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

// ---------------------------------------------------------------------------------------------
// RÄSTIK v2: adversarial expansion. Same hypothesis for every case ("the mutated receipt/sequence
// gets ADMITted"); the same fresh-session reproduction rule turns a bypass into a CONFIRMED finding.
// Cases flagged `openDefect` are real bypasses found against the current verifier (see
// docs/factory/MUTATION-CHECKS.md and the RÄSTIK v2 report); everything else is REPELLED.
// ---------------------------------------------------------------------------------------------

type Any = Record<string, any>;
/** Mutate receipt AND envelope together: a self-consistent forgery (both sides agree). */
const both = (g: ActionReceipt, e: TaskEnvelope, f: (r: Any, env: Any) => void): { seq: unknown[]; envelope: unknown } => {
  const r = clone(g) as unknown as Any;
  const env = clone(e) as unknown as Any;
  f(r, env);
  return { seq: [r], envelope: env };
};
/** Add an OWN enumerable data property even for names like __proto__ (a plain assignment would hit the setter). */
const own = (o: object, k: string, v: unknown): void => {
  Object.defineProperty(o, k, { value: v, enumerable: true, configurable: true, writable: true });
};
const reverseKeysDeep = (v: unknown): unknown =>
  Array.isArray(v) ? v.map(reverseKeysDeep) : typeof v === "object" && v !== null ? Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, reverseKeysDeep(x)])) : v;
/** A SELF-CONSISTENT forged result: evidence checks + verdict + digest and the receipt result all say pass/fail. */
const forgeChecks = (c: Any, pass: number, fail: number): void => {
  const ev = c.evidence as Any;
  ev.checks = { pass, fail };
  const { evidenceDigest: _d, verdict: _v, ...body } = ev;
  void _d;
  void _v;
  ev.verdict = computeVerdict(body as never);
  reseal(ev);
  c.result.checks = { pass, fail };
};
const hasTwoArtifacts = (g: ActionReceipt): boolean => Array.isArray(g.evidence.artifacts) && g.evidence.artifacts.length >= 2;
const retimestamp = (g: ActionReceipt, ts: string): unknown => mutate(g, (c) => { c.timestamp = ts; });
const nest = (depth: number): unknown => {
  let o: Record<string, unknown> = {};
  for (let i = 0; i < depth; i++) o = { a: o };
  return o;
};

const CONFUSABLE_IDS: [string, string][] = [
  ["cyrillic-a", "t\u0430sk-1"],
  ["fullwidth-digit", "task-\uff11"],
  ["zero-width-space", "task\u200b-1"],
  ["trailing-newline", "task-1\n"],
  ["right-to-left-override", "task-\u202e1"],
  ["uppercase", "TASK-1"],
  ["greek-omicron", "t\u03bfsk-1"],
];
const TRAVERSAL_SCOPES: [string, string][] = [
  ["dotdot", "../../etc/passwd"],
  ["absolute", "/etc/passwd"],
  ["backslash", "..\\..\\windows\\system32"],
  ["mid-dotdot", "cerberus/../../etc/passwd"],
  ["percent-encoded", "%2e%2e/%2e%2e/etc/passwd"],
  ["nul-byte", "cerberus/core/decide.ts\u0000.png"],
  ["dot-segment", "cerberus/./core/decide.ts"],
  ["double-slash", "cerberus//core/decide.ts"],
  ["dot-git", ".git/config"],
  ["drive-letter", "C:/Windows/win.ini"],
  ["trailing-slash", "cerberus/core/"],
  ["unicode-dot-leader", "\u2025/\u2025/etc/passwd"],
];

const V2: Record<AttackClass, Case[]> = {
  "invalid-input": [
    { id: "oversized-evidence-payload", hypothesis: "a 2 MB evidence payload is admitted (resource exhaustion / digest bypass)", fix: "Bound evidence size (kratt MAX_EVIDENCE_BYTES) before hashing.", build: (g) => one(g, (c) => { c.evidence.padding = "A".repeat(2_000_000); }) },
    { id: "oversized-task-id-1mb", hypothesis: "a 1 MB task_id in receipt and envelope is admitted", fix: "TASK_ID length bound (64) in the closed schema.", build: (g, e) => both(g, e, (r, env) => { r.task_id = env.task_id = "a".repeat(1_000_000); }) },
    { id: "oversized-scope-path-10k", hypothesis: "a 10,000 character scope path in receipt and envelope is admitted", fix: "relPath max 200 in the closed schema.", build: (g, e) => both(g, e, (r, env) => { const p = "a".repeat(10_000); r.scope = [...r.scope, p]; env.scope = [...env.scope, p]; }) },
    { id: "deeply-nested-evidence", hypothesis: "evidence nested 10,000 levels deep is admitted or crashes the verifier open", fix: "Reject evidence that does not parse as the closed KRATT evidence shape; verifier is fail-closed on throw.", build: (g) => one(g, (c) => { c.evidence.padding = nest(10_000); }) },
    { id: "wrong-type-task-id-number", hypothesis: "task_id as a number is admitted", fix: "Closed schema: task_id is a string matching TASK_ID.", build: (g) => one(g, (c) => { c.task_id = 5; }) },
    { id: "wrong-type-scope-string", hypothesis: "scope as a bare string is admitted", fix: "Closed schema: scope is an array.", build: (g) => one(g, (c) => { c.scope = "cerberus/core/decide.ts"; }) },
    { id: "wrong-type-scope-entry-number", hypothesis: "a numeric scope entry is admitted", fix: "Closed schema: scope entries are REL_PATH strings.", build: (g) => one(g, (c) => { c.scope = [...c.scope, 7]; }) },
    { id: "wrong-type-protocol-version-string", hypothesis: "protocol_version '1' (string) is admitted", fix: "Literal integer 1 only.", build: (g) => one(g, (c) => { c.protocol_version = "1"; }) },
    { id: "wrong-type-result-array", hypothesis: "result as an array is admitted", fix: "Closed schema: result is a plain object.", build: (g) => one(g, (c) => { c.result = [c.result]; }) },
    { id: "wrong-type-timestamp-number", hypothesis: "a numeric timestamp is admitted", fix: "Closed schema: ISO-8601 UTC string.", build: (g) => one(g, (c) => { c.timestamp = 1_700_000_000; }) },
    { id: "prototype-pollution-own-proto-key", hypothesis: "a receipt with an own __proto__ key is admitted", fix: "Closed key set rejects any extra own key, including __proto__.", build: (g) => one(g, (c) => { own(c, "__proto__", { admin: true }); }) },
    { id: "prototype-pollution-proto-key-in-evidence", hypothesis: "evidence with an own __proto__ key is admitted", fix: "Evidence parser requires the closed key set.", build: (g) => one(g, (c) => { own(c.evidence, "__proto__", { admin: true }); }) },
    { id: "prototype-pollution-constructor-key", hypothesis: "a receipt carrying constructor.prototype is admitted", fix: "Closed key set.", build: (g) => one(g, (c) => { own(c, "constructor", { prototype: { admin: true } }); }) },
    { id: "prototype-pollution-key-in-result", hypothesis: "result with an own __proto__ key is admitted", fix: "Closed key set on nested objects.", build: (g) => one(g, (c) => { own(c.result, "__proto__", { ok: true }); }) },
    ...CONFUSABLE_IDS.map(([n, id]): Case => ({
      id: `confusable-task-id-${n}-both`,
      hypothesis: `task_id '${JSON.stringify(id).slice(1, -1)}' (${n}) in receipt and envelope is admitted`,
      fix: "TASK_ID is an ASCII allow-list (^[a-z0-9][a-z0-9-]{0,63}$); never normalise or case-fold ids.",
      build: (g, e) => both(g, e, (r, env) => { r.task_id = env.task_id = id; }),
    })),
    { id: "confusable-task-id-cyrillic-receipt-only", hypothesis: "a receipt whose task_id swaps in a Cyrillic 'а' is accepted for the genuine envelope", fix: "Exact string equality between receipt.task_id and envelope.task_id.", build: (g) => one(g, (c) => { c.task_id = `${String(c.task_id).slice(0, -1)}\u0430`; }) },
    ...TRAVERSAL_SCOPES.map(([n, p]): Case => ({
      id: `scope-traversal-${n}-both`,
      hypothesis: `scope entry '${JSON.stringify(p).slice(1, -1)}' appended to receipt AND envelope scope is admitted`,
      fix: "REL_PATH allow-list for scope entries (same language as kratt relPathFailure).",
      build: (g, e) => both(g, e, (r, env) => { r.scope = [...r.scope, p]; env.scope = [...env.scope, p]; }),
    })),
    { id: "prototype-pollution-inherited-prototype", hypothesis: "a receipt whose own keys are valid but whose prototype is a custom object is admitted", fix: "Validators accept plain objects only (prototype === Object.prototype or null).", build: (g) => one(g, (c) => { Object.setPrototypeOf(c, { inherited: true }); }) },
    { id: "oversized-objective-envelope", hypothesis: "an envelope with a 100 kB objective is admitted", fix: "Enforce the string max length (500) from the closed schema.", build: (g, e) => both(g, e, (_r, env) => { env.objective = "A".repeat(100_000); }) },
    { id: "scope-case-alias-duplicate", hypothesis: "a case-variant alias of a scope file is admitted (aliases on case-insensitive filesystems)", fix: "Artifacts must equal scope exactly; scope uniqueness is exact-match.", build: (g) => one(g, (c) => { c.scope = [...c.scope, String(c.scope[0]).toUpperCase()]; }) },
  ],
  boundary: [
    {
      id: "timestamp-impossible-calendar-date",
      hypothesis: "timestamp 2026-13-45T99:99:99Z (matches the ISO regex, is not a date) is admitted",
      fix: "After the ISO_UTC regex, also require !Number.isNaN(Date.parse(v)) and a round-trip toISOString() check in the ActionReceipt timestamp spec.",
      openDefect: { component: "factory/protocol/types.ts (ActionReceipt.timestamp = ISO_UTC regex only)" },
      build: (g) => one(g, (c) => { c.timestamp = "2026-13-45T99:99:99Z"; }),
    },
    { id: "scope-0-entries", hypothesis: "an empty scope is admitted", fix: "scope minItems 1.", build: (g, e) => both(g, e, (r, env) => { r.scope = []; env.scope = []; }) },
    { id: "result-checks-fail-nonzero-ok-true", hypothesis: "ok=true with fail=1 is admitted", fix: "ok requires fail === 0 (action-succeeded check).", build: (g) => one(g, (c) => { c.result.checks.fail = 1; }) },
  ],
  "missing-evidence": [
    { id: "evidence-artifacts-key-deleted", hypothesis: "evidence with the artifacts key deleted (digest re-sealed) is admitted", fix: "Closed evidence shape: artifacts required.", build: (g) => one(g, (c) => { delete c.evidence.artifacts; reseal(c.evidence); }) },
    { id: "evidence-digest-key-deleted", hypothesis: "evidence without evidenceDigest is admitted", fix: "Closed evidence shape: evidenceDigest required.", build: (g) => one(g, (c) => { delete c.evidence.evidenceDigest; }) },
  ],
  "tampered-evidence": [
    {
      id: "evidence-substitution-swap-artifact-hashes",
      hypothesis: "evidence whose two artifacts exchanged their sha256 values (digest re-sealed) is admitted: hash swapped between files",
      fix: "Recompute each artifact digest from git at base_sha (done by TÖEPÄRA); never trust the producer's pairing of name and digest.",
      build: (g) => (hasTwoArtifacts(g) ? one(g, (c) => { const a = c.evidence.artifacts; [a[0].sha256, a[1].sha256] = [a[1].sha256, a[0].sha256]; reseal(c.evidence); }) : null),
    },
    {
      id: "evidence-substitution-swap-artifact-names",
      hypothesis: "evidence whose two artifacts exchanged their names (digest re-sealed) is admitted",
      fix: "Compare each artifact name+digest+bytes with git at base_sha.",
      build: (g) => (hasTwoArtifacts(g) ? one(g, (c) => { const a = c.evidence.artifacts; [a[0].name, a[1].name] = [a[1].name, a[0].name]; reseal(c.evidence); }) : null),
    },
    {
      id: "evidence-substitution-swap-artifact-bytes",
      hypothesis: "evidence whose artifacts exchanged their byte sizes (digest re-sealed) is admitted",
      fix: "Compare bytes with git at base_sha.",
      build: (g) => (hasTwoArtifacts(g) ? one(g, (c) => { const a = c.evidence.artifacts; if (a[0].bytes === a[1].bytes) a[0].bytes += 1; else [a[0].bytes, a[1].bytes] = [a[1].bytes, a[0].bytes]; reseal(c.evidence); }) : null),
    },
    {
      id: "evidence-substitution-from-other-task",
      hypothesis: "evidence that names a different task id (digest re-sealed) is admitted for this task",
      fix: "evidence.taskId must equal receipt.task_id and the re-derived task digest.",
      build: (g) => one(g, (c) => { c.evidence.taskId = "some-other-task"; reseal(c.evidence); }),
    },
    {
      id: "evidence-substitution-from-other-action",
      hypothesis: "evidence of a different action (digest re-sealed) is admitted for this action",
      fix: "evidence.action must equal receipt.action and the mapped KRATT task action.",
      build: (g) => one(g, (c) => { c.evidence.action = c.evidence.action === "run-test" ? "hash-files" : "run-test"; reseal(c.evidence); }),
    },
    {
      id: "evidence-substitution-foreign-real-artifact",
      hypothesis: "evidence whose first artifact is a different file with its REAL digest (not in scope; digest re-sealed) is admitted",
      fix: "Artifacts must equal the envelope scope exactly.",
      build: (g) => {
        const d = blobDigest(parentRoot, g.base_sha, "package.json");
        if (d === null) return null;
        return one(g, (c) => { c.evidence.artifacts[0] = { name: "package.json", sha256: d.sha256, bytes: d.bytes }; c.evidence.artifacts.sort((x: Any, y: Any) => (x.name < y.name ? -1 : x.name > y.name ? 1 : 0)); reseal(c.evidence); });
      },
    },
    {
      id: "evidence-artifact-dropped-resealed",
      hypothesis: "evidence listing only a subset of the scope (one artifact dropped, digest re-sealed) is admitted",
      fix: "Artifacts must equal the scope set: compare size AND membership (artifacts-equal-scope).",
      build: (g) => (hasTwoArtifacts(g) ? one(g, (c) => { c.evidence.artifacts.pop(); reseal(c.evidence); }) : null),
    },
    {
      id: "self-consistent-failed-action-claims-success",
      hypothesis: "a receipt and evidence that consistently report one FAILED check (verdict REJECTED, digest re-sealed) while result.ok = true is admitted",
      fix: "Success claim requires ok && checks.fail === 0 && checks.pass >= 1 (action-succeeded), independent of producer consistency.",
      build: (g) => one(g, (c) => { forgeChecks(c, c.result.checks.pass, 1); }),
    },
    {
      id: "self-consistent-zero-checks-claims-success",
      hypothesis: "a receipt and evidence that consistently report ZERO passed checks (verdict REJECTED, digest re-sealed) while result.ok = true is admitted",
      fix: "Success claim requires checks.pass >= 1 (action-succeeded).",
      build: (g) => one(g, (c) => { forgeChecks(c, 0, 0); }),
    },
    {
      id: "evidence-substitution-duplicate-artifact",
      hypothesis: "evidence listing the first artifact twice instead of the second (digest re-sealed) is admitted",
      fix: "Artifacts must equal the scope set (size and membership).",
      build: (g) => (hasTwoArtifacts(g) ? one(g, (c) => { c.evidence.artifacts[1] = clone(c.evidence.artifacts[0]); reseal(c.evidence); }) : null),
    },
  ],
  "unauthorized-action": [
    {
      id: "forged-role-toepara-commander-produces-kratt-receipt",
      hypothesis: "a KRATT action receipt/envelope issued to CITADEL-101 (the TÖEPÄRA commander) is admitted: the verifier certifies work that its own role produced",
      fix: "In localPolicyTrustGate (and TÖEPÄRA identity checks) require agent_id to hold the capability `kratt:<action>` per CAPABILITIES (FORGE-026 only) and reject CITADEL-1xx as producer of a KRATT receipt.",
      openDefect: { component: "factory/cerberus-gate.ts localPolicyTrustGate + factory/toepara.ts identity checks (no producer-capability / separation-of-duty check)" },
      build: (g, e) => both(g, e, (r, env) => { r.agent_id = env.agent_id = "CITADEL-101"; env.factory = "CITADEL"; }),
    },
    {
      id: "forged-role-cerberus-commander-produces-kratt-receipt",
      hypothesis: "a KRATT action receipt/envelope issued to CITADEL-111 (the CERBERUS commander) is admitted by CERBERUS itself",
      fix: "Same as forged-role-toepara-commander: producer must hold `kratt:<action>`; the deciding role may not be the producing role.",
      openDefect: { component: "factory/cerberus-gate.ts localPolicyTrustGate (no producer-capability / separation-of-duty check)" },
      build: (g, e) => both(g, e, (r, env) => { r.agent_id = env.agent_id = "CITADEL-111"; env.factory = "CITADEL"; }),
    },
    {
      id: "forged-role-rastik-commander-produces-kratt-receipt",
      hypothesis: "a KRATT action receipt/envelope issued to SERPENT-051 (the RÄSTIK commander, the attacker) is admitted",
      fix: "Producer must hold `kratt:<action>`; an attacker role may not produce the evidence it attacks.",
      openDefect: { component: "factory/cerberus-gate.ts localPolicyTrustGate (no producer-capability check)" },
      build: (g, e) => both(g, e, (r, env) => { r.agent_id = env.agent_id = "SERPENT-051"; env.factory = "SERPENT"; }),
    },
    { id: "envelope-factory-prefix-mismatch", hypothesis: "an envelope whose factory (SERPENT) does not match its agent_id prefix (FORGE) is admitted", fix: "validateEnvelope: agent_id must start with `${factory}-`.", build: (g, e) => both(g, e, (_r, env) => { env.factory = "SERPENT"; }) },
    { id: "forbidden-actions-emptied", hypothesis: "an envelope that no longer forbids merge/deploy is admitted", fix: "Local policy trust gate requires merge and deploy to be forbidden.", build: (g, e) => both(g, e, (_r, env) => { env.forbidden_actions = []; }) },
    { id: "allowed-actions-widened-to-merge", hypothesis: "an envelope that additionally allows merge is admitted", fix: "Local policy trust gate: allowed actions must be KRATT actions only.", build: (g, e) => both(g, e, (_r, env) => { env.allowed_actions = [...env.allowed_actions, "merge"]; }) },
    {
      id: "kratt-self-certifies-forged-evidence",
      hypothesis: "KRATT certifying KRATT: a receipt claiming VERIFIED whose evidence was forged and re-sealed is admitted",
      fix: "Ignore verification_state from the producer; only TÖEPÄRA's recomputation may verify; KRATT receipts must be UNVERIFIED.",
      build: (g) => one(g, (c) => { c.verification_state = "VERIFIED"; c.evidence.artifacts[0].sha256 = flip(c.evidence.artifacts[0].sha256); reseal(c.evidence); }),
    },
    { id: "kratt-self-certifies-rejected-state", hypothesis: "a receipt with verification_state REJECTED/INSUFFICIENT_EVIDENCE set by the producer is admitted", fix: "Producer-set states other than UNVERIFIED are rejected.", build: (g) => one(g, (c) => { c.verification_state = "INSUFFICIENT_EVIDENCE"; }) },
  ],
  "stale-base-sha": [],
  "malformed-receipt": [
    { id: "result-exit-code-contradicts-evidence", hypothesis: "result.exit_code = 1 with ok = true, contradicting the evidence (exit code 0), is admitted", fix: "result.exit_code must equal evidence.exitCode (result-matches-evidence).", build: (g) => one(g, (c) => { c.result.exit_code = 1; }) },
    { id: "extra-key-in-result", hypothesis: "result with an extra key is admitted", fix: "Closed key set on nested objects.", build: (g) => one(g, (c) => { c.result.verified = true; }) },
    { id: "extra-key-in-result-checks", hypothesis: "result.checks with an extra key is admitted", fix: "Closed key set on nested objects.", build: (g) => one(g, (c) => { c.result.checks.skipped = 0; }) },
    { id: "accessor-property-receipt", hypothesis: "a receipt whose task_id is a getter (TOCTOU: value changes between reads) is admitted", fix: "Validators reject accessor properties (own data properties only).", build: (g) => one(g, (c) => { const v = c.task_id; let n = 0; Object.defineProperty(c, "task_id", { enumerable: true, configurable: true, get: () => (n++ === 0 ? v : "other") }); }) },
  ],
  replay: [
    { id: "same-receipt-twice-reordered-keys", hypothesis: "the identical receipt with its keys in reverse order is admitted a second time", fix: "Replay guard keys on the canonical (key-sorted) digest.", build: (g) => ({ seq: [clone(g), reverseKeysDeep(clone(g))] }) },
    {
      id: "replay-retimestamped",
      hypothesis: "the identical receipt with only its timestamp changed is admitted a second time (replay guard keyed on a digest that covers the timestamp)",
      fix: "Key the replay guard on the stable identity of the work, e.g. digestOf({task_id, action, base_sha, kratt_evidence_digest}), not on bundle_digest (which covers receipt.timestamp); or reject non-monotonic/duplicate task_id.",
      openDefect: { component: "factory/cerberus-gate.ts replay guard (ctx.guard.consume(freshBundle.bundle_digest)); bundle_digest covers receipt.timestamp" },
      build: (g) => ({ seq: [clone(g), retimestamp(g, "2030-01-01T00:00:00.000Z")] }),
    },
    {
      id: "replay-reordered-retimestamped",
      hypothesis: "a re-timestamped copy, then the original, then another re-timestamped copy are all admitted (reordered replay; last one decides)",
      fix: "Same as replay-retimestamped: replay guard must be independent of receipt.timestamp.",
      openDefect: { component: "factory/cerberus-gate.ts replay guard (ctx.guard.consume(freshBundle.bundle_digest)); bundle_digest covers receipt.timestamp" },
      build: (g) => ({ seq: [retimestamp(g, "2029-01-01T00:00:00Z"), clone(g), retimestamp(g, "2031-01-01T00:00:00Z")] }),
    },
    { id: "replay-against-other-task-envelope", hypothesis: "a valid receipt replayed against the envelope of a different task is admitted", fix: "receipt.task_id must equal envelope.task_id.", build: (g, e) => ({ seq: [clone(g)], envelope: { ...clone(e), task_id: `${e.task_id}-b`.slice(0, 64) } }) },
    { id: "replay-against-other-scope-envelope", hypothesis: "a valid receipt replayed against an envelope with a different scope is admitted", fix: "Canonical scope equality between receipt and envelope.", build: (g, e) => ({ seq: [clone(g)], envelope: { ...clone(e), scope: [...e.scope, "package.json"] } }) },
  ],
};
for (const cls of Object.keys(V2) as AttackClass[]) CASES[cls].push(...V2[cls]);

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
    `  const { env, receipt } = await genuine(); // factory/tests/helpers.ts`,
    `  const real = realAttackTarget({ root: ROOT, repository: REPO, rerun: new Map() });`,
    `  const r = await runAttackClass(${JSON.stringify(cls)}, receipt, env, { target: real, only: ${JSON.stringify(c.id)}, includeOpenDefects: true });`,
    `  assert.equal(r.control_admitted, true);`,
    `  assert.deepEqual(r.findings.map((f) => f.finding_id), []); // smallest fix: ${c.fix.replace(/\s+/g, " ")}`,
    `});`,
  ].join("\n");
}

export interface AttackDeps {
  target: AttackTarget;
  /** Also run cases flagged `openDefect` (default false). */
  includeOpenDefects?: boolean;
  /** Run only the case with this id (used by generated regression tests). */
  only?: string;
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
  for (const c of selectCases(cls, deps)) {
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
      target: `${c.openDefect ? `${c.openDefect.component}; reached via ` : ""}factory receipt verification (toeparaVerify + cerberusDecide), task ${envelope.task_id}`.slice(0, 300),
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

/**
 * For every selected case: does its mutation actually change the candidate (receipt sequence or
 * envelope)? A no-op mutation would be "admitted" for the wrong reason and produce a false
 * finding; tests assert `changed` for every case on several fixtures.
 */
export function describeCases(good: ActionReceipt, envelope: TaskEnvelope, o: { includeOpenDefects?: boolean } = {}): { attack_id: string; applicable: boolean; changed: boolean }[] {
  const out: { attack_id: string; applicable: boolean; changed: boolean }[] = [];
  for (const cls of ATTACK_CLASSES_LIST)
    for (const c of selectCases(cls, o)) {
      const built = c.build(clone(good), clone(envelope));
      if (built === null) {
        out.push({ attack_id: `${cls}/${c.id}`, applicable: false, changed: false });
        continue;
      }
      const g = canonicalize(good);
      const sameEnv = canonicalize(built.envelope ?? envelope) === canonicalize(envelope);
      const last = built.seq[built.seq.length - 1];
      let lastSame = false;
      try {
        const hasAccessor = typeof last === "object" && last !== null && Object.values(Object.getOwnPropertyDescriptors(last)).some((d) => !("value" in d));
        const proto = typeof last === "object" && last !== null ? Object.getPrototypeOf(last) : Object.prototype;
        const exotic = proto !== Object.prototype && proto !== null;
        lastSame = !hasAccessor && !exotic && canonicalize(last) === g;
      } catch {
        lastSame = false;
      }
      // a sequence like [good, good] is a deliberate replay, not a no-op: only single-candidate cases must differ
      out.push({ attack_id: `${cls}/${c.id}`, applicable: true, changed: built.seq.length > 1 || !sameEnv || !lastSame });
    }
  return out;
}

export function caseCount(cls: AttackClass, opts: { includeOpenDefects?: boolean } = {}): number {
  return selectCases(cls, opts).length;
}

/** Ids of the cases currently flagged as known-open defects (see Case.openDefect). */
export function openDefectCases(): { attack_id: string; component: string }[] {
  return ATTACK_CLASSES_LIST.flatMap((cls) => CASES[cls].filter((c) => c.openDefect).map((c) => ({ attack_id: `${cls}/${c.id}`, component: c.openDefect?.component ?? "" })));
}

function selectCases(cls: AttackClass, o: { includeOpenDefects?: boolean; only?: string }): Case[] {
  return CASES[cls].filter((c) => (o.includeOpenDefects === true || !c.openDefect) && (o.only === undefined || c.id === o.only));
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

// ---------------------------------------------------------------------------------------------
// Final-receipt (CERBERUS output) attacks: trust bypass on the STORED closed-loop receipt.
// The hypothesis is "the stored, tampered final receipt passes the independent self-check".
// `check` is injected (selfCheckFinalReceipt from factory/loop.ts) so this file does not import
// the loop (which imports this file).
// ---------------------------------------------------------------------------------------------
export type FinalReceiptCheck = (receipt: never) => string[];

interface FinalCase {
  id: string;
  hypothesis: string;
  fix: string;
  openDefect?: { component: string };
  /** Mutate a clone of the genuine ADMIT final receipt (final_digest is re-sealed afterwards unless `noReseal`). */
  mutate: (r: Any) => void;
  noReseal?: boolean;
}

const LOOP_SELF_CHECK = "factory/loop.ts selfCheckFinalReceipt (checks final_digest + 4 flags only; inner digests and cross-links are not recomputed)";
const FINAL_FIX =
  "In selfCheckFinalReceipt also: validateCerberusDecision + recompute decision_digest = digestOf(decision minus decision_digest); decision.toepara_evidence_digest === toepara.verdict.evidence_digest; validateEvidenceBundle + recompute bundle_digest; bundle.action_receipt_digest === digestOf(action_receipt); rastikEvidenceDigest recompute.";

const FINAL_CASES: FinalCase[] = [
  { id: "cerberus-decision-deleted", hypothesis: "a final receipt with the CERBERUS decision deleted (final_digest re-sealed) passes the self-check", fix: "Missing CERBERUS decision must be a reported violation (cerberus-decision-missing), never an uncaught exception or a pass.", mutate: (r) => { delete r.cerberus; } },
  { id: "cerberus-decision-null", hypothesis: "a final receipt with cerberus.decision = null (final_digest re-sealed) passes the self-check", fix: "Same as cerberus-decision-deleted.", mutate: (r) => { r.cerberus.decision = null; } },
  { id: "cerberus-receipt-deleted", hypothesis: "a final receipt without the CERBERUS recovery receipt passes the self-check", fix: "Same as cerberus-decision-deleted.", mutate: (r) => { delete r.cerberus.cerberus_receipt; } },
  { id: "final-decision-flipped", hypothesis: "final_decision flipped away from the CERBERUS decision (re-sealed) passes the self-check", fix: "final_decision must equal cerberus.decision.decision.", mutate: (r) => { r.final_decision = "DENY"; } },
  { id: "final-digest-not-resealed", hypothesis: "a body change without recomputing final_digest passes the self-check", fix: "Recompute final_digest.", noReseal: true, mutate: (r) => { r.task_id = "tampered-task"; } },
  { id: "admit-with-toepara-removed", hypothesis: "an ADMIT with the TÖEPÄRA result removed (re-sealed) passes the self-check", fix: "ADMIT requires toepara.verdict VERIFIED.", mutate: (r) => { r.toepara = null; } },
  { id: "kratt-receipt-claims-verified", hypothesis: "an ADMIT whose KRATT action receipt claims verification_state VERIFIED (KRATT certifying KRATT; re-sealed) passes the self-check", fix: "ADMIT requires the producer receipt to be UNVERIFIED (admit-without-independent-verification).", mutate: (r) => { r.action_receipt.verification_state = "VERIFIED"; } },
  { id: "caller-claims-real-goliath", hypothesis: "a receipt claiming a real GOLIATH caller passes the self-check", fix: "caller.real_goliath must be false.", mutate: (r) => { r.caller.real_goliath = true; } },
  {
    id: "decision-body-tampered-decision-digest-stale",
    hypothesis: "a CERBERUS decision whose reasons were edited (decision_digest left stale, final_digest re-sealed) passes the self-check",
    fix: FINAL_FIX,
    openDefect: { component: LOOP_SELF_CHECK },
    mutate: (r) => { r.cerberus.decision.reasons = [...r.cerberus.decision.reasons, "attacker-edited"]; },
  },
  {
    id: "decision-bound-to-other-toepara-evidence",
    hypothesis: "a CERBERUS decision pointing at a different TÖEPÄRA evidence digest (evidence substitution between tasks; re-sealed) passes the self-check",
    fix: FINAL_FIX,
    openDefect: { component: LOOP_SELF_CHECK },
    mutate: (r) => { r.cerberus.decision.toepara_evidence_digest = flip(r.cerberus.decision.toepara_evidence_digest); },
  },
  {
    id: "toepara-bundle-body-tampered",
    hypothesis: "a TÖEPÄRA bundle whose source digest was swapped (bundle_digest left stale, re-sealed) passes the self-check",
    fix: FINAL_FIX,
    openDefect: { component: LOOP_SELF_CHECK },
    mutate: (r) => { r.toepara.bundle.source_digests[0].sha256 = flip(r.toepara.bundle.source_digests[0].sha256); },
  },
  {
    id: "action-receipt-swapped-after-verification",
    hypothesis: "an action receipt edited after TÖEPÄRA verified it (bundle.action_receipt_digest no longer matches; re-sealed) passes the self-check",
    fix: FINAL_FIX,
    openDefect: { component: LOOP_SELF_CHECK },
    mutate: (r) => { r.action_receipt.agent_id = "CITADEL-111"; },
  },
  {
    id: "rastik-report-tampered-evidence-digest-stale",
    hypothesis: "a RÄSTIK report whose findings/cases were edited (evidence_digest stale; re-sealed) passes the self-check",
    fix: FINAL_FIX,
    openDefect: { component: LOOP_SELF_CHECK },
    mutate: (r) => { r.rastik.cases_executed += 1; },
  },
];

const sealFinal = (r: Any): void => {
  const { final_digest: _f, ...body } = r;
  void _f;
  r.final_digest = digestOf(body);
};

export interface FinalAttackRecord {
  attack_id: string;
  case_id: string;
  hypothesis: string;
  outcome: "REPELLED" | "SUCCEEDED";
  /** How the check responded: violations it listed, "threw:<ErrorName>" (fail-closed but uncaught), or "accepted". */
  detail: string;
  reproduced: boolean | null;
}

export function finalReceiptCaseCount(o: { includeOpenDefects?: boolean } = {}): number {
  return FINAL_CASES.filter((c) => o.includeOpenDefects === true || !c.openDefect).length;
}

export function runFinalReceiptAttacks(
  genuineFinal: unknown,
  check: FinalReceiptCheck,
  o: { includeOpenDefects?: boolean; only?: string } = {},
): { control_clean: boolean; records: FinalAttackRecord[]; findings: RastikFinding[] } {
  const verdict = (r: unknown): { accepted: boolean; detail: string } => {
    try {
      const v = check(r as never);
      return v.length === 0 ? { accepted: true, detail: "accepted" } : { accepted: false, detail: `violations:${v.join(",")}` };
    } catch (e) {
      return { accepted: false, detail: `threw:${e instanceof Error ? e.name : "unknown"}` }; // fail-closed
    }
  };
  const control_clean = verdict(clone(genuineFinal)).accepted;
  const records: FinalAttackRecord[] = [];
  const findings: RastikFinding[] = [];
  if (!control_clean) return { control_clean, records, findings };
  const digest = digestOf(genuineFinal);
  for (const c of FINAL_CASES) {
    if ((c.openDefect && o.includeOpenDefects !== true) || (o.only !== undefined && c.id !== o.only)) continue;
    const attempt = () => {
      const t = clone(genuineFinal) as Any;
      c.mutate(t);
      if (!c.noReseal) sealFinal(t);
      return verdict(t);
    };
    const first = attempt();
    const attack_id = `final-receipt/${c.id}`;
    if (!first.accepted) {
      records.push({ attack_id, case_id: c.id, hypothesis: c.hypothesis, outcome: "REPELLED", detail: first.detail, reproduced: null });
      continue;
    }
    const again = attempt().accepted;
    records.push({ attack_id, case_id: c.id, hypothesis: c.hypothesis, outcome: "SUCCEEDED", detail: first.detail, reproduced: again });
    findings.push({
      finding_id: `RASTIK-FINAL-${c.id}`,
      target: `${c.openDefect?.component ?? "factory/loop.ts selfCheckFinalReceipt"}`.slice(0, 300),
      hypothesis: c.hypothesis,
      reproduction: `Take a genuine ADMIT final receipt (digest ${digest}), apply mutation "${c.id}" (factory/rastik-attacks.ts FINAL_CASES), re-seal final_digest (no secret is needed); selfCheckFinalReceipt returned no violations${again ? " on two independent runs" : " once, but not on the re-run"}.`,
      severity: "high",
      status: again ? "CONFIRMED" : "UNCONFIRMED",
      evidence: { attack_id, final_receipt_digest: digest, admitted_on_rerun: again },
      regression_test: [
        `test(${JSON.stringify(`RASTIK final-receipt/${c.id}: self-check must flag it`)}, async () => {`,
        `  // hypothesis: ${c.hypothesis}`,
        `  const { stand } = setup({ runProbes: false }); // factory/tests/helpers.ts`,
        `  const final = await stand.submit(stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "regr-final" }));`,
        `  const r = runFinalReceiptAttacks(final, selfCheckFinalReceipt, { only: ${JSON.stringify(c.id)}, includeOpenDefects: true });`,
        `  assert.equal(r.control_clean, true);`,
        `  assert.deepEqual(r.findings.map((f) => f.finding_id), []); // smallest fix: ${c.fix.replace(/\s+/g, " ")}`,
        `});`,
      ].join("\n").slice(0, 4000),
      proposed_smallest_fix: c.fix.slice(0, 1000),
    });
  }
  return { control_clean, records, findings };
}

// ---------------------------------------------------------------------------------------------
// Runtime drift attacks: local Node != declared engines / .nvmrc != CI node.
// The declarations that must name ONE Node major (.nvmrc is the source of truth) are read once
// (bounded, read-only), then mutated; the hypothesis for each case is "the drifted declarations
// pass the drift check". The check is injectable so a weak checker can be shown to be attacked.
// ---------------------------------------------------------------------------------------------
export interface RuntimeDeclarations {
  /** Raw .nvmrc content, or null when absent. */
  nvmrc: string | null;
  /** package.json engines.node, or null when absent. */
  engines_node: string | null;
  /** devcontainer node feature version, or null when absent. */
  devcontainer_node: string | null;
  /** EVERY `node-version:` value found in .github/workflows/*.yml (an empty list means CI pins nothing). */
  ci_node_versions: string[];
  /** process.versions.node of the interpreter that is running the factory (e.g. "22.23.3"). */
  actual: string;
}

const NODE_VERSION = /^v?(\d{1,3})(\.\d{1,3}){0,2}$/;
const ENGINES = /^(\d{1,3})\.x$/;
const majorOf = (v: string | null, re: RegExp): number | null => {
  const m = v === null ? null : re.exec(v.trim());
  return m ? Number(m[1]) : null;
};

/** Reasons the declarations are inconsistent; [] means "one Node major everywhere, and it is the one running". */
export function runtimeDriftViolations(d: RuntimeDeclarations): string[] {
  const why: string[] = [];
  const pin = majorOf(d.nvmrc, NODE_VERSION);
  if (pin === null) why.push("nvmrc-not-a-numeric-version");
  const eng = majorOf(d.engines_node, ENGINES);
  if (eng === null) why.push("engines-not-exact-major-x");
  else if (pin !== null && eng !== pin) why.push("engines-major-differs-from-nvmrc");
  const dc = majorOf(d.devcontainer_node, NODE_VERSION);
  if (dc === null) why.push("devcontainer-node-not-numeric");
  else if (pin !== null && dc !== pin) why.push("devcontainer-major-differs-from-nvmrc");
  if (d.ci_node_versions.length === 0) why.push("ci-pins-no-node");
  for (const v of d.ci_node_versions) {
    const m = majorOf(v, NODE_VERSION);
    if (m === null) why.push(`ci-node-not-numeric:${v.slice(0, 20)}`);
    else if (pin !== null && m !== pin) why.push(`ci-major-differs-from-nvmrc:${v.slice(0, 20)}`);
  }
  const act = majorOf(d.actual, NODE_VERSION);
  if (act === null) why.push("actual-node-unreadable");
  else if (pin !== null && act !== pin) why.push("actual-major-differs-from-nvmrc");
  return why;
}

/** Bounded read of the real declarations under `root` (no network, no writes). */
export function readRuntimeDeclarations(root: string): RuntimeDeclarations {
  const rd = (p: string): string | null => {
    try {
      const st = statSync(join(root, p));
      return st.isFile() && st.size <= 262_144 ? readFileSync(join(root, p), "utf8") : null;
    } catch {
      return null;
    }
  };
  const pkg = (() => {
    try {
      return JSON.parse(rd("package.json") ?? "null") as { engines?: { node?: unknown } } | null;
    } catch {
      return null;
    }
  })();
  const dcFeature = (() => {
    try {
      const dc = JSON.parse(rd(".devcontainer/devcontainer.json") ?? "null") as { features?: Record<string, { version?: unknown }> } | null;
      const f = Object.entries(dc?.features ?? {}).find(([k]) => k.includes("/features/node"));
      return f ? String(f[1]?.version ?? "") : null;
    } catch {
      return null;
    }
  })();
  const ci: string[] = [];
  try {
    for (const f of readdirSync(join(root, ".github/workflows")).sort().slice(0, 50)) {
      if (!/\.ya?ml$/.test(f)) continue;
      for (const m of (rd(`.github/workflows/${f}`) ?? "").matchAll(/^\s*node-version:\s*["']?([^"'\s#]*)["']?/gm)) if (ci.length < 100) ci.push(m[1] ?? "");
    }
  } catch {
    /* no workflows directory: ci stays empty, which the check reports */
  }
  const nv = rd(".nvmrc");
  return {
    nvmrc: nv === null ? null : nv.replace(/\n$/, ""),
    engines_node: typeof pkg?.engines?.node === "string" ? pkg.engines.node : null,
    devcontainer_node: dcFeature,
    ci_node_versions: ci,
    actual: process.versions.node,
  };
}

interface RuntimeCase {
  id: string;
  hypothesis: string;
  fix: string;
  mutate: (d: RuntimeDeclarations) => void;
}
const RUNTIME_FIX = "Make runtimeDriftViolations (and scripts/node-pin.test.mjs) parse every declaration strictly and compare ALL of them, including every CI setup-node entry and the running interpreter, with the .nvmrc major.";
const RUNTIME_CASES: RuntimeCase[] = [
  { id: "nvmrc-other-major", hypothesis: ".nvmrc = 20 while everything else says 22 passes", fix: RUNTIME_FIX, mutate: (d) => { d.nvmrc = "20"; } },
  { id: "nvmrc-lts-alias", hypothesis: ".nvmrc = lts/* (floating) passes", fix: RUNTIME_FIX, mutate: (d) => { d.nvmrc = "lts/*"; } },
  { id: "nvmrc-empty", hypothesis: "an empty .nvmrc passes", fix: RUNTIME_FIX, mutate: (d) => { d.nvmrc = ""; } },
  { id: "nvmrc-missing", hypothesis: "a missing .nvmrc passes", fix: RUNTIME_FIX, mutate: (d) => { d.nvmrc = null; } },
  { id: "nvmrc-two-lines", hypothesis: ".nvmrc with a second line (22 then 20) passes", fix: RUNTIME_FIX, mutate: (d) => { d.nvmrc = "22\n20"; } },
  { id: "nvmrc-trailing-text", hypothesis: ".nvmrc = '22 # latest' passes", fix: RUNTIME_FIX, mutate: (d) => { d.nvmrc = "22 # latest"; } },
  { id: "engines-open-range", hypothesis: "engines.node = '>=18' (admits Node 18/20/24) passes", fix: RUNTIME_FIX, mutate: (d) => { d.engines_node = ">=18"; } },
  { id: "engines-caret-union", hypothesis: "engines.node = '^20 || ^22' passes", fix: RUNTIME_FIX, mutate: (d) => { d.engines_node = "^20 || ^22"; } },
  { id: "engines-other-major", hypothesis: "engines.node = '20.x' while .nvmrc = 22 passes", fix: RUNTIME_FIX, mutate: (d) => { d.engines_node = "20.x"; } },
  { id: "engines-missing", hypothesis: "a package.json without engines.node passes", fix: RUNTIME_FIX, mutate: (d) => { d.engines_node = null; } },
  { id: "devcontainer-other-major", hypothesis: "devcontainer node feature 20 passes", fix: RUNTIME_FIX, mutate: (d) => { d.devcontainer_node = "20"; } },
  { id: "devcontainer-lts", hypothesis: "devcontainer node feature 'lts' passes", fix: RUNTIME_FIX, mutate: (d) => { d.devcontainer_node = "lts"; } },
  { id: "ci-other-major", hypothesis: "CI setup-node 20 passes", fix: RUNTIME_FIX, mutate: (d) => { d.ci_node_versions = ["20"]; } },
  { id: "ci-floating-lts", hypothesis: "CI setup-node 'lts/*' passes", fix: RUNTIME_FIX, mutate: (d) => { d.ci_node_versions = ["lts/*"]; } },
  { id: "ci-floating-latest", hypothesis: "CI setup-node 'latest' passes", fix: RUNTIME_FIX, mutate: (d) => { d.ci_node_versions = ["latest"]; } },
  { id: "ci-floating-node-alias", hypothesis: "CI setup-node 'node' (current) passes", fix: RUNTIME_FIX, mutate: (d) => { d.ci_node_versions = ["node"]; } },
  { id: "ci-second-setup-node-drifts", hypothesis: "a second workflow job on Node 20 (the first still says 22) passes", fix: RUNTIME_FIX, mutate: (d) => { d.ci_node_versions = [...d.ci_node_versions, "20"]; } },
  { id: "ci-pins-nothing", hypothesis: "CI that pins no Node version passes", fix: RUNTIME_FIX, mutate: (d) => { d.ci_node_versions = []; } },
  { id: "actual-older-major", hypothesis: "running the factory on Node 20.11.0 passes", fix: RUNTIME_FIX, mutate: (d) => { d.actual = "20.11.0"; } },
  { id: "actual-newer-major", hypothesis: "running the factory on Node 24.0.0 passes", fix: RUNTIME_FIX, mutate: (d) => { d.actual = "24.0.0"; } },
  { id: "actual-unreadable", hypothesis: "an unreadable running version passes", fix: RUNTIME_FIX, mutate: (d) => { d.actual = ""; } },
];

export interface RuntimeAttackRecord {
  attack_id: string;
  case_id: string;
  hypothesis: string;
  outcome: "REPELLED" | "SUCCEEDED";
  reproduced: boolean | null;
  detail: string;
}

export function runtimeCaseCount(): number {
  return RUNTIME_CASES.length;
}

export function runRuntimeDriftAttacks(
  genuineDecl: RuntimeDeclarations,
  check: (d: RuntimeDeclarations) => string[] = runtimeDriftViolations,
  o: { only?: string } = {},
): { control_clean: boolean; control_violations: string[]; records: RuntimeAttackRecord[]; findings: RastikFinding[] } {
  const safe = (d: RuntimeDeclarations): string[] | null => {
    try {
      return check(d);
    } catch {
      return ["check-threw"]; // fail-closed
    }
  };
  const control_violations = safe(clone(genuineDecl)) ?? [];
  const control_clean = control_violations.length === 0;
  const records: RuntimeAttackRecord[] = [];
  const findings: RastikFinding[] = [];
  if (!control_clean) return { control_clean, control_violations, records, findings };
  const digest = digestOf(genuineDecl);
  for (const c of RUNTIME_CASES) {
    if (o.only !== undefined && c.id !== o.only) continue;
    const attempt = (): string[] => {
      const d = clone(genuineDecl);
      c.mutate(d);
      return safe(d) ?? [];
    };
    const first = attempt();
    const attack_id = `runtime-drift/${c.id}`;
    if (first.length > 0) {
      records.push({ attack_id, case_id: c.id, hypothesis: c.hypothesis, outcome: "REPELLED", reproduced: null, detail: first.join(",") });
      continue;
    }
    const again = attempt().length === 0;
    records.push({ attack_id, case_id: c.id, hypothesis: c.hypothesis, outcome: "SUCCEEDED", reproduced: again, detail: "accepted" });
    findings.push({
      finding_id: `RASTIK-RUNTIME-${c.id}`,
      target: "runtime drift check over .nvmrc, package.json engines, .devcontainer, .github/workflows node-version, running interpreter".slice(0, 300),
      hypothesis: c.hypothesis,
      reproduction: `Take the declarations (digest ${digest}), apply mutation "${c.id}" (factory/rastik-attacks.ts RUNTIME_CASES); the drift check returned no violation${again ? " on two independent runs" : " once, but not on the re-run"}.`,
      severity: "medium",
      status: again ? "CONFIRMED" : "UNCONFIRMED",
      evidence: { attack_id, declarations_digest: digest, admitted_on_rerun: again },
      regression_test: [
        `test(${JSON.stringify(`RASTIK runtime-drift/${c.id}: drift must be reported`)}, () => {`,
        `  // hypothesis: ${c.hypothesis}`,
        `  const r = runRuntimeDriftAttacks(readRuntimeDeclarations(ROOT), runtimeDriftViolations, { only: ${JSON.stringify(c.id)} });`,
        `  assert.equal(r.control_clean, true);`,
        `  assert.deepEqual(r.findings.map((f) => f.finding_id), []);`,
        `});`,
      ].join("\n"),
      proposed_smallest_fix: c.fix.slice(0, 1000),
    });
  }
  return { control_clean, control_violations, records, findings };
}
