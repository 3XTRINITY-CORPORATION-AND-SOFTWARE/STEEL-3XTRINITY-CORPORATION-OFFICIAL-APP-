import { canonicalize } from "../cerberus/core/decide.ts";
import { executeTask } from "../kratt/actions.ts";
import { parseEvidence, type ToeparaEvidence } from "../kratt/evidence.ts";
import { taskDigest } from "../kratt/task.ts";
import { blobDigest, blobState, commitExists, diffDigest, headSha, isShallow } from "./git.ts";
import { envelopeToKrattTask } from "./kratt-stage.ts";
import {
  PROTOCOL_VERSION,
  digestOf,
  validateActionReceipt,
  validateEnvelope,
  validateEvidenceBundle,
  validateRastikFinding,
  type ActionReceipt,
  type EvidenceBundle,
  type TaskEnvelope,
  type ToeparaVerdict,
} from "./protocol/types.ts";
import { rastikEvidenceDigest, type RastikRun } from "./rastik-types.ts";
import { producerMayRunAction } from "./trust-gate.ts";

/**
 * TÖEPÄRA stage: independent evidence verification (the brief's "KRATT output alone can
 * never yield VERIFIED").
 *
 * What is recomputed from source rather than read from the receipt:
 *  - file digests/sizes: `git cat-file blob <base_sha>:<path>` (not the KRATT-reported values);
 *  - the working-tree diff against base_sha for the scope (must be empty);
 *  - the KRATT task digest, derived again from the envelope;
 *  - the evidence digest and verdict derivation (kratt `parseEvidence`, pure);
 *  - for `run-test`: the test itself is executed again by TÖEPÄRA (same bounded KRATT runner;
 *    independent invocation, not an independent implementation);
 *  - the RÄSTIK report digest, and that it targeted this exact receipt.
 * KRATT's own `verdict: ADMITTED` and `verification_state` are never accepted as authority.
 *
 * LIMITS: nothing is signed. A party who can rewrite the receipt AND the git object database
 * could forge consistent evidence; origin is not proven. The RÄSTIK report is hash-checked
 * for self-consistency only.
 */
export interface ToeparaCtx {
  root: string;
  /** Host-configured repository this installation verifies for. */
  repository: string;
  /** Cache of TÖEPÄRA's own re-executions, keyed by KRATT task digest. */
  rerun?: Map<string, Awaited<ReturnType<typeof executeTask>>>;
}

export interface ToeparaResult {
  verdict: ToeparaVerdict;
  bundle: EvidenceBundle | null;
}

const SUPPORTED_EVIDENCE = new Set(["source_digests", "rastik_findings", "test_evidence"]);

type Check = { name: string; ok: boolean };

export function bundleDigest(b: Omit<EvidenceBundle, "bundle_digest">): string {
  return digestOf(b);
}

export async function toeparaVerify(
  envelopeRaw: unknown,
  receiptRaw: unknown,
  rastik: RastikRun | null,
  ctx: ToeparaCtx,
): Promise<ToeparaResult> {
  try {
    return await verifyInner(envelopeRaw, receiptRaw, rastik, ctx);
  } catch {
    return rejected("unknown", ["toepara-internal-error"], [], safeDigest({ internal: "error" }), "REJECTED");
  }
}

function safeDigest(v: unknown): string {
  try {
    return digestOf(v);
  } catch {
    return digestOf({ unserializable: true });
  }
}

function rejected(taskId: string, reasons: string[], checks: Check[], evidenceDigest: string, verdict: "REJECTED" | "INSUFFICIENT_EVIDENCE"): ToeparaResult {
  const id = /^[a-z0-9][a-z0-9-]{0,63}$/.test(taskId) ? taskId : "invalid-task-id";
  return {
    verdict: {
      protocol_version: PROTOCOL_VERSION,
      task_id: id,
      verdict,
      reasons: reasons.map((r) => r.slice(0, 300)).slice(0, 64),
      checks: checks.slice(0, 64),
      evidence_digest: evidenceDigest,
    },
    bundle: null,
  };
}

async function verifyInner(envelopeRaw: unknown, receiptRaw: unknown, rastik: RastikRun | null, ctx: ToeparaCtx): Promise<ToeparaResult> {
  const checks: Check[] = [];
  const reject: string[] = [];
  const insufficient: string[] = [];
  const note = (name: string, ok: boolean, why: string, kind: "reject" | "insufficient" = "reject") => {
    checks.push({ name, ok });
    if (!ok) (kind === "reject" ? reject : insufficient).push(why);
    return ok;
  };

  const ev = validateEnvelope(envelopeRaw);
  if (!ev.ok) return rejected("unknown", [`envelope-invalid:${ev.reason}`], [{ name: "envelope-valid", ok: false }], safeDigest({ envelope_invalid: ev.reason }), "REJECTED");
  const env: TaskEnvelope = ev.value;

  // --- receipt presence / shape --------------------------------------------------------
  if (typeof receiptRaw !== "object" || receiptRaw === null || Array.isArray(receiptRaw))
    return rejected(env.task_id, ["receipt-missing"], [{ name: "receipt-present", ok: false }], safeDigest({ task: env.task_id, receipt: "missing" }), "INSUFFICIENT_EVIDENCE");
  const own = (k: string) => Object.prototype.hasOwnProperty.call(receiptRaw, k);
  if (!own("evidence") || !own("result"))
    return rejected(env.task_id, [`evidence-missing:${!own("evidence") ? "evidence" : "result"}`], [{ name: "evidence-present", ok: false }], safeDigest({ task: env.task_id, missing: true }), "INSUFFICIENT_EVIDENCE");
  const rv = validateActionReceipt(receiptRaw);
  if (!rv.ok) {
    const ek = (receiptRaw as { evidence?: unknown }).evidence;
    const emptyEvidence = typeof ek === "object" && ek !== null && !Array.isArray(ek) && Object.keys(ek).length === 0;
    return rejected(env.task_id, [`receipt-invalid:${rv.reason}`], [{ name: "receipt-schema", ok: false }], safeDigest({ task: env.task_id, schema: rv.reason }), emptyEvidence ? "INSUFFICIENT_EVIDENCE" : "REJECTED");
  }
  const r: ActionReceipt = rv.value;
  if (Object.keys(r.evidence).length === 0)
    return rejected(env.task_id, ["evidence-missing:empty"], [{ name: "evidence-present", ok: false }], safeDigest({ task: env.task_id, evidence: "empty" }), "INSUFFICIENT_EVIDENCE");
  checks.push({ name: "receipt-schema", ok: true });
  const receiptDigest = digestOf(r);

  // --- identity / authority --------------------------------------------------------------
  note("identity-task", r.task_id === env.task_id, "receipt-task-id-mismatch");
  note("identity-agent", r.agent_id === env.agent_id, "receipt-agent-mismatch");
  note("identity-repository", r.repository === env.repository && env.repository === ctx.repository, "repository-mismatch");
  note("identity-base-sha", r.base_sha === env.base_sha, "receipt-base-sha-mismatch");
  note("identity-scope", canonicalize(r.scope) === canonicalize(env.scope), "receipt-scope-mismatch");
  note("not-self-verified", r.verification_state === "UNVERIFIED", `kratt-self-verified:${r.verification_state}`);
  note("producer-role", producerMayRunAction(r.agent_id, r.action), `producer-lacks-capability:kratt:${r.action}`);
  note("action-authorized", env.allowed_actions.includes(r.action) && !env.forbidden_actions.includes(r.action), `unauthorized-action:${r.action}`);

  // --- freshness ------------------------------------------------------------------------
  // Shallow checkout: a base commit that is simply not present cannot be recomputed from. That is missing
  // evidence (INSUFFICIENT_EVIDENCE), never a pass, and the checks that depend on it are not run (no derived noise).
  const exists = commitExists(ctx.root, r.base_sha);
  const baseUnavailable = !exists && isShallow(ctx.root);
  if (baseUnavailable) note("base-commit-available", false, "base-commit-unavailable:shallow-checkout", "insufficient");
  else {
    note("base-sha-exists", exists, "base-sha-unknown-commit");
    const head = headSha(ctx.root);
    note("base-sha-is-current-head", head !== null && head === r.base_sha, "stale-base-sha");
  }

  // --- KRATT evidence structure + binding ------------------------------------------------
  const parsed = parseEvidence(canonicalize(r.evidence));
  let kev: ToeparaEvidence | null = null;
  if (!note("kratt-evidence-parses", parsed.ok, `kratt-evidence-invalid:${parsed.ok ? "" : parsed.reason}`)) {
    // fallthrough with what we have
  } else if (parsed.ok) kev = parsed.evidence;

  const mapped = envelopeToKrattTask(env);
  note("kratt-task-derivable", mapped.ok, `kratt-task-not-derivable:${mapped.ok ? "" : mapped.reason}`);
  if (kev && mapped.ok) {
    note("evidence-task-digest", kev.taskDigest === taskDigest(mapped.task), "evidence-task-digest-mismatch");
    note("evidence-binds-task", kev.taskId === r.task_id && kev.action === r.action && mapped.action === r.action, "evidence-task-or-action-mismatch");
    note(
      "result-matches-evidence",
      r.result.exit_code === kev.exitCode && r.result.checks.pass === kev.checks.pass && r.result.checks.fail === kev.checks.fail && r.result.failure === kev.failure && r.result.ok === (kev.exitCode === 0 && kev.failure === null),
      "receipt-result-contradicts-evidence",
    );
  }

  // --- recompute source digests from git (never from the receipt) ------------------------
  const sourceDigests: EvidenceBundle["source_digests"] = [];
  let blobsUnavailable = false;
  if (kev && !baseUnavailable) {
    const names = kev.artifacts.map((a) => a.name);
    const scopeSet = new Set(env.scope);
    if (r.action === "validate-manifest") note("artifacts-cover-scope", names.includes(env.scope[0] ?? ""), "artifacts-do-not-include-manifest");
    else note("artifacts-equal-scope", names.length === scopeSet.size && names.every((n) => scopeSet.has(n)), "artifacts-differ-from-scope");
    let allMatch = true;
    for (const a of kev.artifacts) {
      const d = blobDigest(ctx.root, r.base_sha, a.name);
      if (d === null) {
        allMatch = false;
        if (blobState(ctx.root, r.base_sha, a.name) === "object-unavailable") {
          blobsUnavailable = true;
          insufficient.push(`base-blob-unavailable:${a.name}`);
        } else reject.push(`source-not-in-base-sha:${a.name}`);
        continue;
      }
      sourceDigests.push({ path: a.name, sha256: d.sha256, bytes: d.bytes });
      if (d.sha256 !== a.sha256 || d.bytes !== a.bytes) {
        allMatch = false;
        reject.push(`source-digest-mismatch:${a.name}`);
      }
    }
    checks.push({ name: "source-digests-recomputed-from-git", ok: allMatch });
    // hash-files: KRATT's claimed check count must equal the number of files TÖEPÄRA itself found in git (regression: R-IND-1, an inflated count used to pass)
    if (r.action === "hash-files" && !blobsUnavailable) note("hash-files-check-count-recomputed", kev.checks.pass === scopeSet.size && kev.checks.fail === 0 && r.result.checks.pass === scopeSet.size, "check-count-differs-from-recomputed-files");
  }
  const scopeDiff = exists && !blobsUnavailable ? diffDigest(ctx.root, r.base_sha, env.scope) : null;
  if (!baseUnavailable && !blobsUnavailable) note("diff-computable", scopeDiff !== null, "diff-not-computable");
  if (scopeDiff) note("working-tree-matches-base-sha", scopeDiff.empty, "working-tree-differs-from-base-sha");

  // --- independent test re-execution (run-test) ------------------------------------------
  let testEvidence: EvidenceBundle["test_evidence"] = null;
  if (kev && mapped.ok && mapped.action === "run-test") {
    const key = taskDigest(mapped.task);
    const cache = ctx.rerun ?? new Map();
    let again = cache.get(key);
    if (!again) {
      again = await executeTask(ctx.root, mapped.task);
      cache.set(key, again);
    }
    const same =
      again.exitCode === kev.exitCode &&
      again.failure === kev.failure &&
      again.checks.pass === kev.checks.pass &&
      again.checks.fail === kev.checks.fail &&
      canonicalize(again.artifacts) === canonicalize(kev.artifacts);
    note("test-reexecution-agrees", same, "test-reexecution-disagrees");
    testEvidence = { pass: again.checks.pass, fail: again.checks.fail, reexecuted: true };
  }

  // --- success claim -------------------------------------------------------------------------
  note("action-succeeded", r.result.ok && r.result.checks.fail === 0 && r.result.checks.pass >= 1, "action-result-not-successful");

  // --- required evidence ---------------------------------------------------------------------
  for (const need of env.required_evidence) {
    if (!SUPPORTED_EVIDENCE.has(need)) note(`required:${need}`, false, `required-evidence-unsupported:${need}`, "insufficient");
    else if (need === "test_evidence") note("required:test_evidence", testEvidence !== null, "required-evidence-missing:test_evidence", "insufficient");
    else if (need === "source_digests") note("required:source_digests", sourceDigests.length >= 1, "required-evidence-missing:source_digests", "insufficient");
  }

  // --- RÄSTIK report (only when the envelope requires it) ------------------------------------------------------------
  let rastikDigest = digestOf(null);
  let findingIds: string[] = [];
  if (env.required_evidence.includes("rastik_findings")) {
    if (rastik === null) note("required:rastik_findings", false, "required-evidence-missing:rastik_findings", "insufficient");
    else {
      note("rastik-targets-this-receipt", rastik.target_receipt_digest === receiptDigest, "rastik-report-for-different-receipt");
      const { evidence_digest, ...body } = rastik;
      const recomputed = rastikEvidenceDigest(body);
      note("rastik-digest-recomputed", recomputed === evidence_digest, "rastik-report-digest-mismatch");
      note("rastik-executed-cases", rastik.cases_executed >= 1 && rastik.attacks.length >= 1, "rastik-executed-no-cases", "insufficient");
      note("rastik-findings-valid", rastik.findings.every((f) => validateRastikFinding(f).ok), "rastik-finding-malformed");
      rastikDigest = recomputed;
      findingIds = rastik.findings.map((f) => f.finding_id);
    }
  }

  const tid = env.task_id;
  if (reject.length > 0 || insufficient.length > 0 || kev === null) {
    const reasons = [...reject, ...insufficient];
    const verdict = reject.length > 0 ? "REJECTED" : "INSUFFICIENT_EVIDENCE";
    return rejected(tid, reasons, checks, safeDigest({ task: tid, receipt: receiptDigest, reasons }), verdict);
  }

  const body: Omit<EvidenceBundle, "bundle_digest"> = {
    protocol_version: PROTOCOL_VERSION,
    task_id: tid,
    repository: r.repository,
    base_sha: r.base_sha,
    action: r.action,
    source_digests: sourceDigests,
    diff_digest: (scopeDiff as { sha256: string }).sha256,
    action_receipt_digest: receiptDigest,
    kratt_evidence_digest: (kev as ToeparaEvidence).evidenceDigest,
    rastik_evidence_digest: rastikDigest,
    rastik_finding_ids: findingIds,
    test_evidence: testEvidence,
  };
  const bundle: EvidenceBundle = { ...body, bundle_digest: bundleDigest(body) };
  if (!validateEvidenceBundle(bundle).ok) return rejected(tid, ["bundle-schema-invalid"], checks, safeDigest({ task: tid, bundle: "invalid" }), "REJECTED");
  return {
    verdict: { protocol_version: PROTOCOL_VERSION, task_id: tid, verdict: "VERIFIED", reasons: [], checks, evidence_digest: bundle.bundle_digest },
    bundle,
  };
}
