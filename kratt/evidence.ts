import { createHash } from "node:crypto";
import { canonicalize } from "../cerberus/core/decide.ts";
import type { NormalizedInput } from "../cerberus/core/normalize.ts";
import type { VerdictAdapter } from "../cerberus/integrations/verdict-adapters.ts";
import { sha256Hex } from "../cerberus/artifact-trust/artifact-trust.ts";
import type { ActionResult, Artifact } from "./actions.ts";
import { relPathFailure } from "./paths.ts";
import { KRATT_ACTIONS, taskDigest, type KrattTask } from "./task.ts";

/**
 * TÖEPÄRA evidence PRODUCER for KRATT. The verdict is computed from the recorded facts
 * of a real execution (exit code, timeout/truncation flags, check counts, artifact
 * SHA-256s); it is never a string a caller types in. `createToeparaAdapter` re-derives
 * everything from the artifact content that reaches Cerberus, so tampering is detected
 * independently of the producer.
 *
 * LIMITATION: the evidence is integrity-hashed, NOT signed. Whoever can rewrite the
 * evidence AND recompute every digest can forge it. Origin is not proven (needs a signing
 * key / real TÖEPÄRA service, which does not exist in this repo).
 */
export const EVIDENCE_VERSION = "toepara-evidence/v1";
export const PRODUCER = "kratt/v1";
export const MAX_EVIDENCE_BYTES = 256 * 1024;
export type ToeparaVerdict = "ADMITTED" | "REJECTED";

export interface EvidenceBody {
  version: typeof EVIDENCE_VERSION;
  producer: typeof PRODUCER;
  taskId: string;
  action: string;
  taskDigest: string;
  command: string[];
  exitCode: number;
  timedOut: boolean;
  truncated: boolean;
  outputBytes: number;
  stdoutSha256: string;
  stderrSha256: string;
  artifacts: Artifact[];
  checks: { pass: number; fail: number };
  failure: string | null;
  verdict: ToeparaVerdict;
}
export interface ToeparaEvidence extends EvidenceBody {
  evidenceDigest: string;
}

const HEX64 = /^[0-9a-f]{64}$/;
const digestOf = (body: EvidenceBody) => createHash("sha256").update(canonicalize(body), "utf8").digest("hex");

/** The ONLY place a verdict is decided. Pure function of recorded facts. */
export function computeVerdict(b: Omit<EvidenceBody, "verdict">): ToeparaVerdict {
  const ok =
    b.exitCode === 0 &&
    !b.timedOut &&
    !b.truncated &&
    b.failure === null &&
    b.checks.fail === 0 &&
    b.checks.pass >= 1 &&
    b.artifacts.length >= 1;
  return ok ? "ADMITTED" : "REJECTED";
}

export function produceEvidence(task: KrattTask, r: ActionResult): ToeparaEvidence {
  const base = {
    version: EVIDENCE_VERSION,
    producer: PRODUCER,
    taskId: task.taskId,
    action: task.action,
    taskDigest: taskDigest(task),
    command: r.command,
    exitCode: r.exitCode,
    timedOut: r.timedOut,
    truncated: r.truncated,
    outputBytes: r.outputBytes,
    stdoutSha256: r.stdoutSha256,
    stderrSha256: r.stderrSha256,
    artifacts: r.artifacts,
    checks: r.checks,
    failure: r.failure,
  } as const;
  const body: EvidenceBody = { ...base, verdict: computeVerdict(base) };
  return { ...body, evidenceDigest: digestOf(body) };
}

/** The `artifact` Cerberus receives: canonical evidence JSON + its SHA-256. */
export function evidenceToArtifact(ev: ToeparaEvidence): { name: string; content: string; sha256: string } {
  const content = canonicalize(ev);
  return { name: `toepara-evidence-${ev.taskId}.json`, content, sha256: sha256Hex(content) };
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const isCount = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const sameKeys = (o: Record<string, unknown>, keys: string[]) =>
  Object.keys(o).sort().join(",") === [...keys].sort().join(",");

export type ParseResult = { ok: true; evidence: ToeparaEvidence } | { ok: false; reason: string };

/** Strict structural + cryptographic validation of evidence JSON text. */
export function parseEvidence(content: unknown): ParseResult {
  const bad = (reason: string): ParseResult => ({ ok: false, reason });
  if (typeof content !== "string") return bad("evidence-not-string");
  if (content.length === 0 || content.length > MAX_EVIDENCE_BYTES) return bad("evidence-size-invalid");
  let v: unknown;
  try {
    v = JSON.parse(content);
  } catch {
    return bad("evidence-invalid-json");
  }
  if (!isObj(v)) return bad("evidence-not-object");
  if (!sameKeys(v, [
    "version", "producer", "taskId", "action", "taskDigest", "command", "exitCode", "timedOut", "truncated",
    "outputBytes", "stdoutSha256", "stderrSha256", "artifacts", "checks", "failure", "verdict", "evidenceDigest",
  ])) return bad("evidence-unexpected-keys");
  if (v.version !== EVIDENCE_VERSION) return bad("evidence-version-unsupported");
  if (v.producer !== PRODUCER) return bad("evidence-producer-unknown");
  if (typeof v.taskId !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(v.taskId)) return bad("evidence-taskId-invalid");
  if (typeof v.action !== "string" || !(KRATT_ACTIONS as readonly string[]).includes(v.action)) return bad("evidence-action-invalid");
  for (const k of ["taskDigest", "stdoutSha256", "stderrSha256", "evidenceDigest"])
    if (typeof v[k] !== "string" || !HEX64.test(v[k] as string)) return bad(`evidence-${k}-malformed`);
  const cmd = v.command;
  if (!Array.isArray(cmd) || cmd.length < 1 || cmd.length > 32 || !cmd.every((c) => typeof c === "string" && c.length <= 300))
    return bad("evidence-command-invalid");
  // exitCode: finite integer only (rejects null produced by NaN/Infinity serialisation).
  if (typeof v.exitCode !== "number" || !Number.isSafeInteger(v.exitCode)) return bad("evidence-exitCode-invalid");
  if (typeof v.timedOut !== "boolean" || typeof v.truncated !== "boolean") return bad("evidence-flags-invalid");
  if (!isCount(v.outputBytes)) return bad("evidence-outputBytes-invalid");
  if (!isObj(v.checks) || !sameKeys(v.checks, ["pass", "fail"]) || !isCount(v.checks.pass) || !isCount(v.checks.fail))
    return bad("evidence-checks-invalid");
  if (v.failure !== null && (typeof v.failure !== "string" || v.failure.length > 300)) return bad("evidence-failure-invalid");
  if (v.verdict !== "ADMITTED" && v.verdict !== "REJECTED") return bad("evidence-verdict-invalid");
  const arts = v.artifacts;
  if (!Array.isArray(arts) || arts.length > 130) return bad("evidence-artifacts-invalid");
  let prev = "";
  for (const a of arts) {
    if (!isObj(a) || !sameKeys(a, ["name", "sha256", "bytes"])) return bad("evidence-artifact-invalid");
    if (relPathFailure(a.name) !== null || typeof a.name !== "string") return bad("evidence-artifact-name-invalid");
    if (typeof a.sha256 !== "string" || !HEX64.test(a.sha256)) return bad("evidence-artifact-sha256-malformed");
    if (!isCount(a.bytes)) return bad("evidence-artifact-bytes-invalid");
    if (a.name <= prev) return bad("evidence-artifacts-unsorted-or-duplicate");
    prev = a.name;
  }
  if (canonicalize(v) !== content) return bad("evidence-not-canonical");
  const { evidenceDigest, ...body } = v as Record<string, unknown>;
  if (digestOf(body as unknown as EvidenceBody) !== evidenceDigest) return bad("evidence-digest-mismatch");
  const ev = v as unknown as ToeparaEvidence;
  const { verdict, evidenceDigest: _d, ...facts } = ev;
  if (computeVerdict(facts) !== verdict) return bad("evidence-verdict-not-derivable-from-facts");
  return { ok: true, evidence: ev };
}

/** One-time-use registry of evidence digests (in-memory; see SLICE.md for limits). */
export class ReplayGuard {
  #seen = new Set<string>();
  /** true the first time a digest is seen, false for every later attempt. */
  consume(evidenceDigest: string): boolean {
    if (this.#seen.has(evidenceDigest)) return false;
    this.#seen.add(evidenceDigest);
    return true;
  }
}

export interface ToeparaAdapter extends VerdictAdapter {
  /** Reason for the last non-ADMITTED verdict (diagnostics only; the receipt only sees the verdict). */
  readonly lastReason: string | null;
}

/**
 * TÖEPÄRA adapter backed by real evidence validation. Returns "ADMITTED" only when the
 * evidence parses strictly, its digests verify, its verdict re-derives from its facts,
 * the verdict is ADMITTED, and the digest has not been presented before.
 */
export function createToeparaAdapter(guard: ReplayGuard): ToeparaAdapter {
  let lastReason: string | null = null;
  return {
    name: "kratt-evidence-toepara",
    get lastReason() {
      return lastReason;
    },
    verdict(snapshot: Readonly<NormalizedInput>): string {
      lastReason = null;
      const reject = (r: string) => {
        lastReason = r;
        return "REJECTED";
      };
      const a = snapshot.artifact;
      if (a === null || a.content === null) return reject("evidence-missing");
      const p = parseEvidence(a.content);
      if (!p.ok) return reject(p.reason);
      if (!guard.consume(p.evidence.evidenceDigest)) return reject("replayed-evidence");
      if (p.evidence.verdict !== "ADMITTED") return reject(`evidence-verdict-rejected:${p.evidence.failure ?? "checks"}`);
      return "ADMITTED";
    },
  };
}
