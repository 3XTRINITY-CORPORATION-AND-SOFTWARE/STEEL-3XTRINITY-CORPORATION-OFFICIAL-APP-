import { types as utilTypes } from "node:util";
import { canonicalize } from "../../cerberus/core/decide.ts";
import { sha256Hex } from "../../cerberus/artifact-trust/artifact-trust.ts";
import { arr, bool, check, int, json, lit, nul, obj, oneOf, or, str, toJsonSchema, type Spec } from "./spec.ts";

/**
 * 3XTRINITY shared factory protocol, version 1.
 *
 * Reuse, not duplication: KRATT evidence stays `kratt/evidence.ts` `ToeparaEvidence` (carried
 * opaquely in `ActionReceipt.evidence` and re-validated by its own parser), the Cerberus
 * receipt stays `cerberus/core/decide.ts` `RecoveryReceipt`, and RÄSTIK probe findings from
 * `rastik/types.ts` are mapped onto `RastikFinding` by a thin adapter (factory/rastik-adapter).
 *
 * Compatibility: `protocol_version` is an integer major. Anything other than the current
 * major is rejected (`protocol-incompatible-major`); there are no minor versions yet.
 */
export const PROTOCOL_VERSION = 1 as const;

export const TASK_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const AGENT_ID = /^(FORGE|SERPENT|CITADEL)-\d{3}$/;
export const SHA1_HEX = /^[0-9a-f]{40}$/;
export const SHA256_HEX = /^[0-9a-f]{64}$/;
/** Same language as kratt/paths.ts relPathFailure (asserted by a test). */
export const REL_PATH = /^[A-Za-z0-9_][A-Za-z0-9._-]*(\/[A-Za-z0-9_][A-Za-z0-9._-]*)*$/;
export const TOKEN = /^[a-z][a-z0-9:_-]{0,63}$/;
const REPO = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const BRANCH = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
// eslint-disable-next-line no-control-regex
const TEXT = /^[^\u0000-\u001f\u007f]*$/;

// eslint-disable-next-line no-control-regex
const TEXT_ML = /^[^\u0000-\u0008\u000b-\u001f\u007f]*$/; // multi-line text: \n and \t allowed
const taskId = str({ re: TASK_ID });
const agentId = str({ re: AGENT_ID });
const sha1 = str({ re: SHA1_HEX });
const sha256 = str({ re: SHA256_HEX });
const relPath = str({ re: REL_PATH, min: 1, max: 200 });
const token = str({ re: TOKEN });
const text = (max: number): Spec => str({ re: TEXT, min: 1, max });
const multiline = (max: number): Spec => str({ re: TEXT_ML, min: 1, max });
const factory = oneOf("FORGE", "SERPENT", "CITADEL");
const version = lit(PROTOCOL_VERSION);

export const VERIFICATION_STATES = ["UNVERIFIED", "VERIFIED", "REJECTED", "INSUFFICIENT_EVIDENCE"] as const;
export type VerificationState = (typeof VERIFICATION_STATES)[number];
export type ToeparaVerdictValue = "VERIFIED" | "REJECTED" | "INSUFFICIENT_EVIDENCE";
export type CerberusDecisionValue = "ADMIT" | "DENY" | "QUARANTINE";
export type Severity = "low" | "medium" | "high" | "critical";

export interface TaskEnvelope {
  task_id: string;
  factory: "FORGE" | "SERPENT" | "CITADEL";
  agent_id: string;
  objective: string;
  repository: string;
  branch: string;
  base_sha: string;
  scope: string[];
  allowed_actions: string[];
  forbidden_actions: string[];
  required_evidence: string[];
  resource_budget: { max_wall_ms: number; max_output_bytes: number; max_files: number };
  protocol_version: 1;
}

export interface ActionReceipt {
  task_id: string;
  agent_id: string;
  repository: string;
  base_sha: string;
  action: string;
  scope: string[];
  result: { ok: boolean; exit_code: number; checks: { pass: number; fail: number }; failure: string | null };
  /** Opaque here; for KRATT this is `kratt/evidence.ts` ToeparaEvidence, re-validated by parseEvidence. */
  evidence: Record<string, unknown>;
  verification_state: VerificationState;
  timestamp: string;
  protocol_version: 1;
}

export interface EvidenceBundle {
  protocol_version: 1;
  task_id: string;
  repository: string;
  base_sha: string;
  action: string;
  /** Recomputed by TÖEPÄRA from `git cat-file blob <base_sha>:<path>`, never copied from KRATT. */
  source_digests: { path: string; sha256: string; bytes: number }[];
  /** SHA-256 of `git diff <base_sha> -- <scope>` (empty diff => SHA-256 of ""). */
  diff_digest: string;
  action_receipt_digest: string;
  kratt_evidence_digest: string;
  rastik_evidence_digest: string;
  rastik_finding_ids: string[];
  test_evidence: { pass: number; fail: number; reexecuted: boolean } | null;
  bundle_digest: string;
}

export interface RastikFinding {
  finding_id: string;
  target: string;
  hypothesis: string;
  reproduction: string;
  severity: Severity;
  /** CONFIRMED only when an independent re-run reproduced the violation. */
  status: "CONFIRMED" | "UNCONFIRMED";
  evidence: Record<string, unknown>;
  regression_test: string;
  proposed_smallest_fix: string;
}

export interface ToeparaVerdict {
  protocol_version: 1;
  task_id: string;
  verdict: ToeparaVerdictValue;
  reasons: string[];
  checks: { name: string; ok: boolean }[];
  /** bundle_digest when a bundle could be formed, else digest of the rejected input's reasons. */
  evidence_digest: string;
}

export interface CerberusDecision {
  protocol_version: 1;
  task_id: string;
  decision: CerberusDecisionValue;
  reasons: string[];
  toepara_evidence_digest: string;
  cerberus_receipt_digest: string;
  unresolved_high_findings: string[];
  decision_digest: string;
}

export const SPECS = {
  TaskEnvelope: obj({
    task_id: taskId,
    factory,
    agent_id: agentId,
    objective: text(500),
    repository: str({ re: REPO }),
    branch: str({ re: BRANCH }),
    base_sha: sha1,
    scope: arr(relPath, 1, 64, true),
    allowed_actions: arr(token, 1, 16, true),
    forbidden_actions: arr(token, 0, 32, true),
    required_evidence: arr(token, 1, 16, true),
    resource_budget: obj({
      max_wall_ms: int(100, 600_000),
      max_output_bytes: int(1024, 1_048_576),
      max_files: int(1, 64),
    }),
    protocol_version: version,
  }),
  ActionReceipt: obj({
    task_id: taskId,
    agent_id: agentId,
    repository: str({ re: REPO }),
    base_sha: sha1,
    action: token,
    scope: arr(relPath, 1, 64, true),
    result: obj({
      ok: bool,
      exit_code: int(-1, 255),
      checks: obj({ pass: int(0, 1_000_000), fail: int(0, 1_000_000) }),
      failure: or(nul, text(300)),
    }),
    evidence: json,
    verification_state: oneOf(...VERIFICATION_STATES),
    timestamp: str({ re: ISO_UTC }),
    protocol_version: version,
  }),
  EvidenceBundle: obj({
    protocol_version: version,
    task_id: taskId,
    repository: str({ re: REPO }),
    base_sha: sha1,
    action: token,
    source_digests: arr(obj({ path: relPath, sha256, bytes: int(0, 8 * 1024 * 1024) }), 0, 64),
    diff_digest: sha256,
    action_receipt_digest: sha256,
    kratt_evidence_digest: sha256,
    rastik_evidence_digest: sha256,
    rastik_finding_ids: arr(text(200), 0, 256, true),
    test_evidence: or(nul, obj({ pass: int(0, 1_000_000), fail: int(0, 1_000_000), reexecuted: bool })),
    bundle_digest: sha256,
  }),
  RastikFinding: obj({
    finding_id: text(200),
    target: text(300),
    hypothesis: text(500),
    reproduction: text(2000),
    severity: oneOf("low", "medium", "high", "critical"),
    status: oneOf("CONFIRMED", "UNCONFIRMED"),
    evidence: json,
    regression_test: multiline(4000),
    proposed_smallest_fix: text(1000),
  }),
  ToeparaVerdict: obj({
    protocol_version: version,
    task_id: taskId,
    verdict: oneOf("VERIFIED", "REJECTED", "INSUFFICIENT_EVIDENCE"),
    reasons: arr(text(300), 0, 64),
    checks: arr(obj({ name: token, ok: bool }), 0, 64),
    evidence_digest: sha256,
  }),
  CerberusDecision: obj({
    protocol_version: version,
    task_id: taskId,
    decision: oneOf("ADMIT", "DENY", "QUARANTINE"),
    reasons: arr(text(300), 0, 64),
    toepara_evidence_digest: sha256,
    cerberus_receipt_digest: sha256,
    unresolved_high_findings: arr(text(200), 0, 256, true),
    decision_digest: sha256,
  }),
} as const;

export type ProtocolType = keyof typeof SPECS;
export type Validation<T> = { ok: true; value: T } | { ok: false; reason: string };

function protocolVersionFailure(input: unknown): string | null {
  try {
    if (typeof input !== "object" || input === null) return null;
    const d = Object.getOwnPropertyDescriptor(input, "protocol_version");
    if (d === undefined || !("value" in d)) return null; // structural check will report it
    const v = d.value;
    if (typeof v === "number" && Number.isInteger(v) && v !== PROTOCOL_VERSION) return `protocol-incompatible-major:${v}`;
    return null;
  } catch {
    return null;
  }
}

function validateAs<T>(type: ProtocolType, input: unknown): Validation<T> {
  const pv = protocolVersionFailure(input);
  if (pv) return { ok: false, reason: pv };
  const r = check(SPECS[type], input);
  return r === null ? { ok: true, value: input as T } : { ok: false, reason: r };
}

/**
 * Single-read deep copy of already-structurally-valid JSON data. Every property is read exactly once, through its own
 * data descriptor (never [[Get]], so getters are never invoked). Proxies are refused outright. Throws on anything unexpected.
 */
function snapshotJson(v: unknown, depth = 0): unknown {
  if (depth > 4) throw new Error("too-deep");
  if (v === null || typeof v === "string" || typeof v === "number" || typeof v === "boolean") return v;
  if (typeof v !== "object") throw new Error("not-json");
  if (utilTypes.isProxy(v)) throw new Error("proxy"); // never legitimate JSON input; its traps could answer differently per call
  if (Array.isArray(v)) {
    const n = v.length;
    const out: unknown[] = [];
    for (let i = 0; i < n; i++) {
      const d = Object.getOwnPropertyDescriptor(v, String(i));
      if (d === undefined || !("value" in d)) throw new Error("unreadable");
      out.push(snapshotJson(d.value, depth + 1));
    }
    return out;
  }
  const out: Record<string, unknown> = {};
  for (const k of Reflect.ownKeys(v)) {
    if (typeof k !== "string") throw new Error("symbol-key");
    const d = Object.getOwnPropertyDescriptor(v, k);
    if (d === undefined || !("value" in d)) throw new Error("unreadable");
    Object.defineProperty(out, k, { value: snapshotJson(d.value, depth + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

// Characters that are legal in a single-line TEXT field but that make log/terminal/UI output lie:
// C1 controls (incl. NEL U+0085), soft hyphen U+00AD, combining grapheme joiner U+034F, ALM U+061C, Mongolian vowel
// separator U+180E, zero-width space/LRM/RLM (U+200B/E/F), LINE/PARAGRAPH SEPARATOR, bidi embeddings/overrides/isolates
// (U+202A-E, U+2066-9), word joiner and invisible math operators (U+2060-2064), deprecated format chars (U+206A-F),
// Hangul/halfwidth fillers (U+3164, U+FFA0), variation selectors (U+FE00-FE0F and U+E0100-E01EF), BOM U+FEFF,
// Unicode tag characters (U+E0000-E007F) and unpaired surrogates.
// ZWNJ/ZWJ (U+200C/D) stay legal: they are needed for real scripts and emoji sequences.
// Trade-off: emoji presentation selectors (U+FE0F, e.g. "\u2764\uFE0F") are rejected too; the bare symbol is accepted.
const OBJECTIVE_SPOOFING =
  // eslint-disable-next-line no-misleading-character-class -- the class deliberately lists combining/joining format characters
  /[\u0080-\u009f\u00ad\u034f\u061c\u180e\u200b\u200e\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\u206a-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ud800-\udfff\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/u;
const isDotSegment = (s: string): boolean => /^\.+$/.test(s);
/** Mirrors `git check-ref-format` for the parts the permissive BRANCH character class leaves open. */
function branchRefFailure(b: string): string | null {
  if (b.endsWith("/") || b.endsWith(".")) return "ref-trailing-separator";
  if (b.includes("..")) return "ref-double-dot";
  for (const c of b.split("/")) {
    if (c === "") return "ref-empty-component";
    if (c.startsWith(".")) return "ref-dot-component";
    if (c.endsWith(".lock")) return "ref-lock-suffix";
  }
  return null;
}

export function validateEnvelope(input: unknown): Validation<TaskEnvelope> {
  const v = validateAs<TaskEnvelope>("TaskEnvelope", input);
  if (!v.ok) return v;
  // Re-read the input ONCE into a plain snapshot and validate and return THAT. Validation walks property descriptors,
  // but consumers read fields normally; a Proxy with a throwing/lying trap would otherwise either throw out of this
  // function or hand back an object whose later reads differ from what was validated.
  let snap: unknown;
  try {
    snap = snapshotJson(v.value);
  } catch {
    return { ok: false, reason: "$:unreadable" };
  }
  const s = validateAs<TaskEnvelope>("TaskEnvelope", snap);
  if (!s.ok) return s;
  const e = s.value;
  if (!e.agent_id.startsWith(`${e.factory}-`)) return { ok: false, reason: "agent-not-in-factory" };
  if (e.allowed_actions.some((a) => e.forbidden_actions.includes(a))) return { ok: false, reason: "action-both-allowed-and-forbidden" };
  if (e.scope.length > e.resource_budget.max_files) return { ok: false, reason: "scope-exceeds-max-files" };
  if (OBJECTIVE_SPOOFING.test(e.objective)) return { ok: false, reason: "$.objective:forbidden-character" };
  if (e.repository.split("/").some(isDotSegment)) return { ok: false, reason: "$.repository:dot-segment" };
  const ref = branchRefFailure(e.branch);
  if (ref) return { ok: false, reason: `$.branch:${ref}` };
  return s;
}
export const validateActionReceipt = (i: unknown) => validateAs<ActionReceipt>("ActionReceipt", i);
export const validateEvidenceBundle = (i: unknown) => validateAs<EvidenceBundle>("EvidenceBundle", i);
export const validateRastikFinding = (i: unknown) => validateAs<RastikFinding>("RastikFinding", i);
export const validateToeparaVerdict = (i: unknown) => validateAs<ToeparaVerdict>("ToeparaVerdict", i);
export const validateCerberusDecision = (i: unknown) => validateAs<CerberusDecision>("CerberusDecision", i);

/** SHA-256 over canonical JSON (keys sorted); throws on cyclic/BigInt input - callers pass validated data. */
export const digestOf = (value: unknown): string => sha256Hex(canonicalize(value));

/** JSON Schema document generated from SPECS (committed as protocol.schema.json). */
export function buildJsonSchema(): Record<string, unknown> {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "urn:3xtrinity:factory-protocol:v1",
    title: "3XTRINITY factory protocol v1 (generated from factory/protocol/types.ts; do not edit by hand)",
    $defs: Object.fromEntries(Object.entries(SPECS).map(([k, s]) => [k, toJsonSchema(s)])),
  };
}
