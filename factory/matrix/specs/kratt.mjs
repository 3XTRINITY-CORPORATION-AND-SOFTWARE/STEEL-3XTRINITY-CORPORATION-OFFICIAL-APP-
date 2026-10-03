// KRATT/TOEPARA domain (slots 101-129): kratt/task.ts, paths.ts, actions.ts, evidence.ts.
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const TASK = "kratt/task.ts";
const PATHS = "kratt/paths.ts";
const ACT = "kratt/actions.ts";
const EVD = "kratt/evidence.ts";
const sha = (/** @type {any} */ s) => createHash("sha256").update(s).digest("hex");
function root(files = {}) {
  const r = mkdtempSync(join(tmpdir(), "m-kratt-"));
  for (const [rel, c] of Object.entries(files)) { mkdirSync(dirname(join(r, rel)), { recursive: true }); writeFileSync(join(r, rel), c); }
  return r;
}
const hashTask = (/** @type {any} */ files, taskId = "t1") => ({ taskId, action: "hash-files", files });
const rt = (over = {}) => ({ taskId: "rt1", action: "run-test", testFile: "kratt/tests/x.test.ts", timeoutMs: 5000, maxOutputBytes: 4096, ...over });
/** ADMITTED-shaped facts for computeVerdict differentials. */
const FACTS = { version: "toepara-evidence/v1", producer: "kratt/v1", taskId: "t", action: "hash-files", taskDigest: "0".repeat(64), command: ["in-process:hash-files"], exitCode: 0, timedOut: false, truncated: false, outputBytes: 0, stdoutSha256: "0".repeat(64), stderrSha256: "0".repeat(64), artifacts: [{ name: "a.txt", sha256: "1".repeat(64), bytes: 1 }], checks: { pass: 1, fail: 0 }, failure: null };
const A = /** @type {{ taskId: string, action: "hash-files", files: string[] }} */ ({ taskId: "a1", action: "hash-files", files: ["a.txt"] });
const evOf = async (/** @type {any} */ m) => { const r = root({ "a.txt": "hello" }); const res = await m.executeTask(r, A); return res; };

/** @type {import("../types.d.ts").Spec[]} */
export const SPECS = [
  { slot: 101, target: TASK, fn: "validateTask", input: [hashTask(["a/b.txt", "c.md"])], expected: { ok: true, task: { taskId: "t1", action: "hash-files", files: ["a/b.txt", "c.md"] } },
    claim: "a well-formed hash-files task is accepted and returned unchanged" },
  { slot: 102, target: TASK, fn: "validateTask", input: [{ taskId: "m-1", action: "validate-manifest", manifest: "docs/m.json" }], expected: { ok: true, task: { taskId: "m-1", action: "validate-manifest", manifest: "docs/m.json" } },
    claim: "a well-formed validate-manifest task is accepted" },
  { slot: 103, target: TASK, fn: "validateTask", input: [rt()], expected: { ok: true, task: { taskId: "rt1", action: "run-test", testFile: "kratt/tests/x.test.ts", timeoutMs: 5000, maxOutputBytes: 4096 } },
    claim: "a run-test task needs a .test.ts/.mjs file plus explicit timeout and output cap, and is accepted when all are stated" },
  { slot: 104, target: TASK, fn: "validateTask", input: [{ taskId: "t", action: "exec", files: ["a"] }], expected: { ok: false, reason: "action-not-allowed" },
    claim: "a shell/exec-style action is not on the allow-list" },
  { slot: 105, target: TASK, fn: "validateTask", input: [hashTask(["../etc/passwd"])], expected: { ok: false, reason: "path-segment-invalid" },
    claim: "a traversal path in files is rejected by the character allow-list" },
  { slot: 106, target: PATHS, fn: "relPathFailure", input: [7], expected: "path-not-string", claim: "a non-string path is rejected before any segment check" },
  { slot: 107, target: PATHS, fn: "relPathFailure", input: ["x".repeat(201)], expected: "path-length-invalid", claim: "a 201-character path exceeds MAX_PATH_LENGTH (200)" },
  { slot: 108, target: ACT, expected: { exitCode: 1, failure: "test-dir-not-allowed", spawned: false },
    run: async (m) => { const r = await m.executeTask(root(), { taskId: "rt", action: "run-test", testFile: "scripts/evil.test.mjs", timeoutMs: 5000, maxOutputBytes: 4096 }); return { exitCode: r.exitCode, failure: r.failure, spawned: r.outputBytes > 0 }; },
    claim: "a test file outside cerberus/tests and kratt/tests is refused before any subprocess is spawned" },
  { slot: 109, target: TASK, fn: "validateTask", input: [{ taskId: "m", action: "validate-manifest", manifest: "m.json", extra: 1 }], expected: { ok: false, reason: "unexpected-keys" },
    claim: "an extra key beyond the closed per-action schema is rejected" },
  { slot: 110, target: TASK, expected: { ok: false, reason: "accessor-property" },
    run: (m) => m.validateTask({ get taskId() { return "evil"; }, action: "hash-files", files: ["a"] }), claim: "a getter-backed taskId (could change between reads) is rejected" },
  { slot: 111, target: TASK, fn: "validateTask", input: [["not", "an", "object"]], expected: { ok: false, reason: "task-not-plain-object" }, claim: "an array is not a task object" },
  { slot: 112, target: TASK, fn: "validateTask", input: [rt({ timeoutMs: NaN })], expected: { ok: false, reason: "timeoutMs-not-integer" }, claim: "NaN is not an acceptable timeout" },
  { slot: 113, target: TASK, fn: "validateTask", input: [rt({ timeoutMs: 50 })], expected: { ok: false, reason: "timeoutMs-out-of-range" }, claim: "a 50 ms timeout is below the 100 ms floor" },
  { slot: 114, target: TASK, fn: "validateTask", input: [rt({ maxOutputBytes: 2_000_000 })], expected: { ok: false, reason: "maxOutputBytes-out-of-range" }, claim: "a 2,000,000-byte output cap exceeds the 1 MiB ceiling" },
  { slot: 115, target: TASK, expected: { sameTaskSameDigest: true, differentFilesDifferentDigest: true, hexLength: 64 },
    run: (m) => { const a = m.taskDigest(A); return { sameTaskSameDigest: a === m.taskDigest({ ...A }), differentFilesDifferentDigest: a !== m.taskDigest({ ...A, files: ["b.txt"] }), hexLength: a.length }; },
    claim: "taskDigest is deterministic, changes with the files, and is a 64-hex SHA-256" },
  { slot: 116, target: TASK, fn: "validateTask", input: [hashTask(["a.txt", "a.txt"])], expected: { ok: false, reason: "files-duplicate" }, claim: "listing the same file twice is rejected" },
  { slot: 117, target: TASK, fn: "validateTask", input: [hashTask([])], expected: { ok: false, reason: "files-count-invalid" }, claim: "an empty files list is rejected (no vacuous hashing task)" },
  { slot: 118, target: TASK, fn: "validateTask", input: [rt({ testFile: "kratt/tests/x.ts" })], expected: { ok: false, reason: "testFile-not-test" }, claim: "a run-test target must end in .test.ts or .test.mjs" },
  { slot: 119, target: ACT, expected: { exitCode: 0, checks: { pass: 1, fail: 0 }, artifacts: [{ name: "a.txt", sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", bytes: 5 }], failure: null },
    run: async (m) => { const r = await evOf(m); return { exitCode: r.exitCode, checks: r.checks, artifacts: r.artifacts, failure: r.failure }; },
    claim: "hash-files on a real file 'hello' records the independently known SHA-256 2cf24dba... and 5 bytes" },
  { slot: 120, target: ACT, expected: { exitCode: 1, failure: "path-not-found:nope.txt", checks: { pass: 0, fail: 1 } },
    run: async (m) => { const r = await m.executeTask(root(), hashTask(["nope.txt"])); return { exitCode: r.exitCode, failure: r.failure, checks: r.checks }; }, claim: "a missing file fails the whole hash task and names the file" },
  { slot: 121, target: ACT, expected: { exitCode: 1, failure: "path-escapes-root:link.txt" },
    run: async (m) => { const outside = root({ "secret.txt": "s" }); const r = root(); symlinkSync(join(outside, "secret.txt"), join(r, "link.txt")); const x = await m.executeTask(r, hashTask(["link.txt"])); return { exitCode: x.exitCode, failure: x.failure }; },
    claim: "a symlink pointing outside the root is refused, not followed" },
  { slot: 122, target: ACT, expected: { exitCode: 0, checks: { pass: 1, fail: 0 }, names: ["a.txt", "m.json"] },
    run: async (m) => { const man = JSON.stringify({ version: 1, files: [{ path: "a.txt", sha256: sha("hello") }] }); const r = await m.executeTask(root({ "a.txt": "hello", "m.json": man }), { taskId: "m", action: "validate-manifest", manifest: "m.json" }); return { exitCode: r.exitCode, checks: r.checks, names: r.artifacts.map((/** @type {any} */ a) => a.name) }; },
    claim: "a manifest whose declared SHA-256 matches the real file passes and records both manifest and file as artifacts" },
  { slot: 123, target: ACT, expected: { exitCode: 1, failure: "sha256-mismatch:a.txt", checks: { pass: 0, fail: 1 } },
    run: async (m) => { const man = JSON.stringify({ version: 1, files: [{ path: "a.txt", sha256: sha("tampered") }] }); const r = await m.executeTask(root({ "a.txt": "hello", "m.json": man }), { taskId: "m", action: "validate-manifest", manifest: "m.json" }); return { exitCode: r.exitCode, failure: r.failure, checks: r.checks }; },
    claim: "a manifest declaring the wrong digest fails with sha256-mismatch naming the file" },
  { slot: 124, target: EVD, fn: "computeVerdict", input: [FACTS], expected: "ADMITTED", claim: "clean facts (exit 0, no flags, >=1 check passed, >=1 artifact) derive ADMITTED" },
  { slot: 125, target: EVD, expected: { zeroChecks: "REJECTED", timedOut: "REJECTED", truncated: "REJECTED", failureSet: "REJECTED", noArtifacts: "REJECTED", nonZeroExit: "REJECTED", failedCheck: "REJECTED" },
    run: (m) => ({ zeroChecks: m.computeVerdict({ ...FACTS, checks: { pass: 0, fail: 0 } }), timedOut: m.computeVerdict({ ...FACTS, timedOut: true }), truncated: m.computeVerdict({ ...FACTS, truncated: true }), failureSet: m.computeVerdict({ ...FACTS, failure: "x" }), noArtifacts: m.computeVerdict({ ...FACTS, artifacts: [] }), nonZeroExit: m.computeVerdict({ ...FACTS, exitCode: 1 }), failedCheck: m.computeVerdict({ ...FACTS, checks: { pass: 1, fail: 1 } }) }),
    claim: "each single defect (vacuous 0 checks, timeout, truncation, failure text, no artifacts, non-zero exit, failed check) alone flips ADMITTED to REJECTED" },
  { slot: 126, target: EVD, expected: { parsed: true, verdict: "ADMITTED", digestLen: 64, artifactSha: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" },
    run: async (m) => { const { executeTask } = await import("../../../kratt/actions.ts"); const res = await executeTask(root({ "a.txt": "hello" }), A); const ev = m.produceEvidence(A, res); const p = m.parseEvidence(m.evidenceToArtifact(ev).content); return { parsed: p.ok, verdict: p.evidence.verdict, digestLen: p.evidence.evidenceDigest.length, artifactSha: p.evidence.artifacts[0].sha256 }; },
    claim: "evidence produced from a real execution survives the strict parser round-trip with the real file hash inside" },
  { slot: 127, target: EVD, expected: { ok: false, reason: "evidence-digest-mismatch" },
    run: async (m) => { const { executeTask } = await import("../../../kratt/actions.ts"); const ev = m.produceEvidence(A, await executeTask(root({ "a.txt": "hello" }), A)); const c = m.evidenceToArtifact(ev).content.replace('"bytes":5', '"bytes":6'); return m.parseEvidence(c); },
    claim: "changing one recorded value (bytes 5 -> 6) without recomputing the digest is caught by evidenceDigest" },
  { slot: 128, target: EVD, expected: { ok: false, reason: "evidence-not-canonical" },
    run: async (m) => { const { executeTask } = await import("../../../kratt/actions.ts"); const ev = m.produceEvidence(A, await executeTask(root({ "a.txt": "hello" }), A)); return m.parseEvidence(JSON.stringify(ev, null, 2)); },
    claim: "pretty-printed (non-canonical) but otherwise valid evidence is rejected" },
  { slot: 129, target: EVD, expected: [true, false, true],
    run: (m) => { const g = new m.ReplayGuard(); return [g.consume("d1"), g.consume("d1"), g.consume("d2")]; },
    claim: "the replay guard admits a digest once, refuses its repeat, and still admits a different digest" },
];
