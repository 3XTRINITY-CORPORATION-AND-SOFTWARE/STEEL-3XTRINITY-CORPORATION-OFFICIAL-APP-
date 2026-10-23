import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalize, verifyReceipt } from "../../cerberus/core/decide.ts";
import { stubAdapter } from "../../cerberus/integrations/verdict-adapters.ts";
import { evidenceToArtifact, parseEvidence, ReplayGuard, type ToeparaEvidence } from "../evidence.ts";
import { gateArtifact, runKrattTask, type KrattDeps } from "../run.ts";
import { validateTask } from "../task.ts";

const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const temps: string[] = [];
after(() => temps.forEach((t) => rmSync(t, { recursive: true, force: true })));

function fixtureRoot(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "kratt-"));
  temps.push(root);
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), content);
  }
  return root;
}
const AUTH = stubAdapter("trust-gate", "AUTHORIZED");
const deps = (root: string, over: Partial<KrattDeps> = {}): KrattDeps => ({
  root,
  trustGate: AUTH,
  guard: new ReplayGuard(),
  ...over,
});
const hashTask = (files: string[], taskId = "t1") => ({ taskId, action: "hash-files", files });
const testTask = (testFile: string, over: Record<string, unknown> = {}) => ({
  taskId: "rt1",
  action: "run-test",
  testFile,
  timeoutMs: 20_000,
  maxOutputBytes: 65_536,
  ...over,
});

describe("task schema (fail closed)", () => {
  it("accepts one valid task per allow-listed action", () => {
    assert.ok(validateTask(hashTask(["a/b.txt"])).ok);
    assert.ok(validateTask({ taskId: "m", action: "validate-manifest", manifest: "m.json" }).ok);
    assert.ok(validateTask(testTask("kratt/tests/x.test.ts")).ok);
  });

  it("rejects disallowed actions (incl. shell/exec style)", () => {
    for (const action of ["exec", "shell", "write-file", "hash-files ", "HASH-FILES", "", 1, null, {}]) {
      const r = validateTask({ taskId: "t", action, files: ["a"] });
      assert.equal(r.ok, false, String(action));
    }
  });

  it("rejects path traversal / absolute / hidden / odd paths", () => {
    const bad = ["../x", "a/../b", "/etc/passwd", "a//b", "a\\b", "a\0b", ".env", ".git/config", "a/.hidden", "./a", "a/", "C:/x", "a b", "a;rm", "", "x".repeat(201), 5, null, ["a"]];
    for (const p of bad) assert.equal(validateTask(hashTask([p as string])).ok, false, JSON.stringify(p));
    assert.equal(validateTask({ taskId: "m", action: "validate-manifest", manifest: "../m.json" }).ok, false);
    assert.equal(validateTask(testTask("../kratt/tests/x.test.ts")).ok, false);
  });

  it("rejects malformed tasks: non-objects, missing/extra keys, bad ids, accessors, Proxy", () => {
    for (const t of [null, undefined, 1, "x", [], () => 1, new Map()]) assert.equal(validateTask(t).ok, false);
    assert.equal(validateTask({ action: "hash-files", files: ["a"] }).ok, false);
    assert.equal(validateTask({ ...hashTask(["a"]), cmd: "rm -rf /" }).ok, false);
    assert.equal(validateTask({ ...testTask("kratt/tests/x.test.ts"), env: { A: "1" } }).ok, false);
    for (const id of ["", "UP", "a b", "-a", "a".repeat(65), "a/b"]) assert.equal(validateTask(hashTask(["a"], id)).ok, false, id);
    const acc = { taskId: "t", action: "hash-files" } as Record<string, unknown>;
    Object.defineProperty(acc, "files", { enumerable: true, get: () => ["a"] });
    assert.equal(validateTask(acc).ok, false);
    const px = new Proxy({}, { ownKeys() { throw new Error("boom"); }, getOwnPropertyDescriptor() { throw new Error("boom"); } });
    assert.equal(validateTask(px).ok, false);
    assert.equal(validateTask(hashTask([])).ok, false);
    assert.equal(validateTask(hashTask(Array.from({ length: 65 }, (_, i) => `f${i}`))).ok, false);
    assert.equal(validateTask(hashTask(["a", "a"])).ok, false);
    const sparse = ["a", , "b"] as unknown as string[]; // eslint-disable-line no-sparse-arrays
    assert.equal(validateTask(hashTask(sparse)).ok, false);
    assert.equal(validateTask(testTask("kratt/tests/x.txt")).ok, false);
  });

  it("rejects non-finite / non-integer / out-of-range numbers", () => {
    for (const v of [NaN, Infinity, -Infinity, 1.5, -1, 0, 99, 60_001, "1000", null, 2 ** 53, undefined])
      assert.equal(validateTask(testTask("kratt/tests/x.test.ts", { timeoutMs: v })).ok, false, `timeoutMs=${String(v)}`);
    for (const v of [NaN, Infinity, 0, 1023, 1_048_577, 1.2, "5000"])
      assert.equal(validateTask(testTask("kratt/tests/x.test.ts", { maxOutputBytes: v })).ok, false, `maxOutputBytes=${String(v)}`);
  });
});

describe("hash-files: execution -> TÖEPÄRA evidence -> Cerberus", () => {
  const files = { "src/a.txt": "alpha", "src/b.txt": "bravo\n" };

  it("PROCEEDs with evidence whose SHA-256s equal independently computed hashes", async () => {
    const root = fixtureRoot(files);
    const o = await runKrattTask(hashTask(["src/b.txt", "src/a.txt"]), deps(root));
    assert.equal(o.receipt.decision, "PROCEED");
    assert.equal(o.receipt.verdictSource, "adapter");
    assert.ok(Object.values(o.receipt.stages).every((s) => s === "PASS"));
    assert.ok(verifyReceipt(o.receipt));
    const ev = o.evidence!;
    assert.equal(ev.verdict, "ADMITTED");
    assert.equal(ev.exitCode, 0);
    assert.deepEqual(ev.artifacts, [
      { name: "src/a.txt", sha256: sha("alpha"), bytes: 5 },
      { name: "src/b.txt", sha256: sha("bravo\n"), bytes: 6 },
    ]);
    assert.deepEqual(ev.command, ["in-process:hash-files"]);
    // the receipt records the digest of the exact evidence document it decided on
    assert.equal(o.receipt.evidence.artifact?.computedSha256, evidenceToArtifact(ev).sha256);
  });

  it("is deterministic: same task + same files + fresh guard => identical receipt, no timestamps", async () => {
    const root = fixtureRoot(files);
    const a = await runKrattTask(hashTask(["src/a.txt"]), deps(root));
    const b = await runKrattTask(hashTask(["src/a.txt"]), deps(root));
    assert.deepEqual(a.receipt, b.receipt);
    assert.equal(a.receipt.receiptDigest, b.receipt.receiptDigest);
    assert.doesNotMatch(JSON.stringify(a.receipt) + JSON.stringify(a.evidence), /\d{4}-\d\d-\d\dT|"(ts|time|timestamp|date)"/i);
  });

  it("DENIES a replayed evidence document (same guard)", async () => {
    const root = fixtureRoot(files);
    const d = deps(root);
    const first = await runKrattTask(hashTask(["src/a.txt"]), d);
    const second = await runKrattTask(hashTask(["src/a.txt"]), d);
    assert.equal(first.receipt.decision, "PROCEED");
    assert.equal(second.receipt.decision, "FAIL_CLOSED");
    assert.equal(second.toeparaReason, "replayed-evidence");
    assert.equal(second.receipt.stages.toepara, "FAIL");
    // directly re-presenting the first artifact is also a replay
    const g = gateArtifact(evidenceToArtifact(first.evidence!), d);
    assert.equal(g.receipt.decision, "FAIL_CLOSED");
    assert.equal(g.toeparaReason, "replayed-evidence");
  });

  it("DENIES a missing file, a symlink escaping the root, and an oversized file", async () => {
    const root = fixtureRoot({ "ok.txt": "x" });
    const outside = fixtureRoot({ "secret.txt": "top secret" });
    symlinkSync(join(outside, "secret.txt"), join(root, "link.txt"));
    writeFileSync(join(root, "big.bin"), Buffer.alloc(8 * 1024 * 1024 + 1));
    for (const [f, why] of [["nope.txt", "path-not-found"], ["link.txt", "path-escapes-root"], ["big.bin", "file-too-large"]] as const) {
      const o = await runKrattTask(hashTask([f]), deps(root));
      assert.equal(o.receipt.decision, "FAIL_CLOSED", f);
      assert.match(o.evidence!.failure ?? "", new RegExp(why));
      assert.equal(o.evidence!.verdict, "REJECTED");
    }
  });

  it("DENIES an invalid task without executing anything (receipt still produced)", async () => {
    const root = fixtureRoot(files);
    const o = await runKrattTask({ taskId: "t", action: "exec", cmd: "id" }, deps(root));
    assert.equal(o.receipt.decision, "FAIL_CLOSED");
    assert.equal(o.evidence, null);
    assert.match(o.receipt.reasons[0], /^kratt-task-invalid:/);
    assert.ok(verifyReceipt(o.receipt));
  });
});

describe("validate-manifest", () => {
  const body = { "a.txt": "A", "d/b.txt": "B" };
  const manifest = (over: Record<string, unknown> = {}) =>
    JSON.stringify({ version: 1, files: [{ path: "a.txt", sha256: sha("A") }, { path: "d/b.txt", sha256: sha("B") }], ...over });
  const task = { taskId: "m1", action: "validate-manifest", manifest: "m.json" };

  it("PROCEEDs when every declared hash matches; evidence includes manifest + files", async () => {
    const root = fixtureRoot({ ...body, "m.json": manifest() });
    const o = await runKrattTask(task, deps(root));
    assert.equal(o.receipt.decision, "PROCEED");
    assert.deepEqual(o.evidence!.checks, { pass: 2, fail: 0 });
    assert.deepEqual(o.evidence!.artifacts.map((a) => a.name), ["a.txt", "d/b.txt", "m.json"]);
  });

  it("DENIES on a hash mismatch, bad JSON, unknown keys, wrong version, malformed digest, duplicate entry", async () => {
    const cases: Record<string, string> = {
      "sha256-mismatch": manifest({ files: [{ path: "a.txt", sha256: sha("tampered") }] }),
      "manifest-invalid-json": "{not json",
      "manifest-unexpected-keys": manifest({ extra: 1 }),
      "manifest-version-unsupported": manifest({ version: 2 }),
      "manifest-entry-digest-malformed": manifest({ files: [{ path: "a.txt", sha256: "ABC" }] }),
      "manifest-lists-itself-or-duplicate": manifest({ files: [{ path: "a.txt", sha256: sha("A") }, { path: "a.txt", sha256: sha("A") }] }),
    };
    for (const [why, m] of Object.entries(cases)) {
      const root = fixtureRoot({ ...body, "m.json": m });
      const o = await runKrattTask(task, deps(root));
      assert.equal(o.receipt.decision, "FAIL_CLOSED", why);
      assert.match(o.evidence!.failure ?? "", new RegExp(why), why);
    }
  });
});

describe("run-test: allow-listed, bounded subprocess", () => {
  const T = "kratt/tests/";
  const pass = `import {test} from "node:test"; import assert from "node:assert/strict";
test("env is empty", () => { assert.equal(process.env.HOME, undefined); assert.equal(process.env.PATH, undefined); });
test("second", () => assert.equal(1 + 1, 2));`;

  it("PROCEEDs for a passing test; evidence has command, exit code, output digests, test file SHA-256", async () => {
    const root = fixtureRoot({ [`${T}p.test.mjs`]: pass });
    const o = await runKrattTask(testTask(`${T}p.test.mjs`), deps(root));
    assert.equal(o.receipt.decision, "PROCEED", JSON.stringify(o.evidence));
    const ev = o.evidence!;
    assert.equal(ev.exitCode, 0);
    assert.deepEqual(ev.checks, { pass: 2, fail: 0 });
    assert.deepEqual(ev.artifacts, [{ name: `${T}p.test.mjs`, sha256: sha(pass), bytes: pass.length }]);
    assert.equal(ev.command[0], "node");
    assert.deepEqual(ev.command.slice(1), ["--permission", "--allow-fs-read=<root>", "--experimental-test-isolation=none", "--experimental-strip-types", "--test-reporter=tap", "--test", `${T}p.test.mjs`]);
    assert.match(ev.stdoutSha256, /^[0-9a-f]{64}$/);
    assert.ok(ev.outputBytes > 0);
  });

  it("DENIES a failing test (exit code != 0 recorded)", async () => {
    const root = fixtureRoot({ [`${T}f.test.mjs`]: `import {test} from "node:test"; test("x", () => { throw new Error("no"); });` });
    const o = await runKrattTask(testTask(`${T}f.test.mjs`), deps(root));
    assert.equal(o.receipt.decision, "FAIL_CLOSED");
    assert.notEqual(o.evidence!.exitCode, 0);
    assert.equal(o.evidence!.verdict, "REJECTED");
    assert.equal(o.evidence!.failure, "nonzero-exit");
  });

  it("DENIES a file that runs zero tests (vacuous exit 0)", async () => {
    const root = fixtureRoot({ [`${T}z.test.mjs`]: "// no tests\n" });
    const o = await runKrattTask(testTask(`${T}z.test.mjs`), deps(root));
    assert.equal(o.receipt.decision, "FAIL_CLOSED");
    assert.equal(o.evidence!.failure, "no-tests-ran");
  });

  it("kills and DENIES on timeout", async () => {
    const root = fixtureRoot({ [`${T}t.test.mjs`]: `import {test} from "node:test"; test("spin", () => { for(;;){} });` });
    const t0 = Date.now();
    const o = await runKrattTask(testTask(`${T}t.test.mjs`, { timeoutMs: 400 }), deps(root));
    assert.ok(Date.now() - t0 < 10_000);
    assert.equal(o.receipt.decision, "FAIL_CLOSED");
    assert.equal(o.evidence!.timedOut, true);
    assert.equal(o.evidence!.failure, "timeout");
  });

  it("kills and DENIES on oversized output (cap enforced)", async () => {
    const root = fixtureRoot({ [`${T}o.test.mjs`]: `import {test} from "node:test"; test("flood", () => { const s="x".repeat(65536); for(let i=0;i<500;i++) process.stdout.write(s); });` });
    const o = await runKrattTask(testTask(`${T}o.test.mjs`, { maxOutputBytes: 2048 }), deps(root));
    assert.equal(o.receipt.decision, "FAIL_CLOSED");
    assert.equal(o.evidence!.truncated, true);
    assert.ok(o.evidence!.outputBytes <= 2048);
    assert.equal(o.evidence!.failure, "output-cap-exceeded");
  });

  it("sandbox: writes and child processes are denied (permission model), nothing is created", async () => {
    const root = fixtureRoot({
      [`${T}w.test.mjs`]: `import fs from "node:fs"; import {test} from "node:test";
test("write", () => { fs.writeFileSync(new URL("../../pwned.txt", import.meta.url), "x"); });`,
      [`${T}c.test.mjs`]: `import cp from "node:child_process"; import {test} from "node:test";
test("spawn", () => { cp.execSync("echo hi"); });`,
      [`${T}r.test.mjs`]: `import fs from "node:fs"; import {test} from "node:test";
test("read outside root", () => { fs.readFileSync("/etc/hostname"); });`,
    });
    for (const f of ["w", "c", "r"]) {
      const o = await runKrattTask(testTask(`${T}${f}.test.mjs`), deps(root));
      assert.equal(o.receipt.decision, "FAIL_CLOSED", f);
    }
    assert.equal(existsSync(join(root, "pwned.txt")), false);
  });

  it("DENIES test files outside the allow-listed directories and non-matching paths", async () => {
    const root = fixtureRoot({ "scripts/x.test.mjs": pass });
    const o = await runKrattTask(testTask("scripts/x.test.mjs"), deps(root));
    assert.equal(o.receipt.decision, "FAIL_CLOSED");
    assert.equal(o.evidence!.failure, "test-dir-not-allowed");
    const o2 = await runKrattTask(testTask(`${T}missing.test.mjs`), deps(root));
    assert.equal(o2.receipt.decision, "FAIL_CLOSED");
  });

  it("REAL repo run: cerberus/tests/decide.test.ts PROCEEDs with real evidence", async () => {
    const o = await runKrattTask(testTask("cerberus/tests/decide.test.ts"), deps(REPO_ROOT));
    assert.equal(o.receipt.decision, "PROCEED", JSON.stringify(o.evidence));
    assert.ok(o.evidence!.checks.pass >= 1);
    assert.equal(o.evidence!.checks.fail, 0);
    assert.equal(o.evidence!.artifacts[0].name, "cerberus/tests/decide.test.ts");
    assert.match(o.evidence!.artifacts[0].sha256, /^[0-9a-f]{64}$/);
  });
});

describe("Cerberus integration: TÖEPÄRA / Trust Gate cannot be bypassed", () => {
  async function good() {
    const root = fixtureRoot({ "a.txt": "A" });
    const o = await runKrattTask(hashTask(["a.txt"]), deps(root));
    assert.equal(o.receipt.decision, "PROCEED");
    return o.evidence!;
  }
  const art = (content: string) => ({ name: "toepara-evidence-t1.json", content, sha256: sha(content) });
  const reseal = (ev: ToeparaEvidence, mut: (e: Record<string, unknown>) => void, fixDigest: boolean) => {
    const e = JSON.parse(JSON.stringify(ev)) as Record<string, unknown>;
    mut(e);
    if (fixDigest) {
      const { evidenceDigest: _d, ...body } = e;
      e.evidenceDigest = sha(canonicalize(body));
    }
    return canonicalize(e);
  };
  const gate = (a: { name: string; content: string; sha256: string }) => gateArtifact(a, deps(REPO_ROOT));

  it("Trust Gate denial or absence => FAIL_CLOSED even with ADMITTED evidence", async () => {
    const ev = await good();
    const denied = gateArtifact(evidenceToArtifact(ev), deps(REPO_ROOT, { trustGate: stubAdapter("tg", "DENIED") }));
    assert.equal(denied.receipt.decision, "FAIL_CLOSED");
    assert.deepEqual(denied.receipt.reasons, ["trust-gate-not-authorized"]);
    const absent = gateArtifact(evidenceToArtifact(ev), { guard: new ReplayGuard(), trustGate: undefined as never });
    assert.equal(absent.receipt.decision, "FAIL_CLOSED");
    const throwing = gateArtifact(evidenceToArtifact(ev), deps(REPO_ROOT, { trustGate: { name: "x", verdict: () => { throw new Error("down"); } } }));
    assert.equal(throwing.receipt.decision, "FAIL_CLOSED");
  });

  it("missing / non-evidence artifact => TÖEPÄRA rejects => FAIL_CLOSED", () => {
    for (const content of ["", "{}", "[]", "null", "not json", "A".repeat(300_000)]) {
      const g = gate(art(content));
      assert.equal(g.receipt.decision, "FAIL_CLOSED", content.slice(0, 20));
      assert.equal(g.receipt.stages.toepara, "FAIL");
    }
  });

  it("tampered evidence content with stale declared SHA => artifact trust + TÖEPÄRA both fail", async () => {
    const ev = await good();
    const content = reseal(ev, (e) => { e.exitCode = 0; e.failure = null; e.checks = { pass: 9, fail: 0 }; }, false);
    const g = gate({ name: "toepara-evidence-t1.json", content, sha256: evidenceToArtifact(ev).sha256 });
    assert.equal(g.receipt.decision, "FAIL_CLOSED");
    assert.equal(g.receipt.stages.artifactTrust, "FAIL");
    assert.ok(g.receipt.reasons.includes("artifact-digest-mismatch"));
  });

  it("tampered evidence with re-declared SHA but stale evidenceDigest => rejected", async () => {
    const ev = await good();
    const g = gate(art(reseal(ev, (e) => { e.checks = { pass: 99, fail: 0 }; }, false)));
    assert.equal(g.receipt.decision, "FAIL_CLOSED");
    assert.equal(g.toeparaReason, "evidence-digest-mismatch");
  });

  it("flipping a REJECTED verdict to ADMITTED (digests recomputed) => verdict not derivable from facts", async () => {
    const root = fixtureRoot({});
    const bad = await runKrattTask(hashTask(["missing.txt"]), deps(root));
    assert.equal(bad.evidence!.verdict, "REJECTED");
    const g = gate(art(reseal(bad.evidence!, (e) => { e.verdict = "ADMITTED"; }, true)));
    assert.equal(g.receipt.decision, "FAIL_CLOSED");
    assert.equal(g.toeparaReason, "evidence-verdict-not-derivable-from-facts");
  });

  it("non-finite numbers in evidence => rejected (NaN/Infinity serialise to null)", async () => {
    const ev = await good();
    for (const [key, val] of [["exitCode", NaN], ["outputBytes", Infinity], ["checks", { pass: NaN, fail: 0 }]] as const) {
      const e = { ...ev, [key]: val } as Record<string, unknown>;
      const g = gate(art(canonicalize(e))); // canonical JSON turns NaN into null
      assert.equal(g.receipt.decision, "FAIL_CLOSED", key);
      assert.equal(g.receipt.stages.toepara, "FAIL");
    }
    assert.equal(parseEvidence(canonicalize(ev).replace('"exitCode":0', '"exitCode":1e400')).ok, false);
  });

  it("non-canonical (pretty-printed), extra-key, or unsorted-artifact evidence => rejected", async () => {
    const ev = await good();
    assert.equal(gate(art(JSON.stringify(ev, null, 2))).toeparaReason, "evidence-not-canonical");
    assert.equal(gate(art(reseal(ev, (e) => { e.extra = 1; }, true))).toeparaReason, "evidence-unexpected-keys");
    const two = { ...ev, artifacts: [{ name: "b", sha256: sha("b"), bytes: 1 }, { name: "a", sha256: sha("a"), bytes: 1 }] };
    assert.equal(gate(art(reseal(two as ToeparaEvidence, () => {}, true))).toeparaReason, "evidence-artifacts-unsorted-or-duplicate");
  });

  it("LIMITATION (documented, not a defence): fully re-forged + re-hashed evidence is accepted — origin is unsigned", async () => {
    const root = fixtureRoot({});
    const bad = await runKrattTask(hashTask(["missing.txt"]), deps(root));
    const forged = reseal(
      bad.evidence!,
      (e) => {
        e.exitCode = 0; e.failure = null; e.checks = { pass: 1, fail: 0 }; e.verdict = "ADMITTED";
        e.artifacts = [{ name: "missing.txt", sha256: sha("x"), bytes: 1 }];
      },
      true,
    );
    const g = gate(art(forged));
    assert.equal(g.receipt.decision, "PROCEED"); // proves why SLICE.md says: no signature => no origin proof
  });

  it("caller-supplied verdict strings are impossible to inject through the KRATT pipeline", async () => {
    const root = fixtureRoot({});
    const o = await runKrattTask({ ...hashTask(["missing.txt"]), toepara: "ADMITTED", trustGate: "AUTHORIZED" }, deps(root));
    assert.equal(o.receipt.decision, "FAIL_CLOSED"); // extra keys rejected by the closed schema
    assert.equal(o.evidence, null);
  });
});
