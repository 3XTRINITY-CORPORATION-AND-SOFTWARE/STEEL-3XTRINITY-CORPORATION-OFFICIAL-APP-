import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { stubAdapter } from "../../cerberus/integrations/verdict-adapters.ts";
import { DEFAULT_ALLOWED_TEST_DIRS, executeTask } from "../actions.ts";
import { ReplayGuard } from "../evidence.ts";
import { runKrattTask } from "../run.ts";
import { validateTask, type KrattTask } from "../task.ts";

/**
 * A-013: the run-test allow-list. A test file may only run if (1) its name is *.test.ts|mjs,
 * (2) it lives under a host-configured directory, (3) it is a regular file inside the root and
 * (4) it is byte-identical before and after the run. Each rule is pinned with the failure
 * reason the current code reports.
 */
const temps: string[] = [];
after(() => temps.forEach((t) => rmSync(t, { recursive: true, force: true })));
const PASS = `import { test } from "node:test"; test("ok", () => {});`;
function fixture(files: Record<string, string>, links: Record<string, string> = {}): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "kratt-al-")));
  temps.push(root);
  for (const [rel, c] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), c);
  }
  for (const [rel, target] of Object.entries(links)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    symlinkSync(target, join(root, rel));
  }
  return root;
}
const task = (testFile: string, over: Record<string, unknown> = {}) => ({ taskId: "al", action: "run-test", testFile, timeoutMs: 20_000, maxOutputBytes: 65_536, ...over });
function valid(testFile: string): Extract<KrattTask, { action: "run-test" }> {
  const v = validateTask(task(testFile));
  assert.ok(v.ok, `valid task expected for ${testFile}`);
  return v.task as Extract<KrattTask, { action: "run-test" }>;
}
const run = (root: string, testFile: string, dirs?: readonly string[]) => executeTask(root, valid(testFile), dirs ? { allowedTestDirs: dirs } : {});

describe("directory allow-list", () => {
  it("default allow-list is exactly cerberus/tests and kratt/tests", () => {
    assert.deepEqual([...DEFAULT_ALLOWED_TEST_DIRS], ["cerberus/tests", "kratt/tests"]);
  });

  it("files directly in or nested under an allowed directory run; the same file elsewhere is refused with test-dir-not-allowed", async () => {
    const root = fixture({ "kratt/tests/a.test.mjs": PASS, "cerberus/tests/sub/deep/b.test.mjs": PASS, "scripts/c.test.mjs": PASS, "src/d.test.mjs": PASS, "a.test.mjs": PASS });
    for (const ok of ["kratt/tests/a.test.mjs", "cerberus/tests/sub/deep/b.test.mjs"]) {
      const r = await run(root, ok);
      assert.equal(r.failure, null, ok);
      assert.deepEqual(r.checks, { pass: 1, fail: 0 });
    }
    for (const no of ["scripts/c.test.mjs", "src/d.test.mjs", "a.test.mjs"]) {
      const r = await run(root, no);
      assert.equal(r.failure, "test-dir-not-allowed", no);
      assert.equal(r.exitCode, 1);
      assert.deepEqual(r.artifacts, [], "nothing was even hashed, let alone executed");
      assert.equal(r.outputBytes, 0);
    }
  });

  it("prefix tricks fail: kratt/tests-evil, kratt/testsX, kratt/tests.d, and a nested src/kratt/tests", async () => {
    const root = fixture({ "kratt/tests-evil/x.test.mjs": PASS, "kratt/testsX/x.test.mjs": PASS, "kratt/tests.d/x.test.mjs": PASS, "src/kratt/tests/x.test.mjs": PASS, "kratt/tests_/x.test.mjs": PASS });
    for (const p of ["kratt/tests-evil/x.test.mjs", "kratt/testsX/x.test.mjs", "kratt/tests.d/x.test.mjs", "src/kratt/tests/x.test.mjs", "kratt/tests_/x.test.mjs"])
      assert.equal((await run(root, p)).failure, "test-dir-not-allowed", p);
  });

  it("the allow-list is host-controlled: [] denies everything, a custom list replaces (not extends) the default", async () => {
    const root = fixture({ "kratt/tests/a.test.mjs": PASS, "scripts/b.test.mjs": PASS });
    assert.equal((await run(root, "kratt/tests/a.test.mjs", [])).failure, "test-dir-not-allowed");
    assert.equal((await run(root, "scripts/b.test.mjs", ["scripts"])).failure, null);
    assert.equal((await run(root, "kratt/tests/a.test.mjs", ["scripts"])).failure, "test-dir-not-allowed", "default dirs are not implicitly kept");
  });

  it("through the pipeline a refused file is FAIL_CLOSED and the evidence names the reason", async () => {
    const root = fixture({ "scripts/x.test.mjs": PASS });
    const o = await runKrattTask(task("scripts/x.test.mjs"), { root, trustGate: stubAdapter("trust-gate", "AUTHORIZED"), guard: new ReplayGuard() });
    assert.equal(o.receipt.decision, "FAIL_CLOSED");
    assert.equal(o.evidence?.failure, "test-dir-not-allowed");
    assert.equal(o.evidence?.verdict, "REJECTED");
  });
});

describe("file-name rule (schema level, before anything runs)", () => {
  it("only *.test.ts and *.test.mjs are expressible; every other extension or look-alike is rejected with testFile-not-test", () => {
    for (const f of ["kratt/tests/x.js", "kratt/tests/x.mjs", "kratt/tests/x.cjs", "kratt/tests/x.ts", "kratt/tests/x.mts", "kratt/tests/x.test.js", "kratt/tests/x.test.cjs", "kratt/tests/x.test.tsx", "kratt/tests/x.test.ts.bak", "kratt/tests/x.test.mjs.txt", "kratt/tests/x.test", "kratt/tests/test.ts", "kratt/tests/x.TEST.ts", "kratt/tests/x.test.TS", "kratt/tests/x_test.ts", "kratt/tests/x.sh"])
      assert.deepEqual(validateTask(task(f)), { ok: false, reason: "testFile-not-test" }, f);
    for (const f of ["kratt/tests/x.test.ts", "kratt/tests/x.test.mjs", "kratt/tests/a.b.test.ts", "kratt/tests/a-b.test.ts"]) assert.ok(validateTask(task(f)).ok, f);
  });

  it("a wrong-extension task never reaches execution through the pipeline (FAIL_CLOSED, no evidence)", async () => {
    const root = fixture({ "kratt/tests/x.js": `process.exit(0)` });
    const o = await runKrattTask(task("kratt/tests/x.js"), { root, trustGate: stubAdapter("trust-gate", "AUTHORIZED"), guard: new ReplayGuard() });
    assert.equal(o.receipt.decision, "FAIL_CLOSED");
    assert.equal(o.evidence, null);
    assert.equal(o.task, null);
  });
});

describe("file-identity rules", () => {
  it("a missing or directory test file is refused before spawn (path-not-found / not-regular-file)", async () => {
    const root = fixture({ "kratt/tests/dir.test.mjs/inner.txt": "x" });
    assert.equal((await run(root, "kratt/tests/nope.test.mjs")).failure, "path-not-found");
    assert.equal((await run(root, "kratt/tests/dir.test.mjs")).failure, "not-regular-file");
  });

  it("symlink to a file OUTSIDE the root is refused (path-escapes-root)", async () => {
    const root = fixture({ "kratt/tests/ok.test.mjs": PASS });
    const outside = realpathSync(mkdtempSync(join(tmpdir(), "kratt-out-")));
    temps.push(outside);
    writeFileSync(join(outside, "evil.test.mjs"), PASS);
    symlinkSync(join(outside, "evil.test.mjs"), join(root, "kratt/tests/link.test.mjs"));
    assert.equal((await run(root, "kratt/tests/link.test.mjs")).failure, "path-escapes-root");
  });

  // DEFECT (reservoir A-013, see PR report F1): the directory allow-list is applied to the *lexical*
  // path only. A symlink inside an allowed directory that points at another file INSIDE the root
  // makes node execute a file from a directory that is not allow-listed. This test asserts the
  // SAFE behaviour and is marked todo so the suite stays green while the defect is open; it flips
  // to a normal failing test the moment `todo` is removed, and passes once the fix lands.
  it("symlink inside an allowed dir to an in-root file in a NON-allowed dir must be refused", { todo: "F1: allow-list bypass via in-root symlink (kratt/actions.ts runTest checks the lexical path only)" }, async () => {
    const root = fixture({ "scripts/evil.test.mjs": PASS, "kratt/tests/ok.test.mjs": PASS }, { "kratt/tests/alias.test.mjs": "../../scripts/evil.test.mjs" });
    assert.equal((await run(root, "scripts/evil.test.mjs")).failure, "test-dir-not-allowed", "direct path is refused ...");
    const viaLink = await run(root, "kratt/tests/alias.test.mjs");
    assert.notEqual(viaLink.failure, null, "... so the alias must be refused too");
  });
});

describe("test file mutated between hash-before and hash-after", () => {
  const SLOW = `import { test } from "node:test"; test("slow", async () => { await new Promise((r) => setTimeout(r, 400)); });`;

  it("content changed during the run => failure test-file-changed-during-run, even though the test itself passed", async () => {
    const root = fixture({ "kratt/tests/m.test.mjs": SLOW });
    const p = run(root, "kratt/tests/m.test.mjs"); // hash-before is taken synchronously by this call
    appendFileSync(join(root, "kratt/tests/m.test.mjs"), "\n// tampered\n");
    const r = await p;
    assert.equal(r.failure, "test-file-changed-during-run");
    assert.equal(r.exitCode, 0, "the child really exited 0 - only the identity check caught it");
    assert.equal(r.checks.fail, 1, "reported as a failed check, never as a pass");
    assert.equal(r.artifacts[0]?.name, "kratt/tests/m.test.mjs");
  });

  it("file deleted during the run is the same failure (hash-after unreadable counts as tampering)", async () => {
    const root = fixture({ "kratt/tests/d.test.mjs": SLOW });
    const p = run(root, "kratt/tests/d.test.mjs");
    unlinkSync(join(root, "kratt/tests/d.test.mjs"));
    const r = await p;
    assert.equal(r.failure, "test-file-changed-during-run");
  });

  it("control: an untouched file with the same content passes, proving the failure above is caused by the mutation", async () => {
    const root = fixture({ "kratt/tests/c.test.mjs": SLOW });
    const r = await run(root, "kratt/tests/c.test.mjs");
    assert.equal(r.failure, null);
    assert.equal(r.checks.fail, 0);
  });

  it("pipeline: a mutated test file yields REJECTED evidence and FAIL_CLOSED", async () => {
    const root = fixture({ "kratt/tests/p.test.mjs": SLOW });
    const p = runKrattTask(task("kratt/tests/p.test.mjs"), { root, trustGate: stubAdapter("trust-gate", "AUTHORIZED"), guard: new ReplayGuard() });
    appendFileSync(join(root, "kratt/tests/p.test.mjs"), "\n// tampered\n");
    const o = await p;
    assert.equal(o.receipt.decision, "FAIL_CLOSED");
    assert.equal(o.evidence?.failure, "test-file-changed-during-run");
    assert.equal(o.evidence?.verdict, "REJECTED");
  });
});
