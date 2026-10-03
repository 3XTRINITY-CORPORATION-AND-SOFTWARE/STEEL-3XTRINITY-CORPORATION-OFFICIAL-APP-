import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { executeTask, type ActionResult } from "../actions.ts";
import { validateTask } from "../task.ts";

/**
 * A-016: validate-manifest strict-parse negatives. Manifest schema (kratt/actions.ts):
 * { "version": 1, "files": [ { "path": <rel>, "sha256": <lowercase hex64> } ... ] }, closed at both levels,
 * 1..64 entries. Every negative asserts the exact failure string and that the run is a failure (exit 1).
 */
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const temps: string[] = [];
after(() => temps.forEach((t) => rmSync(t, { recursive: true, force: true })));
const A = "alpha";
const GOOD = sha(A);

function root(files: Record<string, string> = {}): string {
  const r = realpathSync(mkdtempSync(join(tmpdir(), "kratt-mn-")));
  temps.push(r);
  for (const [rel, c] of Object.entries({ "a.txt": A, ...files })) {
    mkdirSync(dirname(join(r, rel)), { recursive: true });
    writeFileSync(join(r, rel), c);
  }
  return r;
}
async function validateManifest(rawManifest: string | object, extra: Record<string, string> = {}): Promise<{ r: ActionResult; root: string }> {
  const dir = root(extra);
  writeFileSync(join(dir, "m.json"), typeof rawManifest === "string" ? rawManifest : JSON.stringify(rawManifest));
  const v = validateTask({ taskId: "mn", action: "validate-manifest", manifest: "m.json" });
  assert.ok(v.ok);
  return { r: await executeTask(dir, v.task), root: dir };
}
const entry = (over: Record<string, unknown> = {}) => ({ path: "a.txt", sha256: GOOD, ...over });
const man = (over: Record<string, unknown> = {}) => ({ version: 1, files: [entry()], ...over });

describe("validate-manifest: positive control", () => {
  it("a well-formed manifest passes, and the manifest file itself is bound into the evidence by raw-byte SHA-256", async () => {
    const text = JSON.stringify(man());
    const { r } = await validateManifest(text);
    assert.equal(r.failure, null);
    assert.equal(r.exitCode, 0);
    assert.deepEqual(r.checks, { pass: 1, fail: 0 });
    assert.deepEqual(r.artifacts.map((a) => [a.name, a.sha256]), [["a.txt", GOOD], ["m.json", sha(text)]]);
  });
});

describe("validate-manifest: strict-parse negatives (each => failure, exit 1, no verification counted)", () => {
  const cases: [string, string | object, string][] = [
    // ---- not JSON / wrong top level
    ["empty file", "", "manifest-invalid-json"],
    ["not JSON", "version: 1", "manifest-invalid-json"],
    ["trailing comma", '{"version":1,"files":[],}', "manifest-invalid-json"],
    ["UTF-8 BOM prefix", "\uFEFF" + JSON.stringify(man()), "manifest-invalid-json"],
    ["top-level array", "[]", "manifest-not-object"],
    ["top-level null", "null", "manifest-not-object"],
    ["top-level string", '"x"', "manifest-not-object"],
    ["top-level number", "1", "manifest-not-object"],
    // ---- key set (closed)
    ["missing version", { files: [entry()] }, "manifest-unexpected-keys"],
    ["missing files", { version: 1 }, "manifest-unexpected-keys"],
    ["extra top-level key", { ...man(), note: "x" }, "manifest-unexpected-keys"],
    ["extra top-level key that looks harmless (_comment)", { ...man(), _comment: "x" }, "manifest-unexpected-keys"],
    ["own __proto__ key (JSON.parse creates it as data)", '{"__proto__":{"version":1},"version":1,"files":[]}', "manifest-unexpected-keys"],
    ["case-variant key (Version)", { Version: 1, files: [entry()] }, "manifest-unexpected-keys"],
    // ---- version
    ["version 0", man({ version: 0 }), "manifest-version-unsupported"],
    ["version 2", man({ version: 2 }), "manifest-version-unsupported"],
    ["version -1", man({ version: -1 }), "manifest-version-unsupported"],
    ['version "1" (string)', man({ version: "1" }), "manifest-version-unsupported"],
    ["version 1.5", man({ version: 1.5 }), "manifest-version-unsupported"],
    ["version true", man({ version: true }), "manifest-version-unsupported"],
    ["version null", man({ version: null }), "manifest-version-unsupported"],
    ["version [1]", man({ version: [1] }), "manifest-version-unsupported"],
    // ---- files container
    ["files is an object", man({ files: { 0: entry() } }), "manifest-files-invalid"],
    ["files is a string", man({ files: "a.txt" }), "manifest-files-invalid"],
    ["files is null", man({ files: null }), "manifest-files-invalid"],
    ["files is empty", man({ files: [] }), "manifest-files-invalid"],
    ["files has 65 entries", man({ files: Array.from({ length: 65 }, (_, i) => entry({ path: `f${i}.txt` })) }), "manifest-files-invalid"],
    // ---- entries
    ["entry is a string", man({ files: ["a.txt"] }), "manifest-entry-invalid"],
    ["entry is null", man({ files: [null] }), "manifest-entry-invalid"],
    ["entry is an array", man({ files: [["a.txt", GOOD]] }), "manifest-entry-invalid"],
    ["entry has an extra key", man({ files: [entry({ mode: "0644" })] }), "manifest-entry-invalid"],
    ["entry missing sha256", man({ files: [{ path: "a.txt" }] }), "manifest-entry-invalid"],
    ["entry missing path", man({ files: [{ sha256: GOOD }] }), "manifest-entry-invalid"],
    ["entry with sha256 spelled sha-256", man({ files: [{ path: "a.txt", "sha-256": GOOD }] }), "manifest-entry-invalid"],
    ["second entry bad although first is fine", man({ files: [entry(), { path: "b.txt" }] }), "manifest-entry-invalid"],
    // ---- entry paths
    ["path traversal", man({ files: [entry({ path: "../a.txt" })] }), "manifest-entry-path-invalid"],
    ["absolute path", man({ files: [entry({ path: "/etc/passwd" })] }), "manifest-entry-path-invalid"],
    ["empty path", man({ files: [entry({ path: "" })] }), "manifest-entry-path-invalid"],
    ["hidden path", man({ files: [entry({ path: ".env" })] }), "manifest-entry-path-invalid"],
    ["backslash path", man({ files: [entry({ path: "a\\b" })] }), "manifest-entry-path-invalid"],
    ["NUL in path", man({ files: [entry({ path: "a\u0000.txt" })] }), "manifest-entry-path-invalid"],
    ["numeric path", man({ files: [entry({ path: 5 })] }), "manifest-entry-path-invalid"],
    ["null path", man({ files: [entry({ path: null })] }), "manifest-entry-path-invalid"],
    // ---- sha256 shape
    ["sha256 63 chars", man({ files: [entry({ sha256: GOOD.slice(0, 63) })] }), "manifest-entry-digest-malformed"],
    ["sha256 65 chars", man({ files: [entry({ sha256: GOOD + "0" })] }), "manifest-entry-digest-malformed"],
    ["sha256 empty", man({ files: [entry({ sha256: "" })] }), "manifest-entry-digest-malformed"],
    ["sha256 UPPERCASE", man({ files: [entry({ sha256: GOOD.toUpperCase() })] }), "manifest-entry-digest-malformed"],
    ["sha256 mixed case", man({ files: [entry({ sha256: GOOD.slice(0, 32) + GOOD.slice(32).toUpperCase() })] }), "manifest-entry-digest-malformed"],
    ["sha256 non-hex char", man({ files: [entry({ sha256: "g" + GOOD.slice(1) })] }), "manifest-entry-digest-malformed"],
    ["sha256 with 0x prefix", man({ files: [entry({ sha256: "0x" + GOOD.slice(2) })] }), "manifest-entry-digest-malformed"],
    ["sha256 with trailing newline (anchor must be end-of-input)", man({ files: [entry({ sha256: GOOD + "\n" })] }), "manifest-entry-digest-malformed"],
    ["sha256 with leading space", man({ files: [entry({ sha256: " " + GOOD.slice(1) })] }), "manifest-entry-digest-malformed"],
    ["sha256 as number", man({ files: [entry({ sha256: 123 })] }), "manifest-entry-digest-malformed"],
    ["sha256 as array", man({ files: [entry({ sha256: [GOOD] })] }), "manifest-entry-digest-malformed"],
    ["sha256 null", man({ files: [entry({ sha256: null })] }), "manifest-entry-digest-malformed"],
  ];
  for (const [name, content, reason] of cases) {
    it(`${name} => ${reason}`, async () => {
      const { r } = await validateManifest(content);
      assert.equal(r.failure, reason);
      assert.equal(r.exitCode, 1);
      assert.equal(r.checks.pass, 0, "a rejected manifest must never count a passing check");
      assert.ok(r.checks.fail >= 1);
      const names = r.artifacts.map((a) => a.name);
      assert.ok(!names.includes("a.txt"), "no listed file is hashed once the manifest itself is rejected");
    });
  }
});

describe("validate-manifest: semantic negatives (well-formed manifest, wrong facts)", () => {
  it("digest mismatch => sha256-mismatch:<path>; counted as fail, other entries still verified", async () => {
    const { r } = await validateManifest(man({ files: [entry({ sha256: sha("other") }), entry({ path: "b.txt", sha256: sha("beta") })] }), { "b.txt": "beta" });
    assert.equal(r.failure, "sha256-mismatch:a.txt");
    assert.deepEqual(r.checks, { pass: 1, fail: 1 });
    assert.equal(r.exitCode, 1);
  });

  it("two digest mismatches: the FIRST one is reported, both are counted", async () => {
    const { r } = await validateManifest(
      man({ files: [entry({ sha256: sha("other") }), entry({ path: "b.txt", sha256: sha("other2") })] }),
      { "b.txt": "beta" },
    );
    assert.equal(r.failure, "sha256-mismatch:a.txt");
    assert.deepEqual(r.checks, { pass: 0, fail: 2 });
  });

  it("listed file missing / directory / escapes root => failure carries the reason and the path; counted as mismatch", async () => {
    const m1 = (await validateManifest(man({ files: [entry({ path: "nope.txt" })] }))).r;
    assert.equal(m1.failure, "path-not-found:nope.txt");
    const m2 = (await validateManifest(man({ files: [entry({ path: "d" })] }), { "d/x.txt": "x" })).r;
    assert.equal(m2.failure, "not-regular-file:d");
    for (const r of [m1, m2]) assert.deepEqual(r.checks, { pass: 0, fail: 1 });
  });

  it("duplicate path in the manifest => manifest-lists-itself-or-duplicate (the second occurrence does not count as a second pass)", async () => {
    const { r } = await validateManifest(man({ files: [entry(), entry()] }));
    assert.equal(r.failure, "manifest-lists-itself-or-duplicate:a.txt");
    assert.deepEqual(r.checks, { pass: 1, fail: 1 }, "1 pass, never 2");
    assert.equal(r.exitCode, 1);
  });

  it("manifest listing ITSELF is refused (cannot vouch for its own bytes)", async () => {
    const { r } = await validateManifest(man({ files: [entry(), entry({ path: "m.json", sha256: sha("whatever") })] }));
    assert.equal(r.failure, "manifest-lists-itself-or-duplicate:m.json");
    assert.deepEqual(r.checks, { pass: 1, fail: 1 });
  });

  it("first failure wins in the message while counts stay complete (mismatch + not-found + duplicate => fail 3, pass 0)", async () => {
    const files = [entry({ sha256: sha("x") }), entry({ path: "gone.txt" }), entry({ path: "a.txt", sha256: GOOD })];
    const { r } = await validateManifest(man({ files }));
    assert.equal(r.failure, "sha256-mismatch:a.txt");
    assert.deepEqual(r.checks, { pass: 0, fail: 3 }, "the 3rd entry is a duplicate of the 1st even though its digest is right");
  });

  it("non-lowercase-hex digest of the RIGHT file is still rejected: matching case-insensitively would be a silent leniency", async () => {
    const { r } = await validateManifest(man({ files: [entry({ sha256: GOOD.toUpperCase() })] }));
    assert.equal(r.failure, "manifest-entry-digest-malformed");
  });

  it("CHARACTERISATION: duplicate JSON keys are last-wins (JSON.parse); the exact bytes parsed are still bound by the manifest artifact digest", async () => {
    const text = `{"version":2,"version":1,"files":[{"path":"a.txt","sha256":"${GOOD}"}]}`;
    const { r } = await validateManifest(text);
    assert.equal(r.failure, null);
    assert.equal(r.artifacts.find((a) => a.name === "m.json")?.sha256, sha(text));
  });
});

describe("validate-manifest: manifest file itself", () => {
  it("missing manifest => manifest-path-not-found; directory => manifest-not-regular-file", async () => {
    const dir = root({ "dir/x.txt": "x" });
    const run = async (p: string) => {
      const v = validateTask({ taskId: "mn", action: "validate-manifest", manifest: p });
      assert.ok(v.ok);
      return executeTask(dir, v.task);
    };
    assert.equal((await run("missing.json")).failure, "manifest-path-not-found");
    assert.equal((await run("dir")).failure, "manifest-not-regular-file");
    assert.equal((await run("missing.json")).artifacts.length, 0);
  });
});
