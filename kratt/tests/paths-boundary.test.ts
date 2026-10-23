import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { executeTask } from "../actions.ts";
import { MAX_PATH_LENGTH, relPathFailure, resolveRegularFile } from "../paths.ts";
import { validateTask } from "../task.ts";

/**
 * A-012: KRATT path boundary tests. Every assertion states the reason string the current code
 * produces, so a refactor that accepts the input (or rejects it for a different reason) is noticed.
 */
const temps: string[] = [];
after(() => temps.forEach((t) => rmSync(t, { recursive: true, force: true })));
function tree(files: Record<string, string>, links: Record<string, string> = {}): { root: string; outside: string } {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "kratt-pb-")));
  temps.push(base);
  const root = join(base, "root");
  const outside = join(base, "outside");
  mkdirSync(root);
  mkdirSync(outside);
  writeFileSync(join(outside, "secret.txt"), "TOP SECRET");
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), content);
  }
  for (const [rel, target] of Object.entries(links)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    symlinkSync(target, join(root, rel));
  }
  return { root, outside };
}
const hash = (files: string[]) => ({ taskId: "pb", action: "hash-files", files });

describe("relPathFailure: lexical boundary", () => {
  it("accepts ordinary nested paths, dots and dashes inside a segment, and a 200-char path", () => {
    for (const ok of ["a", "a/b", "a/b/c.test.ts", "_x/y", "a-b/c_d/e.f.g", "a..b", "a.", "9/9", "Mixed/CASE.Txt", "a".repeat(MAX_PATH_LENGTH)])
      assert.equal(relPathFailure(ok), null, ok);
  });

  it("length boundary: 200 accepted, 201 and empty rejected with path-length-invalid", () => {
    assert.equal(relPathFailure("a".repeat(200)), null);
    assert.equal(relPathFailure("a".repeat(201)), "path-length-invalid");
    assert.equal(relPathFailure(""), "path-length-invalid");
    assert.equal(relPathFailure(`${"a/".repeat(99)}a`), null, "199 chars across many segments");
    assert.equal(relPathFailure(`${"a/".repeat(100)}a`), "path-length-invalid", "201 chars across many segments");
  });

  it("traversal: .. in any position is rejected (segment starts with '.')", () => {
    for (const p of ["..", "../x", "x/..", "x/../y", "x/../../y", "a/b/../../..", "..x/y" /* starts with '.' */ ])
      assert.equal(relPathFailure(p), "path-segment-invalid", p);
  });

  it("absolute, drive-letter, UNC, home and URL-ish forms are rejected", () => {
    for (const p of ["/", "/etc/passwd", "//server/share", "C:/Windows", "C:\\Windows", "~/x", "~", "file:///etc/passwd", "http://x/y", "\\\\server\\share"])
      assert.notEqual(relPathFailure(p), null, p);
    assert.equal(relPathFailure("/etc/passwd"), "path-segment-invalid", "leading '/' makes an empty first segment");
  });

  it("empty segments and trailing slash: // , leading / , trailing / , lone . are rejected", () => {
    for (const p of ["a//b", "/a", "a/", "a/./b", "./a", "."]) assert.equal(relPathFailure(p), "path-segment-invalid", p);
  });

  it("NUL and every other C0 control, DEL, backslash and whitespace are rejected", () => {
    for (let c = 0; c < 0x20; c++) assert.equal(relPathFailure(`a${String.fromCharCode(c)}b`), "path-segment-invalid", `U+${c.toString(16)}`);
    for (const ch of ["\u007f", "\\", " ", "\u00a0", "\u2028"]) assert.equal(relPathFailure(`a${ch}b`), "path-segment-invalid", JSON.stringify(ch));
    assert.equal(relPathFailure("a\0"), "path-segment-invalid");
    assert.equal(relPathFailure("a\0/../../etc/passwd"), "path-segment-invalid");
  });

  it("shell/URL metacharacters and percent-encoding are rejected (no decoding happens anywhere)", () => {
    for (const ch of [";", "|", "&", "$", "`", "'", '"', "<", ">", "*", "?", "[", "]", "{", "}", "(", ")", "!", "#", "%", ":", "=", "+", ",", "@", "^"])
      assert.equal(relPathFailure(`a${ch}b`), "path-segment-invalid", ch);
    for (const p of ["%2e%2e/x", "%2e%2e%2fx", "a%2fb", "..%2f"]) assert.equal(relPathFailure(p), "path-segment-invalid", p);
  });

  it("hidden files and directories (leading dot) are rejected: .git, .env, .ssh", () => {
    for (const p of [".git/config", ".env", "a/.env", "a/.hidden/b", ".ssh/id_rsa", ".github/workflows/ci.yml"]) assert.equal(relPathFailure(p), "path-segment-invalid", p);
  });

  it("unicode: non-ASCII letters, lookalikes, fullwidth dots, bidi overrides, zero-width and combining marks are all rejected", () => {
    const cyrillicA = "\u0430";
    const cases = ["caf\u00e9", `c${cyrillicA}t`, "\uff0e\uff0e/x", "a\u202eb", "a\u200bb", "e\u0301", "\u00e9", "\ud83d\ude00", "\u2024\u2024/x"];
    for (const p of cases) assert.equal(relPathFailure(p), "path-segment-invalid", JSON.stringify(p));
    assert.equal(relPathFailure("\u00e9"), relPathFailure("e\u0301"), "NFC and NFD forms are rejected identically, so normalisation can never alias two names");
  });

  it("non-string inputs are rejected with path-not-string (no coercion)", () => {
    for (const v of [null, undefined, 0, 1, true, {}, [], ["a"], () => "a", Symbol("a"), 10n, new String("a"), { toString: () => "a" }])
      assert.equal(relPathFailure(v), "path-not-string", String(typeof v));
  });
});

describe("validateTask: path boundary surfaces through every action", () => {
  it("hash-files: each hostile element is rejected with the lexical reason, wherever it sits in the list", () => {
    for (const bad of ["../x", "/abs", "a\0b", "a\\b", ""]) {
      for (const files of [[bad], ["ok.txt", bad], [bad, "ok.txt"]]) {
        const r = validateTask(hash(files));
        assert.equal(r.ok, false, JSON.stringify(files));
        assert.match(!r.ok ? r.reason : "", /^path-(segment-invalid|length-invalid)$/);
      }
    }
  });

  it("duplicate paths: exact duplicates are rejected (files-duplicate); empty list and a lone path are not duplicates", () => {
    const r = validateTask(hash(["a.txt", "b.txt", "a.txt"]));
    assert.deepEqual(r, { ok: false, reason: "files-duplicate" });
    assert.equal(validateTask(hash(["a.txt"])).ok, true);
    assert.deepEqual(validateTask(hash([])), { ok: false, reason: "files-count-invalid" });
  });

  it("CHARACTERISATION: duplicates are detected by exact string only; case-variants are distinct names (safe on Linux, aliases on case-insensitive FS)", () => {
    const r = validateTask(hash(["A.txt", "a.txt"]));
    assert.equal(r.ok, true);
  });

  it("validate-manifest and run-test paths use the same boundary", () => {
    assert.deepEqual(validateTask({ taskId: "m", action: "validate-manifest", manifest: "../m.json" }), { ok: false, reason: "path-segment-invalid" });
    assert.deepEqual(validateTask({ taskId: "m", action: "validate-manifest", manifest: "" }), { ok: false, reason: "path-length-invalid" });
    assert.deepEqual(validateTask({ taskId: "r", action: "run-test", testFile: "/kratt/tests/x.test.ts", timeoutMs: 1000, maxOutputBytes: 1024 }), { ok: false, reason: "path-segment-invalid" });
  });
});

describe("resolveRegularFile: filesystem boundary (symlinks, directories, missing)", () => {
  it("resolves a regular file and reports its size; refuses directory, missing and oversized with distinct reasons", () => {
    const { root } = tree({ "d/f.txt": "12345" });
    const ok = resolveRegularFile(root, "d/f.txt", 100);
    assert.ok(ok.ok && ok.bytes === 5 && ok.abs === join(root, "d", "f.txt"));
    assert.deepEqual(resolveRegularFile(root, "d", 100), { ok: false, reason: "not-regular-file" });
    assert.deepEqual(resolveRegularFile(root, "d/nope.txt", 100), { ok: false, reason: "path-not-found" });
    assert.deepEqual(resolveRegularFile(root, "d/f.txt", 4), { ok: false, reason: "file-too-large" });
    assert.ok(resolveRegularFile(root, "d/f.txt", 5).ok, "size == limit is allowed");
  });

  it("symlink to a file OUTSIDE the root is refused (path-escapes-root), absolute and relative targets alike", () => {
    const base = tree({ "ok.txt": "x" });
    symlinkSync(join(base.outside, "secret.txt"), join(base.root, "abs-link.txt"));
    symlinkSync("../outside/secret.txt", join(base.root, "rel-link.txt"));
    assert.deepEqual(resolveRegularFile(base.root, "abs-link.txt", 1000), { ok: false, reason: "path-escapes-root" });
    assert.deepEqual(resolveRegularFile(base.root, "rel-link.txt", 1000), { ok: false, reason: "path-escapes-root" });
  });

  it("symlinked DIRECTORY pointing outside is refused for any file reached through it, including chained links", () => {
    const b = tree({ "ok.txt": "x" });
    symlinkSync(b.outside, join(b.root, "evil-dir"));
    symlinkSync("evil-dir", join(b.root, "hop1"));
    symlinkSync("hop1/secret.txt", join(b.root, "hop2.txt"));
    assert.deepEqual(resolveRegularFile(b.root, "evil-dir/secret.txt", 1000), { ok: false, reason: "path-escapes-root" });
    assert.deepEqual(resolveRegularFile(b.root, "hop1/secret.txt", 1000), { ok: false, reason: "path-escapes-root" });
    assert.deepEqual(resolveRegularFile(b.root, "hop2.txt", 1000), { ok: false, reason: "path-escapes-root" });
  });

  it("sibling-prefix trick: a root named 'root' must not accept a real path under 'root-evil' (prefix match needs the separator)", () => {
    const b = tree({ "ok.txt": "x" });
    const evil = join(dirname(b.root), "root-evil");
    mkdirSync(evil);
    writeFileSync(join(evil, "s.txt"), "s");
    symlinkSync(join(evil, "s.txt"), join(b.root, "lnk.txt"));
    assert.deepEqual(resolveRegularFile(b.root, "lnk.txt", 1000), { ok: false, reason: "path-escapes-root" });
  });

  it("dangling symlink and symlink loop are path-not-found, never an exception", () => {
    const b = tree({ "ok.txt": "x" });
    symlinkSync(join(b.root, "gone.txt"), join(b.root, "dangling.txt"));
    symlinkSync("loop-b", join(b.root, "loop-a"));
    symlinkSync("loop-a", join(b.root, "loop-b"));
    assert.deepEqual(resolveRegularFile(b.root, "dangling.txt", 1000), { ok: false, reason: "path-not-found" });
    assert.deepEqual(resolveRegularFile(b.root, "loop-a", 1000), { ok: false, reason: "path-not-found" });
  });

  it("CHARACTERISATION: a symlink that stays INSIDE the root is followed and resolves to the real file", () => {
    const b = tree({ "real/data.txt": "abc" }, { "alias.txt": "real/data.txt" });
    const r = resolveRegularFile(b.root, "alias.txt", 1000);
    assert.ok(r.ok);
    assert.equal(r.ok && r.abs, join(b.root, "real", "data.txt"));
  });

  it("lexical check runs BEFORE the filesystem: a hostile path never touches the disk, even if it would exist", () => {
    const b = tree({ "ok.txt": "x" });
    assert.deepEqual(resolveRegularFile(b.root, "../outside/secret.txt", 1000), { ok: false, reason: "path-segment-invalid" });
    assert.deepEqual(resolveRegularFile(b.root, join(b.outside, "secret.txt"), 1000), { ok: false, reason: "path-segment-invalid" });
  });
});

describe("executeTask end-to-end: path boundary yields a failed result and never leaks bytes outside the root", () => {
  it("hash-files with a symlink-out fails with path-escapes-root and reports no artifact for it", async () => {
    const b = tree({ "ok.txt": "fine" });
    symlinkSync(join(b.outside, "secret.txt"), join(b.root, "leak.txt"));
    const v = validateTask(hash(["ok.txt", "leak.txt"]));
    assert.ok(v.ok);
    const r = await executeTask(b.root, v.task);
    assert.equal(r.exitCode, 1);
    assert.equal(r.failure, "path-escapes-root:leak.txt");
    assert.deepEqual(r.artifacts.map((a) => a.name), ["ok.txt"], "only the in-root file was hashed before the failure");
  });

  it("hash-files naming a directory or a missing file fails with the matching reason and file name", async () => {
    const b = tree({ "d/f.txt": "x" });
    const dir = validateTask(hash(["d"]));
    const gone = validateTask(hash(["d/missing.txt"]));
    assert.ok(dir.ok && gone.ok);
    assert.equal((await executeTask(b.root, dir.task)).failure, "not-regular-file:d");
    assert.equal((await executeTask(b.root, gone.task)).failure, "path-not-found:d/missing.txt");
  });

  it("two names for the same in-root file are NOT collapsed: each is hashed under its own name (alias visible in evidence)", async () => {
    const b = tree({ "real.txt": "same" }, { "alias.txt": "real.txt" });
    const v = validateTask(hash(["real.txt", "alias.txt"]));
    assert.ok(v.ok);
    const r = await executeTask(b.root, v.task);
    assert.equal(r.failure, null);
    assert.deepEqual(r.artifacts.map((a) => a.name), ["alias.txt", "real.txt"]);
    assert.equal(r.artifacts[0]?.sha256, r.artifacts[1]?.sha256);
  });
});
