import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { HANDLERS, executeHandler, handlerFor, runHandlerTask, type HandlerReceipt } from "../handlers/index.ts";
import { classifyRange } from "../handlers/deps-package.ts";
import { extractLinks, headingSlugs } from "../handlers/docs-links.ts";
import { schemaProblems, validate } from "../handlers/json-schema.ts";
import { RULES } from "../handlers/secrets.ts";
import { digestOf, type TaskEnvelope } from "../protocol/types.ts";
import { makeDispatcher } from "../loop.ts";
import { fixedClock } from "./fixtures.ts";

const REPO_SLUG = "o/r";
const sha = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");
const GIT_ENV = (dir: string) => ({ PATH: process.env.PATH ?? "", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t", HOME: dir });

/** Throwaway git repo; `commit()` makes further commits so tests can tamper between SHAs. */
function repo(files: Record<string, string | Buffer>, links: Record<string, string> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "factory-handlers-"));
  const git = (...a: string[]) => execFileSync("git", a, { cwd: dir, encoding: "utf8", env: GIT_ENV(dir) }).trim();
  git("init", "-q");
  const put = (fs: Record<string, string | Buffer>, ls: Record<string, string> = {}) => {
    for (const [p, c] of Object.entries(fs)) {
      mkdirSync(dirname(join(dir, p)), { recursive: true });
      writeFileSync(join(dir, p), c);
    }
    for (const [p, t] of Object.entries(ls)) symlinkSync(t, join(dir, p));
    git("add", "-A");
    git("-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "c");
    return git("rev-parse", "HEAD");
  };
  const first = put(files, links);
  return { dir, sha: first, commit: put, git };
}

const covered = new Set<string>();
let n = 0;
function envFor(cap: string, base_sha: string, scope: string[], over: Partial<TaskEnvelope> = {}): TaskEnvelope {
  const h = HANDLERS.find((x) => x.contract.capability === cap)!;
  const agent = h.contract.agent_id;
  return {
    task_id: `h-${++n}`, factory: agent.split("-")[0] as TaskEnvelope["factory"], agent_id: agent, objective: `${cap} test`, repository: REPO_SLUG, branch: "t", base_sha,
    scope, allowed_actions: [cap], forbidden_actions: ["merge", "deploy", "network", "write-files"], required_evidence: ["x"],
    resource_budget: { max_wall_ms: 10_000, max_output_bytes: 1_048_576, max_files: 64 }, protocol_version: 1, ...over,
  };
}
function run(cap: string, dir: string, base: string, scope: string[], over: Partial<TaskEnvelope> = {}): HandlerReceipt {
  covered.add(cap);
  const h = handlerFor(HANDLERS.find((x) => x.contract.capability === cap)!.contract.agent_id, cap)!;
  const r = executeHandler(h, envFor(cap, base, scope, over), dir, fixedClock());
  assert.ok(r.ok, r.ok ? "" : r.reason);
  if (r.receipt.result.failure === null) for (const k of h.contract.summary_keys) assert.ok(k in r.receipt.result.summary, `summary key ${k}`);
  assert.equal(r.receipt.verification_state, "UNVERIFIED", "a handler never verifies itself");
  const { receipt_digest, ...body } = r.receipt;
  assert.equal(digestOf(body), receipt_digest, "receipt digest is self-consistent");
  return r.receipt;
}
const codes = (r: HandlerReceipt) => r.result.findings.map((f) => f.code);

// ---------------------------------------------------------------- repo:map-tree (FORGE-002)
test("repo:map-tree inventories tree metadata: counts, bytes, histograms, symlinks; missing path is an error", () => {
  const R = repo({ "a.ts": "1", "src/b.ts": "22", "src/c.ts": "333", "docs/x.md": "4444", Makefile: "5", "big/huge.bin": "x".repeat(1000) }, { "src/link": "b.ts" });
  const r = run("repo:map-tree", R.dir, R.sha, ["src", "docs", "a.ts", "Makefile", "big"]);
  const s = r.result.summary as Record<string, unknown>;
  assert.equal(s.files, 7);
  assert.equal(s.bytes, 1 + 2 + 3 + 4 + 1 + 1000 + 4, "symlink counts its target-path bytes (\"b.ts\" = 4)");
  assert.deepEqual(s.by_extension, { ".bin": 1, ".md": 1, ".ts": 3, "(none)": 2 });
  assert.deepEqual(s.by_top_dir, { "(root)": 2, big: 1, docs: 1, src: 3 });
  assert.equal(s.symlinks, 1);
  assert.deepEqual((s.largest as { path: string }[])[0]?.path, "big/huge.bin");
  assert.deepEqual(codes(r), ["symlink"]);
  assert.equal(r.result.ok, true, "warnings do not fail the check");
  const miss = run("repo:map-tree", R.dir, R.sha, ["src", "nope"]);
  assert.equal(miss.result.ok, false);
  assert.deepEqual(codes(miss), ["path-not-found", "symlink"], "errors sort before warnings");
  const again = run("repo:map-tree", R.dir, R.sha, ["src", "docs", "a.ts", "Makefile", "big"]);
  assert.deepEqual(again.result.summary, r.result.summary, "deterministic");
});

// ---------------------------------------------------------------- deps:map-package (FORGE-003)
test("deps:map-package classifies specifiers and flags wildcards, URL/git sources, duplicates", () => {
  assert.deepEqual(
    ["1.2.3", "^1.0.0", "~2.0.0", ">=1 <2", "1.x", "*", "latest", "", "github:a/b", "a/b#main", "git+ssh://x/y.git", "https://x/y.tgz", "file:../z", "npm:foo@1", "next"].map(classifyRange),
    ["exact", "caret", "tilde", "range", "range", "wildcard", "wildcard", "wildcard", "git", "git", "git", "url", "file", "alias", "tag"],
  );
  const bad = JSON.stringify({ dependencies: { a: "^1.0.0", b: "*", c: "github:x/y", d: "latest", e: 5 }, devDependencies: { a: "^1.0.0", z: "file:../z" }, peerDependencies: { a: "^1" } });
  const good = JSON.stringify({ dependencies: { a: "^1.0.0", b: "1.2.3" }, devDependencies: { t: "~5.0.0" } });
  const R = repo({ "bad/package.json": bad, "good/package.json": good, "broken/package.json": "{nope" });
  const g = run("deps:map-package", R.dir, R.sha, ["good/package.json"]);
  assert.equal(g.result.ok, true);
  assert.deepEqual(g.result.summary, { manifests: 1, totals: { dependencies: 2, devDependencies: 1, optionalDependencies: 0, peerDependencies: 0 }, by_kind: { caret: 1, exact: 1, tilde: 1 } });
  const b = run("deps:map-package", R.dir, R.sha, ["bad/package.json"]);
  assert.equal(b.result.ok, false);
  assert.deepEqual(new Set(codes(b)), new Set(["unpinned-wildcard", "non-registry-source", "specifier-not-string", "duplicate-dependency", "local-source"]));
  assert.equal(b.result.finding_counts.error, 4);
  assert.ok(!b.result.findings.some((f) => f.detail.includes("peerDependencies") && f.code === "duplicate-dependency"), "peer duplicates are legitimate");
  const u = run("deps:map-package", R.dir, R.sha, ["broken/package.json"]);
  assert.equal(u.result.failure, "manifest-unreadable:broken/package.json:json-parse-error");
});

// ---------------------------------------------------------------- schema:validate-json (FORGE-014)
test("schema:validate-json validates instances, reports each violation, and fails closed on unsupported/unsafe schemas", () => {
  const schema = {
    type: "object", required: ["id", "kind"], additionalProperties: false,
    properties: { id: { type: "string", pattern: "^[a-z]{3}-\\d+$" }, kind: { enum: ["a", "b"] }, n: { type: "integer", minimum: 0, maximum: 9 }, tags: { type: "array", items: { type: "string" }, uniqueItems: true, maxItems: 2 } },
  };
  const R = repo({
    "s.json": JSON.stringify(schema),
    "ok.json": JSON.stringify({ id: "abc-12", kind: "a", n: 3, tags: ["x"] }),
    "bad.json": JSON.stringify({ id: "ABC", kind: "z", n: 1.5, extra: true, tags: ["x", "x", "y"] }),
    "garbage.json": "{{",
    "ref.json": JSON.stringify({ $ref: "#/definitions/x" }),
    "redos.json": JSON.stringify({ type: "string", pattern: "(a+)+$" }),
  });
  const ok = run("schema:validate-json", R.dir, R.sha, ["s.json", "ok.json"]);
  assert.equal(ok.result.ok, true);
  assert.deepEqual(ok.result.summary, { schema: "s.json", instances: 1, valid: 1, invalid: 0 });
  const bad = run("schema:validate-json", R.dir, R.sha, ["s.json", "ok.json", "bad.json", "garbage.json"]);
  assert.equal(bad.result.ok, false);
  const details = bad.result.findings.map((f) => `${f.path} ${f.detail}`).join("\n");
  for (const want of ["$.id: pattern-mismatch", "$.kind: not-in-enum", "$.n: type-mismatch:expected=integer:got=number", "additional-property:extra", "$.tags: maxItems:2", "$.tags: uniqueItems", "garbage.json json-parse-error"])
    assert.ok(details.includes(want), `missing: ${want}\n${details}`);
  assert.deepEqual((bad.result.summary as { valid: number; invalid: number }).valid, 1);
  const ref = run("schema:validate-json", R.dir, R.sha, ["ref.json", "ok.json"]);
  assert.equal(ref.result.failure, "schema-unusable");
  assert.ok(ref.result.findings[0]?.detail.includes("unsupported-keyword:$ref"));
  const rx = run("schema:validate-json", R.dir, R.sha, ["redos.json", "ok.json"]);
  assert.equal(rx.result.failure, "schema-unusable", "quantified-group patterns are refused (ReDoS)");
  // pure validator edge cases
  assert.deepEqual(schemaProblems({ type: "string", minLength: -1 }), ["#: bad-minLength"]);
  assert.deepEqual(validate({ const: { b: 1, a: 2 } }, { a: 2, b: 1 }), [], "const compares canonically (key order irrelevant)");
  assert.equal(validate({ type: "number" }, Number.NaN).length, 1);
});

// ---------------------------------------------------------------- docs:check-links (FORGE-049)
test("docs:check-links resolves relative links and #anchors against the same commit; ignores code and external URLs", () => {
  assert.deepEqual([...headingSlugs("# Hello, World!\n## Hello, World!\n```\n# not a heading\n```\n### `Code` & [Link](x)")], ["hello-world", "hello-world-1", "code--link"]);
  assert.deepEqual(extractLinks("[a](b.md) `[x](no.md)` ![i](p.png \"t\")\n```\n[y](no2.md)\n```\n[ref]: dest.md").map((l) => l.target), ["b.md", "p.png", "dest.md"]);
  const R = repo({
    "README.md": [
      "# Top", "[ok](docs/a.md#intro)", "[ok2](./docs/a.md#intro-1)", "[dir](docs/)", "[self](#top)", "[ext](https://example.com/x) [mail](mailto:a@b.c)", "[line](docs/a.md#L10)",
      "[badanchor](docs/a.md#nope)", "[missing](docs/gone.md)", "[escape](../../etc/passwd)", "[selfbad](#nothing)", "[enc](docs/sp%20ace.md)", "```", "[inert](nowhere.md)", "```",
    ].join("\n"),
    "docs/a.md": "# Intro\ntext\n# Intro\n",
    "docs/sp ace.md": "x",
  });
  const r = run("docs:check-links", R.dir, R.sha, ["README.md"]);
  const s = r.result.summary as { links: number; external_skipped: number; broken: number };
  assert.equal(s.external_skipped, 2);
  assert.equal(s.broken, 4);
  assert.deepEqual(codes(r).sort(), ["broken-anchor", "broken-anchor", "broken-link", "link-escapes-root"]);
  assert.equal(r.result.ok, false);
  const fixed = repo({ "README.md": "# T\n[a](docs/a.md#intro)\n", "docs/a.md": "# Intro\n" });
  const clean = run("docs:check-links", fixed.dir, fixed.sha, ["README.md"]);
  assert.equal(clean.result.ok, true);
  assert.equal(clean.result.findings.length, 0);
  assert.equal(run("docs:check-links", fixed.dir, fixed.sha, ["NOPE.md"]).result.failure, "markdown-unreadable:NOPE.md:path-not-found");
});

// ---------------------------------------------------------------- lockfile:audit-integrity (SERPENT-078)
const sri = (algo: "sha512" | "sha256" | "sha1", bytes: number) => `${algo}-${randomBytes(bytes).toString("base64")}`;
const lock = (pk: Record<string, unknown>, v: number = 3) => JSON.stringify({ name: "x", lockfileVersion: v, packages: pk });
test("lockfile:audit-integrity checks SRI presence, format, digest length and root-dependency coverage", () => {
  const good = lock({
    "": { dependencies: { a: "^1" }, devDependencies: { b: "^1" } },
    "node_modules/a": { version: "1.0.0", resolved: "https://registry.npmjs.org/a/-/a-1.0.0.tgz", integrity: sri("sha512", 64) },
    "node_modules/b": { version: "1.0.0", resolved: "https://registry.npmjs.org/b/-/b-1.0.0.tgz", integrity: sri("sha512", 64) },
    "packages/ws": { version: "1.0.0" },
    "node_modules/ws": { resolved: "packages/ws", link: true },
  });
  const bad = lock({
    "": { dependencies: { a: "^1", ghost: "^1" } },
    "node_modules/a": { resolved: "https://registry.npmjs.org/a/-/a-1.tgz" },
    "node_modules/b": { resolved: "https://registry.npmjs.org/b/-/b-1.tgz", integrity: "md5-abc" },
    "node_modules/c": { resolved: "https://registry.npmjs.org/c/-/c-1.tgz", integrity: sri("sha512", 20) },
    "node_modules/d": { resolved: "https://registry.npmjs.org/d/-/d-1.tgz", integrity: sri("sha1", 20) },
    "node_modules/e": { version: "1.0.0" },
    "node_modules/f": { inBundle: true, version: "1" },
  });
  const R = repo({ "good/package-lock.json": good, "bad/package-lock.json": bad, "old/package-lock.json": lock({}, 1), "junk/package-lock.json": "[" });
  const g = run("lockfile:audit-integrity", R.dir, R.sha, ["good/package-lock.json"]);
  assert.equal(g.result.ok, true);
  assert.deepEqual(g.result.summary, { lockfile_version: 3, packages: 2, with_integrity: 2, algorithms: { sha512: 2 }, lock_digest: sha(good) }, "link/workspace entries are not counted; digest is of the committed bytes");
  const b = run("lockfile:audit-integrity", R.dir, R.sha, ["bad/package-lock.json"]);
  assert.equal(b.result.ok, false);
  assert.deepEqual(codes(b).sort(), ["integrity-length-mismatch", "malformed-integrity", "missing-integrity", "no-resolved", "root-dependency-not-locked", "weak-integrity"]);
  assert.equal(b.result.finding_counts.error, 4);
  assert.equal(run("lockfile:audit-integrity", R.dir, R.sha, ["old/package-lock.json"]).result.failure, "unsupported-lockfileVersion:1");
  assert.equal(run("lockfile:audit-integrity", R.dir, R.sha, ["junk/package-lock.json"]).result.failure, "lockfile-unreadable:json-parse-error");
});

// ---------------------------------------------------------------- supply-chain:review-lockfile (SERPENT-068)
test("supply-chain:review-lockfile reports install scripts, git/insecure/foreign sources and deprecations (not integrity)", () => {
  const reg = (n: string) => `https://registry.npmjs.org/${n}/-/${n}-1.tgz`;
  const clean = lock({ "": {}, "node_modules/a": { resolved: reg("a"), hasInstallScript: true }, "node_modules/b": { resolved: reg("b") } });
  const dirty = lock({
    "": {},
    "node_modules/a": { resolved: "git+ssh://git@github.com/x/a.git#abc", hasInstallScript: true },
    "node_modules/b": { resolved: "http://registry.npmjs.org/b/-/b-1.tgz" },
    "node_modules/c": { resolved: "https://npm.corp.example/c/-/c-1.tgz" },
    "node_modules/d": { resolved: reg("d"), deprecated: "use e instead" },
    "node_modules/e": { resolved: "not a url" },
    "node_modules/x/node_modules/f": { resolved: reg("f"), hasInstallScript: true },
  });
  const R = repo({ "clean/package-lock.json": clean, "dirty/package-lock.json": dirty });
  const c = run("supply-chain:review-lockfile", R.dir, R.sha, ["clean/package-lock.json"]);
  assert.equal(c.result.ok, true, "install scripts are informational, not blocking");
  assert.deepEqual(c.result.summary, { packages: 2, install_script_count: 1, install_script_packages: ["a"], non_registry_sources: 0, deprecated: 0, hosts: { "registry.npmjs.org": 2 } });
  const d = run("supply-chain:review-lockfile", R.dir, R.sha, ["dirty/package-lock.json"]);
  assert.equal(d.result.ok, false);
  assert.deepEqual(codes(d).sort(), ["deprecated", "git-source", "insecure-transport", "install-script", "install-script", "non-default-registry", "unparseable-source"]);
  assert.deepEqual((d.result.summary as { install_script_packages: string[] }).install_script_packages, ["a", "f"], "nested package name is the last node_modules segment");
});

// ---------------------------------------------------------------- secrets:scan-files (SERPENT-069)
test("secrets:scan-files finds credential shapes, never echoes them, skips binaries and stays quiet on clean files", () => {
  const aws = "AKIA" + "ABCDEFGHIJKLMNOP";
  const gh = "ghp_" + "a1B2c3D4e5".repeat(4);
  const pem = "-----BEGIN " + "RSA PRIVATE KEY-----";
  const slack = "xoxb-" + "1234567890-abcdefghij";
  const R = repo({
    "src/leak.ts": `const a = "${aws}";\nline2\nconst t = '${gh}'; // ${slack}\n`,
    "keys/id.txt": `${pem}\nMIIE...\n`,
    "src/clean.ts": "export const x = 'AKIA is just a prefix'; // ghp_short\n",
    "bin/blob.dat": Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(aws)]),
  });
  const r = run("secrets:scan-files", R.dir, R.sha, ["src", "keys", "bin"]);
  assert.equal(r.result.ok, false);
  const got = r.result.findings.map((f) => `${f.code}@${f.path}:${f.line}`).sort();
  assert.deepEqual(got, ["secret:aws-access-key-id@src/leak.ts:1", "secret:github-token@src/leak.ts:3", "secret:private-key-block@keys/id.txt:1", "secret:slack-token@src/leak.ts:3"]);
  const aws1 = r.result.findings.find((f) => f.code === "secret:aws-access-key-id")!;
  assert.equal(aws1.detail, `fingerprint=${sha(aws).slice(0, 16)}`);
  const wire = JSON.stringify(r);
  for (const secret of [aws, gh, slack]) assert.ok(!wire.includes(secret), "receipt must not contain the secret");
  const s = r.result.summary as { files_scanned: number; binary_skipped: number };
  assert.deepEqual([s.files_scanned, s.binary_skipped], [3, 1]);
  const clean = run("secrets:scan-files", R.dir, R.sha, ["src/clean.ts"]);
  assert.equal(clean.result.ok, true);
  assert.equal(clean.result.findings.length, 0);
  assert.ok(RULES.length >= 8);
});

// ---------------------------------------------------------------- evidence:hash-blobs (CITADEL-104)
test("evidence:hash-blobs yields a deterministic, order-independent manifest digest of git blobs (not the working tree)", () => {
  const R = repo({ "a/one.txt": "one", "a/two.txt": "two", "b.txt": "bee" });
  const r1 = run("evidence:hash-blobs", R.dir, R.sha, ["a", "b.txt"]);
  const sum = r1.result.summary as { files: number; bytes: number; manifest_digest: string; entries: { path: string; sha256: string; bytes: number }[] };
  assert.deepEqual(sum.entries, [
    { path: "a/one.txt", sha256: sha("one"), bytes: 3 },
    { path: "a/two.txt", sha256: sha("two"), bytes: 3 },
    { path: "b.txt", sha256: sha("bee"), bytes: 3 },
  ]);
  assert.equal(sum.manifest_digest, digestOf(sum.entries));
  assert.equal(sum.bytes, 9);
  const r2 = run("evidence:hash-blobs", R.dir, R.sha, ["b.txt", "a/two.txt", "a/one.txt"]);
  assert.equal((r2.result.summary as { manifest_digest: string }).manifest_digest, sum.manifest_digest, "scope order does not matter");
  writeFileSync(join(R.dir, "b.txt"), "DIRTY working tree");
  const r3 = run("evidence:hash-blobs", R.dir, R.sha, ["a", "b.txt"]);
  assert.equal((r3.result.summary as { manifest_digest: string }).manifest_digest, sum.manifest_digest, "uncommitted edits are invisible");
  const sha2 = R.commit({ "b.txt": "changed" });
  const r4 = run("evidence:hash-blobs", R.dir, sha2, ["a", "b.txt"]);
  assert.notEqual((r4.result.summary as { manifest_digest: string }).manifest_digest, sum.manifest_digest);
  const many = repo(Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`m/f${i}.txt`, String(i)])));
  assert.equal(run("evidence:hash-blobs", many.dir, many.sha, ["m"]).result.failure, "expansion-exceeds-256-files");
  const miss = run("evidence:hash-blobs", R.dir, R.sha, ["nope"]);
  assert.equal(miss.result.ok, false);
  assert.equal((miss.result.summary as { manifest_digest: unknown }).manifest_digest, null, "no digest is issued for an incomplete set");
});

// ---------------------------------------------------------------- artifact:verify-manifest (SERPENT-066)
test("artifact:verify-manifest detects digest drift between commits, missing files, malformed and duplicate rows", () => {
  const files = { "dist/a.js": "alpha", "dist/b.js": "beta" };
  const manifest = (rows: unknown[]) => JSON.stringify({ manifest_version: 1, files: rows });
  const rows = [{ path: "dist/a.js", sha256: sha("alpha") }, { path: "dist/b.js", sha256: sha("beta") }];
  const R = repo({ ...files, "m.json": manifest(rows), "wrong-version.json": JSON.stringify({ manifest_version: 2, files: rows }), "empty.json": manifest([]) });
  const ok = run("artifact:verify-manifest", R.dir, R.sha, ["m.json"]);
  assert.equal(ok.result.ok, true);
  assert.deepEqual(ok.result.summary, { manifest: "m.json", declared: 2, verified: 2, mismatched: 0, missing: 0 });
  const tampered = R.commit({ "dist/b.js": "BETA!" });
  const t = run("artifact:verify-manifest", R.dir, tampered, ["m.json"]);
  assert.equal(t.result.ok, false);
  assert.deepEqual(t.result.summary, { manifest: "m.json", declared: 2, verified: 1, mismatched: 1, missing: 0 });
  assert.deepEqual(codes(t), ["digest-mismatch"]);
  assert.equal(t.result.findings[0]?.path, "dist/b.js");
  const weird = repo({
    "dist/a.js": "alpha",
    "m.json": manifest([{ path: "dist/a.js", sha256: sha("alpha") }, { path: "dist/a.js", sha256: sha("alpha") }, { path: "dist/gone.js", sha256: sha("x") }, { path: "dist/a.js" }, { path: 5, sha256: "zz" }]),
  });
  const w = run("artifact:verify-manifest", weird.dir, weird.sha, ["m.json"]);
  assert.deepEqual(codes(w).sort(), ["duplicate-path", "file-unreadable", "malformed-row", "malformed-row"]);
  assert.equal(run("artifact:verify-manifest", R.dir, R.sha, ["wrong-version.json"]).result.failure, "manifest-malformed");
  assert.equal(run("artifact:verify-manifest", R.dir, R.sha, ["empty.json"]).result.failure, "manifest-file-count-out-of-range");
});

// ---------------------------------------------------------------- framework: budgets, refusals, dispatcher walk
test("output budget: findings are truncated deterministically; an oversized summary is refused instead of overflowing", () => {
  const rows = Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`d${String(i).padStart(2, "0")}`, "*"]));
  const R = repo({ "package.json": JSON.stringify({ dependencies: rows }), ...Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`f/${i}.txt`, String(i)])) });
  const full = run("deps:map-package", R.dir, R.sha, ["package.json"]);
  assert.equal(full.result.findings.length, 60);
  assert.equal(full.result.findings_truncated, false);
  const small = run("deps:map-package", R.dir, R.sha, ["package.json"], { resource_budget: { max_wall_ms: 1000, max_output_bytes: 2048, max_files: 4 } });
  assert.ok(Buffer.byteLength(JSON.stringify(small)) <= 2048);
  assert.equal(small.result.findings_truncated, true);
  assert.equal(small.result.finding_counts.error, 60, "counts stay truthful when findings are cut");
  assert.equal(small.result.ok, false);
  const big = run("evidence:hash-blobs", R.dir, R.sha, ["f"], { resource_budget: { max_wall_ms: 1000, max_output_bytes: 1024, max_files: 4 } });
  assert.equal(big.result.failure, "output-budget-exceeded");
  assert.equal(big.result.ok, false);
  assert.ok(Buffer.byteLength(JSON.stringify(big)) <= 1024);
});

test("per-file and total byte budgets: oversized or symlinked inputs are refused, not read", () => {
  const R = repo({ "ok.json": "{}", "huge.json": JSON.stringify({ pad: "x".repeat(2 * 1024 * 1024 + 10) }), "s.json": "{}" }, { "link.json": "ok.json" });
  assert.equal(run("schema:validate-json", R.dir, R.sha, ["huge.json", "ok.json"]).result.failure, "schema-unreadable:file-too-large");
  assert.equal(run("schema:validate-json", R.dir, R.sha, ["link.json", "ok.json"]).result.failure, "schema-unreadable:not-regular-file:symlink");
  assert.equal(run("schema:validate-json", R.dir, R.sha, ["dir-missing.json", "ok.json"]).result.failure, "schema-unreadable:path-not-found");
});

test("executeHandler refuses: unknown base_sha, foreign agent, wrong action, bad scope size, invalid envelope", () => {
  const R = repo({ "a.json": "{}" });
  const h = handlerFor("FORGE-003", "deps:map-package")!;
  const go = (e: unknown) => executeHandler(h, e, R.dir, fixedClock());
  const e = envFor("deps:map-package", R.sha, ["a.json"]);
  assert.equal(go({ ...e, base_sha: "b".repeat(40) }).ok, false);
  assert.deepEqual(go({ ...e, base_sha: "b".repeat(40) }), { ok: false, reason: "base-sha-not-found" });
  assert.deepEqual(go({ ...e, agent_id: "FORGE-004" }), { ok: false, reason: "agent-not-handler-owner" });
  assert.match((go({ ...e, allowed_actions: ["hash-files"] }) as { reason: string }).reason, /exactly/);
  assert.match((go({ ...e, scope: Array.from({ length: 9 }, (_, i) => `p${i}.json`), resource_budget: { max_wall_ms: 1000, max_output_bytes: 4096, max_files: 64 } }) as { reason: string }).reason, /scope-size-out-of-contract/);
  assert.match((go({ ...e, scope: ["../etc/passwd"] }) as { reason: string }).reason, /envelope-invalid/);
  assert.match((go("nope") as { reason: string }).reason, /envelope-invalid/);
});

test("DISPATCHER WALK: a passing handler task goes SLEEP->READY->ACTIVE->VERIFY->DONE->SLEEP and records evidence; a failing check ends BLOCKED with its receipt", async () => {
  const R = repo({ "ok/package.json": JSON.stringify({ dependencies: { a: "1.0.0" } }), "bad/package.json": JSON.stringify({ dependencies: { a: "*" } }) });
  const d = makeDispatcher(fixedClock());
  const deps = { root: R.dir, repository: REPO_SLUG, dispatcher: d, clock: fixedClock() };
  const pass = await runHandlerTask(envFor("deps:map-package", R.sha, ["ok/package.json"]), deps);
  covered.add("deps:map-package");
  assert.equal(pass.status, "DONE");
  const w = d.worker("FORGE-003");
  assert.equal(w.state, "SLEEP");
  assert.equal(w.completed_tasks, 1);
  assert.match(w.evidence[0] ?? "", /^handler-receipt:h-\d+:[0-9a-f]{64}$/);
  assert.equal(d.log.filter((t) => t.agent_id === "FORGE-003").map((t) => `${t.from}->${t.to}`).join(","), "SLEEP->READY,READY->ACTIVE,ACTIVE->VERIFY,VERIFY->DONE,DONE->SLEEP");
  const fail = await runHandlerTask(envFor("deps:map-package", R.sha, ["bad/package.json"]), deps);
  assert.equal(fail.status, "BLOCKED");
  assert.ok(fail.status === "BLOCKED" && fail.receipt?.result.finding_counts.error === 1, "evidence of the failed check is kept");
  assert.equal(w.failed_tasks, 1);
  assert.equal(w.state, "SLEEP");
  assert.deepEqual(d.watchdog(), []);
  const stale = await runHandlerTask(envFor("deps:map-package", "c".repeat(40), ["ok/package.json"]), deps);
  assert.deepEqual(stale, { status: "BLOCKED", receipt: null, reason: "base-sha-not-found" });
  assert.equal(w.failed_tasks, 2);
  assert.equal(w.completed_tasks, 1, "nothing is DONE without a real result");
});

test("DISPATCHER refusals happen before any worker wakes: wrong repository, duplicate task, unknown capability, loop-only capability", async () => {
  const R = repo({ "package.json": "{}" });
  const d = makeDispatcher(fixedClock());
  const deps = { root: R.dir, repository: REPO_SLUG, dispatcher: d, clock: fixedClock() };
  const e = envFor("deps:map-package", R.sha, ["package.json"]);
  assert.deepEqual(await runHandlerTask({ ...e, repository: "x/y" }, deps), { status: "REFUSED", reason: "repository-mismatch" });
  assert.equal((await runHandlerTask({ ...e, allowed_actions: ["deps:nothing"] }, deps)).status, "REFUSED");
  assert.equal((await runHandlerTask({ ...e, agent_id: "FORGE-026", allowed_actions: ["hash-files"] }, deps)).status, "REFUSED");
  assert.equal(d.log.length, 0, "no transition was attempted");
  assert.equal((await runHandlerTask(e, deps)).status, "DONE");
  assert.deepEqual(await runHandlerTask(e, deps), { status: "REFUSED", reason: "duplicate-task" });
  covered.add("deps:map-package");
});

// MUST stay the last test of this file: node:test runs top-level tests in order.
test("COVERAGE GATE: every registered handler capability was exercised by a behavioural test above (no handler without a test)", () => {
  const registered = HANDLERS.map((h) => h.contract.capability).sort();
  assert.deepEqual([...covered].sort(), registered);
});
