// Fixture tests for scripts/runtime-verify.mjs: each mismatch kind is detected, and the real repo passes.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseMajor, satisfies, rangePinsMajor, stripJsonc, verifyRuntime, render } from "./runtime-verify.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const OK_LOCAL = "22.12.0";
const WF = (nodeVersion, extra = "") => `name: ci\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: Setup Node.js\n        uses: actions/setup-node@v4\n        with:\n          ${nodeVersion}\n          cache: npm\n${extra}`;
const base = {
  ".nvmrc": "22\n",
  "package.json": JSON.stringify({ name: "x", engines: { node: "22.x" } }),
  ".github/workflows/ci.yml": WF('node-version: "22"'),
  ".devcontainer/devcontainer.json": JSON.stringify({ image: "mcr.microsoft.com/devcontainers/universal:2", features: { "ghcr.io/devcontainers/features/node:1": { version: "22" } } }),
};
function fixture(over = {}) {
  const root = mkdtempSync(join(tmpdir(), "rv-"));
  for (const [rel, text] of Object.entries({ ...base, ...over })) {
    if (text === null) continue;
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}
const run = (over = {}, localVersion = OK_LOCAL) => verifyRuntime({ root: fixture(over), localVersion });
const drifted = (r) => r.drift.map((d) => d.source);

describe("runtime verifier: contract holds", () => {
  it("a conforming fixture is RUNTIME_OK with every source listed", () => {
    const r = run();
    assert.equal(r.status, "RUNTIME_OK");
    assert.deepEqual(r.drift, []);
    assert.deepEqual(r.sources.map((s) => s.source.replace(/:\d+ /, ":N ")), ["local node", ".nvmrc", "package.json engines.node", ".github/workflows/ci.yml:N setup-node", ".devcontainer/devcontainer.json feature ghcr.io/devcontainers/features/node:1"]);
    assert.match(render(r), /^RUNTIME_OK expected node major 22 \(5 sources agree\)/);
  });
  it("the real repository passes (with a pinned local version, so it is deterministic)", () => {
    const r = verifyRuntime({ root: REPO, localVersion: OK_LOCAL });
    assert.equal(r.status, "RUNTIME_OK", render(r));
    assert.ok(r.sources.some((s) => s.source === ".nvmrc") && r.sources.some((s) => s.source.includes("setup-node")) && r.sources.some((s) => s.source.includes("devcontainer")));
  });
  it("the CLI exits 0 on the real repo exactly when the running node is 22, and 1 with RUNTIME_DRIFT otherwise", () => {
    const p = spawnSync(process.execPath, [join(REPO, "scripts/runtime-verify.mjs")], { encoding: "utf8" });
    const is22 = process.versions.node.split(".")[0] === "22";
    assert.equal(p.status, is22 ? 0 : 1, p.stdout + p.stderr);
    assert.match(p.stdout, is22 ? /^RUNTIME_OK/ : /^RUNTIME_DRIFT[\s\S]*MISMATCH local node/);
    const j = spawnSync(process.execPath, [join(REPO, "scripts/runtime-verify.mjs"), "--json"], { encoding: "utf8" });
    assert.equal(JSON.parse(j.stdout).expected, 22);
  });
  it("is deterministic: two runs over the same tree are identical", () => {
    const root = fixture();
    assert.deepEqual(verifyRuntime({ root, localVersion: OK_LOCAL }), verifyRuntime({ root, localVersion: OK_LOCAL }));
  });
});

describe("runtime verifier: each mismatch is detected and named", () => {
  it("local node major", () => {
    const r = run({}, "20.11.1");
    assert.equal(r.status, "RUNTIME_DRIFT");
    assert.deepEqual(drifted(r), ["local node"]);
    assert.match(render(r), /MISMATCH local node: found "20\.11\.1" - major 20, expected 22/);
    assert.deepEqual(drifted(run({}, "24.0.0")), ["local node"]);
  });
  it(".nvmrc wrong, non-numeric or missing", () => {
    assert.deepEqual(drifted(run({ ".nvmrc": "20\n" })), [".nvmrc"]);
    assert.deepEqual(drifted(run({ ".nvmrc": "lts/*\n" })), [".nvmrc"]);
    assert.deepEqual(drifted(run({ ".nvmrc": null })), [".nvmrc"]);
    assert.equal(run({ ".nvmrc": "v22.3.0\n" }).status, "RUNTIME_OK");
  });
  it("package.json engines: wrong major, too wide, too narrow, missing, unparseable range", () => {
    const eng = (node) => ({ "package.json": JSON.stringify({ engines: node === undefined ? {} : { node } }) });
    for (const bad of ["20.x", ">=22", ">=20 <23", "22.1.x", "^20", "*", "22 || 24"]) assert.deepEqual(drifted(run(eng(bad))), ["package.json engines.node"], bad);
    assert.deepEqual(drifted(run(eng(undefined))), ["package.json engines.node"]);
    assert.deepEqual(drifted(run(eng("lts"))), ["package.json engines.node"]);
    assert.deepEqual(drifted(run({ "package.json": "{nope" })), ["package.json engines.node"]);
    for (const good of ["22.x", ">=22 <23", ">=22.0.0 <23.0.0", "^22", "~22", "22", "22.*", ">=22 <22.99.99 || 22.99.99"]) assert.equal(run(eng(good)).status, "RUNTIME_OK", good);
  });
  it("CI setup-node: wrong version, matrix, expression, missing version, second workflow, no setup-node at all", () => {
    const only = (o) => drifted(run(o)).map((s) => s.replace(/:\d+ /, ":N "));
    assert.deepEqual(only({ ".github/workflows/ci.yml": WF('node-version: "20"') }), [".github/workflows/ci.yml:N setup-node"]);
    assert.deepEqual(only({ ".github/workflows/ci.yml": WF("node-version: [20, 22]") }), [".github/workflows/ci.yml:N setup-node"]);
    assert.deepEqual(only({ ".github/workflows/ci.yml": WF("node-version: ${{ matrix.node }}") }), [".github/workflows/ci.yml:N setup-node"]);
    assert.deepEqual(only({ ".github/workflows/ci.yml": WF("cache-dependency-path: package-lock.json") }), [".github/workflows/ci.yml:N setup-node"]);
    assert.deepEqual(only({ ".github/workflows/release.yml": WF("node-version: 18") }), [".github/workflows/release.yml:N setup-node"]);
    assert.deepEqual(only({ ".github/workflows/ci.yml": "name: ci\njobs: {}\n" }), [".github/workflows"]);
    assert.equal(run({ ".github/workflows/ci.yml": WF("node-version: 22.4.0") }).status, "RUNTIME_OK");
    assert.equal(run({ ".github/workflows/ci.yml": WF("node-version: '22' # pinned") }).status, "RUNTIME_OK");
  });
  it("CI node-version-file follows the file it names", () => {
    assert.equal(run({ ".github/workflows/ci.yml": WF("node-version-file: .nvmrc") }).status, "RUNTIME_OK");
    const r = run({ ".github/workflows/ci.yml": WF("node-version-file: .node-version"), ".node-version": "20.1.0\n" });
    assert.equal(r.status, "RUNTIME_DRIFT");
    assert.match(r.drift[0].found, /node-version-file: \.node-version -> 20\.1\.0/);
    assert.equal(run({ ".github/workflows/ci.yml": WF("node-version-file: .missing") }).status, "RUNTIME_DRIFT");
  });
  it("a setup-node step is judged on its own keys only: a later step's node-version does not rescue it, a column-0 comment inside the step does not end it", () => {
    const later = "      - name: other\n        uses: actions/something@v1\n        with:\n          node-version: \"22\"\n";
    const r = run({ ".github/workflows/ci.yml": WF("cache: npm", later) });
    assert.equal(r.status, "RUNTIME_DRIFT");
    assert.match(r.drift[0].reason, /no node-version/);
    const withComment = "name: ci\njobs:\n  t:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n# a comment at column 0\n          node-version: 22\n";
    assert.equal(run({ ".github/workflows/ci.yml": withComment }).status, "RUNTIME_OK");
  });
  it("only the node devcontainer feature is read: another feature's version is ignored", () => {
    const dc = JSON.stringify({ features: { "ghcr.io/devcontainers/features/node:1": { version: "22" }, "ghcr.io/devcontainers/features/python:1": { version: "3.11" } } });
    assert.equal(run({ ".devcontainer/devcontainer.json": dc }).status, "RUNTIME_OK");
  });
  it("commented-out setup-node steps are ignored", () => {
    const wf = WF('node-version: "22"') + "      # - uses: actions/setup-node@v4\n      #   with:\n      #     node-version: 18\n";
    assert.equal(run({ ".github/workflows/ci.yml": wf }).status, "RUNTIME_OK");
  });
  it("devcontainer: wrong feature version, no version, node image tag, build arg, JSONC comments, unparseable", () => {
    const dc = (o) => ({ ".devcontainer/devcontainer.json": typeof o === "string" ? o : JSON.stringify(o) });
    const feat = (version) => ({ features: { "ghcr.io/devcontainers/features/node:1": version === undefined ? {} : { version } } });
    assert.deepEqual(drifted(run(dc(feat("20")))), [".devcontainer/devcontainer.json feature ghcr.io/devcontainers/features/node:1"]);
    assert.deepEqual(drifted(run(dc(feat(undefined)))), [".devcontainer/devcontainer.json feature ghcr.io/devcontainers/features/node:1"]);
    assert.deepEqual(drifted(run(dc({ image: "mcr.microsoft.com/devcontainers/javascript-node:20-bookworm" }))), [".devcontainer/devcontainer.json image"]);
    assert.equal(run(dc({ image: "mcr.microsoft.com/devcontainers/javascript-node:22-bookworm" })).status, "RUNTIME_OK");
    assert.deepEqual(drifted(run(dc({ build: { args: { NODE_VERSION: "18" } } }))), [".devcontainer/devcontainer.json build.args.NODE_VERSION"]);
    assert.deepEqual(drifted(run(dc("{ not json"))), [".devcontainer/devcontainer.json"]);
    assert.equal(run(dc('{\n // comment with "quotes" and a url http://x\n "features": { "ghcr.io/devcontainers/features/node:1": { "version": "22" /* pin */ } }\n}')).status, "RUNTIME_OK");
  });
  it("devcontainer absent is fine (where present only)", () => {
    const r = run({ ".devcontainer/devcontainer.json": null });
    assert.equal(r.status, "RUNTIME_OK");
    assert.ok(!r.sources.some((s) => s.source.includes("devcontainer")));
  });
  it("Dockerfile: wrong FROM tag, unpinned node image, ARG default, wrong ARG, nested devcontainer Dockerfile, multi-stage", () => {
    const dk = (text, name = "Dockerfile") => ({ [name]: text });
    assert.deepEqual(drifted(run(dk("FROM node:20-alpine\n"))), ["Dockerfile:1"]);
    assert.deepEqual(drifted(run(dk("FROM node:latest\n"))), ["Dockerfile:1"]);
    assert.deepEqual(drifted(run(dk("FROM node\n"))), ["Dockerfile:1"]);
    assert.deepEqual(drifted(run(dk("ARG NODE_VERSION=20\nFROM node:${NODE_VERSION}-slim\n"))).sort(), ["Dockerfile:1 ARG NODE_VERSION", "Dockerfile:2"].sort());
    assert.deepEqual(drifted(run(dk("FROM node:${UNSET}\n"))), ["Dockerfile:1"]);
    assert.deepEqual(drifted(run(dk("FROM docker.io/library/node:18 AS build\nFROM node:22-alpine\n"))), ["Dockerfile:1"]);
    assert.deepEqual(drifted(run(dk("FROM node:18\n", ".devcontainer/Dockerfile"))), [".devcontainer/Dockerfile:1"]);
    assert.equal(run(dk("ARG NODE_VERSION=22\nFROM --platform=linux/amd64 node:${NODE_VERSION}-slim AS app\nFROM ubuntu:24.04\n")).status, "RUNTIME_OK");
    assert.equal(run(dk("FROM node:22.4.1-bookworm\n")).status, "RUNTIME_OK");
  });
  it("several mismatches are all reported at once, sorted, with the exact sources", () => {
    const r = run({ ".nvmrc": "20", "package.json": JSON.stringify({ engines: { node: ">=18" } }), Dockerfile: "FROM node:18\n" }, "20.0.0");
    assert.deepEqual(drifted(r), ["local node", ".nvmrc", "package.json engines.node", "Dockerfile:1"]);
    const out = render(r);
    assert.match(out, /^RUNTIME_DRIFT expected node major 22 \(4 of 6 sources mismatch\)/);
    assert.equal(out.split("\n").filter((l) => l.includes("MISMATCH")).length, 4);
  });
});

describe("runtime verifier: CLI exit code on a drifted tree", () => {
  it("exits 1 and prints RUNTIME_DRIFT with the source when run against a modified copy of the repo", () => {
    const root = mkdtempSync(join(tmpdir(), "rv-cli-"));
    mkdirSync(join(root, "scripts"));
    cpSync(join(REPO, "scripts/runtime-verify.mjs"), join(root, "scripts/runtime-verify.mjs"));
    for (const rel of [".nvmrc", "package.json", ".github/workflows/ci.yml", ".devcontainer/devcontainer.json"]) { mkdirSync(dirname(join(root, rel)), { recursive: true }); cpSync(join(REPO, rel), join(root, rel)); }
    writeFileSync(join(root, ".nvmrc"), "20\n");
    const p = spawnSync(process.execPath, [join(root, "scripts/runtime-verify.mjs")], { encoding: "utf8" });
    assert.equal(p.status, 1);
    assert.match(p.stdout, /^RUNTIME_DRIFT/);
    assert.match(p.stdout, /MISMATCH \.nvmrc: found "20" - major 20, expected 22/);
  });
});

describe("runtime verifier: helpers and safety", () => {
  it("parseMajor", () => {
    for (const [t, m] of [["22", 22], ["v22.1.0", 22], ["22.x", 22], [" 22\n", 22], ["lts/*", null], ["latest", null], ["", null], ["22-alpine", null], ["node", null]]) assert.equal(parseMajor(t), m, t);
  });
  it("satisfies / rangePinsMajor implement the needed npm range subset", () => {
    assert.equal(satisfies("22.5.0", ">=22 <23"), true);
    assert.equal(satisfies("23.0.0", ">=22 <23"), false);
    assert.equal(satisfies("22.1.0", "~22.1"), true);
    assert.equal(satisfies("22.2.0", "~22.1"), false);
    assert.equal(satisfies("22.2.0", ">22.1"), true);
    assert.equal(satisfies("22.1.9", ">22.1"), false);
    assert.equal(satisfies("22.1.9", "<=22.1"), true);
    assert.equal(satisfies("20.0.0", "20 || 22"), true);
    assert.throws(() => satisfies("22.0.0", "22 - 23"));
    assert.throws(() => satisfies("22.0.0", ">=22 <banana"));
    assert.deepEqual(rangePinsMajor("22.x"), { ok: true, missing: [], leaked: [] });
    assert.equal(rangePinsMajor(">=22").ok, false);
    assert.equal(rangePinsMajor("22.x", 20).ok, false);
  });
  it("stripJsonc keeps comment-like text inside strings", () => {
    assert.deepEqual(JSON.parse(stripJsonc('{"u": "http://a//b /* c */", /* x */ "v": 1 // y\n}')), { u: "http://a//b /* c */", v: 1 });
  });
  it("the verifier is read-only and offline by construction: no write, spawn, network or installer API in its source", () => {
    const src = readFileSync(join(REPO, "scripts/runtime-verify.mjs"), "utf8").split("\n").filter((l) => !l.trimStart().startsWith("//")).join("\n");
    for (const banned of [/writeFile|appendFile|mkdir|rmSync|unlink|rename|copyFile|chmod/, /child_process|\bspawn|\bexecSync|\bexecFile|(?<![.\w])exec\(/, /node:(net|http|https|dns|tls|dgram)|fetch\(|XMLHttpRequest|WebSocket/, /\bnvm\b.*install|curl|wget/]) assert.doesNotMatch(src, banned);
  });
  it("the repo ships no nvm installer or node-version-manager bootstrap script", () => {
    for (const f of ["install-nvm.sh", "scripts/install-nvm.sh", "scripts/install-node.sh", "scripts/nvm-install.sh"]) assert.equal(existsSync(join(REPO, f)), false, f);
  });
});
