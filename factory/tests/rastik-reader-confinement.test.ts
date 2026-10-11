// RÄSTIK's repository readers (readRuntimeDeclarations / readConfigDeclarations) read fixed repo-relative paths. A committed
// symlink must not make them read a file OUTSIDE the repository root (same escape class as the runtime-verify
// node-version-file "../x" defect): an escaping file is treated as absent.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readConfigDeclarations, readRuntimeDeclarations } from "../rastik-attacks.ts";

function fixture(): { root: string; outside: string } {
  const base = mkdtempSync(join(tmpdir(), "rastik-confine-"));
  const root = join(base, "repo");
  const outside = join(base, "outside");
  mkdirSync(root);
  mkdirSync(join(outside, "workflows"), { recursive: true });
  writeFileSync(join(outside, "nvmrc"), "22\n");
  writeFileSync(join(outside, "package.json"), '{"engines":{"node":"22.x"},"scripts":{"test":"node scripts/run-tests.mjs"}}\n');
  writeFileSync(join(outside, "workflows", "ci.yml"), 'jobs:\n  b:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: "22"\n');
  return { root, outside };
}

test("readRuntimeDeclarations: symlinked .nvmrc / package.json / .github/workflows pointing outside the root are treated as absent", () => {
  const { root, outside } = fixture();
  symlinkSync(join(outside, "nvmrc"), join(root, ".nvmrc"));
  symlinkSync(join(outside, "package.json"), join(root, "package.json"));
  mkdirSync(join(root, ".github"));
  symlinkSync(join(outside, "workflows"), join(root, ".github", "workflows"));
  const d = readRuntimeDeclarations(root);
  assert.equal(d.nvmrc, null, "file symlink out of the root");
  assert.equal(d.engines_node, null, "package.json symlink out of the root");
  assert.deepEqual(d.ci_node_versions, [], "workflows directory symlink out of the root");
});

test("readConfigDeclarations: symlinked package.json and workflows directory pointing outside the root are treated as absent", () => {
  const { root, outside } = fixture();
  symlinkSync(join(outside, "package.json"), join(root, "package.json"));
  mkdirSync(join(root, ".github"));
  symlinkSync(join(outside, "workflows"), join(root, ".github", "workflows"));
  const d = readConfigDeclarations(root);
  assert.equal(d.package_json, null);
  assert.deepEqual(d.workflows, []);
});

test("control: in-root files and in-root symlinks are still read", () => {
  const { root } = fixture();
  writeFileSync(join(root, "real-nvmrc"), "22\n");
  symlinkSync("real-nvmrc", join(root, ".nvmrc"));
  writeFileSync(join(root, "package.json"), '{"engines":{"node":"22.x"}}\n');
  mkdirSync(join(root, ".github", "workflows"), { recursive: true });
  writeFileSync(join(root, ".github", "workflows", "ci.yml"), 'jobs:\n  b:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: "22"\n');
  const d = readRuntimeDeclarations(root);
  assert.equal(d.nvmrc?.trim(), "22");
  assert.equal(d.engines_node, "22.x");
  assert.deepEqual(d.ci_node_versions, ["22"]);
  const c = readConfigDeclarations(root);
  assert.match(c.package_json ?? "", /22\.x/);
  assert.deepEqual(c.workflows.map((w) => w.name), ["ci.yml"]);
});
