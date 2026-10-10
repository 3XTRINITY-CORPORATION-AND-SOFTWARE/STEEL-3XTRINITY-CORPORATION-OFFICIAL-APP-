// Guards that every place that names a Node major agrees on the same one.
// Source of truth: .nvmrc. Drift between .nvmrc, package.json engines,
// the devcontainer Node feature, and the CI setup-node version fails here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(root, p), "utf8");

const nvmrcMajor = read(".nvmrc").trim().replace(/^v/, "").split(".")[0];

test(".nvmrc names a numeric Node major", () => {
  assert.match(nvmrcMajor, /^\d+$/);
});

test("package.json engines.node pins the .nvmrc major", () => {
  const pkg = JSON.parse(read("package.json"));
  assert.equal(typeof pkg.engines?.node, "string", "engines.node missing");
  assert.equal(pkg.engines.node, `${nvmrcMajor}.x`);
});

test("devcontainer Node feature uses the .nvmrc major", () => {
  const dc = JSON.parse(read(".devcontainer/devcontainer.json"));
  const feature = Object.entries(dc.features ?? {}).find(([k]) =>
    k.includes("/features/node"),
  );
  assert.ok(feature, "devcontainer has no node feature");
  assert.equal(String(feature[1].version), nvmrcMajor);
});

test("CI setup-node uses the .nvmrc major", () => {
  const ci = read(".github/workflows/ci.yml");
  const m = ci.match(/node-version:\s*["']?(\d+)/);
  assert.ok(m, "ci.yml has no node-version");
  assert.equal(m[1], nvmrcMajor);
});
