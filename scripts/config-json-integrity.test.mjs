// Regression: a stacked squash-merge once left a duplicate "include" key without a
// conflict marker in tsconfig.cerberus.json (and package.json, matrix tests), which broke `npm run typecheck` on main.
// STACKED_CONFIG_COLLISION (docs/factory/INCIDENTS.md): stacked PRs each edited the one-line `test` script and the
// merge left two `"test"` keys in package.json (four times). The guard below (1) detects duplicate keys, (2) proves it
// rejects that exact shape, (3) pins `scripts.test` to the discovery runner (scripts/run-tests.mjs), so no PR ever needs to
// edit it again, and (4) proves the runner discovers and runs every test file on disk exactly once, so a new *.test.* can
// neither be forgotten nor registered twice.
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { buildPlan, discoverTests } from "./run-tests.mjs";

const root = new URL("../", import.meta.url);

/** Syntax errors and duplicate object keys (at any depth) of a JSON/JSONC text. Returns a list of problem strings. */
export function configProblems(name, text) {
  const problems = [];
  const { error } = ts.parseConfigFileTextToJson(name, text);
  if (error) problems.push(`syntax: ${ts.flattenDiagnosticMessageText(error.messageText, "\n")}`);
  const sf = ts.parseJsonText(name, text);
  if (sf.parseDiagnostics.length !== 0) problems.push(`parse diagnostics: ${sf.parseDiagnostics.length}`);
  const walk = (node) => {
    if (node.kind === ts.SyntaxKind.ObjectLiteralExpression) {
      const names = node.properties.map((p) => p.name && p.name.text);
      const seen = new Set();
      for (const n of names) {
        if (seen.has(n)) problems.push(`duplicate key '${n}' in ${name}: ${names.join(",")}`);
        seen.add(n);
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(sf);
  return problems;
}

const factoryJson = (existsSync(new URL("factory/", root)) ? readdirSync(new URL("factory/", root)) : [])
  .filter((n) => n.endsWith(".json"))
  .map((n) => `factory/${n}`);

for (const f of [...readdirSync(root).filter((n) => /^(tsconfig.*|package)\.json$/.test(n)), ...factoryJson]) {
  test(`${f} parses without syntax errors and has no duplicate keys`, () => {
    const problems = configProblems(f, readFileSync(new URL(f, root), "utf8"));
    assert.deepEqual(problems, []);
  });
}

// ---- STACKED_CONFIG_COLLISION regression ----------------------------------------------------------------------------
test("STACKED_CONFIG_COLLISION: a package.json with two `test` script keys is rejected (the incident shape)", () => {
  const good = '{\n  "scripts": {\n    "lint": "eslint .",\n    "test": "node --test a.test.mjs"\n  }\n}\n';
  const stacked =
    '{\n  "scripts": {\n    "lint": "eslint .",\n    "test": "node --test a.test.mjs",\n    "test": "node --test a.test.mjs b.test.mjs"\n  }\n}\n';
  assert.deepEqual(configProblems("package.json", good), []);
  const problems = configProblems("package.json", stacked);
  assert.equal(problems.length, 1, problems.join(" | "));
  assert.match(problems[0], /duplicate key 'test' in package\.json/);
  // three occurrences (#50/#51/#52) are three reports' worth of the same defect, never silently accepted
  const triple = stacked.replace('"test": "node --test a.test.mjs b.test.mjs"', '"test": "x",\n    "test": "y"');
  assert.equal(configProblems("package.json", triple).length, 2);
  // duplicates nested elsewhere are caught too
  assert.equal(configProblems("tsconfig.json", '{"compilerOptions":{"strict":true},"include":["a"],"include":["b"]}').length, 1);
});

// ---- test-file coverage guard -----------------------------------------------------------------------------------------
const TEST_FILE = /\.(test|spec)\.(mjs|cjs|js|mts|cts|ts|tsx|jsx)$/;
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", ".vercel", ".turbo", ".cache", "out"]);

// Independent walk (deliberately NOT the runner's own function) so the guard does not just ask the runner to grade itself.
function testFilesOnDisk(dir = "") {
  const out = [];
  for (const e of readdirSync(new URL(dir, root), { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) out.push(...testFilesOnDisk(`${dir}${e.name}/`));
    } else if (e.isFile() && TEST_FILE.test(e.name)) out.push(`${dir}${e.name}`);
  }
  return out.sort();
}

test("coverage guard: `scripts.test` is exactly the discovery runner (no hand-maintained file list can drift or collide)", () => {
  const pkg = JSON.parse(readFileSync(new URL("package.json", root), "utf8"));
  assert.equal(pkg.scripts.test, "node scripts/run-tests.mjs");
  assert.ok(existsSync(new URL("scripts/run-tests.mjs", root)));
  // test:coverage wraps `npm test`, so coverage runs the same discovered set
  assert.match(pkg.scripts["test:coverage"], /\bnpm test\b/);
});

test("coverage guard: the runner discovers and runs every *.test.* / *.spec.* file on disk exactly once", () => {
  const disk = testFilesOnDisk();
  assert.ok(disk.length > 10, "found test files on disk");
  const discovered = discoverTests(fileURLToPath(root));
  assert.deepEqual(discovered, disk, "runner discovery differs from an independent walk of the repo");
  const plan = buildPlan(discovered); // throws on a file type the runner cannot execute (fail closed)
  const run = plan.flatMap((g) => g.args.filter((a) => TEST_FILE.test(a)));
  const counts = new Map();
  for (const f of run) counts.set(f, (counts.get(f) ?? 0) + 1);
  assert.deepEqual([...counts.keys()].sort(), disk, "files the runner would execute differ from files on disk");
  assert.deepEqual([...counts].filter(([, n]) => n !== 1), [], "a test file would run more than once");
  assert.equal(readdirSync(new URL("scripts/", root)).filter((n) => n === "run-tests.test.mjs").length, 1, "the runner has its own regression test");
});
