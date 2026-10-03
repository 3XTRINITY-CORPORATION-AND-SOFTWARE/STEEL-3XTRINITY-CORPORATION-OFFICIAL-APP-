// Regression: a stacked squash-merge once left a duplicate "include" key without a
// conflict marker in tsconfig.cerberus.json (and package.json, matrix tests), which broke `npm run typecheck` on main.
// STACKED_CONFIG_COLLISION (docs/factory/INCIDENTS.md): two stacked PRs each edited the one-line `test` script and the
// merge left two `"test"` keys in package.json. The guard below (1) detects duplicate keys, (2) proves it rejects that
// exact shape, and (3) proves every test file on disk is run by the `test` script exactly once, so a new *.test.* that
// nobody registered (or registered twice) fails here instead of silently never running.
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import ts from "typescript";

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

function testFilesOnDisk(dir = "") {
  const out = [];
  for (const e of readdirSync(new URL(dir, root), { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) out.push(...testFilesOnDisk(`${dir}${e.name}/`));
    } else if (e.isFile() && TEST_FILE.test(e.name)) out.push(`${dir}${e.name}`);
  }
  return out.sort();
}

const globToRegExp = (g) =>
  new RegExp(
    "^" +
      g
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*\*\//g, "@@GLOBSTAR@@")
        .replace(/\*/g, "[^/]*")
        .replace(/@@GLOBSTAR@@/g, "(?:.*/)?") +
      "$",
  );

/** Every path/glob argument that follows a `--test` flag in the `test` script (quotes stripped). */
export function testScriptArgs(script) {
  const args = [];
  for (const segment of script.split("&&")) {
    const tokens = segment.trim().split(/\s+/);
    const at = tokens.indexOf("--test");
    if (at < 0) continue;
    for (const tok of tokens.slice(at + 1)) {
      if (tok.startsWith("-")) continue;
      args.push(tok.replace(/^['"]|['"]$/g, ""));
    }
  }
  return args;
}

/** For each test file on disk, the list of script arguments that run it. */
export function coverage(files, args) {
  return Object.fromEntries(files.map((f) => [f, args.filter((a) => (a.includes("*") ? globToRegExp(a).test(f) : a === f))]));
}

test("coverage guard: every *.test.* / *.spec.* file in the repo is run by the `test` script exactly once", () => {
  const script = JSON.parse(readFileSync(new URL("package.json", root), "utf8")).scripts.test;
  assert.equal(typeof script, "string");
  const args = testScriptArgs(script);
  assert.ok(args.length > 10, "test script lists test files/globs");
  const files = testFilesOnDisk();
  assert.ok(files.length > 10, "found test files on disk");
  const cov = coverage(files, args);
  const unregistered = files.filter((f) => cov[f].length === 0);
  const duplicated = files.filter((f) => cov[f].length > 1);
  assert.deepEqual(unregistered, [], `test files NOT run by npm test (add them to the single "test" script): ${unregistered.join(", ")}`);
  assert.deepEqual(duplicated, [], `test files run more than once: ${duplicated.join(", ")}`);
  // the script must not name a file that does not exist (typos would otherwise hide as 'cancelled' or be ignored)
  const missing = args.filter((a) => !a.includes("*") && !files.includes(a));
  assert.deepEqual(missing, [], `test script names non-existent test files: ${missing.join(", ")}`);
  // an explicit file listed twice in the script
  const explicit = args.filter((a) => !a.includes("*"));
  assert.equal(new Set(explicit).size, explicit.length, "test script lists a file twice");
});

test("coverage guard: it fails for an unregistered, a doubly-registered and a misspelled test file (self-check)", () => {
  const args = testScriptArgs("node --test 'scripts/**/*.test.mjs' && node --experimental-strip-types --test a/x.test.ts a/y.test.ts a/y.test.ts");
  assert.deepEqual(args, ["scripts/**/*.test.mjs", "a/x.test.ts", "a/y.test.ts", "a/y.test.ts"]);
  const cov = coverage(["scripts/a.test.mjs", "scripts/deep/b.test.mjs", "a/x.test.ts", "a/y.test.ts", "a/new.test.ts", "other/scripts/c.test.mjs"], args);
  assert.deepEqual(cov["scripts/a.test.mjs"], ["scripts/**/*.test.mjs"]);
  assert.deepEqual(cov["scripts/deep/b.test.mjs"], ["scripts/**/*.test.mjs"]);
  assert.equal(cov["a/new.test.ts"].length, 0, "unregistered file detected");
  assert.equal(cov["a/y.test.ts"].length, 2, "double registration detected");
  assert.equal(cov["other/scripts/c.test.mjs"].length, 0, "glob is anchored at the repo root");
});
