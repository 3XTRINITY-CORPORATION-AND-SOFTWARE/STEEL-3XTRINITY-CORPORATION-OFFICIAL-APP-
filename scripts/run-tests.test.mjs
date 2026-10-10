// Regression tests for scripts/run-tests.mjs (discovery, order, exit-code propagation, fail-closed behaviour).
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { EXCLUDE, NESTED_ENV, SKIP_DIRS, buildPlan, discoverTests, main, runPlan } from "./run-tests.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const RUNNER = join(HERE, "run-tests.mjs");
const tree = (files) => {
  const root = mkdtempSync(join(tmpdir(), "run-tests-"));
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), c);
  }
  return root;
};
/** Child env without the outer test runner's context, so the nested `node --test` behaves like a top-level run. */
const cleanEnv = () => {
  const e = { ...process.env };
  delete e.NODE_TEST_CONTEXT;
  delete e.RUN_TESTS_ACTIVE;
  return e;
};
// ALWAYS the fixture repo's own copy of the runner (running the real one would run the real suite, i.e. this file, recursively)
const runReal = (root, args = []) => spawnSync(process.execPath, [join(root, "scripts/run-tests.mjs"), ...args], { cwd: root, env: cleanEnv(), encoding: "utf8" });
// the runner resolves the repo root as its own parent directory, so give each fixture repo its own copy
const withRunnerCopy = (files) => tree({ ...files, "scripts/run-tests.mjs": runnerSource });
const runnerSource = readFileSync(RUNNER, "utf8");
const PASS = 'import t from "node:test"; t("ok", () => {});\n';
const FAIL = 'import t from "node:test"; import a from "node:assert/strict"; t("bad", () => a.equal(1, 2));\n';
const TS_PASS = 'import t from "node:test"; const n: number = 1; t("ts ok", () => { if (n !== 1) throw new Error("x"); });\n';
const TS_FAIL = 'import t from "node:test"; const n: number = 1; t("ts bad", () => { if (n === 1) throw new Error("x"); });\n';

test("DISCOVERY: finds *.test.* / *.spec.* at any depth, sorted by code point, repo-relative with '/'; ignores helpers, non-tests and skipped dirs", () => {
  const root = tree({
    "b.test.mjs": PASS, "a.test.mjs": PASS, "scripts/z.test.mjs": PASS, "scripts/deep/er/y.spec.mjs": PASS, "m/x.test.mjs": PASS, "m.test.mjs": PASS,
    "factory/tests/helpers.ts": "export {}", "factory/tests/fixtures.ts": "export {}", "factory/tests/x.test.ts": TS_PASS, "Cap.test.ts": TS_PASS,
    "node_modules/pkg/dep.test.mjs": PASS, ".git/hooks/h.test.mjs": PASS, "dist/d.test.mjs": PASS, "coverage/c.test.mjs": PASS,
    "readme.md": "x", "latest.mjs": "x", "test.mjs": "x", "contest.mjs": "x", "a.tests.mjs": "x",
  });
  assert.deepEqual(discoverTests(root), ["Cap.test.ts", "a.test.mjs", "b.test.mjs", "factory/tests/x.test.ts", "m.test.mjs", "m/x.test.mjs", "scripts/deep/er/y.spec.mjs", "scripts/z.test.mjs"]);
  assert.deepEqual(discoverTests(root), discoverTests(root), "deterministic");
  for (const d of ["node_modules", ".git", "dist", "build", "coverage"]) assert.ok(SKIP_DIRS.has(d), d);
  assert.deepEqual({ ...EXCLUDE }, {}, "nothing is excluded today; adding an entry is a reviewed change");
});

test("DISCOVERY: an explicit exclude entry removes exactly that file", () => {
  const root = tree({ "a.test.mjs": PASS, "fixtures/not-a-test.test.mjs": PASS });
  assert.deepEqual(discoverTests(root, { "fixtures/not-a-test.test.mjs": "intentional fixture" }), ["a.test.mjs"]);
});

test("PLAN (order): the .mjs group runs first with `node --test`, then the .ts group with --experimental-strip-types; each group is sorted; every file appears exactly once", () => {
  const plan = buildPlan(["a.test.mjs", "c.test.ts", "scripts/b.test.mjs", "d.test.mts", "e.spec.cjs"], "NODE");
  assert.deepEqual(plan.map((g) => [g.cmd, g.args]), [
    ["NODE", ["--test", "a.test.mjs", "scripts/b.test.mjs", "e.spec.cjs"]],
    ["NODE", ["--experimental-strip-types", "--test", "c.test.ts", "d.test.mts"]],
  ]);
  assert.deepEqual(buildPlan(["x.test.ts"], "N").map((g) => g.name), ["node --experimental-strip-types --test"]);
  assert.deepEqual(buildPlan([], "N"), []);
});

test("PLAN (fail closed): a test file type the runner cannot execute is an error, never silently skipped", () => {
  assert.throws(() => buildPlan(["ok.test.mjs", "ui.test.tsx"]), /ui\.test\.tsx/);
  assert.throws(() => buildPlan(["ui.spec.jsx"]), /cannot execute/);
});

test("EXIT PROPAGATION (injected spawn): 0 only if every group exits 0; the failing group's code is returned and later groups are NOT run (old `&&`)", () => {
  const plan = buildPlan(["a.test.mjs", "b.test.ts"], "N");
  const calls = [];
  const fake = (codes) => (cmd, args) => {
    calls.push(args[0]);
    const r = codes.shift();
    return typeof r === "object" ? r : { status: r };
  };
  assert.equal(runPlan(plan, { spawn: fake([0, 0]) }), 0);
  assert.deepEqual(calls.splice(0), ["--test", "--experimental-strip-types"]);
  assert.equal(runPlan(plan, { spawn: fake([3, 0]) }), 3);
  assert.deepEqual(calls.splice(0), ["--test"], "ts group skipped after mjs failure");
  assert.equal(runPlan(plan, { spawn: fake([0, 7]) }), 7);
  const logged = [];
  const keep = console.error;
  console.error = (m) => logged.push(String(m));
  try {
    assert.equal(runPlan(plan, { spawn: fake([{ status: null, signal: "SIGKILL" }]) }), 1, "signal => failure");
    assert.equal(runPlan(plan, { spawn: fake([{ status: null, error: new Error("ENOENT") }]) }), 1, "spawn error => failure");
  } finally {
    console.error = keep;
  }
  assert.match(logged[0] ?? "", /terminated by SIGKILL/);
  assert.match(logged[1] ?? "", /failed to start .*ENOENT/);
  assert.equal(runPlan(plan, { spawn: fake([{ status: null }]) }), 1, "no status => failure");
  assert.equal(runPlan([], { spawn: fake([]) }), 0, "an empty plan is handled by main(), not by runPlan");
});

test("MAIN: refuses an empty suite and unknown arguments (exit != 0)", () => {
  const root = tree({ "readme.md": "x" });
  const silent = console.error;
  console.error = () => {};
  try {
    assert.equal(main([], root, {}), 1);
    assert.equal(main(["--bogus"], root, {}), 2);
    assert.equal(main(["--list", "x"], root, {}), 2);
  } finally {
    console.error = silent;
  }
});

test("REAL RUN (e2e): passing .mjs + .ts tests => exit 0 and both groups ran; --list prints the discovered files in run order", () => {
  const root = withRunnerCopy({ "scripts/ok.test.mjs": PASS, "factory/tests/ok.test.ts": TS_PASS });
  const r = runReal(root);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /ok/);
  assert.match(r.stdout, /ts ok/, "the .ts group ran under --experimental-strip-types");
  const l = runReal(root, ["--list"]);
  assert.equal(l.status, 0);
  assert.deepEqual(l.stdout.trim().split("\n"), ["scripts/ok.test.mjs", "factory/tests/ok.test.ts"]);
});

test("REAL RUN (e2e): a failing .mjs test => non-zero exit and the .ts group does not run; a failing .ts test => non-zero exit", () => {
  const a = withRunnerCopy({ "scripts/bad.test.mjs": FAIL, "factory/tests/ok.test.ts": TS_PASS });
  const ra = runReal(a);
  assert.notEqual(ra.status, 0);
  assert.doesNotMatch(ra.stdout, /ts ok/, "ts group skipped after the mjs failure");
  const b = withRunnerCopy({ "scripts/ok.test.mjs": PASS, "factory/tests/bad.test.ts": TS_FAIL });
  const rb = runReal(b);
  assert.notEqual(rb.status, 0, rb.stdout);
  assert.match(rb.stdout, /ts bad/);
  const c = withRunnerCopy({ "scripts/ok.test.mjs": PASS, "ui/x.test.tsx": PASS });
  const rc = runReal(c);
  assert.equal(rc.status, 1);
  assert.match(rc.stderr, /cannot execute/);
});

test("COVERAGE SELF-CHECK: a repo with an extra, unregistered test file is picked up automatically (no package.json edit), and a runner that dropped a file would differ from disk", () => {
  const root = withRunnerCopy({ "scripts/a.test.mjs": PASS });
  const before = discoverTests(root);
  writeFileSync(join(root, "scripts/new.test.mjs"), PASS);
  mkdirSync(join(root, "factory/tests"), { recursive: true });
  writeFileSync(join(root, "factory/tests/new.test.ts"), TS_PASS);
  const after = discoverTests(root);
  assert.deepEqual(after.filter((f) => !before.includes(f)), ["factory/tests/new.test.ts", "scripts/new.test.mjs"]);
  const r = runReal(root);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /ts ok/);
});

test("RECURSION GUARD: the runner marks its children and refuses to run when started inside another run; children really see the marker", () => {
  const root = withRunnerCopy({ "scripts/env.test.mjs": 'import t from "node:test"; import a from "node:assert/strict"; t("marker", () => a.equal(process.env.RUN_TESTS_ACTIVE, "1"));\n' });
  const ok = runReal(root);
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /marker/);
  const nested = spawnSync(process.execPath, [join(root, "scripts/run-tests.mjs")], { cwd: root, env: { ...cleanEnv(), [NESTED_ENV]: "1" }, encoding: "utf8" });
  assert.equal(nested.status, 3);
  assert.match(nested.stderr, /nested/);
  assert.doesNotMatch(nested.stdout, /marker/, "nothing was run");
});
