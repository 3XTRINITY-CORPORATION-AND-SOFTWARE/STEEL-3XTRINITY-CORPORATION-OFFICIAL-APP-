import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CHILD_ENV, applyMutant, formatMarkdown, reportProblems, runMutation, validateCatalog, type Mutant, type MutationOptions } from "../mutation/engine.ts";
import { MUTANTS } from "../mutation/mutants.ts";
import { ROOT } from "./helpers.ts";

/**
 * Tests of the mutation harness itself. Skipped inside mutant child processes (the harness runs the
 * factory tests; those must not start another harness).
 */
const inChild = process.env[CHILD_ENV] === "1";
const t = inChild ? test.skip : test;

const LIB = `export function add(a: number, b: number): number {\n  return a + b;\n}\nexport function sign(n: number): number {\n  if (n < 0) return -1;\n  return 1;\n}\n`;
const LIB_TEST = `import test from "node:test";\nimport assert from "node:assert/strict";\nimport { add, sign } from "../src/lib.ts";\ntest("add", () => assert.equal(add(2, 3), 5));\ntest("sign of a negative number", () => assert.equal(sign(-4), -1));\n`;

function fixture(libTest = LIB_TEST): string {
  const dir = mkdtempSync(join(tmpdir(), "mutation-fixture-"));
  mkdirSync(join(dir, "src"));
  mkdirSync(join(dir, "tests"));
  writeFileSync(join(dir, "package.json"), '{"type":"module"}\n');
  writeFileSync(join(dir, "src/lib.ts"), LIB);
  writeFileSync(join(dir, "tests/lib.test.ts"), libTest);
  return dir;
}
const opts = (dir: string, mutants: Mutant[], extra: Partial<MutationOptions> = {}): MutationOptions => ({
  sourceRoot: dir,
  copyPaths: ["src", "tests", "package.json"],
  testFiles: ["tests/lib.test.ts"],
  mutants,
  git: false,
  concurrency: 3,
  timeoutMs: 20_000,
  nodeArgs: ["--experimental-strip-types"],
  ...extra,
});
const mk = (id: string, find: string, replace: string, equivalent?: string): Mutant => ({ id, file: "src/lib.ts", description: id, find, replace, ...(equivalent ? { equivalent } : {}) });

t("applyMutant: exact single replacement; missing, ambiguous, empty and no-op edits are errors (a stale mutant can never pass as 'survived')", () => {
  assert.equal(applyMutant("a + b", { id: "x", find: "+", replace: "-" }), "a - b");
  assert.throws(() => applyMutant("a + b", { id: "x", find: "*", replace: "-" }), /not present/);
  assert.throws(() => applyMutant("a + b + c", { id: "x", find: "+", replace: "-" }), /ambiguous/);
  assert.throws(() => applyMutant("a", { id: "x", find: "", replace: "-" }), /empty find/);
  assert.throws(() => applyMutant("a", { id: "x", find: "a", replace: "a" }), /no-op/);
});

t("catalog: every mutant matches the CURRENT source exactly once, ids are unique, equivalent annotations carry a real justification", () => {
  assert.deepEqual(validateCatalog(ROOT, MUTANTS), []);
  assert.ok(MUTANTS.length >= 60, `${MUTANTS.length} mutants`);
  for (const m of MUTANTS) if (m.equivalent !== undefined) assert.ok(m.equivalent.length >= 60, `${m.id}: equivalence needs a concrete reason`);
  assert.equal(new Set(MUTANTS.map((m) => m.file)).size >= 8, true, "mutants span the gate/validator files");
});

t("engine (fixture project): KILLED / SURVIVED / TIMEOUT / INVALID are classified correctly, the score is exactly (killed+timeout)/total, order follows the catalog, the source tree is untouched", async () => {
  const dir = fixture();
  try {
    const before = readFileSync(join(dir, "src/lib.ts"), "utf8");
    const mutants = [
      mk("M-kill", "return a + b;", "return a - b;"),
      mk("M-survive", "if (n < 0) return -1;", "if (n < 0.5) return -1;"),
      mk("M-timeout", "return a + b;", "for (;;) {}"),
      mk("M-syntax", "return a + b;", "return a + ;"),
      mk("M-stale", "this text is not in the file", "x"),
      mk("M-kill-2", "return 1;", "return 2;"),
    ];
    const rep = await runMutation(opts(dir, mutants, { timeoutMs: 6000 }));
    assert.equal(rep.baseline.ok, true);
    assert.deepEqual(rep.results.map((r) => [r.id, r.status]), [
      ["M-kill", "KILLED"],
      ["M-survive", "SURVIVED"],
      ["M-timeout", "TIMEOUT"],
      ["M-syntax", "INVALID"],
      ["M-stale", "INVALID"],
      ["M-kill-2", "SURVIVED"],
    ]);
    assert.equal(rep.total, 6);
    assert.equal(rep.killed, 1);
    assert.equal(rep.timeout, 1);
    assert.equal(rep.survived, 2);
    assert.equal(rep.invalid, 2);
    assert.equal(rep.score, 2 / 6);
    assert.equal(rep.results[0]?.first_failing_test, "add");
    assert.match(rep.results[4]?.detail ?? "", /stale mutant/);
    assert.equal(readFileSync(join(dir, "src/lib.ts"), "utf8"), before, "the original tree is never modified");
    const problems = reportProblems(rep);
    assert.equal(problems.filter((p) => p.includes("INVALID")).length, 2);
    assert.equal(problems.filter((p) => p.includes("SURVIVED")).length, 2);
    assert.match(formatMarkdown(rep), /Mutation score: \*\*2\/6 killed \(33\.3%\)\*\*; survived 2; invalid 2; timeout 1/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

t("engine: an annotated equivalent survivor is acceptable, an unannotated one is a problem; results do not depend on concurrency", async () => {
  const dir = fixture();
  try {
    const mutants = [
      mk("E1", "if (n < 0) return -1;", "if (n < 0.5) return -1;", "test-only equivalence in this fixture: no test observes sign(0) and the input domain of the callers is integers < 0 or > 0"),
      mk("K1", "return a + b;", "return a * b;"),
    ];
    const a = await runMutation(opts(dir, mutants, { concurrency: 1 }));
    const b = await runMutation(opts(dir, mutants, { concurrency: 4 }));
    assert.deepEqual(a.results, b.results);
    assert.deepEqual(reportProblems(a), []);
    assert.equal(a.survived, 1);
    assert.equal(a.score, 1 / 2, "equivalent survivors stay in the denominator");
    const bad = await runMutation(opts(dir, [mk("S1", "if (n < 0) return -1;", "if (n < 0.5) return -1;")]));
    assert.equal(reportProblems(bad).length, 1);
    assert.match(reportProblems(bad)[0] ?? "", /^S1: SURVIVED/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

t("engine: a red baseline aborts the run (nothing is reported as killed) and `only` restricts the mutants", async () => {
  const red = fixture(LIB_TEST.replace("add(2, 3), 5", "add(2, 3), 6"));
  try {
    const rep = await runMutation(opts(red, [mk("M", "return a + b;", "return a - b;")]));
    assert.equal(rep.baseline.ok, false);
    assert.equal(rep.total, 0);
    assert.equal(rep.killed, 0);
    assert.equal(rep.score, null);
    assert.ok(reportProblems(rep)[0]?.startsWith("baseline is not green"));
  } finally {
    rmSync(red, { recursive: true, force: true });
  }
  const dir = fixture();
  try {
    const rep = await runMutation(opts(dir, [mk("A", "return a + b;", "return a - b;"), mk("B", "return 1;", "return 2;")], { only: ["A"] }));
    assert.deepEqual(rep.results.map((r) => r.id), ["A"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

t("engine on the REAL factory sources (git workspace): the baseline is green and one real guard mutant (CERBERUS replay guard ignored) is KILLED", async () => {
  const g01 = MUTANTS.find((m) => m.id === "G01");
  assert.ok(g01);
  const rep = await runMutation({
    sourceRoot: ROOT,
    copyPaths: ["cerberus", "kratt", "rastik", "factory", "package.json"],
    testFiles: ["factory/tests/cerberus-gate.test.ts", "factory/tests/loop.test.ts"],
    mutants: [g01],
    git: true,
    concurrency: 1,
    timeoutMs: 120_000,
    nodeArgs: ["--experimental-strip-types"],
  });
  assert.equal(rep.baseline.ok, true, rep.baseline.detail ?? "");
  assert.equal(rep.results[0]?.status, "KILLED");
  assert.ok((rep.results[0]?.failing_tests ?? 0) >= 1);
});
