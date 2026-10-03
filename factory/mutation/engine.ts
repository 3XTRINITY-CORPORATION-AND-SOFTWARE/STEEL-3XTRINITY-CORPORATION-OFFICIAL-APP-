import { spawn, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

/**
 * Small deterministic mutation-testing harness. No dependencies.
 *
 * A mutant is an EXACT, hand-written source edit (`find` must occur exactly once in `file`;
 * a stale or ambiguous edit is a harness error, never a silent no-op). Each mutant is applied to a
 * private temporary copy of the project (the working tree under test is never modified), the copy is
 * committed to a throw-away git repo (the factory verifiers recompute from git), and the test files are
 * run with Node's built-in runner. Outcome per mutant:
 *
 *   KILLED   - the tests fail (non-zero exit with at least one failing test)
 *   TIMEOUT  - the tests did not finish in time (counted as killed, listed separately)
 *   SURVIVED - every test passed against the mutated source (a gap in the tests, or an equivalent mutant)
 *   INVALID  - the mutant does not compile/parse or crashed the runner without a failing test: this is a
 *              harness error, NOT a kill (it would inflate the score), and makes the run fail.
 *
 * The score is exactly killed(+timeout)/total over ALL mutants; equivalent mutants are not excluded
 * from the denominator (they can only be annotated with a justification).
 */
export interface Mutant {
  id: string;
  /** Path relative to the project root. */
  file: string;
  /** Human-readable, exact description of the edit. */
  description: string;
  /** Source text to replace; must occur exactly once. */
  find: string;
  replace: string;
  /** If this mutant is semantically equivalent to the original, say why. Still counted as survived. */
  equivalent?: string;
}

export type MutantStatus = "KILLED" | "TIMEOUT" | "SURVIVED" | "INVALID";

export interface MutantResult {
  id: string;
  file: string;
  description: string;
  status: MutantStatus;
  /** Number of failing top-level tests. */
  failing_tests: number;
  /** Name of the first failing test (TAP order), or null. */
  first_failing_test: string | null;
  equivalent: string | null;
  detail: string | null;
}

export interface MutationReport {
  baseline: { ok: boolean; tests: number; failing: number; detail: string | null };
  total: number;
  killed: number;
  timeout: number;
  survived: number;
  invalid: number;
  /** (killed + timeout) / total, or null when total is 0. */
  score: number | null;
  results: MutantResult[];
}

export interface MutationOptions {
  /** Project root to copy from (read-only). */
  sourceRoot: string;
  /** Paths (relative to sourceRoot) copied into every mutant workspace. */
  copyPaths: string[];
  /** Test files (relative paths) run in every workspace. */
  testFiles: string[];
  mutants: Mutant[];
  /** Commit the workspace twice into a throw-away git repo (needed by the factory verifiers). */
  git: boolean;
  concurrency?: number;
  timeoutMs?: number;
  /** Extra args for the node binary, e.g. ["--experimental-strip-types"]. */
  nodeArgs?: string[];
  /** Restrict to these mutant ids (the baseline still runs). */
  only?: string[];
}

export const CHILD_ENV = "FACTORY_MUTATION_CHILD";
const COPY_SKIP = new Set(["node_modules", ".git", "coverage", "dist", ".vercel", ".output"]);

/** Applies one mutant to source text. Throws unless `find` occurs exactly once. */
export function applyMutant(source: string, m: Pick<Mutant, "id" | "find" | "replace">): string {
  if (m.find.length === 0) throw new Error(`mutant ${m.id}: empty find`);
  if (m.find === m.replace) throw new Error(`mutant ${m.id}: replace equals find (no-op)`);
  const first = source.indexOf(m.find);
  if (first === -1) throw new Error(`mutant ${m.id}: find text not present in source (stale mutant)`);
  if (source.indexOf(m.find, first + 1) !== -1) throw new Error(`mutant ${m.id}: find text is ambiguous (occurs more than once)`);
  return source.slice(0, first) + m.replace + source.slice(first + m.find.length);
}

/** Checks the whole catalog against the current sources without running any test. Returns problems. */
export function validateCatalog(sourceRoot: string, mutants: readonly Mutant[]): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();
  for (const m of mutants) {
    if (ids.has(m.id)) problems.push(`duplicate mutant id ${m.id}`);
    ids.add(m.id);
    try {
      applyMutant(readFileSync(resolve(sourceRoot, m.file), "utf8"), m);
    } catch (e) {
      problems.push(e instanceof Error ? e.message : String(e));
    }
  }
  return problems;
}

interface RunOutcome {
  exitCode: number | null;
  timedOut: boolean;
  output: string;
  failing: string[];
  tests: number;
}

function parseTap(out: string): { failing: string[]; tests: number } {
  const failing: string[] = [];
  let tests = 0;
  for (const line of out.split("\n")) {
    const nok = /^not ok \d+ - (.*)$/.exec(line); // top level only (no indentation)
    if (nok) failing.push((nok[1] ?? "").trim());
    const t = /^# tests (\d+)$/.exec(line);
    if (t) tests = Number(t[1]);
  }
  return { failing, tests };
}

function gitIn(dir: string, args: string[]): void {
  const r = spawnSync("git", ["-c", "commit.gpgsign=false", "-c", "user.name=mutation", "-c", "user.email=mutation@invalid", ...args], {
    cwd: dir,
    shell: false,
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "", HOME: dir, GIT_TERMINAL_PROMPT: "0" },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${(r.stderr || r.stdout || "").slice(0, 300)}`);
}

function runTests(dir: string, o: MutationOptions): Promise<RunOutcome> {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, [...(o.nodeArgs ?? []), "--test", "--test-reporter=tap", ...o.testFiles], {
      cwd: dir,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH ?? "", HOME: dir, [CHILD_ENV]: "1", NODE_ENV: "test" },
    });
    let output = "";
    const cap = 4 * 1024 * 1024;
    const take = (b: Buffer) => {
      if (output.length < cap) output += b.toString("utf8");
    };
    child.stdout.on("data", take);
    child.stderr.on("data", take);
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, o.timeoutMs ?? 180_000);
    child.on("error", (e) => {
      clearTimeout(timer);
      resolveRun({ exitCode: null, timedOut: false, output: `spawn-error: ${e.message}`, failing: [], tests: 0 });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolveRun({ exitCode: code, timedOut, output, ...parseTap(output) });
    });
  });
}

function workspace(o: MutationOptions, mutant: Mutant | null): string {
  const dir = mkdtempSync(join(tmpdir(), "factory-mutation-"));
  for (const p of o.copyPaths) {
    const from = resolve(o.sourceRoot, p);
    cpSync(from, join(dir, p), { recursive: true, filter: (src) => !src.split(sep).some((seg) => COPY_SKIP.has(seg)) });
  }
  if (o.git) {
    gitIn(dir, ["init", "-q"]);
    gitIn(dir, ["add", "-A"]);
    gitIn(dir, ["commit", "-q", "-m", "baseline"]);
  }
  if (mutant) {
    const target = join(dir, mutant.file);
    writeFileSync(target, applyMutant(readFileSync(target, "utf8"), mutant));
  }
  if (o.git) {
    gitIn(dir, ["add", "-A"]);
    gitIn(dir, ["commit", "-q", "--allow-empty", "-m", mutant ? `mutant ${mutant.id}` : "baseline-2"]);
  }
  return dir;
}

async function runOne(o: MutationOptions, m: Mutant): Promise<MutantResult> {
  const base = { id: m.id, file: m.file, description: m.description, equivalent: m.equivalent ?? null };
  let dir = "";
  try {
    dir = workspace(o, m);
    const r = await runTests(dir, o);
    // A test FILE that fails as a whole (its name is the failing "test") because it could not even be
    // parsed/imported means the mutant is not a valid program: that is not a kill.
    const fileLevel = r.failing.some((n) => /\.test\.ts$/.test(n));
    const looksBroken = fileLevel && /SyntaxError|ERR_INVALID_TYPESCRIPT_SYNTAX|ERR_MODULE_NOT_FOUND|ERR_UNKNOWN_FILE_EXTENSION|ERR_UNSUPPORTED/.test(r.output);
    if (r.timedOut) return { ...base, status: "TIMEOUT", failing_tests: 0, first_failing_test: null, detail: `no result within ${o.timeoutMs ?? 180_000} ms` };
    if (r.exitCode === 0) return { ...base, status: "SURVIVED", failing_tests: 0, first_failing_test: null, detail: null };
    if (r.failing.length === 0 || looksBroken)
      return { ...base, status: "INVALID", failing_tests: 0, first_failing_test: null, detail: `mutant is not a loadable program or the runner failed without a failing test (exit ${r.exitCode}): ${r.output.slice(0, 300).replace(/\s+/g, " ")}` };
    return { ...base, status: "KILLED", failing_tests: r.failing.length, first_failing_test: r.failing[0] ?? null, detail: null };
  } catch (e) {
    return { ...base, status: "INVALID", failing_tests: 0, first_failing_test: null, detail: e instanceof Error ? e.message : String(e) };
  } finally {
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
}

export async function runMutation(o: MutationOptions): Promise<MutationReport> {
  // baseline: the unmodified tree must be green, otherwise "killed" means nothing
  const bdir = workspace(o, null);
  let baseline: MutationReport["baseline"];
  try {
    const b = await runTests(bdir, o);
    baseline = { ok: b.exitCode === 0 && !b.timedOut && b.tests > 0, tests: b.tests, failing: b.failing.length, detail: b.exitCode === 0 ? null : b.output.slice(-600) };
  } finally {
    rmSync(bdir, { recursive: true, force: true });
  }
  const selected = o.only ? o.mutants.filter((m) => o.only?.includes(m.id)) : [...o.mutants];
  const results: MutantResult[] = new Array(selected.length);
  if (baseline.ok) {
    let next = 0;
    const worker = async () => {
      for (;;) {
        const i = next++;
        const m = selected[i];
        if (!m) return;
        results[i] = await runOne(o, m);
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(o.concurrency ?? 4, selected.length || 1)) }, worker));
  }
  const done = results.filter(Boolean);
  const count = (s: MutantStatus) => done.filter((r) => r.status === s).length;
  const killed = count("KILLED");
  const timeout = count("TIMEOUT");
  return {
    baseline,
    total: baseline.ok ? done.length : 0,
    killed,
    timeout,
    survived: count("SURVIVED"),
    invalid: count("INVALID"),
    score: done.length === 0 ? null : (killed + timeout) / done.length,
    results: done,
  };
}

/** A report is acceptable only if the baseline is green, nothing is INVALID, and every survivor is annotated equivalent. */
export function reportProblems(r: MutationReport): string[] {
  const p: string[] = [];
  if (!r.baseline.ok) p.push(`baseline is not green (tests=${r.baseline.tests}, failing=${r.baseline.failing}): ${r.baseline.detail ?? ""}`);
  for (const x of r.results) {
    if (x.status === "INVALID") p.push(`${x.id}: INVALID mutant (${x.detail})`);
    if (x.status === "SURVIVED" && x.equivalent === null) p.push(`${x.id}: SURVIVED (${x.description}) - add or strengthen a test that kills it`);
  }
  return p;
}

export function formatMarkdown(r: MutationReport): string {
  const killed = r.killed + r.timeout;
  const pct = r.score === null ? "n/a" : `${(r.score * 100).toFixed(1)}%`;
  const out = [
    `Mutation score: **${killed}/${r.total} killed (${pct})**; survived ${r.survived}; invalid ${r.invalid}; timeout ${r.timeout}. Baseline: ${r.baseline.ok ? "green" : "RED"} (${r.baseline.tests} tests).`,
    "",
    "| mutant | file | mutation (exact) | result | failing tests | first failing test |",
    "|---|---|---|---|---|---|",
  ];
  const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\s+/g, " ");
  for (const x of r.results)
    out.push(`| ${x.id} | ${x.file} | ${cell(x.description)} | ${x.status}${x.equivalent ? " (equivalent)" : ""} | ${x.failing_tests} | ${cell((x.first_failing_test ?? "-").slice(0, 90))} |`);
  const eq = r.results.filter((x) => x.status === "SURVIVED" && x.equivalent);
  if (eq.length > 0) {
    out.push("", "Survivors annotated as equivalent (counted as survived, NOT excluded from the score):");
    for (const x of eq) out.push(`- ${x.id}: ${x.equivalent}`);
  }
  return out.join("\n");
}
