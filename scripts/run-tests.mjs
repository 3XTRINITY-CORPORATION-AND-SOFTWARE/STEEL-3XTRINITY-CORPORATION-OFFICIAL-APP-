#!/usr/bin/env node
// Deterministic test runner (INCIDENTS.md: STACKED_CONFIG_COLLISION).
//
// `npm test` is `node scripts/run-tests.mjs`. This runner discovers EVERY *.test.* / *.spec.* file on disk, so adding a
// test never requires editing package.json (the single-line `test` script was edited by stacked PRs four times, and each
// squash merge left duplicate "test" keys on main).
//
// Behaviour is the same as the former script:
//   node --test <every .mjs/.cjs/.js test, sorted>
//   && node --experimental-strip-types --test <every .ts/.mts/.cts test, sorted>
// i.e. the .mjs group runs first; if it fails its exit code is returned and the .ts group is NOT run (the old `&&`).
// Exit code of the failing group is propagated; a signal-terminated group is a failure (1).
//
// Fail closed: a test file whose extension this runner cannot execute (.tsx, .jsx, ...) is an ERROR (exit 1), never skipped.
// Files that are intentionally not tests must NOT be named *.test.* / *.spec.*; the explicit EXCLUDE list below is the only
// other way out, and every entry needs a reason.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const TEST_FILE = /\.(test|spec)\.(mjs|cjs|js|mts|cts|ts|tsx|jsx)$/;
export const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", ".vercel", ".turbo", ".cache", "out"]);
/** repo-relative POSIX paths -> reason. Empty on purpose: nothing is excluded today. */
export const EXCLUDE = Object.freeze({});

const PLAIN = new Set([".mjs", ".cjs", ".js"]);
const STRIP_TYPES = new Set([".ts", ".mts", ".cts"]);

const ext = (f) => f.slice(f.lastIndexOf("."));
const byCodePoint = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** All test files under `root`, repo-relative with "/" separators, sorted by code point (locale independent). */
export function discoverTests(root, exclude = EXCLUDE) {
  const out = [];
  const walk = (abs) => {
    for (const e of readdirSync(abs, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) walk(join(abs, e.name));
      } else if (e.isFile() && TEST_FILE.test(e.name)) {
        const rel = relative(root, join(abs, e.name)).split(sep).join("/");
        if (!Object.prototype.hasOwnProperty.call(exclude, rel)) out.push(rel);
      }
    }
  };
  walk(root);
  return out.sort(byCodePoint);
}

/** The ordered groups of commands to run. Throws on a file this runner cannot execute. */
export function buildPlan(files, nodeBin = process.execPath) {
  const plain = [];
  const ts = [];
  const unsupported = [];
  for (const f of files) {
    const x = ext(f);
    if (PLAIN.has(x)) plain.push(f);
    else if (STRIP_TYPES.has(x)) ts.push(f);
    else unsupported.push(f);
  }
  if (unsupported.length > 0) throw new Error(`test files this runner cannot execute (rename, convert or add an explicit EXCLUDE entry with a reason): ${unsupported.join(", ")}`);
  const plan = [];
  if (plain.length > 0) plan.push({ name: "node --test", cmd: nodeBin, args: ["--test", ...plain], files: plain });
  if (ts.length > 0) plan.push({ name: "node --experimental-strip-types --test", cmd: nodeBin, args: ["--experimental-strip-types", "--test", ...ts], files: ts });
  return plan;
}

/** Runs the plan like `a && b`. `spawn` is injectable for tests. Returns the process exit code. */
export function runPlan(plan, { cwd, env = process.env, spawn = spawnSync } = {}) {
  for (const g of plan) {
    const r = spawn(g.cmd, g.args, { cwd, env, stdio: "inherit" });
    if (r.error) {
      console.error(`run-tests: failed to start ${g.name}: ${r.error.message}`);
      return 1;
    }
    if (r.signal) {
      console.error(`run-tests: ${g.name} was terminated by ${r.signal}`);
      return 1;
    }
    if (r.status !== 0) return typeof r.status === "number" ? r.status : 1;
  }
  return 0;
}

export const NESTED_ENV = "RUN_TESTS_ACTIVE";

export function main(argv, root, env = process.env) {
  // A test that (indirectly) starts the runner on the real repo would run the suite inside itself, recursively.
  if (env[NESTED_ENV] === "1") {
    console.error(`run-tests: refusing to run nested inside another run-tests (${NESTED_ENV}=1)`);
    return 3;
  }
  const rest = argv.filter((a) => a !== "--list");
  if (rest.length > 0) {
    console.error(`run-tests: unexpected arguments: ${rest.join(" ")} (only --list is supported)`);
    return 2;
  }
  let plan;
  try {
    plan = buildPlan(discoverTests(root));
  } catch (e) {
    console.error(`run-tests: ${e.message}`);
    return 1;
  }
  if (plan.length === 0) {
    console.error("run-tests: no test files found (refusing to report success for an empty suite)");
    return 1;
  }
  if (argv.includes("--list")) {
    for (const g of plan) for (const f of g.files) console.log(f);
    return 0;
  }
  return runPlan(plan, { cwd: root, env: { ...env, [NESTED_ENV]: "1" } });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2), resolve(dirname(fileURLToPath(import.meta.url)), ".."));
}
