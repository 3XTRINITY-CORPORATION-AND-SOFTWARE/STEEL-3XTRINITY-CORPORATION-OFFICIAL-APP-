// Driver for per-slot specifications (see factory/matrix/spec-lib.mjs and docs/factory/MATRIX.md).
// Synchronous on purpose: runMatrix() is synchronous. Every spec file is executed by factory/matrix/runner.mjs in
// its own child process; the child validates, fingerprints and runs the specs and reports plain data.
import { readdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { combineEntries } from "../../factory/matrix/spec-lib.mjs";

export const SPEC_DIR = "factory/matrix/specs";

export function specFiles(root = process.cwd()) {
  const dir = join(root, SPEC_DIR);
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith(".mjs")).sort().map((f) => `${SPEC_DIR}/${f}`);
}

/** Execute one spec file in a clean child process (type stripping on, no inherited node:test context). */
export function execSpecFile(file, { mutate = false, root = process.cwd(), spawn = spawnSync } = {}) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const args = ["--experimental-strip-types", "--no-warnings", join(root, "factory/matrix/runner.mjs"), file];
  if (mutate) args.push("--mutate");
  const r = spawn(process.execPath, args, { encoding: "utf8", timeout: 120_000, env, cwd: root, maxBuffer: 32 * 1024 * 1024 });
  const line = String(r.stdout ?? "").split("\n").find((l) => l.startsWith("MATRIX_SPEC_RESULTS:"));
  if (!line) return { error: `no results from ${file}: ${String(r.error?.message ?? r.stderr ?? "").slice(0, 300)}` };
  return JSON.parse(line.slice("MATRIX_SPEC_RESULTS:".length));
}

export const GUARD_DIR = "factory/matrix/guards";

export function guardFiles(root = process.cwd()) {
  const dir = join(root, GUARD_DIR);
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith(".mjs")).sort().map((f) => `${GUARD_DIR}/${f}`);
}

/**
 * Run every spec file and merge. Result:
 *   { entries, specified: Map<slot, entry>, domainVerified: Set<slot>, configPinned: Set<slot>,
 *     sharedPathGroups: number[][], sharedPathSlots: Set<slot>, guards: { entries, total, passed }, violations, errors }
 * Regression guards (factory/matrix/guards) are executed with the same runner but are NOT slots: they never count towards
 * SPECIFIED_SLOTS / DOMAIN_VERIFIED; they only have to pass and be unique (also against the slot specs).
 * `exec` is injectable so tests can feed synthetic runner output. With explicit `files`, guards run only if `guards` is passed.
 */
export function runSpecs({ root = process.cwd(), mutate = false, files, guards, exec = execSpecFile } = {}) {
  const specList = files ?? specFiles(root);
  const guardList = guards ?? (files === undefined ? guardFiles(root) : []);
  const entries = [];
  const guardEntries = [];
  const violations = [];
  const errors = [];
  const collect = (list, into) => {
    for (const f of list) {
      const r = exec(f, { mutate, root });
      if (r.error) { errors.push(r.error); violations.push(`spec file ${f} did not run: ${r.error}`); continue; }
      into.push(...r.entries);
      violations.push(...r.violations.map((v) => `${f}: ${v}`));
    }
  };
  collect(specList, entries);
  collect(guardList, guardEntries);
  const c = combineEntries(entries);
  const g = combineEntries(guardEntries);
  const guardViolations = g.violations.map((v) => `guards: ${v}`);
  for (const [slot, e] of g.specified) {
    if (entries.some((x) => x.fingerprint && x.fingerprint === e.fingerprint)) guardViolations.push(`guard ${slot} duplicates the assertion of a slot spec`);
  }
  const failedGuards = guardEntries.filter((e) => !(e.valid && e.result && e.result.ok));
  for (const e of failedGuards) guardViolations.push(`guard ${e.slot} failed: ${e.result?.error ?? "invalid guard spec"}`);
  return {
    entries,
    specified: c.specified,
    domainVerified: c.domainVerified,
    configPinned: c.configPinned,
    sharedPathGroups: c.sharedPathGroups,
    sharedPathSlots: c.sharedPathSlots,
    guards: { entries: guardEntries, total: guardEntries.length, passed: guardEntries.length - failedGuards.length },
    violations: [...violations, ...c.violations, ...guardViolations],
    errors,
  };
}

export const EMPTY_SPEC_RUN = Object.freeze({ entries: [], specified: new Map(), domainVerified: new Set(), configPinned: new Set(), sharedPathGroups: [], sharedPathSlots: new Set(), guards: { entries: [], total: 0, passed: 0 }, violations: [], errors: [] });
