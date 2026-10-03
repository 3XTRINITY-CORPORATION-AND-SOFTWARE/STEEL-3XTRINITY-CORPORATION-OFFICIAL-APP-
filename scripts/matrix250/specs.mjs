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

/**
 * Run every spec file and merge. Result:
 *   { entries, specified: Map<slot, entry>, domainVerified: Set<slot>, violations, errors }
 * `exec` is injectable so tests can feed synthetic runner output.
 */
export function runSpecs({ root = process.cwd(), mutate = false, files = specFiles(root), exec = execSpecFile } = {}) {
  const entries = [];
  const violations = [];
  const errors = [];
  for (const f of files) {
    const r = exec(f, { mutate, root });
    if (r.error) { errors.push(r.error); violations.push(`spec file ${f} did not run: ${r.error}`); continue; }
    entries.push(...r.entries);
    violations.push(...r.violations.map((v) => `${f}: ${v}`));
  }
  const c = combineEntries(entries);
  return { entries, specified: c.specified, domainVerified: c.domainVerified, violations: [...violations, ...c.violations], errors };
}

export const EMPTY_SPEC_RUN = Object.freeze({ entries: [], specified: new Map(), domainVerified: new Set(), violations: [], errors: [] });
