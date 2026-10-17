import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { formatMarkdown, reportProblems, runMutation, validateCatalog } from "./engine.ts";
import { MUTANTS } from "./mutants.ts";
import { availableParallelism } from "node:os";
import { existsSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";

/**
 * node --experimental-strip-types factory/mutation/run.ts [--only T01,G01] [--json out.json] [--md out.md] [--concurrency N] [--timeout-ms N]
 * Exit 0 only if the baseline is green, no mutant is INVALID and every survivor is annotated equivalent.
 */
const root = resolve(import.meta.dirname, "../..");
const args = process.argv.slice(2);
const opt = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const problems = validateCatalog(root, MUTANTS);
if (problems.length > 0) {
  console.error(`mutant catalog is stale:\n${problems.join("\n")}`);
  process.exit(2);
}
// mutation.test.ts tests this harness itself (it skips inside mutant runs); every other factory test, incl. mutation-kills.test.ts, runs.
const testFiles = readdirSync(resolve(root, "factory/tests"))
  .filter((f) => f.endsWith(".test.ts") && f !== "mutation.test.ts")
  .sort()
  .map((f) => `factory/tests/${f}`);
// The whole TRACKED project (top-level entries of `git ls-files`): repo-level guards (config/test-coverage, runtime drift)
// read scripts/, src/, workflows etc., so a partial copy turns the baseline red for reasons unrelated to any mutant.
const copyPaths = [
  ...new Set(
    execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
      .split("\0")
      .filter(Boolean)
      .map((f) => f.split("/")[0] as string),
  ),
].filter((p) => existsSync(resolve(root, p))).sort();
const only = opt("--only")?.split(",").filter(Boolean);
const report = await runMutation({
  sourceRoot: root,
  copyPaths,
  testFiles,
  mutants: MUTANTS,
  git: true,
  concurrency: Number(opt("--concurrency") ?? Math.max(1, Math.min(4, availableParallelism()))),
  timeoutMs: Number(opt("--timeout-ms") ?? 180_000),
  nodeArgs: ["--experimental-strip-types"],
  ...(only ? { only } : {}),
});
const md = formatMarkdown(report);
console.log(md);
const j = opt("--json");
if (j) writeFileSync(j, `${JSON.stringify(report, null, 2)}\n`);
const m = opt("--md");
if (m) writeFileSync(m, `${md}\n`);
const bad = reportProblems(report);
if (bad.length > 0) {
  console.error(`\n${bad.join("\n")}`);
  process.exit(1);
}
