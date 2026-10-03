import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { formatMarkdown, reportProblems, runMutation, validateCatalog } from "./engine.ts";
import { MUTANTS } from "./mutants.ts";
import { availableParallelism } from "node:os";
import { readFileSync, readdirSync } from "node:fs";

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
// mutation.test.ts tests this harness (skipped in children anyway); mutation-kills.test.ts is registered through the
// side-effect import in rastik-attacks.test.ts (asserted below), so listing it again would only run it twice.
const attacksTest = readFileSync(resolve(root, "factory/tests/rastik-attacks.test.ts"), "utf8");
if (!attacksTest.includes('import "./mutation-kills.test.ts";')) {
  console.error("factory/tests/rastik-attacks.test.ts must import ./mutation-kills.test.ts (otherwise the kill tests are not part of the mutant runs)");
  process.exit(2);
}
const testFiles = readdirSync(resolve(root, "factory/tests"))
  .filter((f) => f.endsWith(".test.ts") && f !== "mutation.test.ts" && f !== "mutation-kills.test.ts")
  .sort()
  .map((f) => `factory/tests/${f}`);
const only = opt("--only")?.split(",").filter(Boolean);
const report = await runMutation({
  sourceRoot: root,
  copyPaths: ["cerberus", "kratt", "rastik", "factory", "package.json"],
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
