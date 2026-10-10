import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { changedFiles } from "./changed.ts";
import { hasFailures, renderReport, runRastik } from "./run.ts";

/** npm run rastik -- --base <ref> [--all] [--json] */
async function main(argv: string[]): Promise<number> {
  let base: string | null = null;
  let all = false;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--base") base = argv[++i] ?? null;
    else if (argv[i] === "--all") all = true;
    else if (argv[i] === "--json") json = true;
    else {
      console.error(`unknown argument: ${argv[i]}`);
      return 2;
    }
  }
  if (base === null && !all) {
    console.error("usage: rastik --base <git-ref> [--all] [--json]");
    return 2;
  }
  const root = resolve(import.meta.dirname, "..");
  let files: string[] = [];
  if (base !== null) {
    try {
      files = changedFiles(base, root);
    } catch (e) {
      console.error(`rastik: cannot compute changed files: ${(e as Error).message}`);
      return 2;
    }
  }
  const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8", shell: false }).stdout.trim() || null;
  const report = await runRastik({ root, files, base, head, all });
  console.log(json ? JSON.stringify(report, null, 2) : renderReport(report));
  return hasFailures(report) ? 1 : 0;
}

process.exitCode = await main(process.argv.slice(2));
