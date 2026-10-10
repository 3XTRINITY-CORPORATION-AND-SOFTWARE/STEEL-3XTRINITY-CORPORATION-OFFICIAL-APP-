import { spawnSync } from "node:child_process";

const REF = /^[A-Za-z0-9_][A-Za-z0-9._/-]{0,99}$/;

/** Fixed-argv `git diff` (no shell). The ref is validated so it can never be parsed as an option. */
export function changedFiles(base: string, cwd: string): string[] {
  if (!REF.test(base) || base.includes("..")) throw new Error("invalid-base-ref");
  const r = spawnSync("git", ["diff", "--name-only", "--diff-filter=ACMR", `${base}...HEAD`, "--"], {
    cwd,
    encoding: "utf8",
    shell: false,
    timeout: 20_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`git-diff-failed:${(r.stderr ?? "").trim().slice(0, 200)}`);
  return r.stdout.split("\n").filter(Boolean).sort();
}
