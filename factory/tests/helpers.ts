import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ReplayGuard } from "../../kratt/evidence.ts";
import { repoSlug } from "../git.ts";
import { GoliathStandIn, makeDispatcher, type LoopDeps } from "../loop.ts";
import { runKrattStage } from "../kratt-stage.ts";
import type { ActionReceipt, TaskEnvelope } from "../protocol/types.ts";
import { fixedClock } from "./fixtures.ts";

export const ROOT = resolve(import.meta.dirname, "../..");
export const REPO = repoSlug(ROOT) ?? "3XTRINITY-CORPORATION-AND-SOFTWARE/STEEL-3XTRINITY-CORPORATION-OFFICIAL-APP-";
export const SCOPE = ["cerberus/core/decide.ts", "cerberus/core/normalize.ts", "cerberus/policy/policy.ts", "cerberus/artifact-trust/artifact-trust.ts"];

export function setup(over: Partial<LoopDeps> = {}) {
  const clock = fixedClock();
  const dispatcher = makeDispatcher(clock);
  const deps: LoopDeps = { root: ROOT, repository: REPO, dispatcher, guard: new ReplayGuard(), clock, runProbes: false, ...over };
  return { deps, dispatcher, clock, stand: new GoliathStandIn(deps) };
}

/** Envelope + the genuine KRATT receipt for it (hash-files over SCOPE at the current HEAD). */
export async function genuine(action: "hash-files" | "run-test" = "hash-files", root = ROOT, repository = REPO) {
  const { deps, stand, clock } = setup({ root, repository });
  const env: TaskEnvelope = stand.issueEnvelope({
    action,
    branch: "t",
    scope: action === "hash-files" ? [...SCOPE] : ["cerberus/tests/decide.test.ts"],
    task_id: `t-${action}-${Math.random().toString(16).slice(2, 8)}`,
  });
  const r = await runKrattStage(env, root, clock);
  if (!r.ok) throw new Error(`fixture: ${r.reason}`);
  // attack/ verify envelopes only require source digests unless a RÄSTIK report is supplied
  const env2: TaskEnvelope = { ...env, required_evidence: action === "run-test" ? ["source_digests", "test_evidence"] : ["source_digests"] };
  return { env: env2, receipt: r.receipt as ActionReceipt, deps };
}

/** A throwaway git repo with one committed file, for tests that must not depend on this repo's history. */
export function tempRepo(files: Record<string, string>): { dir: string; sha: string } {
  const dir = mkdtempSync(join(tmpdir(), "factory-git-"));
  const git = (...a: string[]) => execFileSync("git", a, { cwd: dir, encoding: "utf8", env: { PATH: process.env.PATH ?? "", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t", HOME: dir } }).trim();
  git("init", "-q");
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(join(dir, p, ".."), { recursive: true });
    writeFileSync(join(dir, p), c);
  }
  git("add", "-A");
  git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "init");
  return { dir, sha: git("rev-parse", "HEAD") };
}
