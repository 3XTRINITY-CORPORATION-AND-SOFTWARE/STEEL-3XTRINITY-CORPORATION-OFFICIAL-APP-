import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ReplayGuard } from "../../kratt/evidence.ts";
import { cerberusDecide } from "../cerberus-gate.ts";
import { blobState, commitExists, isShallow } from "../git.ts";
import { runKrattStage } from "../kratt-stage.ts";
import type { ActionReceipt, TaskEnvelope } from "../protocol/types.ts";
import { toeparaVerify } from "../toepara.ts";
import { REPO, setup } from "./helpers.ts";

const ID = { PATH: process.env.PATH ?? "", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t", GIT_TERMINAL_PROMPT: "0" };
const git = (cwd: string, ...a: string[]) => execFileSync("git", a, { cwd, encoding: "utf8", env: { ...ID, HOME: cwd } }).trim();
const ctx = (root: string) => ({ root, repository: REPO, rerun: new Map() });

/** Source repo with two commits; returns the parent (A) and child (B) shas. */
function sourceRepo() {
  const dir = mkdtempSync(join(tmpdir(), "shallow-src-"));
  git(dir, "init", "-q");
  git(dir, "config", "uploadpack.allowFilter", "true");
  git(dir, "config", "uploadpack.allowAnySHA1InWant", "true");
  mkdirSync(join(dir, "d"));
  writeFileSync(join(dir, "a.txt"), "alpha\n");
  writeFileSync(join(dir, "d/b.txt"), "beta\n");
  git(dir, "add", "-A");
  git(dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "A");
  const A = git(dir, "rev-parse", "HEAD");
  writeFileSync(join(dir, "c.txt"), "gamma\n");
  git(dir, "add", "-A");
  git(dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "B");
  return { dir, A, B: git(dir, "rev-parse", "HEAD") };
}
async function receiptAt(root: string, sha: string, scope: string[]): Promise<{ env: TaskEnvelope; receipt: ActionReceipt }> {
  const { stand, clock } = setup({ root });
  const env = { ...stand.issueEnvelope({ action: "hash-files", branch: "t", scope, base_sha: sha, task_id: `sh-${Math.random().toString(16).slice(2, 8)}` }), required_evidence: ["source_digests"] };
  const r = await runKrattStage(env, root, clock);
  if (!r.ok) throw new Error(r.reason);
  return { env, receipt: r.receipt };
}
const clone = (src: string, ...args: string[]) => {
  const dest = join(mkdtempSync(join(tmpdir(), "shallow-dst-")), "c");
  git(tmpdir(), "clone", "-q", ...args, `file://${src}`, dest);
  return dest;
};

test("SHALLOW (real `git clone --depth 1`): the clone really is shallow and really lacks the parent commit", () => {
  const s = sourceRepo();
  const c = clone(s.dir, "--depth", "1");
  assert.equal(isShallow(c), true);
  assert.equal(isShallow(s.dir), false);
  assert.equal(commitExists(c, s.B), true);
  assert.equal(commitExists(c, s.A), false, "parent is not in the shallow clone");
  assert.equal(blobState(c, s.A, "a.txt"), "commit-unavailable");
  assert.equal(blobState(c, s.B, "a.txt"), "ok");
  assert.equal(blobState(c, s.B, "nope.txt"), "absent-in-commit");
});

test("SHALLOW: control - a shallow clone is fine when the base commit IS present (base == HEAD) => VERIFIED", async () => {
  const s = sourceRepo();
  const c = clone(s.dir, "--depth", "1");
  const { env, receipt } = await receiptAt(c, s.B, ["a.txt", "d/b.txt"]);
  const t = await toeparaVerify(env, receipt, null, ctx(c));
  assert.equal(t.verdict.verdict, "VERIFIED", t.verdict.reasons.join(","));
});

test("SHALLOW: base commit absent from a `--depth 1` clone => INSUFFICIENT_EVIDENCE (never VERIFIED), no bundle, reason names the shallow checkout, no derived noise", async () => {
  const s = sourceRepo();
  const { env, receipt } = await receiptAt(s.dir, s.A, ["a.txt", "d/b.txt"]); // genuine receipt made where A exists
  const full = await toeparaVerify(env, receipt, null, ctx(s.dir));
  assert.equal(full.verdict.verdict, "REJECTED", "control: in the full repo A is no longer HEAD");
  assert.ok(full.verdict.reasons.includes("stale-base-sha"));

  const c = clone(s.dir, "--depth", "1");
  const t = await toeparaVerify(env, receipt, null, ctx(c));
  assert.equal(t.verdict.verdict, "INSUFFICIENT_EVIDENCE", t.verdict.reasons.join(","));
  assert.equal(t.bundle, null);
  assert.deepEqual(t.verdict.reasons.filter((r) => !r.startsWith("required-evidence-missing")), ["base-commit-unavailable:shallow-checkout"]);
  assert.ok(t.verdict.checks.some((k) => k.name === "base-commit-available" && !k.ok));
  assert.ok(!t.verdict.checks.some((k) => k.name === "source-digests-recomputed-from-git" && k.ok), "nothing was 'recomputed' from a missing base");
});

test("SHALLOW: CERBERUS DENIES (no ADMIT, no bundle) when TÖEPÄRA lacks the base commit in a shallow clone", async () => {
  const s = sourceRepo();
  const { env, receipt } = await receiptAt(s.dir, s.A, ["a.txt"]);
  const c = clone(s.dir, "--depth", "1");
  const toepara = await toeparaVerify(env, receipt, null, ctx(c));
  const guard = new ReplayGuard();
  const g = await cerberusDecide({ envelope: env, receipt, rastik: null, toepara }, { ...ctx(c), guard });
  assert.equal(g.decision.decision, "DENY");
  assert.equal(toepara.bundle, null);
  assert.ok(g.adapter_reasons.some((r) => r.startsWith("bundle-invalid")), g.adapter_reasons.join(","));
  assert.equal(g.cerberus_receipt.decision, "FAIL_CLOSED");
});

test("SHALLOW: an unknown sha in a FULL clone is a plain REJECT (base-sha-unknown-commit), not mislabelled as a shallow problem", async () => {
  const s = sourceRepo();
  const { env, receipt } = await receiptAt(s.dir, s.B, ["a.txt"]);
  const lie = { ...env, base_sha: "e".repeat(40) };
  const t = await toeparaVerify(lie, { ...receipt, base_sha: "e".repeat(40) }, null, ctx(s.dir));
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.ok(t.verdict.reasons.includes("base-sha-unknown-commit"));
  assert.ok(!t.verdict.reasons.includes("base-commit-unavailable:shallow-checkout"));
});

test("PARTIAL CLONE (`--filter=blob:none`, source still reachable): blobs are NOT lazily fetched; TÖEPÄRA => INSUFFICIENT_EVIDENCE base-blob-unavailable", async () => {
  const s = sourceRepo();
  const { env, receipt } = await receiptAt(s.dir, s.B, ["a.txt", "d/b.txt"]);
  const p = clone(s.dir, "--filter=blob:none", "--no-checkout");
  assert.equal(isShallow(p), false);
  assert.equal(blobState(p, s.B, "a.txt"), "object-unavailable");
  const t = await toeparaVerify(env, receipt, null, ctx(p));
  assert.equal(t.verdict.verdict, "INSUFFICIENT_EVIDENCE", t.verdict.reasons.join(","));
  assert.equal(t.bundle, null);
  assert.ok(t.verdict.reasons.includes("base-blob-unavailable:a.txt"));
  assert.equal(blobState(p, s.B, "a.txt"), "object-unavailable", "still absent after verification: nothing was fetched");
});

test("NOT A GIT CHECKOUT (.git removed): genuine KRATT receipt is never VERIFIED", async () => {
  const s = sourceRepo();
  const { env, receipt } = await receiptAt(s.dir, s.B, ["a.txt"]);
  rmSync(join(s.dir, ".git"), { recursive: true, force: true });
  const t = await toeparaVerify(env, receipt, null, ctx(s.dir));
  assert.notEqual(t.verdict.verdict, "VERIFIED");
  assert.equal(t.bundle, null);
});
