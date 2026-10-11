// KRATT bounded handlers verify-runtime + diff-scope-check: closed task schema, allowed/forbidden scope, deterministic
// receipts, positive + negative runs on throwaway git repos, RÄSTIK handler challenges and TÖEPÄRA's independent
// re-verification of each handler's claimed result.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { computeVerdict } from "../../kratt/evidence.ts";
import { executeTask, inAllowedScope, MAX_DIFF_ARTIFACTS } from "../../kratt/actions.ts";
import { KRATT_ACTIONS, validateTask, type KrattTask } from "../../kratt/task.ts";
import { fsSource, verifyRuntime } from "../../scripts/runtime-verify.mjs";
import { CAPABILITIES } from "../capabilities.ts";
import { changedPathsVsFirstParent, runtimeSourceAt } from "../git.ts";
import { envelopeToKrattTask, runKrattStage } from "../kratt-stage.ts";
import { digestOf, type ActionReceipt, type TaskEnvelope } from "../protocol/types.ts";
import { actionChallengeIds, configureParentLookup, realAttackTarget, runAttackClass, type AttackTarget } from "../rastik-attacks.ts";
import { toeparaVerify } from "../toepara.ts";
import { producerMayRunAction } from "../trust-gate.ts";
import { REPO, ROOT, setup } from "./helpers.ts";

const C40 = "a".repeat(40);
const ctx = (root: string) => ({ root, repository: REPO, rerun: new Map() });
const GIT_ENV = { PATH: process.env.PATH ?? "", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t", GIT_CONFIG_NOSYSTEM: "1" };

/** Throwaway repo: commit 1 = `base`, then one commit per entry of `commits` (null content = delete). */
function repo(base: Record<string, string>, ...commits: Record<string, string | null>[]): { dir: string; shas: string[] } {
  const dir = mkdtempSync(join(tmpdir(), "kratt-handlers-"));
  const git = (...a: string[]) => execFileSync("git", a, { cwd: dir, encoding: "utf8", env: { ...GIT_ENV, HOME: dir } }).trim();
  git("init", "-q");
  const shas: string[] = [];
  for (const files of [base, ...commits]) {
    for (const [p, c] of Object.entries(files)) {
      if (c === null) git("rm", "-q", p);
      else {
        mkdirSync(join(dir, p, ".."), { recursive: true });
        writeFileSync(join(dir, p), c);
      }
    }
    git("add", "-A");
    git("-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", `c${shas.length}`);
    shas.push(git("rev-parse", "HEAD"));
  }
  return { dir, shas };
}
/** This repo's own runtime declarations (Node 22 everywhere), so a temp repo verifies RUNTIME_OK like the real one. */
function runtimeFiles(): Record<string, string> {
  const out: Record<string, string> = { ".nvmrc": readFileSync(join(ROOT, ".nvmrc"), "utf8"), "package.json": readFileSync(join(ROOT, "package.json"), "utf8") };
  for (const d of [".github/workflows", ".devcontainer"]) for (const f of readdirSync(join(ROOT, d))) out[`${d}/${f}`] = readFileSync(join(ROOT, d, f), "utf8");
  return out;
}
const BASE = { "src/a.txt": "alpha\n", "src/b.txt": "beta\n", "src2/x.txt": "x\n", "docs/d.md": "doc\n" };

async function receiptFor(dir: string, action: "verify-runtime" | "diff-scope-check", scope: string[], task_id: string): Promise<{ env: TaskEnvelope; receipt: ActionReceipt }> {
  const { stand, clock } = setup({ root: dir });
  const env = { ...stand.issueEnvelope({ action, scope, branch: "t", task_id }), required_evidence: ["source_digests"] };
  const r = await runKrattStage(env, dir, clock);
  if (!r.ok) throw new Error(r.reason);
  return { env, receipt: r.receipt };
}
/** A SELF-CONSISTENT forgery: evidence + verdict + digest + receipt result all agree. */
function forge(r: ActionReceipt, f: (ev: any) => void): ActionReceipt {
  const c = structuredClone(r) as any;
  f(c.evidence);
  const { evidenceDigest: _d, verdict: _v, ...body } = c.evidence;
  void _d;
  void _v;
  c.evidence.verdict = computeVerdict(body);
  const { evidenceDigest: _e, ...sealed } = c.evidence;
  void _e;
  c.evidence.evidenceDigest = digestOf(sealed);
  c.result = { ok: c.evidence.verdict === "VERIFIED" || (c.evidence.exitCode === 0 && c.evidence.failure === null), exit_code: c.evidence.exitCode, checks: { ...c.evidence.checks }, failure: c.evidence.failure };
  return c;
}
const dsc = (commit: string, allowed: string[]): KrattTask => {
  const v = validateTask({ taskId: "t1", action: "diff-scope-check", commit, allowed });
  if (!v.ok) throw new Error(v.reason);
  return v.task;
};

// ---- inventory / registration ------------------------------------------------------------------------------------

test("INVENTORY: every KRATT action is executable (an executeTask case), granted to FORGE-026 and allowed by the trust gate; no capability without an action", () => {
  assert.deepEqual([...KRATT_ACTIONS], ["hash-files", "validate-manifest", "run-test", "verify-runtime", "diff-scope-check"]);
  const src = readFileSync(join(ROOT, "kratt/actions.ts"), "utf8");
  for (const a of KRATT_ACTIONS) {
    assert.match(src, new RegExp(`case "${a}":\\n\\s+return `), `executeTask handles ${a}`);
    assert.equal(producerMayRunAction("FORGE-026", a), true, a);
  }
  assert.deepEqual(CAPABILITIES["FORGE-026"], KRATT_ACTIONS.map((a) => `kratt:${a}`));
});

// ---- closed task schema ------------------------------------------------------------------------------------------

test("SCHEMA verify-runtime: exactly {taskId, action}; any extra key (command, root, env ...) is rejected", () => {
  assert.equal(validateTask({ taskId: "t1", action: "verify-runtime" }).ok, true);
  for (const extra of [{ command: "npm run runtime:verify" }, { root: "/" }, { env: {} }, { files: ["package.json"] }]) {
    const v = validateTask({ taskId: "t1", action: "verify-runtime", ...extra });
    assert.equal(v.ok, false, JSON.stringify(extra));
  }
});

test("SCHEMA diff-scope-check: full 40-hex commit, 1..64 unique allow-listed relative paths; everything else rejected", () => {
  assert.equal(validateTask({ taskId: "t1", action: "diff-scope-check", commit: C40, allowed: ["src", "docs/factory"] }).ok, true);
  const bad: [unknown, string][] = [
    [{ commit: "HEAD", allowed: ["src"] }, "commit-invalid"],
    [{ commit: "a".repeat(39), allowed: ["src"] }, "commit-invalid"],
    [{ commit: "A".repeat(40), allowed: ["src"] }, "commit-invalid"],
    [{ commit: `${C40};rm -rf /`, allowed: ["src"] }, "commit-invalid"],
    [{ commit: C40, allowed: "src" }, "allowed-not-array"],
    [{ commit: C40, allowed: [] }, "allowed-count-invalid"],
    [{ commit: C40, allowed: Array.from({ length: 65 }, (_, i) => `d${i}`) }, "allowed-count-invalid"],
    [{ commit: C40, allowed: ["../etc"] }, ""], // relPath's own reason
    [{ commit: C40, allowed: ["/etc"] }, ""], // relPath's own reason
    [{ commit: C40, allowed: [".github"] }, ""], // relPath's own reason
    [{ commit: C40, allowed: [""] }, ""], // relPath's own reason
    [{ commit: C40, allowed: [7] }, ""], // relPath's own reason
    [{ commit: C40, allowed: ["src", "src"] }, "allowed-duplicate"],
  ];
  for (const [b, reason] of bad) {
    const v = validateTask({ taskId: "t1", action: "diff-scope-check", ...(b as object) });
    assert.equal(v.ok, false, JSON.stringify(b));
    if (!v.ok) assert.ok(v.reason.includes(reason), `${JSON.stringify(b)} -> ${v.reason}`);
  }
  assert.equal(validateTask({ taskId: "t1", action: "diff-scope-check", commit: C40, allowed: ["src"], command: "x" }).ok, false, "closed key set");
});

test("ENVELOPE MAPPING: verify-runtime scope must be exactly [package.json]; diff-scope-check checks base_sha against scope", () => {
  const { stand } = setup();
  const vr = stand.issueEnvelope({ action: "verify-runtime", scope: ["package.json"], branch: "t", task_id: "map-vr" });
  assert.deepEqual(envelopeToKrattTask(vr), { ok: true, task: { taskId: "map-vr", action: "verify-runtime" }, action: "verify-runtime" });
  for (const scope of [["src"], ["package.json", "tsconfig.json"]]) assert.deepEqual(envelopeToKrattTask({ ...vr, scope }), { ok: false, reason: "verify-runtime-scope-must-be-package-json" });
  const d = stand.issueEnvelope({ action: "diff-scope-check", scope: ["factory", "kratt"], branch: "t", task_id: "map-d" });
  const m = envelopeToKrattTask(d);
  assert.equal(m.ok, true);
  if (m.ok) assert.deepEqual(m.task, { taskId: "map-d", action: "diff-scope-check", commit: d.base_sha, allowed: ["factory", "kratt"] });
});

// ---- diff-scope-check: allowed / forbidden scope -----------------------------------------------------------------

test("diff-scope-check scope rule: exact path or under a prefix; never a sibling prefix, never a dot-path", () => {
  assert.equal(inAllowedScope("src/a.txt", ["src"]), true);
  assert.equal(inAllowedScope("src", ["src"]), true);
  assert.equal(inAllowedScope("src2/x.txt", ["src"]), false, "sibling with the same prefix string");
  assert.equal(inAllowedScope("src/.env", ["src"]), false, "dot-paths are never in scope");
  assert.equal(inAllowedScope(".github/workflows/ci.yml", ["src"]), false);
  assert.equal(inAllowedScope("docs/d.md", ["src", "docs"]), true);
});

test("diff-scope-check POSITIVE: in-scope change -> ok, artifacts = changed files hashed from the commit, deterministic", async () => {
  const { dir, shas } = repo(BASE, { "src/a.txt": "alpha2\n", "src/c.txt": "gamma\n", "src/b.txt": null });
  const r1 = await executeTask(dir, dsc(shas[1] as string, ["src"]));
  assert.equal(r1.failure, null);
  assert.equal(r1.exitCode, 0);
  assert.deepEqual(r1.checks, { pass: 3, fail: 0 }, "3 in-scope changes (one is a deletion)");
  assert.deepEqual(r1.artifacts.map((a) => a.name), ["src/a.txt", "src/c.txt"], "deleted files are not artifacts");
  assert.equal(r1.artifacts[0]?.bytes, 7);
  assert.equal(r1.command[0], "git");
  const r2 = await executeTask(dir, dsc(shas[1] as string, ["src"]));
  assert.deepEqual(r2, r1, "same commit, same lease => byte-identical result");
});

test("diff-scope-check NEGATIVE: out-of-scope, sibling prefix, dot-path, no parent, unknown commit, empty commit, deletion-only", async () => {
  const { dir, shas } = repo(BASE, { "src/a.txt": "A\n", "docs/d.md": "D\n" }, { "src2/x.txt": "X\n" }, { ".github/workflows/x.yml": "on: push\n" }, {}, { "src/b.txt": null });
  const cases: [string, string[], RegExp][] = [
    [shas[1] as string, ["src"], /^out-of-scope:1:docs\/d\.md$/],
    [shas[2] as string, ["src"], /^out-of-scope:1:src2\/x\.txt$/],
    [shas[3] as string, ["src"], /^out-of-scope:1:\.github\/workflows\/x\.yml$/],
    [shas[0] as string, ["src"], /^commit-has-no-parent$/],
    ["f".repeat(40), ["src"], /^commit-not-found$/],
    [shas[4] as string, ["src"], /^no-changes$/],
    [shas[5] as string, ["src"], /^only-deletions-no-artifact$/],
  ];
  for (const [c, allowed, want] of cases) {
    const r = await executeTask(dir, dsc(c, allowed));
    assert.match(r.failure ?? "", want, `${c.slice(0, 7)} ${allowed}`);
    assert.notEqual(r.exitCode, 0);
    assert.ok(r.checks.fail >= 1, "a failed check is counted");
  }
  const both = await executeTask(dir, dsc(shas[1] as string, ["src", "docs"]));
  assert.equal(both.failure, null, "widening the lease to the docs prefix admits the same commit");
  assert.ok(MAX_DIFF_ARTIFACTS <= 128, "stays under the evidence artifact cap (130)");
});

test("diff-scope-check FORBIDDEN: a commit string with options/refspec syntax never reaches git (schema), and git never sees the working tree", async () => {
  for (const c of ["--output=/tmp/x", "HEAD~1", `${C40.slice(0, 39)}^`, `${C40} ${C40}`]) assert.equal(validateTask({ taskId: "t1", action: "diff-scope-check", commit: c, allowed: ["src"] }).ok, false, c);
  const { dir, shas } = repo(BASE, { "src/a.txt": "A\n" });
  writeFileSync(join(dir, "docs/d.md"), "dirty working tree, outside scope\n");
  const r = await executeTask(dir, dsc(shas[1] as string, ["src"]));
  assert.equal(r.failure, null, "only the commit's own change is judged, not uncommitted edits");
});

// ---- TÖEPÄRA independent re-verification -----------------------------------------------------------------------

test("TÖEPÄRA diff-scope-check: genuine receipt VERIFIED; its independent ls-tree recomputation equals KRATT's git-diff result", async () => {
  const { dir, shas } = repo(BASE, { "src/a.txt": "alpha2\n", "src/c.txt": "gamma\n" });
  const { env, receipt } = await receiptFor(dir, "diff-scope-check", ["src"], "ds-ok");
  assert.equal(receipt.result.ok, true);
  const t = await toeparaVerify(env, receipt, null, ctx(dir));
  assert.equal(t.verdict.verdict, "VERIFIED", t.verdict.reasons.join(","));
  assert.deepEqual(changedPathsVsFirstParent(dir, shas[1] as string), [{ path: "src/a.txt", deleted: false }, { path: "src/c.txt", deleted: false }]);
  assert.equal(changedPathsVsFirstParent(dir, shas[0] as string), null, "root commit: not recomputable");
});

test("TÖEPÄRA diff-scope-check NEGATIVE: self-consistent forgeries of the handler's claim are REJECTED", async () => {
  const { dir } = repo(BASE, { "src/a.txt": "alpha2\n", "src/c.txt": "gamma\n", "docs/d.md": "changed\n" });
  // genuine out-of-scope result (docs/ changed), then forged into a success claim
  const { env, receipt } = await receiptFor(dir, "diff-scope-check", ["src"], "ds-oos");
  assert.match(receipt.result.failure ?? "", /^out-of-scope:1:docs\/d\.md$/);
  assert.equal((await toeparaVerify(env, receipt, null, ctx(dir))).verdict.verdict, "REJECTED", "a genuine failure is never verified");
  const hidden = forge(receipt, (ev) => { ev.exitCode = 0; ev.failure = null; ev.checks = { pass: 2, fail: 0 }; });
  assert.equal(hidden.result.ok, true);
  const t = await toeparaVerify(env, hidden, null, ctx(dir));
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.ok(t.verdict.reasons.includes("diff-scope-outcome-contradicts-recomputation"), t.verdict.reasons.join(","));
  // genuine success, then an artifact dropped (counts kept consistent)
  const ok = await receiptFor(dir, "diff-scope-check", ["src", "docs"], "ds-ok2");
  assert.equal((await toeparaVerify(ok.env, ok.receipt, null, ctx(dir))).verdict.verdict, "VERIFIED", "control");
  const dropped = forge(ok.receipt, (ev) => { ev.artifacts.pop(); ev.checks = { pass: 2, fail: 0 }; });
  const t2 = await toeparaVerify(ok.env, dropped, null, ctx(dir));
  assert.equal(t2.verdict.verdict, "REJECTED");
  assert.ok(t2.verdict.reasons.includes("diff-scope-artifacts-differ-from-recomputed-change"), t2.verdict.reasons.join(","));
});

// ---- verify-runtime ---------------------------------------------------------------------------------------------

test("verify-runtime POSITIVE: the repo's own declarations -> RUNTIME_OK in-process (no shell), artifact = package.json, deterministic", async () => {
  const r = await executeTask(ROOT, { taskId: "t1", action: "verify-runtime" });
  assert.equal(r.failure, null, r.failure ?? "");
  assert.deepEqual(r.command, ["in-process:verify-runtime", "scripts/runtime-verify.mjs#verifyRuntime"]);
  assert.deepEqual(r.artifacts.map((a) => a.name), ["package.json"]);
  assert.ok(r.checks.pass >= 4 && r.checks.fail === 0, JSON.stringify(r.checks));
  assert.deepEqual(await executeTask(ROOT, { taskId: "t1", action: "verify-runtime" }), r);
  const { dir } = repo({ ...runtimeFiles(), "src/a.txt": "a\n" });
  const { env, receipt } = await receiptFor(dir, "verify-runtime", ["package.json"], "vr-ok");
  const t = await toeparaVerify(env, receipt, null, ctx(dir));
  assert.equal(t.verdict.verdict, "VERIFIED", t.verdict.reasons.join(","));
});

test("verify-runtime NEGATIVE: committed drift -> failure names the source; an uncommitted 'fix' fools KRATT but not TÖEPÄRA (git objects)", async () => {
  const { dir } = repo({ ...runtimeFiles(), ".nvmrc": "20\n" });
  const drift = await executeTask(dir, { taskId: "t1", action: "verify-runtime" });
  assert.match(drift.failure ?? "", /^runtime-drift:.*\.nvmrc/);
  assert.equal(drift.checks.fail, 1);
  writeFileSync(join(dir, ".nvmrc"), "22\n"); // working tree no longer matches the commit
  const { env, receipt } = await receiptFor(dir, "verify-runtime", ["package.json"], "vr-dirty");
  assert.equal(receipt.result.ok, true, "KRATT reads the working tree");
  const t = await toeparaVerify(env, receipt, null, ctx(dir));
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.ok(t.verdict.reasons.includes("runtime-report-differs-from-recomputed"), t.verdict.reasons.join(","));
  assert.ok(t.verdict.reasons.includes("runtime-drift-hidden-by-receipt"), t.verdict.reasons.join(","));
});

test("verify-runtime FORBIDDEN: path confinement - fsSource rejects absolute/.. paths and symlinks leaving the root; the git source reads only runtime files", () => {
  const { dir, shas } = repo({ ...runtimeFiles(), "secret.txt": "s\n" });
  const outside = mkdtempSync(join(tmpdir(), "kratt-outside-"));
  writeFileSync(join(outside, "x"), "22\n");
  symlinkSync(join(outside, "x"), join(dir, "link"));
  const s = fsSource(dir);
  assert.equal(s.isFile(".nvmrc"), true);
  for (const p of ["/etc/passwd", "../x", "a/../../x", "link"]) {
    assert.equal(s.isFile(p), false, p);
    assert.throws(() => s.read(p), /outside root/, p);
  }
  const g = runtimeSourceAt(dir, shas[0] as string);
  assert.ok(g);
  assert.equal(g.isFile(".nvmrc"), true);
  assert.equal(g.isFile("secret.txt"), false);
  assert.throws(() => g.read("secret.txt"), /not a runtime source/);
  assert.deepEqual(g.list(".github/workflows"), readdirSync(join(ROOT, ".github/workflows")).sort());
  // regression (was live on main c9e4e21): a workflow's node-version-file: ../x read a file OUTSIDE the repo and reported it as agreeing
  writeFileSync(join(dir, "..", `${dir.split("/").pop()}-secret`), "22\n");
  mkdirSync(join(dir, ".github/workflows"), { recursive: true });
  writeFileSync(join(dir, ".github/workflows/ci.yml"), `jobs:\n  b:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version-file: ../${dir.split("/").pop()}-secret\n`);
  const nvf = verifyRuntime({ root: dir }).sources.find((x) => x.source.startsWith(".github/workflows/ci.yml") && x.found.includes("node-version-file"));
  assert.equal(nvf?.ok, false, JSON.stringify(nvf));
  assert.doesNotMatch(nvf?.found ?? "", /-> 22/);
});

test("FORBIDDEN (source): the new handlers spawn nothing but read-only git with a fixed argv; no shell, no network modules, no writes", () => {
  const src = readFileSync(join(ROOT, "kratt/actions.ts"), "utf8");
  const body = src.slice(src.indexOf("// ---- verify-runtime"), src.indexOf("/** Never throws"));
  assert.doesNotMatch(body, /shell:\s*true|execSync|exec\(|writeFile|mkdir|rmSync|fetch\(|node:https?|node:net/);
  assert.equal([...body.matchAll(/spawnSync\(/g)].length, 1, "one spawn site (gitRead)");
  assert.match(body, /spawnSync\("git", \["-c", "core\.fsmonitor=false", \.\.\.args\]/);
  const verbs = [...body.matchAll(/gitRead\(realRoot, \[\s*"([a-z-]+)"|const argv = \["([a-z-]+)"/g)].map((m) => m[1] ?? m[2]);
  assert.deepEqual([...new Set(verbs)].sort(), ["cat-file", "diff", "rev-parse"]);
  const rv = readFileSync(join(ROOT, "scripts/runtime-verify.mjs"), "utf8");
  assert.doesNotMatch(rv, /child_process|writeFile|node:https?|node:net|fetch\(/);
});

// ---- RÄSTIK handler challenges + closed loop ---------------------------------------------------------------------

test("RÄSTIK handler challenges: every verify-runtime / diff-scope-check challenge is REPELLED by the real TÖEPÄRA+CERBERUS (control ADMITTED), and is not vacuous", async () => {
  const { dir } = repo({ ...runtimeFiles(), ...BASE }, { "src/a.txt": "alpha2\n", "src/c.txt": "gamma\n" });
  configureParentLookup(dir);
  const accept: AttackTarget = async () => true;
  for (const [action, scope] of [["verify-runtime", ["package.json"]], ["diff-scope-check", ["src"]]] as const) {
    const ids = actionChallengeIds(action);
    assert.ok(ids.length >= 3, `${action}: ${ids.length} challenges`);
    const { env, receipt } = await receiptFor(dir, action, [...scope], `ch-${action}`);
    const r = await runAttackClass("tampered-evidence", receipt, env, { target: realAttackTarget(ctx(dir)) });
    assert.equal(r.control_admitted, true, `${action}: control`);
    const mine = r.records.filter((x) => ids.includes(x.attack_id));
    assert.deepEqual(mine.map((x) => x.attack_id).sort(), ids.filter((id) => !(action === "diff-scope-check" && id.endsWith("replayed-on-narrower-lease") && receipt.evidence.artifacts && (receipt.evidence.artifacts as unknown[]).length < 2)).sort());
    assert.deepEqual(mine.filter((x) => x.outcome !== "REPELLED"), [], `${action}: a challenge succeeded`);
    assert.deepEqual(r.findings, [], `${action}: no generic case succeeded either`);
    const vac = await runAttackClass("tampered-evidence", receipt, env, { target: accept });
    assert.ok(vac.findings.filter((f) => ids.some((id) => f.finding_id.endsWith(id.split("/")[1] as string))).length === mine.length, `${action}: accept-all target is attacked successfully on every challenge`);
  }
  // the challenges never run against another action's receipt (pinned generic counts unchanged)
  assert.deepEqual(actionChallengeIds("hash-files"), []);
});

test("CLOSED LOOP: verify-runtime and diff-scope-check go envelope -> KRATT -> RÄSTIK -> TÖEPÄRA -> CERBERUS = ADMIT on a clean repo; an out-of-lease commit is DENIED", async () => {
  const { dir } = repo({ ...runtimeFiles(), ...BASE }, { "src/a.txt": "alpha2\n", "src/c.txt": "gamma\n" });
  const { stand } = setup({ root: dir, runProbes: false });
  for (const [action, scope] of [["verify-runtime", ["package.json"]], ["diff-scope-check", ["src"]]] as const) {
    const r = await stand.submit(stand.issueEnvelope({ action, scope: [...scope], branch: "t", task_id: `loop-${action}` }));
    assert.equal(r.final_decision, "ADMIT", `${action}: ${JSON.stringify([r.cerberus.decision.reasons, r.toepara?.verdict.reasons])}`);
    assert.equal(r.toepara?.verdict.verdict, "VERIFIED");
    const ids = new Set(r.rastik?.attacks.map((a) => a.attack_id));
    for (const id of actionChallengeIds(action)) if (!id.endsWith("narrower-lease")) assert.ok(ids.has(id), `${action}: loop ran ${id}`);
  }
  const denied = await stand.submit(stand.issueEnvelope({ action: "diff-scope-check", scope: ["docs"], branch: "t", task_id: "loop-oos" }));
  assert.equal(denied.final_decision, "DENY");
  assert.match(denied.action_receipt?.result.failure ?? "", /^out-of-scope:2:src\/a\.txt$/);
});
