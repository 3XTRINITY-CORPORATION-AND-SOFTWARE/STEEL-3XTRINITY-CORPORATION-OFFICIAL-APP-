import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toeparaVerify } from "../toepara.ts";
import { digestOf, type ActionReceipt, type TaskEnvelope } from "../protocol/types.ts";
import { runKrattStage } from "../kratt-stage.ts";
import { REPO, ROOT, setup, tempRepo } from "./helpers.ts";

const FILES = { "a.txt": "alpha\n", "b/c.txt": "beta\n", "d.txt": "delta\n" };
const ctx = (root: string) => ({ root, repository: REPO, rerun: new Map() });
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const flip = (h: string) => (h[0] === "0" ? "1" : "0") + h.slice(1);
const reseal = (c: any) => {
  const { evidenceDigest: _d, ...body } = c.evidence;
  void _d;
  c.evidence.evidenceDigest = digestOf(body);
};

async function genuineIn(dir: string, sha: string, scope: string[]): Promise<{ env: TaskEnvelope; receipt: ActionReceipt }> {
  const { stand, clock } = setup({ root: dir });
  const env = { ...stand.issueEnvelope({ action: "hash-files", branch: "t", scope, base_sha: sha, task_id: `ind-${Math.random().toString(16).slice(2, 8)}` }), required_evidence: ["source_digests"] };
  const r = await runKrattStage(env, dir, clock);
  if (!r.ok) throw new Error(r.reason);
  return { env, receipt: r.receipt };
}
const mut = (r: ActionReceipt, f: (c: any) => void) => {
  const c = structuredClone(r) as any;
  f(c);
  return c as ActionReceipt;
};

test("INDEPENDENCE (source boundary): toepara.ts/git.ts never import KRATT's verdict/replay/adapter code, never read files directly, never use KRATT's own verdict field", () => {
  const src = readFileSync(join(ROOT, "factory/toepara.ts"), "utf8");
  const gsrc = readFileSync(join(ROOT, "factory/git.ts"), "utf8");
  const imports = [...src.matchAll(/from "([^"]+)"/g)].map((m) => m[1]).sort();
  assert.deepEqual(imports, ["../cerberus/core/decide.ts", "../kratt/actions.ts", "../kratt/evidence.ts", "../kratt/task.ts", "./git.ts", "./kratt-stage.ts", "./protocol/types.ts", "./rastik-types.ts", "./trust-gate.ts"]);
  // from kratt/evidence.ts only the pure strict parser (+ the type) may be used
  const evImport = src.match(/import \{([^}]*)\} from "\.\.\/kratt\/evidence\.ts"/)?.[1].split(",").map((x) => x.trim()).sort();
  assert.deepEqual(evImport, ["type ToeparaEvidence", "parseEvidence"].sort());
  assert.doesNotMatch(src, /kratt\/run\.ts|createToeparaAdapter|evidenceToArtifact|computeVerdict|ReplayGuard|gateArtifact|stubAdapter/);
  assert.doesNotMatch(src, /\b(kev|evidence|parsed\.evidence)\.verdict\b/, "KRATT's own verdict must never be read as authority");
  assert.doesNotMatch(src, /["']ADMITTED["']|["']AUTHORIZED["']/, "no hardcoded upstream verdict strings");
  assert.doesNotMatch(src + gsrc, /from "node:fs"|readFileSync|readFile\(|createReadStream/, "file content may only come from git objects");
  // git.ts: fixed read-only subcommands only
  const verbs = [...gsrc.matchAll(/git\(root, \[\s*"([a-z-]+)"/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(verbs)].sort(), ["cat-file", "config", "diff", "ls-tree", "rev-parse"]);
  assert.doesNotMatch(gsrc, /"(fetch|pull|clone|checkout|reset|apply|commit|push|add)"/);
});

test("INDEPENDENCE (control): the VERIFIED bundle contains exactly the digests an independent `git cat-file` + sha256 computes", async () => {
  const { dir, sha } = tempRepo(FILES);
  const { env, receipt } = await genuineIn(dir, sha, ["a.txt", "b/c.txt", "d.txt"]);
  const t = await toeparaVerify(env, receipt, null, ctx(dir));
  assert.equal(t.verdict.verdict, "VERIFIED", t.verdict.reasons.join(","));
  const indep = ["a.txt", "b/c.txt", "d.txt"].map((p) => {
    const b = execFileSync("git", ["cat-file", "blob", `${sha}:${p}`], { cwd: dir });
    return { path: p, sha256: sha256(b), bytes: b.length };
  });
  assert.deepEqual([...(t.bundle?.source_digests ?? [])].sort((x, y) => x.path.localeCompare(y.path)), indep);
});

test("INDEPENDENCE: builder-supplied digests cannot make TÖEPÄRA pass - every self-consistent (evidenceDigest re-sealed) forgery of a digest-bearing field is not VERIFIED", async () => {
  const { dir, sha } = tempRepo(FILES);
  const { env, receipt } = await genuineIn(dir, sha, ["a.txt", "b/c.txt", "d.txt"]);
  assert.equal((await toeparaVerify(env, receipt, null, ctx(dir))).verdict.verdict, "VERIFIED", "control");
  const forgeries: [string, (c: any) => void][] = [
    ["artifact sha256 flipped", (c) => { c.evidence.artifacts[1].sha256 = flip(c.evidence.artifacts[1].sha256); reseal(c); }],
    ["artifact bytes changed", (c) => { c.evidence.artifacts[0].bytes += 1; reseal(c); }],
    ["artifact digest swapped with another file's digest", (c) => { const [x, y] = [c.evidence.artifacts[0].sha256, c.evidence.artifacts[1].sha256]; c.evidence.artifacts[0].sha256 = y; c.evidence.artifacts[1].sha256 = x; reseal(c); }],
    ["artifact dropped from the list", (c) => { c.evidence.artifacts.pop(); reseal(c); }],
    ["artifact renamed to an out-of-scope committed path", (c) => { c.evidence.artifacts[0].name = "zzz.txt"; reseal(c); }],
    ["task digest altered", (c) => { c.evidence.taskDigest = flip(c.evidence.taskDigest); reseal(c); }],
    ["KRATT verdict/checks inflated", (c) => { c.evidence.checks.pass += 3; c.result.checks.pass += 3; reseal(c); }],
    ["only evidence.checks inflated (result untouched)", (c) => { c.evidence.checks.pass += 3; reseal(c); }],
    ["only result.checks inflated (evidence untouched)", (c) => { c.result.checks.pass += 3; }],
    ["receipt claims VERIFIED", (c) => { c.verification_state = "VERIFIED"; }],
    ["evidence replaced by a different valid evidence object", (c) => { c.evidence = { ...c.evidence, taskId: "someone-else" }; reseal(c); }],
  ];
  for (const [name, f] of forgeries) {
    const t = await toeparaVerify(env, mut(receipt, f), null, ctx(dir));
    assert.notEqual(t.verdict.verdict, "VERIFIED", `${name}: ${t.verdict.reasons.join(",")}`);
    assert.equal(t.bundle, null, name);
  }
  // digests that KRATT computed from the WORKING TREE do not count; only the committed bytes do
  const dirty = tempRepo(FILES);
  writeFileSync(join(dirty.dir, "b/c.txt"), "beta-LOCALLY-EDITED\n");
  const { stand, clock } = setup({ root: dirty.dir });
  const env2 = { ...stand.issueEnvelope({ action: "hash-files", branch: "t", scope: ["b/c.txt"], base_sha: dirty.sha, task_id: "ind-dirty" }), required_evidence: ["source_digests"] };
  const r2 = await runKrattStage(env2, dirty.dir, clock);
  assert.ok(r2.ok);
  assert.equal((await toeparaVerify(env2, (r2 as any).receipt, null, ctx(dirty.dir))).verdict.verdict, "REJECTED", "KRATT hashed the edited working tree; git at base_sha says otherwise");
});

test("INDEPENDENCE: KRATT cannot certify KRATT - a perfect KRATT receipt (verdict ADMITTED, all digests right) is NOT verified when TÖEPÄRA has no git to recompute from", async () => {
  const { dir, sha } = tempRepo(FILES);
  const { env, receipt } = await genuineIn(dir, sha, ["a.txt"]);
  assert.equal((receipt.evidence as { verdict: string }).verdict, "ADMITTED");
  assert.equal((await toeparaVerify(env, receipt, null, ctx(dir))).verdict.verdict, "VERIFIED", "control");
  rmSync(join(dir, ".git"), { recursive: true, force: true });
  const t = await toeparaVerify(env, receipt, null, ctx(dir));
  assert.notEqual(t.verdict.verdict, "VERIFIED", "same bytes, same KRATT evidence, no git => no verification");
  assert.equal(t.bundle, null);
  // and an unrelated empty directory (nothing to recompute from at all)
  const empty = mkdtempSync(join(tmpdir(), "toepara-empty-"));
  assert.notEqual((await toeparaVerify(env, receipt, null, ctx(empty))).verdict.verdict, "VERIFIED");
});

test("INDEPENDENCE: the verdict is a function of (envelope, receipt, RÄSTIK report, git) only - changing KRATT's self-assigned verdict string alone changes nothing material, and any KRATT-asserted pass without matching git is REJECTED", async () => {
  const { dir, sha } = tempRepo(FILES);
  const { env, receipt } = await genuineIn(dir, sha, ["a.txt"]);
  const a = await toeparaVerify(env, receipt, null, ctx(dir));
  const b = await toeparaVerify(env, mut(receipt, (c) => { c.evidence.verdict = "REJECTED"; reseal(c); }), null, ctx(dir));
  // KRATT's own verdict is parsed (it must be internally derivable) but is not the authority: a lie about it is invalid evidence, never a pass
  assert.equal(a.verdict.verdict, "VERIFIED");
  assert.notEqual(b.verdict.verdict, "VERIFIED");
});

test("INDEPENDENCE: the envelope's base_sha is the authority - a receipt whose base_sha differs from the envelope's is never VERIFIED, even if it is internally consistent", async () => {
  const { dir, sha } = tempRepo(FILES);
  const { env, receipt } = await genuineIn(dir, sha, ["a.txt"]);
  const other = "1".repeat(40);
  const t = await toeparaVerify({ ...env, base_sha: other } as TaskEnvelope, receipt, null, ctx(dir));
  assert.notEqual(t.verdict.verdict, "VERIFIED");
  assert.ok(t.verdict.reasons.includes("receipt-base-sha-mismatch"), t.verdict.reasons.join(","));
});
