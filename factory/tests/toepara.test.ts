import test from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { toeparaVerify } from "../toepara.ts";
import { digestOf, validateToeparaVerdict, type ActionReceipt } from "../protocol/types.ts";
import { REPO, ROOT, genuine, tempRepo } from "./helpers.ts";
import { assembleRun } from "../rastik-attacks.ts";
import { rastikEvidenceDigest } from "../rastik-types.ts";

const ctx = (root = ROOT, repository = REPO) => ({ root, repository, rerun: new Map() });
const mut = (r: ActionReceipt, f: (c: any) => void) => { const c = structuredClone(r) as any; f(c); return c; };
const flip = (h: string) => (h[0] === "0" ? "1" : "0") + h.slice(1);

test("TÖEPÄRA: a genuine KRATT receipt is VERIFIED from recomputed git digests, and the verdict matches the protocol schema", async () => {
  const { env, receipt } = await genuine();
  assert.equal(receipt.verification_state, "UNVERIFIED", "KRATT must not self-verify");
  assert.equal((receipt.evidence as { verdict: string }).verdict, "ADMITTED", "KRATT's own verdict exists but is not authority");
  const t = await toeparaVerify(env, receipt, null, ctx());
  assert.equal(t.verdict.verdict, "VERIFIED", t.verdict.reasons.join(","));
  assert.ok(validateToeparaVerdict(t.verdict).ok);
  assert.equal(t.bundle?.source_digests.length, 4);
  assert.equal(t.bundle?.bundle_digest, t.verdict.evidence_digest);
  assert.ok(t.verdict.checks.every((c) => c.ok));
});

test("TÖEPÄRA: KRATT output alone never yields VERIFIED (self-verified receipt, even with a perfect evidence digest)", async () => {
  const { env, receipt } = await genuine();
  const t = await toeparaVerify(env, mut(receipt, (c) => { c.verification_state = "VERIFIED"; }), null, ctx());
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.ok(t.verdict.reasons.includes("kratt-self-verified:VERIFIED"));
});

test("TÖEPÄRA: missing receipt / missing evidence / empty evidence => INSUFFICIENT_EVIDENCE (never VERIFIED)", async () => {
  const { env, receipt } = await genuine();
  for (const [name, r] of [["null", null], ["no-evidence", mut(receipt, (c) => { delete c.evidence; })], ["no-result", mut(receipt, (c) => { delete c.result; })], ["empty-evidence", mut(receipt, (c) => { c.evidence = {}; })]] as const) {
    const t = await toeparaVerify(env, r, null, ctx());
    assert.equal(t.verdict.verdict, "INSUFFICIENT_EVIDENCE", name);
    assert.equal(t.bundle, null);
  }
});

test("TÖEPÄRA: tampered evidence (digest untouched) is REJECTED by digest recomputation", async () => {
  const { env, receipt } = await genuine();
  const t = await toeparaVerify(env, mut(receipt, (c) => { c.evidence.artifacts[0].sha256 = flip(c.evidence.artifacts[0].sha256); }), null, ctx());
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.ok(t.verdict.reasons.includes("kratt-evidence-invalid:evidence-digest-mismatch"), t.verdict.reasons.join(","));
});

test("TÖEPÄRA: a self-consistent forgery (wrong file digest, evidenceDigest recomputed) is caught only because digests are recomputed from git", async () => {
  const { env, receipt } = await genuine();
  const forged = mut(receipt, (c) => {
    c.evidence.artifacts[0].sha256 = flip(c.evidence.artifacts[0].sha256);
    const { evidenceDigest: _d, ...body } = c.evidence;
    void _d;
    c.evidence.evidenceDigest = digestOf(body);
  });
  const t = await toeparaVerify(env, forged, null, ctx());
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.ok(t.verdict.reasons.includes(`source-digest-mismatch:${(receipt.evidence as any).artifacts[0].name}`), t.verdict.reasons.join(","));
});

test("TÖEPÄRA: unauthorized action, agent spoof, repository spoof, receipt/envelope mismatch are REJECTED with specific reasons", async () => {
  const { env, receipt } = await genuine();
  const reasons = async (r: unknown, e = env, c = ctx()) => (await toeparaVerify(e, r, null, c)).verdict;
  assert.ok((await reasons(mut(receipt, (c) => { c.action = "deploy"; }))).reasons.includes("unauthorized-action:deploy"));
  assert.ok((await reasons(mut(receipt, (c) => { c.action = "run-test"; }))).reasons.includes("unauthorized-action:run-test"));
  assert.ok((await reasons(mut(receipt, (c) => { c.agent_id = "CITADEL-111"; }))).reasons.includes("receipt-agent-mismatch"));
  assert.ok((await reasons(receipt, env, ctx(ROOT, "other-org/other-repo"))).reasons.includes("repository-mismatch"));
  assert.ok((await reasons(mut(receipt, (c) => { c.scope = ["cerberus/core/decide.ts"]; }))).reasons.includes("receipt-scope-mismatch"));
  assert.ok((await reasons(mut(receipt, (c) => { c.result.checks.pass += 1; }))).reasons.includes("receipt-result-contradicts-evidence"));
});

test("TÖEPÄRA: stale or unknown base_sha is REJECTED", async () => {
  const { env, receipt } = await genuine();
  for (const sha of ["0".repeat(40), "1".repeat(40)]) {
    const t = await toeparaVerify({ ...env, base_sha: sha }, { ...receipt, base_sha: sha }, null, ctx());
    assert.equal(t.verdict.verdict, "REJECTED");
    assert.ok(t.verdict.reasons.includes("stale-base-sha") && t.verdict.reasons.includes("base-sha-unknown-commit"), t.verdict.reasons.join(","));
  }
});

test("TÖEPÄRA (temp repo): a working tree that moved after KRATT ran is REJECTED even though the committed bytes match the evidence", async () => {
  const { dir, sha } = tempRepo({ "a.txt": "alpha\n", "b/c.txt": "beta\n" });
  const { env, receipt } = await (async () => {
    const g = await genuineIn(dir, sha, ["a.txt", "b/c.txt"]);
    return g;
  })();
  const ok = await toeparaVerify(env, receipt, null, ctx(dir));
  assert.equal(ok.verdict.verdict, "VERIFIED", ok.verdict.reasons.join(","));
  writeFileSync(join(dir, "a.txt"), "alpha changed\n");
  const t = await toeparaVerify(env, receipt, null, ctx(dir));
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.ok(t.verdict.reasons.includes("working-tree-differs-from-base-sha"), t.verdict.reasons.join(","));
});

test("TÖEPÄRA (temp repo): KRATT hashed a modified working tree => evidence disagrees with the committed bytes => REJECTED", async () => {
  const { dir, sha } = tempRepo({ "a.txt": "alpha\n" });
  writeFileSync(join(dir, "a.txt"), "alpha but edited before KRATT ran\n");
  const { env, receipt } = await genuineIn(dir, sha, ["a.txt"]);
  const t = await toeparaVerify(env, receipt, null, ctx(dir));
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.ok(t.verdict.reasons.includes("source-digest-mismatch:a.txt"), t.verdict.reasons.join(","));
  assert.ok(t.verdict.reasons.includes("working-tree-differs-from-base-sha"));
});

test("TÖEPÄRA: run-test is re-executed independently and the test evidence is recorded as reexecuted", async () => {
  const { env, receipt } = await genuine("run-test");
  const t = await toeparaVerify(env, receipt, null, ctx());
  assert.equal(t.verdict.verdict, "VERIFIED", t.verdict.reasons.join(","));
  assert.equal(t.bundle?.test_evidence?.reexecuted, true);
  assert.ok((t.bundle?.test_evidence?.pass ?? 0) >= 1);
  assert.equal(t.bundle?.test_evidence?.fail, 0);
  // a receipt that lies about the check count is caught by the re-execution (or the result/evidence cross-check)
  const lie = mut(receipt, (c) => { c.evidence.checks.pass += 5; c.result.checks.pass += 5; const { evidenceDigest: _d, ...b } = c.evidence; void _d; c.evidence.evidenceDigest = digestOf(b); });
  const t2 = await toeparaVerify(env, lie, null, ctx());
  assert.equal(t2.verdict.verdict, "REJECTED");
  assert.ok(t2.verdict.reasons.includes("test-reexecution-disagrees"), t2.verdict.reasons.join(","));
});

test("TÖEPÄRA: the RÄSTIK report is required when the envelope requires it, and is digest-checked and bound to this receipt", async () => {
  const { env, receipt } = await genuine();
  const need = { ...env, required_evidence: ["source_digests", "rastik_findings"] };
  assert.equal((await toeparaVerify(need, receipt, null, ctx())).verdict.verdict, "INSUFFICIENT_EVIDENCE");
  const probe = { probes: 0, cases_executed: 0, confirmed_findings: 0, probe_errors: 0, evidence_digest: null };
  const attack = { attack_id: "invalid-input/null-receipt", class: "invalid-input" as const, agent_id: "SERPENT-052", case_id: "null-receipt", hypothesis: "h", outcome: "REPELLED" as const, reproduced: null };
  const run = assembleRun(receipt, [attack], [], probe);
  assert.equal((await toeparaVerify(need, receipt, run, ctx())).verdict.verdict, "VERIFIED");
  const tampered = { ...run, attacks: [{ ...attack, outcome: "SUCCEEDED" as const }] };
  assert.ok((await toeparaVerify(need, receipt, tampered, ctx())).verdict.reasons.includes("rastik-report-digest-mismatch"));
  const other = { ...run, target_receipt_digest: "f".repeat(64) };
  const t = await toeparaVerify(need, receipt, { ...other, evidence_digest: rastikEvidenceDigest(other) }, ctx());
  assert.ok(t.verdict.reasons.includes("rastik-report-for-different-receipt"));
  const none = assembleRun(receipt, [], [], probe);
  assert.equal((await toeparaVerify(need, receipt, none, ctx())).verdict.verdict, "INSUFFICIENT_EVIDENCE", "a RÄSTIK run with zero cases is not evidence");
});

test("TÖEPÄRA: a truthful FAILED action is REJECTED (verification proves success claims, not just authenticity)", async () => {
  const { dir, sha } = tempRepo({ "a.txt": "alpha\n" });
  const g = await genuineIn(dir, sha, ["a.txt", "missing.txt"]);
  assert.equal(g.receipt.result.ok, false);
  const t = await toeparaVerify(g.env, g.receipt, null, ctx(dir));
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.ok(t.verdict.reasons.includes("action-result-not-successful"), t.verdict.reasons.join(","));
});

test("TÖEPÄRA never throws on hostile input", async () => {
  const { env } = await genuine();
  const evil = new Proxy({}, { ownKeys() { throw new Error("trap"); }, getOwnPropertyDescriptor() { throw new Error("trap"); } });
  for (const bad of [undefined, null, 0, "x", [], evil, Object.create(null), 10n]) {
    const t = await toeparaVerify(env, bad, null, ctx());
    assert.notEqual(t.verdict.verdict, "VERIFIED");
    assert.ok(validateToeparaVerdict(t.verdict).ok);
    assert.notEqual((await toeparaVerify(bad, bad, null, ctx())).verdict.verdict, "VERIFIED");
  }
});

import { runKrattStage } from "../kratt-stage.ts";
import { setup } from "./helpers.ts";
import type { TaskEnvelope } from "../protocol/types.ts";

async function genuineIn(dir: string, sha: string, scope: string[]): Promise<{ env: TaskEnvelope; receipt: ActionReceipt }> {
  const { stand, clock } = setup({ root: dir });
  const env = { ...stand.issueEnvelope({ action: "hash-files", branch: "t", scope, base_sha: sha, task_id: `tmp-${Math.random().toString(16).slice(2, 8)}` }), required_evidence: ["source_digests"] };
  const r = await runKrattStage(env, dir, clock);
  if (!r.ok) throw new Error(r.reason);
  return { env, receipt: r.receipt };
}
