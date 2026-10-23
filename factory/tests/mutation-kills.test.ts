import test from "node:test";
import assert from "node:assert/strict";
import { ReplayGuard } from "../../kratt/evidence.ts";
import { cerberusDecide, localPolicyTrustGate } from "../cerberus-gate.ts";
import { toeparaVerify } from "../toepara.ts";
import { validateActionReceipt, type ActionReceipt, type TaskEnvelope } from "../protocol/types.ts";
import { signSubject, signatureStatus } from "../signing.ts";
import { ephemeralEd25519 } from "./ephemeral-provider.ts";
import { ROOT, REPO, SCOPE, genuine, setup } from "./helpers.ts";

/**
 * Tests added because the mutation harness (factory/mutation/) showed that a guard could be disabled
 * without any test noticing. Each one asserts the SPECIFIC reason of one defence layer, so a layer
 * cannot hide behind another one that happens to reject the same input.
 */
const ctx = () => ({ root: ROOT, repository: REPO, rerun: new Map() });
const verify = (env: unknown, receipt: unknown) => toeparaVerify(env, receipt, null, ctx());
const clone = <T>(v: T): T => structuredClone(v);

test("MUTATION-KILL TÖEPÄRA: each identity / result defence layer reports its OWN reason (task id, base_sha, result vs evidence, success claim)", async () => {
  const { env, receipt } = await genuine();
  const ok = await verify(env, receipt);
  assert.equal(ok.verdict.verdict, "VERIFIED", "control");

  const taskId = clone(receipt);
  taskId.task_id = "t-another-task";
  const a = await verify(env, taskId);
  assert.equal(a.verdict.verdict, "REJECTED");
  assert.ok(a.verdict.reasons.includes("receipt-task-id-mismatch"), a.verdict.reasons.join());

  const base = clone(receipt);
  base.base_sha = "1".repeat(40);
  const b = await verify(env, base);
  assert.equal(b.verdict.verdict, "REJECTED");
  assert.ok(b.verdict.reasons.includes("receipt-base-sha-mismatch"), b.verdict.reasons.join());

  const failCount = clone(receipt);
  failCount.result.checks.fail = 1;
  const c = await verify(env, failCount);
  assert.equal(c.verdict.verdict, "REJECTED");
  assert.ok(c.verdict.reasons.includes("receipt-result-contradicts-evidence"), "result vs evidence layer: " + c.verdict.reasons.join());
  assert.ok(c.verdict.reasons.includes("action-result-not-successful"), "success-claim layer: " + c.verdict.reasons.join());

  const exitCode = clone(receipt);
  exitCode.result.exit_code = 1;
  const d = await verify(env, exitCode);
  assert.ok(d.verdict.reasons.includes("receipt-result-contradicts-evidence"), d.verdict.reasons.join());
});

test("MUTATION-KILL TÖEPÄRA: required evidence that the verifier cannot produce is INSUFFICIENT_EVIDENCE with its own reason (never silently satisfied)", async () => {
  const { env, receipt } = await genuine("hash-files");
  const noTest: TaskEnvelope = { ...clone(env), required_evidence: ["source_digests", "test_evidence"] };
  const a = await verify(noTest, receipt);
  assert.equal(a.verdict.verdict, "INSUFFICIENT_EVIDENCE");
  assert.ok(a.verdict.reasons.includes("required-evidence-missing:test_evidence"), a.verdict.reasons.join());
  const unsupported: TaskEnvelope = { ...clone(env), required_evidence: ["source_digests", "sbom"] };
  const b = await verify(unsupported, receipt);
  assert.equal(b.verdict.verdict, "INSUFFICIENT_EVIDENCE");
  assert.ok(b.verdict.reasons.includes("required-evidence-unsupported:sbom"), b.verdict.reasons.join());
  assert.equal(b.bundle, null);
});

test("MUTATION-KILL CERBERUS local policy trust gate: every policy rule denies on its own (tested directly, independent of TÖEPÄRA's identical checks)", async () => {
  const { env, receipt } = await genuine();
  const gate = (e: TaskEnvelope, r: unknown, repo = REPO) => {
    const sink: string[] = [];
    const v = localPolicyTrustGate(e, r, repo, sink).verdict({} as never);
    return { v, sink };
  };
  assert.deepEqual(gate(env, receipt), { v: "AUTHORIZED", sink: [] });
  const repo = gate(env, receipt, "someone/else");
  assert.equal(repo.v, "DENIED");
  assert.deepEqual(repo.sink, ["policy:repository-mismatch"]);
  const widened = gate({ ...clone(env), allowed_actions: [...env.allowed_actions, "merge"] }, receipt);
  assert.equal(widened.v, "DENIED");
  assert.ok(widened.sink.includes("policy:non-kratt-action-allowed"));
  const notAllowed = gate(env, { ...clone(receipt), action: "validate-manifest" });
  assert.equal(notAllowed.v, "DENIED");
  assert.deepEqual(notAllowed.sink, ["policy:receipt-action-not-allowed"]);
  const noAction = gate(env, null);
  assert.deepEqual(noAction.sink, ["policy:receipt-action-not-allowed"]);
  for (const must of ["merge", "deploy"]) {
    const e = { ...clone(env), forbidden_actions: env.forbidden_actions.filter((a) => a !== must) };
    const r = gate(e, receipt);
    assert.equal(r.v, "DENIED");
    assert.deepEqual(r.sink, [`policy:${must}-not-forbidden`]);
  }
});

test("MUTATION-KILL CERBERUS: a presented bundle with only its bundle_digest altered is DENIED with the bundle-digest reason (not merely the byte-equality layer)", async () => {
  const { env, receipt } = await genuine();
  const t = await toeparaVerify(env, receipt, null, ctx());
  assert.equal(t.verdict.verdict, "VERIFIED");
  const forged = { ...t, bundle: { ...clone(t.bundle!), bundle_digest: (t.bundle!.bundle_digest[0] === "0" ? "1" : "0") + t.bundle!.bundle_digest.slice(1) } };
  const g = await cerberusDecide({ envelope: env, receipt, rastik: null, toepara: forged }, { ...ctx(), guard: new ReplayGuard() });
  assert.equal(g.decision.decision, "DENY");
  assert.ok(g.adapter_reasons.includes("bundle-digest-differs-from-recomputed"), g.adapter_reasons.join());
  const ok = await cerberusDecide({ envelope: env, receipt, rastik: null, toepara: t }, { ...ctx(), guard: new ReplayGuard() });
  assert.equal(ok.decision.decision, "ADMIT", "control");
});

test("MUTATION-KILL closed loop: if RÄSTIK cannot admit its own control receipt in any attack class, the RÄSTIK stage is BLOCKED, no report reaches TÖEPÄRA, and the task is DENIED (no admission without an attack report)", async () => {
  const { stand } = setup({ attackTarget: async () => false });
  const r = await stand.submit(stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "kill-ctl-rej" }));
  assert.equal(r.final_decision, "DENY");
  assert.equal(r.rastik, null, "a BLOCKED RÄSTIK stage must not hand a (partial) report on");
  const rastik = r.stages.find((s) => s.stage === "RASTIK");
  assert.equal(rastik?.outcome, "BLOCKED");
  assert.equal(rastik?.note, "attack-class-not-executed");
  const attack = r.stages.filter((s) => s.stage === "RASTIK_ATTACK");
  assert.equal(attack.length, 8);
  assert.ok(attack.every((s) => s.outcome === "BLOCKED"), attack.map((s) => `${s.capability}:${s.outcome}`).join());
  assert.equal(r.toepara?.verdict.verdict, "INSUFFICIENT_EVIDENCE");
  assert.ok(r.toepara?.verdict.reasons.includes("required-evidence-missing:rastik_findings"));
});

test("MUTATION-KILL fixture sanity: the genuine receipt used by the kill tests is an ActionReceipt for the current scope", async () => {
  const { env, receipt } = await genuine();
  const r: ActionReceipt = receipt;
  assert.deepEqual(r.scope, SCOPE);
  assert.equal(r.verification_state, "UNVERIFIED");
  assert.equal(env.agent_id, r.agent_id);
});

test("MUTATION-KILL protocol validator: an accessor (getter) property is rejected AS an accessor - a TOCTOU-capable value is never read through", async () => {
  const { receipt } = await genuine();
  const r = clone(receipt) as unknown as Record<string, unknown>;
  const v = r.task_id;
  Object.defineProperty(r, "task_id", { enumerable: true, configurable: true, get: () => v });
  const res = validateActionReceipt(r);
  assert.equal(res.ok, false);
  assert.equal(res.ok === false ? res.reason : "", "$.task_id:accessor");
});

test("MUTATION-KILL signing: a genuinely signed signature whose purpose LABEL was changed is VERIFICATION_FAILED (labels are checked, not only the signed payload)", async () => {
  const p = ephemeralEd25519();
  const D = "a".repeat(64);
  const sig = await signSubject(p, "evidence-bundle", D);
  assert.ok(sig);
  assert.equal(await signatureStatus(p, "evidence-bundle", D, sig), "SIGNED", "control");
  assert.equal(await signatureStatus(p, "evidence-bundle", D, { ...sig, purpose: "rastik-report" }), "VERIFICATION_FAILED", "relabelled purpose");
  assert.equal(await signatureStatus(p, "evidence-bundle", D, { ...sig, subject_digest: "b".repeat(64) }), "VERIFICATION_FAILED", "relabelled subject");
  assert.equal(await signatureStatus(p, "rastik-report", D, sig), "VERIFICATION_FAILED", "signature presented for another purpose");
});
