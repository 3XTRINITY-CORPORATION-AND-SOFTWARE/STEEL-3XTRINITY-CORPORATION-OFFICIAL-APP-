import test from "node:test";
import assert from "node:assert/strict";
import { ATTACK_CLASSES } from "../capabilities.ts";
import { caseCount, configureParentLookup, realAttackTarget, runAttackClass, type AttackTarget } from "../rastik-attacks.ts";
import { validateRastikFinding } from "../protocol/types.ts";
import { ROOT, REPO, genuine } from "./helpers.ts";

configureParentLookup(ROOT);
const real = () => realAttackTarget({ root: ROOT, repository: REPO, rerun: new Map() });

test("RÄSTIK: against the real verifier every receipt attack is REPELLED (after a control receipt was ADMITTED), 0 findings", async () => {
  const { env, receipt } = await genuine();
  let executed = 0;
  for (const cls of ATTACK_CLASSES) {
    const r = await runAttackClass(cls, receipt, env, { target: real() });
    assert.equal(r.control_admitted, true, `${cls}: control receipt must be admitted or "all repelled" proves nothing`);
    assert.ok(r.records.length >= caseCount(cls) - 1, cls);
    assert.deepEqual(r.records.filter((x) => x.outcome !== "REPELLED").map((x) => x.attack_id), [], cls);
    assert.deepEqual(r.findings, []);
    executed += r.records.length;
  }
  assert.ok(executed >= 38, `executed ${executed}`);
});

test("RÄSTIK: the battery is not vacuous - a verifier that admits everything is attacked successfully (every case CONFIRMED with a schema-valid finding)", async () => {
  const { env, receipt } = await genuine();
  const admitAll: AttackTarget = async () => true;
  let confirmed = 0;
  for (const cls of ATTACK_CLASSES) {
    const r = await runAttackClass(cls, receipt, env, { target: admitAll });
    assert.equal(r.findings.length, r.records.length);
    for (const f of r.findings) {
      assert.equal(f.status, "CONFIRMED");
      assert.ok(validateRastikFinding(f).ok, f.finding_id);
      assert.match(f.regression_test, /^test\(/);
      confirmed++;
    }
  }
  assert.ok(confirmed >= 38);
});

test("RÄSTIK: a realistic weak verifier that trusts KRATT's own verdict + digest is caught on the right classes only", async () => {
  const { env, receipt } = await genuine();
  const trustingKratt: AttackTarget = async (c) => {
    const r = c as { evidence?: { verdict?: string }; verification_state?: string } | null;
    return r?.evidence?.verdict === "ADMITTED";
  };
  const hits = new Map<string, boolean>();
  for (const cls of ATTACK_CLASSES) {
    const r = await runAttackClass(cls, receipt, env, { target: trustingKratt });
    for (const f of r.findings) hits.set(f.finding_id, f.status === "CONFIRMED");
  }
  assert.equal(hits.get("RASTIK-RCPT-malformed-receipt-self-verified-by-kratt"), true);
  assert.equal(hits.get("RASTIK-RCPT-tampered-evidence-self-consistent-forgery-wrong-source-digest"), true);
  assert.equal(hits.get("RASTIK-RCPT-unauthorized-action-action-deploy"), true);
  assert.equal(hits.has("RASTIK-RCPT-invalid-input-null-receipt"), false, "null receipt has no evidence.verdict: repelled even by the weak verifier");
  assert.equal(hits.has("RASTIK-RCPT-missing-evidence-evidence-deleted"), false);
});

test("RÄSTIK: UNCONFIRMED when the bypass does not reproduce on the independent re-run (flaky acceptance is not a finding)", async () => {
  const { env, receipt } = await genuine();
  let n = 0;
  const flaky: AttackTarget = async () => {
    n++;
    return n === 2; // control is call 1 (rejected) -> would block; make control pass: see below
  };
  // control (call 1) must pass, case first attempt (call 2) admitted, re-run (call 3) refused
  const seq = [true, true, false];
  let i = 0;
  const target: AttackTarget = async () => seq[i++] ?? false;
  void flaky;
  const r = await runAttackClass("invalid-input", receipt, env, { target });
  assert.equal(r.records[0]?.outcome, "SUCCEEDED");
  assert.equal(r.records[0]?.reproduced, false);
  assert.equal(r.findings[0]?.status, "UNCONFIRMED");
});

test("RÄSTIK: if the control receipt is not admitted, no attack results are reported (no false 'all repelled')", async () => {
  const { env, receipt } = await genuine();
  const r = await runAttackClass("boundary", receipt, env, { target: async () => false });
  assert.equal(r.control_admitted, false);
  assert.deepEqual(r.records, []);
});

test("RÄSTIK: a throwing verifier is treated as fail-closed (repelled), never as a bypass", async () => {
  const { env, receipt } = await genuine();
  let calls = 0;
  const target: AttackTarget = async () => {
    if (++calls === 1) return true; // control
    throw new Error("boom");
  };
  const r = await runAttackClass("replay", receipt, env, { target });
  assert.equal(r.records[0]?.outcome, "REPELLED");
});
