import test from "node:test";
import assert from "node:assert/strict";
import { ReplayGuard } from "../../kratt/evidence.ts";
import { cerberusDecide, replayKey } from "../cerberus-gate.ts";
import { selfCheckFinalReceipt, type ClosedLoopReceipt } from "../loop.ts";
import { isoRoundTrips } from "../protocol/spec.ts";
import { digestOf, validateActionReceipt, type ActionReceipt, type EvidenceBundle } from "../protocol/types.ts";
import { assembleRun } from "../rastik-attacks.ts";
import { toeparaVerify } from "../toepara.ts";
import { policyViolations, producerMayRunAction } from "../trust-gate.ts";
import { REPO, ROOT, SCOPE, genuine, setup } from "./helpers.ts";

// Regression tests for the confirmed RÄSTIK findings fixed together:
//   1 replay key excluded the receipt timestamp   2 producer role (kratt:<action>)   3 impossible timestamps
//   4 selfCheckFinalReceipt recomputes inner digests + cross-links and never throws

const base = () => ({ root: ROOT, repository: REPO, rerun: new Map() });
const probe = { probes: 0, cases_executed: 0, confirmed_findings: 0, probe_errors: 0, evidence_digest: null };
const attack = { attack_id: "invalid-input/null-receipt", class: "invalid-input" as const, agent_id: "SERPENT-052", case_id: "null-receipt", hypothesis: "h", outcome: "REPELLED" as const, reproduced: null };

async function admitInput(env: Awaited<ReturnType<typeof genuine>>["env"], receipt: ActionReceipt) {
  const need = { ...env, required_evidence: ["source_digests", "rastik_findings"] };
  const run = assembleRun(receipt, [attack], [], probe);
  const toepara = await toeparaVerify(need, receipt, run, base());
  return { envelope: need, receipt, rastik: run, toepara };
}

// ---- 1. replay key -------------------------------------------------------------------------------------------
test("replay: a re-stamped copy of an already-ADMITted receipt (new timestamp => new receipt/bundle digest) is DENIED as replayed-bundle", async () => {
  const { env, receipt } = await genuine();
  const guard = new ReplayGuard();
  const first = await cerberusDecide(await admitInput(env, receipt), { ...base(), guard });
  assert.equal(first.decision.decision, "ADMIT", first.decision.reasons.join(","));

  const restamped: ActionReceipt = { ...receipt, timestamp: "2031-01-01T00:00:00.000Z" };
  assert.notEqual(digestOf(restamped), digestOf(receipt), "precondition: the copy is a different receipt");
  const input2 = await admitInput(env, restamped);
  assert.equal(input2.toepara.verdict.verdict, "VERIFIED", "precondition: the copy verifies on its own");
  assert.notEqual(input2.toepara.bundle?.bundle_digest, first.decision.toepara_evidence_digest, "precondition: the bundle digest differs, so a bundle_digest replay key would not catch it");
  const second = await cerberusDecide(input2, { ...base(), guard });
  assert.equal(second.decision.decision, "DENY");
  assert.ok(second.adapter_reasons.includes("replayed-bundle"), second.adapter_reasons.join(","));
});

test("replay key: depends on exactly {task_id, action, base_sha, kratt_evidence_digest} - not on the timestamp, the RÄSTIK report or the bundle digest", async () => {
  const { env, receipt } = await genuine();
  const b = (await admitInput(env, receipt)).toepara.bundle as EvidenceBundle;
  const k = replayKey(b);
  assert.match(k, /^[0-9a-f]{64}$/);
  assert.equal(k, digestOf({ task_id: b.task_id, action: b.action, base_sha: b.base_sha, kratt_evidence_digest: b.kratt_evidence_digest }));
  // varying anything that is NOT the work does not change the key
  assert.equal(replayKey({ ...b, action_receipt_digest: "1".repeat(64), rastik_evidence_digest: "2".repeat(64), bundle_digest: "3".repeat(64) } as EvidenceBundle), k);
  // varying any of the four identity fields does
  for (const [f, v] of [["task_id", "other-task"], ["action", "run-test"], ["base_sha", "a".repeat(40)], ["kratt_evidence_digest", "4".repeat(64)]] as const) {
    assert.notEqual(replayKey({ ...b, [f]: v } as EvidenceBundle), k, f);
  }
});

test("replay: a genuinely different task is not blocked by an earlier ADMIT (the key is not over-broad)", async () => {
  const a = await genuine();
  const b = await genuine();
  assert.notEqual(a.env.task_id, b.env.task_id);
  const guard = new ReplayGuard();
  assert.equal((await cerberusDecide(await admitInput(a.env, a.receipt), { ...base(), guard })).decision.decision, "ADMIT");
  assert.equal((await cerberusDecide(await admitInput(b.env, b.receipt), { ...base(), guard })).decision.decision, "ADMIT");
});

// ---- 2. producer role ----------------------------------------------------------------------------------------
test("producer role: only a worker holding kratt:<action> may produce that action's receipt", () => {
  for (const a of ["hash-files", "validate-manifest", "run-test"]) assert.equal(producerMayRunAction("FORGE-026", a), true, a);
  assert.equal(producerMayRunAction("FORGE-026", "merge"), false, "not a kratt action");
  for (const a of ["CITADEL-101", "CITADEL-111", "SERPENT-051", "SERPENT-052"]) assert.equal(producerMayRunAction(a, "hash-files"), false, a);
  assert.equal(producerMayRunAction("FORGE-001", "hash-files"), false, "well-formed id with no capability");
  for (const bad of ["__proto__", "constructor", "toString", "", null, undefined, 26, {}, ["FORGE-026"]]) assert.equal(producerMayRunAction(bad, "hash-files"), false, String(bad));
  for (const bad of [null, undefined, 1, {}]) assert.equal(producerMayRunAction("FORGE-026", bad), false, String(bad));
});

test("producer role: policyViolations adds policy:producer-lacks-capability only when a producer is supplied; undefined = envelope-only evaluation", async () => {
  const { env } = await genuine();
  assert.deepEqual(policyViolations(env, "hash-files", REPO), []);
  assert.deepEqual(policyViolations(env, "hash-files", REPO, "FORGE-026"), []);
  assert.deepEqual(policyViolations(env, "hash-files", REPO, "SERPENT-052"), ["policy:producer-lacks-capability:kratt:hash-files"]);
  assert.deepEqual(policyViolations(env, "hash-files", REPO, null), ["policy:producer-lacks-capability:kratt:hash-files"], "unreadable producer fails closed");
});

for (const [factory, agent] of [["CITADEL", "CITADEL-101"], ["CITADEL", "CITADEL-111"], ["SERPENT", "SERPENT-051"]] as const) {
  test(`producer role: a KRATT receipt produced by ${agent} is REJECTED by TÖEPÄRA and DENIED by CERBERUS even if the envelope names that agent`, async () => {
    const { env, receipt } = await genuine();
    const forgedEnv = { ...env, factory, agent_id: agent, required_evidence: ["source_digests"] };
    const forged: ActionReceipt = { ...receipt, agent_id: agent };
    const t = await toeparaVerify(forgedEnv, forged, null, base());
    assert.equal(t.verdict.verdict, "REJECTED");
    assert.ok(t.verdict.reasons.includes("producer-lacks-capability:kratt:hash-files"), t.verdict.reasons.join(","));
    assert.ok(t.verdict.checks.some((c) => c.name === "producer-role" && !c.ok));
    const g = await cerberusDecide({ envelope: forgedEnv, receipt: forged, rastik: null, toepara: t }, { ...base(), guard: new ReplayGuard() });
    assert.equal(g.decision.decision, "DENY");
    assert.ok(g.adapter_reasons.includes("policy:producer-lacks-capability:kratt:hash-files"), g.adapter_reasons.join(","));
    // the genuine producer still passes
    assert.equal((await toeparaVerify(env, receipt, null, base())).verdict.verdict, "VERIFIED");
  });
}

// ---- 3. impossible timestamps --------------------------------------------------------------------------------
test("timestamp: calendar/clock-impossible ISO strings are rejected by the schema, real ones (leap day, millis) are kept", async () => {
  const { receipt } = await genuine();
  const ok = (ts: string) => validateActionReceipt({ ...receipt, timestamp: ts }).ok;
  for (const good of ["2026-10-03T09:00:00Z", "2026-10-03T09:00:00.1Z", "2026-10-03T09:00:00.12Z", "2026-10-03T09:00:00.123Z", "2024-02-29T12:00:00Z", "2000-02-29T00:00:00Z", "2026-12-31T23:59:59Z", "0001-01-01T00:00:00Z"]) assert.equal(ok(good), true, good);
  for (const bad of ["2026-13-45T99:99:99Z", "2026-02-30T10:00:00Z", "2025-02-29T10:00:00Z", "1900-02-29T10:00:00Z", "2026-13-01T10:00:00Z", "2026-00-10T10:00:00Z", "2026-04-31T10:00:00Z", "2026-10-00T10:00:00Z", "2026-10-32T10:00:00Z", "2026-10-03T24:00:00Z", "2026-10-03T23:60:00Z", "2026-10-03T23:59:60Z", "2026-10-03T25:00:00Z", "9999-99-99T99:99:99Z"]) {
    assert.equal(ok(bad), false, bad);
    assert.match(String((validateActionReceipt({ ...receipt, timestamp: bad }) as { reason?: string }).reason), /timestamp/, bad);
  }
  assert.equal(isoRoundTrips("2026-02-28T23:59:59.999Z"), true);
  assert.equal(isoRoundTrips("2026-02-29T00:00:00Z"), false);
  assert.equal(isoRoundTrips("not a date"), false);
  assert.equal(isoRoundTrips("2026-10-03T09:00:00+00:00"), false, "only the Z form is the protocol's form");
});

test("timestamp: an impossible timestamp on the receipt makes TÖEPÄRA reject it (it cannot reach a bundle)", async () => {
  const { env, receipt } = await genuine();
  const t = await toeparaVerify(env, { ...receipt, timestamp: "2026-13-45T99:99:99Z" }, null, base());
  assert.equal(t.verdict.verdict, "REJECTED");
  assert.equal(t.bundle, null);
});

// ---- 4. selfCheckFinalReceipt --------------------------------------------------------------------------------
async function sealed(task: string) {
  const { stand } = setup();
  const r = await stand.submit(stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: task }));
  assert.deepEqual(selfCheckFinalReceipt(r), [], "precondition: genuine receipt is clean");
  assert.equal(r.final_decision, "ADMIT");
  return r;
}
/** Tamper, then RE-SEAL final_digest so that only the inner recomputation can notice. */
function tamper(r: ClosedLoopReceipt, f: (x: any) => void): ClosedLoopReceipt {
  const t = structuredClone(r) as any;
  f(t);
  const { final_digest: _f, ...body } = t;
  void _f;
  t.final_digest = digestOf(body);
  return t as ClosedLoopReceipt;
}
const reasons = (r: ClosedLoopReceipt) => selfCheckFinalReceipt(r);

test("selfCheck: a missing CERBERUS decision / receipt / section is a violation, never a TypeError", async () => {
  const r = await sealed("self-missing");
  assert.ok(reasons(tamper(r, (x) => delete x.cerberus.decision)).includes("cerberus-decision-missing"));
  assert.ok(reasons(tamper(r, (x) => (x.cerberus.decision = null))).includes("cerberus-decision-missing"));
  assert.ok(reasons(tamper(r, (x) => delete x.cerberus.cerberus_receipt)).includes("cerberus-receipt-missing"));
  assert.ok(reasons(tamper(r, (x) => delete x.cerberus)).includes("cerberus-missing"));
  assert.ok(reasons(tamper(r, (x) => (x.cerberus = 7))).includes("cerberus-missing"));
  assert.ok(reasons(tamper(r, (x) => delete x.cerberus.decision)).includes("final-decision-unverifiable"));
  for (const hostile of [null, undefined, 1, "x", [], {}, { cerberus: {} }, { cerberus: { decision: {} } }, { toepara: { verdict: null }, rastik: 1, cerberus: null }]) {
    assert.doesNotThrow(() => selfCheckFinalReceipt(hostile as never), JSON.stringify(hostile));
    assert.ok(selfCheckFinalReceipt(hostile as never).length > 0, JSON.stringify(hostile));
  }
});

test("selfCheck: recomputes the CERBERUS decision digest and the schema of the embedded decision", async () => {
  const r = await sealed("self-decision");
  assert.ok(reasons(tamper(r, (x) => (x.cerberus.decision.reasons = ["edited"]))).includes("cerberus-decision-digest-mismatch"));
  assert.ok(reasons(tamper(r, (x) => (x.cerberus.decision.decision = "MAYBE"))).some((v) => v.startsWith("cerberus-decision-invalid:")));
  assert.ok(reasons(tamper(r, (x) => (x.final_decision = "DENY"))).includes("final-decision-differs-from-cerberus"));
});

test("selfCheck: a self-consistent decision pointing at a different CERBERUS receipt / TÖEPÄRA digest is caught by the cross-links", async () => {
  const r = await sealed("self-links");
  const relink = (x: any, field: string, value: string) => {
    x.cerberus.decision[field] = value;
    const { decision_digest: _d, ...body } = x.cerberus.decision;
    void _d;
    x.cerberus.decision.decision_digest = digestOf(body); // the decision is internally consistent again
  };
  assert.ok(reasons(tamper(r, (x) => relink(x, "cerberus_receipt_digest", "5".repeat(64)))).includes("decision-cerberus-receipt-link-mismatch"));
  assert.ok(reasons(tamper(r, (x) => relink(x, "toepara_evidence_digest", "6".repeat(64)))).includes("decision-toepara-link-mismatch"));
  assert.ok(reasons(tamper(r, (x) => relink(x, "task_id", "some-other-task"))).includes("decision-task-differs-from-receipt"));
});

test("selfCheck: recomputes the TÖEPÄRA bundle digest and links the bundle to the action receipt and the RÄSTIK report", async () => {
  const r = await sealed("self-bundle");
  assert.ok(reasons(tamper(r, (x) => (x.toepara.bundle.source_digests[0].sha256 = "7".repeat(64)))).includes("bundle-digest-mismatch"));
  assert.ok(reasons(tamper(r, (x) => (x.toepara.verdict.evidence_digest = "8".repeat(64)))).includes("toepara-verdict-bundle-link-mismatch"));
  assert.ok(reasons(tamper(r, (x) => (x.toepara.bundle = null))).includes("toepara-verified-without-bundle"));
  const restamped = tamper(r, (x) => (x.action_receipt.timestamp = "2031-01-01T00:00:00.000Z"));
  assert.ok(reasons(restamped).includes("bundle-action-receipt-link-mismatch"));
  assert.ok(reasons(restamped).includes("rastik-target-receipt-mismatch"));
});

test("selfCheck: recomputes the RÄSTIK report digest", async () => {
  const r = await sealed("self-rastik");
  assert.ok(r.rastik !== null);
  assert.ok(reasons(tamper(r, (x) => (x.rastik.cases_executed += 1))).includes("rastik-digest-mismatch"));
});

test("selfCheck: a genuine DENY receipt (no TÖEPÄRA bundle) has no false positives", async () => {
  const { stand } = setup();
  const env = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "self-deny" });
  const r = await stand.submit({ ...env, base_sha: "a".repeat(40) });
  assert.equal(r.final_decision, "DENY");
  assert.deepEqual(selfCheckFinalReceipt(r), []);
});
