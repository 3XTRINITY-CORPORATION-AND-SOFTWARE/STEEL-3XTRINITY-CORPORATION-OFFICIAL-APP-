import test from "node:test";
import assert from "node:assert/strict";
import { bindEvidence, buildDecisionReceipt, digestJson, verifyDecisionReceipt, EVIDENCE_NAMES, STAGE_NAMES, type DecisionRequest, type EvidenceName } from "../receipts/decision-receipt.ts";

const objs: Record<EvidenceName, unknown> = {
  envelope: { task_id: "t-1", scope: ["a"] },
  action_receipt: { action: "hash-files", n: 1 },
  toepara_evidence: { verdict: "VERIFIED", d: "x" },
  evidence_bundle: { bundle: 1 },
  rastik_report: { findings: [] },
  cerberus_receipt: { decision: "PROCEED" },
};
const refs = (over: Partial<Record<EvidenceName, { state?: unknown; digest?: unknown }>> = {}) =>
  ({ ...Object.fromEntries(EVIDENCE_NAMES.map((n) => [n, { state: "PRESENT", digest: digestJson(objs[n]) }])), ...over }) as DecisionRequest["evidence"];
const passStages = () => Object.fromEntries(STAGE_NAMES.map((s) => [s, "PASS"]));
const req = (over: Partial<DecisionRequest> = {}): DecisionRequest => ({
  task_id: "t-1", proposed: "ADMIT", reasons: [], evidence: refs(), toepara_verdict: "VERIFIED", cerberus_decision: "PROCEED", stages: passStages(), ...over,
});

test("DECISION RECEIPT (positive): ADMIT and QUARANTINE are issued only on complete PRESENT evidence + VERIFIED + PROCEED + all stages PASS, and verify", () => {
  for (const d of ["ADMIT", "QUARANTINE"] as const) {
    const r = buildDecisionReceipt(req({ proposed: d, reasons: d === "QUARANTINE" ? ["unresolved-confirmed-high-rastik-finding"] : [] }));
    assert.equal(r.decision, d);
    assert.equal(r.proposed_decision, d);
    assert.equal(r.authentication, "UNSIGNED");
    assert.deepEqual(verifyDecisionReceipt(r), { ok: true, problems: [] });
    assert.equal(r.evidence_binding_digest, digestJson(r.evidence));
  }
});

test("DECISION RECEIPT (positive): DENY is always issuable, binds whatever evidence exists, and verifies (with a reason)", () => {
  const r = buildDecisionReceipt(req({ proposed: "DENY", reasons: ["policy-action-denied"], evidence: {}, toepara_verdict: undefined, cerberus_decision: "FAIL_CLOSED", stages: undefined }));
  assert.equal(r.decision, "DENY");
  assert.ok(EVIDENCE_NAMES.every((n) => r.evidence[n].state === "MISSING" && r.evidence[n].digest === null));
  assert.deepEqual(verifyDecisionReceipt(r), { ok: true, problems: [] });
  assert.ok(buildDecisionReceipt(req({ proposed: "DENY", reasons: [] })).reasons.length >= 1, "a DENY always carries a reason");
});

test("DECISION RECEIPT (fail closed): any required evidence that is MISSING / UNKNOWN / NOT_IMPLEMENTED / malformed downgrades ADMIT and QUARANTINE to DENY", () => {
  const required: EvidenceName[] = ["envelope", "action_receipt", "toepara_evidence", "evidence_bundle", "cerberus_receipt"];
  const bad: Array<{ state?: unknown; digest?: unknown } | undefined> = [
    undefined, { state: "MISSING" }, { state: "UNKNOWN" }, { state: "NOT_IMPLEMENTED" }, { state: "NOT_APPLICABLE" }, { state: "present", digest: "a".repeat(64) },
    { state: "PRESENT" }, { state: "PRESENT", digest: "A".repeat(64) }, { state: "PRESENT", digest: "a".repeat(63) }, { state: "PRESENT", digest: 5 }, { state: { toString: () => "PRESENT" }, digest: "a".repeat(64) }, {},
  ];
  for (const proposed of ["ADMIT", "QUARANTINE"]) {
    for (const name of required) {
      for (const b of bad) {
        const r = buildDecisionReceipt(req({ proposed, evidence: refs({ [name]: b }) }));
        assert.equal(r.decision, "DENY", `${proposed}/${name}/${JSON.stringify(b)}`);
        assert.equal(r.proposed_decision, proposed, "the downgrade is visible");
        assert.ok(r.reasons.includes("downgraded-to-deny"));
        assert.ok(verifyDecisionReceipt(r).ok);
      }
    }
  }
  // rastik_report: NOT_APPLICABLE is fine, MISSING / UNKNOWN / NOT_IMPLEMENTED are not
  assert.equal(buildDecisionReceipt(req({ evidence: refs({ rastik_report: { state: "NOT_APPLICABLE" } }) })).decision, "ADMIT");
  for (const s of ["MISSING", "UNKNOWN", "NOT_IMPLEMENTED"]) assert.equal(buildDecisionReceipt(req({ evidence: refs({ rastik_report: { state: s } }) })).decision, "DENY", s);
});

test("DECISION RECEIPT (fail closed): TÖEPÄRA verdict other than exactly VERIFIED, Cerberus decision other than exactly PROCEED, and any stage other than exactly PASS => DENY; NOT_IMPLEMENTED is never PASS", () => {
  const notVerified = ["REJECTED", "INSUFFICIENT_EVIDENCE", "UNKNOWN", "NOT_IMPLEMENTED", "verified", "VERIFIED ", "", undefined, null, 1, {}, ["VERIFIED"]];
  for (const v of notVerified) assert.equal(buildDecisionReceipt(req({ toepara_verdict: v })).decision, "DENY", JSON.stringify(v));
  for (const v of ["FAIL_CLOSED", "NOT_IMPLEMENTED", "UNKNOWN", "proceed", "PROCEED\n", undefined, null, true]) assert.equal(buildDecisionReceipt(req({ cerberus_decision: v })).decision, "DENY", JSON.stringify(v));
  for (const stage of STAGE_NAMES) {
    for (const v of ["FAIL", "NOT_EVALUATED", "NOT_IMPLEMENTED", "UNKNOWN", "pass", "PASS ", "", undefined, null, 1, true]) {
      const r = buildDecisionReceipt(req({ stages: { ...passStages(), [stage]: v } }));
      assert.equal(r.decision, "DENY", `${stage}=${JSON.stringify(v)}`);
      assert.ok(r.reasons.some((x) => x.startsWith(`stage-not-pass:${stage}:`)));
    }
  }
  for (const stages of [undefined, null, "PASS", [], {}, { input: "PASS" }]) assert.equal(buildDecisionReceipt(req({ stages })).decision, "DENY", JSON.stringify(stages));
});

test("DECISION RECEIPT (fail closed): invalid proposal / task id / hostile objects never produce ADMIT or throw", () => {
  for (const p of ["admit", "PROCEED", "ALLOW", "", undefined, null, 1, {}, "ADMIT "]) {
    const r = buildDecisionReceipt(req({ proposed: p }));
    assert.equal(r.decision, "DENY");
    assert.equal(r.proposed_decision, "INVALID");
  }
  for (const id of ["", "T-1", "a b", "../x", 5, undefined, "x".repeat(65)]) assert.equal(buildDecisionReceipt(req({ task_id: id })).decision, "DENY", JSON.stringify(id));
  const hostile = new Proxy({}, { get() { throw new Error("boom"); }, ownKeys() { throw new Error("boom"); } });
  const getterReq = req();
  Object.defineProperty(getterReq, "stages", { get() { throw new Error("x"); } });
  for (const r0 of [req({ evidence: hostile as never }), req({ stages: hostile }), req({ toepara_verdict: hostile }), getterReq]) {
    const r = buildDecisionReceipt(r0);
    assert.equal(r.decision, "DENY");
    assert.ok(verifyDecisionReceipt(r).ok);
  }
  assert.equal(buildDecisionReceipt(null as never).decision, "DENY");
});

test("DECISION RECEIPT (tamper): flipping DENY->ADMIT, rewriting a stage/verdict/evidence ref, or changing a reason is caught by verify; ADMIT invariants are re-derived", () => {
  const admit = buildDecisionReceipt(req());
  const deny = buildDecisionReceipt(req({ toepara_verdict: "REJECTED" }));
  const mut = (r: unknown, f: (c: any) => void) => { const c = structuredClone(r) as any; f(c); return c; };
  const cases: Array<[string, unknown]> = [
    ["DENY flipped to ADMIT", mut(deny, (c) => { c.decision = "ADMIT"; })],
    ["DENY flipped to ADMIT and proposed rewritten", mut(deny, (c) => { c.decision = "ADMIT"; c.proposed_decision = "ADMIT"; })],
    ["reason removed", mut(admit, (c) => { c.reasons.push("x"); })],
    ["stage rewritten", mut(admit, (c) => { c.basis.stages.policy = "FAIL"; })],
    ["evidence digest swapped", mut(admit, (c) => { c.evidence.evidence_bundle.digest = "f".repeat(64); })],
    ["evidence state rewritten to MISSING", mut(admit, (c) => { c.evidence.evidence_bundle = { state: "MISSING", digest: null }; })],
    ["authentication claimed", mut(admit, (c) => { c.authentication = "SIGNED"; })],
    ["extra key", mut(admit, (c) => { c.extra = 1; })],
    ["missing key", mut(admit, (c) => { delete c.basis; })],
  ];
  for (const [name, c] of cases) assert.equal(verifyDecisionReceipt(c).ok, false, name);
  // re-sealed forgery (digests recomputed): the ADMIT invariants still catch it
  const forged = mut(deny, (c) => { c.decision = "ADMIT"; c.proposed_decision = "ADMIT"; const { receipt_digest: _d, ...b } = c; void _d; c.receipt_digest = digestJson(b); });
  const v = verifyDecisionReceipt(forged);
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.startsWith("proceed-invariant:toepara-verdict-not-verified")), v.problems.join(","));
  for (const junk of [null, undefined, 5, "x", [], {}]) assert.equal(verifyDecisionReceipt(junk).ok, false);
});

test("DECISION RECEIPT (evidence binding): re-hashing presented evidence matches; any changed byte, a swapped object, or evidence supplied for an absent item is reported", () => {
  const r = buildDecisionReceipt(req());
  assert.deepEqual(bindEvidence(r, objs, { complete: true }), { ok: true, problems: [] });
  assert.deepEqual(bindEvidence(r, { envelope: objs.envelope }), { ok: true, problems: [] }, "partial verification is allowed unless complete is requested");
  assert.deepEqual(bindEvidence(r, { evidence_bundle: { bundle: 2 } }).problems, ["evidence-mismatch:evidence_bundle"]);
  assert.deepEqual(bindEvidence(r, { envelope: objs.action_receipt }).problems, ["evidence-mismatch:envelope"]);
  assert.deepEqual(bindEvidence(r, { envelope: objs.envelope }, { complete: true }).problems.sort(), EVIDENCE_NAMES.filter((n) => n !== "envelope").map((n) => `evidence-not-supplied:${n}`).sort());
  const denied = buildDecisionReceipt(req({ proposed: "DENY", reasons: ["x"], evidence: refs({ evidence_bundle: { state: "MISSING" } }) }));
  assert.deepEqual(bindEvidence(denied, { evidence_bundle: { anything: true } }).problems, ["bound-evidence_bundle-is-missing-but-evidence-supplied"]);
  const cyclic: any = {}; cyclic.self = cyclic;
  assert.equal(bindEvidence(r, { envelope: cyclic }).ok, false, "unhashable evidence is a failure, not a pass");
});

test("DECISION RECEIPT: byte-identical for identical requests (no clock, no randomness)", () => {
  assert.equal(JSON.stringify(buildDecisionReceipt(req())), JSON.stringify(buildDecisionReceipt(req())));
  assert.notEqual(buildDecisionReceipt(req()).receipt_digest, buildDecisionReceipt(req({ reasons: ["note"] })).receipt_digest);
});
