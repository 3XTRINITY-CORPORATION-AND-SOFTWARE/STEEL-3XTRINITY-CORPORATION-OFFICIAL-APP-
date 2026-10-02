import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decide, canonicalize } from "../core/decide.ts";
import { sha256Hex } from "../artifact-trust/artifact-trust.ts";

const content = "artifact-bytes";
const valid = () => ({
  action: "recover",
  toepara: "ADMITTED",
  trustGate: "AUTHORIZED",
  artifact: { name: "a.bin", content, sha256: sha256Hex(content) },
});

describe("cerberus vertical slice", () => {
  it("valid evidence => PROCEED with no reasons", () => {
    const r = decide(valid());
    assert.equal(r.decision, "PROCEED");
    assert.deepEqual(r.reasons, []);
  });
  it("same input => identical receipt (key order irrelevant)", () => {
    const a = valid();
    const b = { artifact: a.artifact, trustGate: a.trustGate, toepara: a.toepara, action: a.action };
    assert.deepEqual(decide(a), decide(b));
    assert.equal(canonicalize(a), canonicalize(b));
  });
  it("different input => different receipt digest", () => {
    assert.notEqual(decide(valid()).receiptDigest, decide({ ...valid(), action: "detect" }).receiptDigest);
  });
  it("missing evidence => FAIL_CLOSED", () => {
    for (const bad of [undefined, null, {}, { action: "recover" }]) {
      assert.equal(decide(bad).decision, "FAIL_CLOSED");
    }
  });
  it("tampered artifact => FAIL_CLOSED", () => {
    const v = valid();
    v.artifact.content = "tampered";
    assert.deepEqual(decide(v).reasons, ["artifact-digest-mismatch"]);
  });
  it("malformed digest => FAIL_CLOSED", () => {
    const v = valid();
    v.artifact.sha256 = "XYZ";
    assert.deepEqual(decide(v).reasons, ["artifact-digest-malformed"]);
  });
  it("TÖEPÄRA not admitted => FAIL_CLOSED (cannot be bypassed)", () => {
    assert.deepEqual(decide({ ...valid(), toepara: "REJECTED" }).reasons, ["toepara-not-admitted"]);
  });
  it("Trust Gate not authorized => FAIL_CLOSED (cannot be bypassed)", () => {
    assert.deepEqual(decide({ ...valid(), trustGate: "DENIED" }).reasons, ["trust-gate-not-authorized"]);
  });
  it("merge/deploy actions are denied by policy even with valid evidence", () => {
    for (const action of ["merge", "deploy", "authorize", ""]) {
      assert.deepEqual(decide({ ...valid(), action }).reasons, ["policy-action-denied"]);
    }
  });
});
