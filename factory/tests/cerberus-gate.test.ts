import test from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt } from "../../cerberus/core/decide.ts";
import { ReplayGuard } from "../../kratt/evidence.ts";
import { cerberusDecide, denyWithoutReceipt } from "../cerberus-gate.ts";
import { digestOf, validateCerberusDecision, type EvidenceBundle, type RastikFinding } from "../protocol/types.ts";
import { assembleRun } from "../rastik-attacks.ts";
import { toeparaVerify } from "../toepara.ts";
import { REPO, ROOT, genuine } from "./helpers.ts";

const base = () => ({ root: ROOT, repository: REPO, rerun: new Map() });
const probe = { probes: 0, cases_executed: 0, confirmed_findings: 0, probe_errors: 0, evidence_digest: null };
const attack = { attack_id: "invalid-input/null-receipt", class: "invalid-input" as const, agent_id: "SERPENT-052", case_id: "null-receipt", hypothesis: "h", outcome: "REPELLED" as const, reproduced: null };
const finding = (severity: RastikFinding["severity"], status: RastikFinding["status"] = "CONFIRMED"): RastikFinding => ({
  finding_id: `F-${severity}-${status}`, target: "t", hypothesis: "h", reproduction: "r", severity, status, evidence: {}, regression_test: "x", proposed_smallest_fix: "y",
});

async function full(rastikFindings: RastikFinding[] = []) {
  const { env, receipt } = await genuine();
  const need = { ...env, required_evidence: ["source_digests", "rastik_findings"] };
  const run = assembleRun(receipt, [attack], rastikFindings, probe);
  const toepara = await toeparaVerify(need, receipt, run, base());
  return { need, receipt, run, toepara };
}
const gate = (i: Awaited<ReturnType<typeof full>>, guard = new ReplayGuard()) =>
  cerberusDecide({ envelope: i.need, receipt: i.receipt, rastik: i.run, toepara: i.toepara }, { ...base(), guard });

test("CERBERUS: verified evidence + local policy => ADMIT with a verifiable, adapter-sourced receipt and a schema-valid decision", async () => {
  const i = await full();
  assert.equal(i.toepara.verdict.verdict, "VERIFIED");
  const g = await gate(i);
  assert.equal(g.decision.decision, "ADMIT", g.decision.reasons.join(","));
  assert.ok(validateCerberusDecision(g.decision).ok);
  assert.equal(g.cerberus_receipt.verdictSource, "adapter");
  assert.equal(g.cerberus_receipt.decision, "PROCEED");
  assert.ok(verifyReceipt(g.cerberus_receipt));
  assert.equal(g.decision.cerberus_receipt_digest, g.cerberus_receipt.receiptDigest);
  assert.equal(g.decision.toepara_evidence_digest, i.toepara.verdict.evidence_digest);
});

test("CERBERUS: deterministic - same inputs and a fresh replay guard give byte-identical decision and receipt", async () => {
  const i = await full();
  const a = await gate(i);
  const b = await gate(i);
  assert.equal(JSON.stringify(a.decision), JSON.stringify(b.decision));
  assert.equal(JSON.stringify(a.cerberus_receipt), JSON.stringify(b.cerberus_receipt));
});

test("CERBERUS: a stale/replayed receipt (same bundle, same guard) is DENIED the second time", async () => {
  const i = await full();
  const guard = new ReplayGuard();
  assert.equal((await gate(i, guard)).decision.decision, "ADMIT");
  const again = await gate(i, guard);
  assert.equal(again.decision.decision, "DENY");
  assert.ok(again.adapter_reasons.includes("replayed-bundle"));
});

test("CERBERUS: caller-supplied trust is worthless - a lying TÖEPÄRA result with a forged (self-consistent) bundle is DENIED", async () => {
  const i = await full();
  const b = i.toepara.bundle as EvidenceBundle;
  const forgedBody = { ...b, source_digests: b.source_digests.map((s, k) => (k === 0 ? { ...s, sha256: "e".repeat(64) } : s)) };
  const { bundle_digest: _d, ...rest } = forgedBody;
  void _d;
  const forged: EvidenceBundle = { ...rest, bundle_digest: digestOf(rest) };
  const lying = { verdict: { ...i.toepara.verdict, verdict: "VERIFIED" as const, evidence_digest: forged.bundle_digest }, bundle: forged };
  const g = await cerberusDecide({ envelope: i.need, receipt: i.receipt, rastik: i.run, toepara: lying }, { ...base(), guard: new ReplayGuard() });
  assert.equal(g.decision.decision, "DENY");
  assert.ok(g.adapter_reasons.some((r) => r.startsWith("bundle-differs-from-recomputed") || r.startsWith("bundle-digest-differs")), g.adapter_reasons.join(","));
});

test("CERBERUS: a receipt tampered AFTER TÖEPÄRA verified it is DENIED (Cerberus recomputes, it does not trust the earlier verdict)", async () => {
  const i = await full();
  const tampered = structuredClone(i.receipt) as any;
  tampered.evidence.artifacts[0].sha256 = "d".repeat(64);
  const g = await cerberusDecide({ envelope: i.need, receipt: tampered, rastik: i.run, toepara: i.toepara }, { ...base(), guard: new ReplayGuard() });
  assert.equal(g.decision.decision, "DENY");
});

test("CERBERUS: a REJECTED / INSUFFICIENT TÖEPÄRA result never becomes ADMIT; the bundle is null so Cerberus fails closed", async () => {
  const i = await full();
  const noRastik = await toeparaVerify(i.need, i.receipt, null, base());
  assert.equal(noRastik.verdict.verdict, "INSUFFICIENT_EVIDENCE");
  const g = await cerberusDecide({ envelope: i.need, receipt: i.receipt, rastik: null, toepara: noRastik }, { ...base(), guard: new ReplayGuard() });
  assert.equal(g.decision.decision, "DENY");
  assert.equal(g.cerberus_receipt.decision, "FAIL_CLOSED");
});

test("CERBERUS: policy violation (envelope does not forbid merge/deploy) => DENY even with VERIFIED evidence", async () => {
  const i = await full();
  const lax = { ...i.need, forbidden_actions: ["network"] };
  const t = await toeparaVerify(lax, i.receipt, i.run, base());
  assert.equal(t.verdict.verdict, "VERIFIED");
  const g = await cerberusDecide({ envelope: lax, receipt: i.receipt, rastik: i.run, toepara: t }, { ...base(), guard: new ReplayGuard() });
  assert.equal(g.decision.decision, "DENY");
  assert.ok(g.adapter_reasons.includes("policy:merge-not-forbidden") && g.adapter_reasons.includes("policy:deploy-not-forbidden"));
});

test("CERBERUS: invalid schema (bad envelope) => DENY", async () => {
  const i = await full();
  const g = await cerberusDecide({ envelope: { ...i.need, protocol_version: 2 }, receipt: i.receipt, rastik: i.run, toepara: i.toepara }, { ...base(), guard: new ReplayGuard() });
  assert.equal(g.decision.decision, "DENY");
  assert.ok(validateCerberusDecision(g.decision).ok);
});

test("CERBERUS: unresolved CONFIRMED high/critical RÄSTIK finding => QUARANTINE; medium or UNCONFIRMED => ADMIT; QUARANTINE never beats DENY", async () => {
  for (const [sev, st, want] of [["high", "CONFIRMED", "QUARANTINE"], ["critical", "CONFIRMED", "QUARANTINE"], ["medium", "CONFIRMED", "ADMIT"], ["high", "UNCONFIRMED", "ADMIT"]] as const) {
    const i = await full([finding(sev, st)]);
    const g = await gate(i);
    assert.equal(g.decision.decision, want, `${sev}/${st}`);
    if (want === "QUARANTINE") assert.deepEqual(g.decision.unresolved_high_findings, [`F-${sev}-${st}`]);
  }
  const i = await full([finding("critical")]);
  const g = await cerberusDecide({ envelope: i.need, receipt: i.receipt, rastik: i.run, toepara: i.toepara }, { ...base(), guard: new ReplayGuard(), repository: "other/repo" });
  assert.equal(g.decision.decision, "DENY");
});

test("CERBERUS: denyWithoutReceipt yields a fail-closed, verifiable receipt and a schema-valid DENY", () => {
  const g = denyWithoutReceipt("t-1", "stale-base-sha");
  assert.equal(g.decision.decision, "DENY");
  assert.equal(g.cerberus_receipt.decision, "FAIL_CLOSED");
  assert.ok(verifyReceipt(g.cerberus_receipt));
  assert.ok(validateCerberusDecision(g.decision).ok);
});

test("CERBERUS: a bundle that keeps the genuine bundle_digest but has an altered body is DENIED (body is compared, not just the digest field)", async () => {
  const i = await full();
  const b = i.toepara.bundle as EvidenceBundle;
  const altered: EvidenceBundle = { ...b, source_digests: b.source_digests.map((s, k) => (k === 0 ? { ...s, sha256: "c".repeat(64) } : s)) };
  assert.equal(altered.bundle_digest, b.bundle_digest);
  const lying = { verdict: i.toepara.verdict, bundle: altered };
  const g = await cerberusDecide({ envelope: i.need, receipt: i.receipt, rastik: i.run, toepara: lying }, { ...base(), guard: new ReplayGuard() });
  assert.equal(g.decision.decision, "DENY");
  assert.ok(g.adapter_reasons.includes("bundle-differs-from-recomputed"), g.adapter_reasons.join(","));
});
