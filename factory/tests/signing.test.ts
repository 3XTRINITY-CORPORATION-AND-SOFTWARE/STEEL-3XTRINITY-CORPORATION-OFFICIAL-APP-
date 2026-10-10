import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ReplayGuard } from "../../kratt/evidence.ts";
import { cerberusDecide } from "../cerberus-gate.ts";
import { bundleSubject, noSigningProvider, rastikSubject, signSubject, signatureStatus, signingPayload, type ArtifactSignatures, type SigningProvider } from "../signing.ts";
import { assembleRun } from "../rastik-attacks.ts";
import { toeparaVerify } from "../toepara.ts";
import type { EvidenceBundle } from "../protocol/types.ts";
import { ephemeralEd25519 } from "./ephemeral-provider.ts";
import { REPO, ROOT, SCOPE, genuine, setup } from "./helpers.ts";

const D = "c".repeat(64);
const E = "d".repeat(64);

test("SIGNING: default provider is none => UNSIGNED; a presented signature cannot be verified by it => VERIFICATION_FAILED", async () => {
  assert.equal(await signSubject(noSigningProvider, "evidence-bundle", D), null);
  assert.equal(await signatureStatus(noSigningProvider, "evidence-bundle", D, null), "UNSIGNED");
  assert.equal(await signatureStatus(noSigningProvider, "evidence-bundle", D, undefined), "UNSIGNED");
  const p = ephemeralEd25519();
  const sig = await signSubject(p, "evidence-bundle", D);
  assert.ok(sig);
  assert.equal(await signatureStatus(noSigningProvider, "evidence-bundle", D, sig), "VERIFICATION_FAILED");
});

test("SIGNING: ephemeral ed25519 provider - SIGNED only for the exact purpose, subject, provider and key", async () => {
  const p = ephemeralEd25519();
  const sig = (await signSubject(p, "evidence-bundle", D))!;
  assert.equal(await signatureStatus(p, "evidence-bundle", D, sig), "SIGNED");
  // wrong subject (signature replayed for another artifact), wrong purpose (bundle sig as RÄSTIK sig)
  assert.equal(await signatureStatus(p, "evidence-bundle", E, sig), "VERIFICATION_FAILED");
  assert.equal(await signatureStatus(p, "rastik-report", D, sig), "VERIFICATION_FAILED");
  // claimed subject edited to match the new artifact: signature no longer verifies
  assert.equal(await signatureStatus(p, "evidence-bundle", E, { ...sig, subject_digest: E }), "VERIFICATION_FAILED");
  // flipped signature bytes, other key, other provider name, malformed shapes
  const raw = Buffer.from(sig.value, "base64");
  raw[0] ^= 1;
  assert.equal(await signatureStatus(p, "evidence-bundle", D, { ...sig, value: raw.toString("base64") }), "VERIFICATION_FAILED");
  const other = ephemeralEd25519();
  assert.equal(await signatureStatus(other, "evidence-bundle", D, sig), "VERIFICATION_FAILED");
  assert.equal(await signatureStatus(p, "evidence-bundle", D, { ...sig, provider: "someone-else" }), "VERIFICATION_FAILED");
  for (const bad of [{}, [], "SIGNED", 7, { ...sig, extra: 1 }, { ...sig, value: "" }, { ...sig, key_id: "bad key!" }, { ...sig, subject_digest: "zz" }, { ...sig, purpose: "other" }]) {
    assert.equal(await signatureStatus(p, "evidence-bundle", D, bad), "VERIFICATION_FAILED", JSON.stringify(bad).slice(0, 60));
  }
  assert.ok(signingPayload("evidence-bundle", D) !== signingPayload("rastik-report", D), "domain separation");
});

test("SIGNING: binding checks hold even against a lenient provider (accept-all verify): wrong claimed subject, and a crafted signature naming the none provider", async () => {
  const lenient: SigningProvider = { name: "lenient", sign: async () => ({ key_id: "k", alg: "x", value: "v" }), verify: async () => true };
  const forE = (await signSubject(lenient, "evidence-bundle", E))!;
  assert.equal(await signatureStatus(lenient, "evidence-bundle", E, forE), "SIGNED", "control: lenient provider accepts its own");
  assert.equal(await signatureStatus(lenient, "evidence-bundle", D, forE), "VERIFICATION_FAILED", "signature for subject E presented for subject D");
  const crafted = { provider: "none", key_id: "k", alg: "x", purpose: "evidence-bundle", subject_digest: D, value: "v" };
  assert.equal(await signatureStatus(noSigningProvider, "evidence-bundle", D, crafted), "VERIFICATION_FAILED");
});

test("SIGNING: a provider that throws or answers non-true never yields SIGNED; a sign() failure leaves the artifact UNSIGNED", async () => {
  const p = ephemeralEd25519();
  const sig = (await signSubject(p, "evidence-bundle", D))!;
  const mk = (verify: SigningProvider["verify"]): SigningProvider => ({ name: p.name, sign: p.sign, verify });
  assert.equal(await signatureStatus(mk(async () => { throw new Error("hsm down"); }), "evidence-bundle", D, sig), "VERIFICATION_FAILED");
  for (const v of ["true", 1, {}, undefined, null]) assert.equal(await signatureStatus(mk((async () => v) as never), "evidence-bundle", D, sig), "VERIFICATION_FAILED", String(v));
  const thrower: SigningProvider = { name: "t", sign: async () => { throw new Error("no"); }, verify: async () => true };
  assert.equal(await signSubject(thrower, "evidence-bundle", D), null);
  const garbage: SigningProvider = { name: "t", sign: async () => ({ key_id: "bad key!", alg: "x", value: "v" }), verify: async () => true };
  assert.equal(await signSubject(garbage, "evidence-bundle", D), null);
});

test("SIGNING: key material never reaches evidence, and no key is generated, stored or serialised by factory source", async () => {
  const p = ephemeralEd25519();
  assert.equal(JSON.stringify(p).includes("PRIVATE"), false);
  const sig = (await signSubject(p, "evidence-bundle", D))!;
  assert.ok(!JSON.stringify(sig).includes("BEGIN"));
  const dir = join(ROOT, "factory");
  const files = [...readdirSync(dir), ...readdirSync(join(dir, "protocol")).map((f) => `protocol/${f}`)].filter((f) => /\.(ts|json)$/.test(f));
  for (const f of readdirSync(join(dir, "tests")).filter((x) => x.endsWith(".ts"))) assert.doesNotMatch(readFileSync(join(dir, "tests", f), "utf8"), /BEGIN [A-Z ]*PRIVATE KEY/, `tests/${f}`);
  for (const f of files) {
    const src = readFileSync(join(dir, f), "utf8");
    assert.doesNotMatch(src, /BEGIN [A-Z ]*PRIVATE KEY/, f);
    if (/^(?!tests\/)/.test(f)) assert.doesNotMatch(src, /generateKeyPair|createPrivateKey|privateKey/, `production file ${f} must not generate or hold keys`);
  }
});

// ---------- CERBERUS policy ----------
async function material() {
  const { env, receipt } = await genuine();
  const need = { ...env, required_evidence: ["source_digests", "rastik_findings"] };
  const run = assembleRun(receipt, [{ attack_id: "invalid-input/null-receipt", class: "invalid-input", agent_id: "SERPENT-052", case_id: "null-receipt", hypothesis: "h", outcome: "REPELLED", reproduced: null }], [], { probes: 0, cases_executed: 0, confirmed_findings: 0, probe_errors: 0, evidence_digest: null });
  const ctx = { root: ROOT, repository: REPO, rerun: new Map() };
  const toepara = await toeparaVerify(need, receipt, run, ctx);
  assert.equal(toepara.verdict.verdict, "VERIFIED");
  return { i: { envelope: need, receipt, rastik: run, toepara }, ctx, bundle: toepara.bundle as EvidenceBundle };
}
const decide = (m: Awaited<ReturnType<typeof material>>, signing: { provider: SigningProvider; required: boolean } | undefined, signatures?: ArtifactSignatures) =>
  cerberusDecide({ ...m.i, signatures }, { ...m.ctx, guard: new ReplayGuard(), signing });

test("CERBERUS signing policy: not required + default provider => ADMIT with both artifacts reported UNSIGNED (honest status)", async () => {
  const m = await material();
  const g = await decide(m, undefined);
  assert.equal(g.decision.decision, "ADMIT");
  assert.deepEqual(g.signature_status, { bundle: "UNSIGNED", rastik: "UNSIGNED" });
});

test("CERBERUS signing policy: required => UNSIGNED bundle or RÄSTIK report is DENIED; both properly signed => ADMIT", async () => {
  const m = await material();
  const p = ephemeralEd25519();
  const req = { provider: p, required: true };
  const bundleSig = (await signSubject(p, "evidence-bundle", bundleSubject(m.bundle)))!;
  const rastikSig = (await signSubject(p, "rastik-report", rastikSubject(m.i.rastik!)))!;

  const none = await decide(m, req);
  assert.equal(none.decision.decision, "DENY");
  assert.ok(none.adapter_reasons.includes("signature:evidence-bundle:UNSIGNED"));
  assert.ok(none.adapter_reasons.includes("signature:rastik-report:UNSIGNED"));

  const onlyBundle = await decide(m, req, { bundle: bundleSig });
  assert.equal(onlyBundle.decision.decision, "DENY");
  assert.ok(onlyBundle.adapter_reasons.includes("signature:rastik-report:UNSIGNED"));

  const onlyRastik = await decide(m, req, { rastik: rastikSig });
  assert.equal(onlyRastik.decision.decision, "DENY");
  assert.ok(onlyRastik.adapter_reasons.includes("signature:evidence-bundle:UNSIGNED"));

  const both = await decide(m, req, { bundle: bundleSig, rastik: rastikSig });
  assert.equal(both.decision.decision, "ADMIT", both.decision.reasons.join(","));
  assert.deepEqual(both.signature_status, { bundle: "SIGNED", rastik: "SIGNED" });
});

test("CERBERUS signing policy: required + forged / swapped / foreign-key signatures => VERIFICATION_FAILED => DENY", async () => {
  const m = await material();
  const p = ephemeralEd25519();
  const req = { provider: p, required: true };
  const good = { bundle: (await signSubject(p, "evidence-bundle", bundleSubject(m.bundle)))!, rastik: (await signSubject(p, "rastik-report", rastikSubject(m.i.rastik!)))! };
  // RÄSTIK and bundle signatures swapped (valid signatures, wrong purpose/subject)
  const swapped = await decide(m, req, { bundle: good.rastik, rastik: good.bundle });
  assert.equal(swapped.decision.decision, "DENY");
  assert.equal(swapped.signature_status.bundle, "VERIFICATION_FAILED");
  assert.equal(swapped.signature_status.rastik, "VERIFICATION_FAILED");
  // signature by a different (attacker) ephemeral key
  const evil = ephemeralEd25519(p.name);
  const forged = { bundle: (await signSubject(evil, "evidence-bundle", bundleSubject(m.bundle)))!, rastik: good.rastik };
  const f = await decide(m, req, forged);
  assert.equal(f.decision.decision, "DENY");
  assert.equal(f.signature_status.bundle, "VERIFICATION_FAILED");
  // signature for a different bundle (evidence substitution)
  const other = await signSubject(p, "evidence-bundle", E);
  const sub = await decide(m, req, { bundle: other, rastik: good.rastik });
  assert.equal(sub.decision.decision, "DENY");
  assert.ok(sub.adapter_reasons.includes("signature:evidence-bundle:VERIFICATION_FAILED"));
});

test("CERBERUS signing policy: a RÄSTIK report altered after signing (digest left as-is or recomputed) no longer verifies; a rejected bundle does not burn the replay digest", async () => {
  const m = await material();
  const p = ephemeralEd25519();
  const req = { provider: p, required: true };
  const bundleSig = (await signSubject(p, "evidence-bundle", bundleSubject(m.bundle)))!;
  const rastikSig = (await signSubject(p, "rastik-report", rastikSubject(m.i.rastik!)))!;
  const edited = { ...m.i.rastik!, cases_executed: m.i.rastik!.cases_executed + 5 };
  const g = await cerberusDecide({ ...m.i, rastik: edited, signatures: { bundle: bundleSig, rastik: rastikSig } }, { ...m.ctx, guard: new ReplayGuard(), signing: req });
  assert.equal(g.decision.decision, "DENY");
  assert.equal(g.signature_status.rastik, "VERIFICATION_FAILED");
  // same guard: first attempt denied for lack of signatures must not consume the digest
  const guard = new ReplayGuard();
  const d1 = await cerberusDecide(m.i, { ...m.ctx, guard, signing: req });
  assert.equal(d1.decision.decision, "DENY");
  assert.ok(!d1.adapter_reasons.includes("replayed-bundle"));
  const d2 = await cerberusDecide({ ...m.i, signatures: { bundle: bundleSig, rastik: rastikSig } }, { ...m.ctx, guard, signing: req });
  assert.equal(d2.decision.decision, "ADMIT", d2.decision.reasons.join(","));
});

test("CERBERUS signing policy: required with the default none provider can never ADMIT (no provider => fail closed)", async () => {
  const m = await material();
  const p = ephemeralEd25519();
  const sigs = { bundle: (await signSubject(p, "evidence-bundle", bundleSubject(m.bundle)))!, rastik: (await signSubject(p, "rastik-report", rastikSubject(m.i.rastik!)))! };
  for (const s of [undefined, sigs]) {
    const g = await decide(m, { provider: noSigningProvider, required: true }, s);
    assert.equal(g.decision.decision, "DENY");
  }
});

test("CERBERUS signing policy: when there is no RÄSTIK report the RÄSTIK signature is NOT_APPLICABLE and only the bundle signature is required", async () => {
  const { env, receipt } = await genuine();
  const ctx = { root: ROOT, repository: REPO, rerun: new Map() };
  const toepara = await toeparaVerify(env, receipt, null, ctx);
  const p = ephemeralEd25519();
  const sig = await signSubject(p, "evidence-bundle", bundleSubject(toepara.bundle!));
  const g = await cerberusDecide({ envelope: env, receipt, rastik: null, toepara, signatures: { bundle: sig } }, { ...ctx, guard: new ReplayGuard(), signing: { provider: p, required: true } });
  assert.equal(g.decision.decision, "ADMIT", g.decision.reasons.join(","));
  assert.deepEqual(g.signature_status, { bundle: "SIGNED", rastik: "NOT_APPLICABLE" });
});

test("CLOSED LOOP + signing: producers sign (RÄSTIK report, TÖEPÄRA bundle) and CERBERUS verifies; required+ephemeral provider => ADMIT/SIGNED, required+none => DENY, default => ADMIT/UNSIGNED and no signing field", async () => {
  const p = ephemeralEd25519();
  const a = setup({ signing: { provider: p, required: true } });
  const ra = await a.stand.submit(a.stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "sig-ok" }));
  assert.equal(ra.final_decision, "ADMIT", ra.cerberus.decision.reasons.join(","));
  assert.deepEqual(ra.signing, { bundle: "SIGNED", rastik: "SIGNED" });

  const b = setup({ signing: { provider: noSigningProvider, required: true } });
  const rb = await b.stand.submit(b.stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "sig-none" }));
  assert.equal(rb.final_decision, "DENY");
  assert.ok(rb.cerberus.decision.reasons.includes("signature:evidence-bundle:UNSIGNED"));

  const c = setup();
  const rc = await c.stand.submit(c.stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "sig-default" }));
  assert.equal(rc.final_decision, "ADMIT");
  assert.equal("signing" in rc, false);
});
