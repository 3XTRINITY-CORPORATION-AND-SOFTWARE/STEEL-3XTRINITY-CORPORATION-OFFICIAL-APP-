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

// =====================================================================================================
// P2 evidence authentication: ActionReceipt + CERBERUS decision-receipt signing (interface + test key only)
// =====================================================================================================
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import {
  SIGNING_KEY_UNAVAILABLE,
  actionReceiptSubject,
  decisionReceiptSignatureStatus,
  ed25519Verifier,
  receiptSigningRequired,
  requireReceiptSigner,
  resolveSigningConfig,
  signActionReceipt,
  signDecisionReceipt,
  type ReceiptSigningPolicy,
} from "../signing.ts";
import { buildDecisionReceipt, digestJson, type DecisionRequest } from "../../cerberus/receipts/decision-receipt.ts";
import type { ActionReceipt } from "../protocol/types.ts";

const keyDir = () => mkdtempSync(join(tmpdir(), "sig-cfg-"));
const required = (p: SigningProvider): ReceiptSigningPolicy => ({ verifier: p, key_configured: true, signer: p });
const tctx = (policy?: ReceiptSigningPolicy) => ({ root: ROOT, repository: REPO, rerun: new Map(), ...(policy ? { receiptSigning: policy } : {}) });

test("RECEIPT SIGNING config: no key provisioned => SIGNING_KEY_UNAVAILABLE, nothing generated, signing refuses with that code, policy not required by default", async () => {
  const c = resolveSigningConfig({});
  assert.equal(c.status, SIGNING_KEY_UNAVAILABLE);
  assert.equal(c.policy.key_configured, false);
  assert.equal(receiptSigningRequired(c.policy), false, "default: require only when a key is configured");
  assert.equal(receiptSigningRequired({ ...c.policy, require: true }), true, "explicit require overrides");
  assert.throws(() => requireReceiptSigner(c.policy), (e: Error & { code?: string }) => e.code === SIGNING_KEY_UNAVAILABLE);
  const { receipt } = await genuine();
  await assert.rejects(signActionReceipt(undefined, receipt), (e: Error & { code?: string }) => e.code === SIGNING_KEY_UNAVAILABLE);
  await assert.rejects(signActionReceipt(noSigningProvider, receipt), (e: Error & { code?: string }) => e.code === SIGNING_KEY_UNAVAILABLE, "a signer that cannot sign is the same as no key");
  assert.equal(receiptSigningRequired(undefined), false);
});

test("RECEIPT SIGNING config: a provisioned Ed25519 PUBLIC key file => CONFIGURED (verify-only, required by default, no signer); private-key material, symlinks, missing files, bad key ids and non-Ed25519 keys fail closed", async () => {
  const p = ephemeralEd25519("ed25519");
  const dir = keyDir();
  const pub = join(dir, "receipt-verify.pem");
  writeFileSync(pub, p.publicKeyPem());
  const ok = resolveSigningConfig({ FACTORY_SIGNING_PUBLIC_KEY_FILE: pub, FACTORY_SIGNING_KEY_ID: p.key_id });
  assert.equal(ok.status, "CONFIGURED", ok.reason);
  assert.equal(ok.policy.key_configured, true);
  assert.equal(receiptSigningRequired(ok.policy), true);
  assert.equal(receiptSigningRequired({ ...ok.policy, require: false }), false, "documented opt-out");
  assert.equal(ok.policy.signer, undefined, "no production signer: key custody is a human gate");
  assert.throws(() => requireReceiptSigner(ok.policy), (e: Error & { code?: string }) => e.code === SIGNING_KEY_UNAVAILABLE);
  // the configured verifier accepts a real Ed25519 signature by the matching key
  const { receipt } = await genuine();
  const sig = await signActionReceipt(p, receipt);
  assert.equal(await signatureStatus(ok.policy.verifier, "action-receipt", actionReceiptSubject(receipt), sig), "SIGNED");

  const priv = join(dir, "priv.pem");
  writeFileSync(priv, "-----BEGIN " + "PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END " + "PRIVATE KEY-----\n");
  const link = join(dir, "link.pem");
  symlinkSync(pub, link);
  const rsa = join(dir, "rsa.pem");
  writeFileSync(rsa, generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({ type: "spki", format: "pem" }).toString());
  const garbage = join(dir, "garbage.pem");
  writeFileSync(garbage, "not a key");
  for (const [name, env] of [
    ["private key material", { FACTORY_SIGNING_PUBLIC_KEY_FILE: priv, FACTORY_SIGNING_KEY_ID: "k1" }],
    ["symlink", { FACTORY_SIGNING_PUBLIC_KEY_FILE: link, FACTORY_SIGNING_KEY_ID: "k1" }],
    ["missing file", { FACTORY_SIGNING_PUBLIC_KEY_FILE: join(dir, "nope.pem"), FACTORY_SIGNING_KEY_ID: "k1" }],
    ["directory", { FACTORY_SIGNING_PUBLIC_KEY_FILE: dir, FACTORY_SIGNING_KEY_ID: "k1" }],
    ["rsa key", { FACTORY_SIGNING_PUBLIC_KEY_FILE: rsa, FACTORY_SIGNING_KEY_ID: "k1" }],
    ["garbage", { FACTORY_SIGNING_PUBLIC_KEY_FILE: garbage, FACTORY_SIGNING_KEY_ID: "k1" }],
    ["no key id", { FACTORY_SIGNING_PUBLIC_KEY_FILE: pub }],
    ["bad key id", { FACTORY_SIGNING_PUBLIC_KEY_FILE: pub, FACTORY_SIGNING_KEY_ID: "../k 1" }],
    ["key id without file", { FACTORY_SIGNING_KEY_ID: "k1" }],
  ] as const) {
    const c = resolveSigningConfig(env);
    assert.equal(c.status, SIGNING_KEY_UNAVAILABLE, name);
    assert.equal(c.policy.key_configured, false, name);
    assert.equal(await signatureStatus(c.policy.verifier, "action-receipt", actionReceiptSubject(receipt), sig), "VERIFICATION_FAILED", `${name}: nothing verifies`);
  }
});

test("RECEIPT SIGNING ed25519Verifier (node:crypto): SIGNED only for the matching key id, alg, provider name and exact payload; malformed values never verify", async () => {
  const p = ephemeralEd25519("ed25519");
  const v = ed25519Verifier(p.publicKeyPem(), p.key_id, "ed25519");
  const payload = signingPayload("action-receipt", D);
  const s = (await p.sign(payload))!;
  assert.equal(await v.verify(payload, s), true);
  assert.equal(await v.verify(signingPayload("action-receipt", E), s), false, "other payload");
  assert.equal(await v.verify(payload, { ...s, key_id: "other" }), false, "other key id");
  assert.equal(await v.verify(payload, { ...s, alg: "rsa" }), false, "other alg");
  for (const value of ["", "!!!!", "A".repeat(4000), Buffer.alloc(63).toString("base64"), Buffer.alloc(64).toString("base64")]) assert.equal(await v.verify(payload, { ...s, value }), false, value.slice(0, 10));
  const evil = ephemeralEd25519("ed25519");
  assert.equal(await v.verify(payload, { ...(await evil.sign(payload))!, key_id: p.key_id }), false, "another key claiming the configured key id");
  assert.equal(await v.sign(payload), null, "a verifier never signs");
  assert.throws(() => ed25519Verifier("not a key", "k1"), (e: Error & { code?: string }) => e.code === SIGNING_KEY_UNAVAILABLE);
  assert.throws(() => ed25519Verifier(p.publicKeyPem(), "bad id!"), (e: Error & { code?: string }) => e.code === SIGNING_KEY_UNAVAILABLE);
});

test("TÖEPÄRA receipt signature: valid => VERIFIED; missing (required) => INSUFFICIENT_EVIDENCE; tampered / re-timestamped / foreign key / other purpose / garbage => REJECTED", async () => {
  const { env, receipt } = await genuine();
  const p = ephemeralEd25519();
  const pol = required(p);
  const sig = await signActionReceipt(p, receipt);
  const ok = await toeparaVerify(env, receipt, null, tctx(pol), sig);
  assert.equal(ok.verdict.verdict, "VERIFIED", ok.verdict.reasons.join(","));
  assert.ok(ok.verdict.checks.some((c) => c.name === "receipt-signature" && c.ok));

  const missing = await toeparaVerify(env, receipt, null, tctx(pol));
  assert.equal(missing.verdict.verdict, "INSUFFICIENT_EVIDENCE");
  assert.deepEqual(missing.verdict.reasons, ["receipt-signature-missing"]);
  assert.equal(missing.bundle, null);
  assert.equal((await toeparaVerify(env, receipt, null, tctx(pol), null)).verdict.verdict, "INSUFFICIENT_EVIDENCE", "explicit null is missing too");

  const restamped = { ...receipt, timestamp: "2031-01-01T00:00:00Z" } as ActionReceipt;
  const evil = ephemeralEd25519(p.name);
  const cases: [string, ActionReceipt, unknown][] = [
    ["payload re-timestamped after signing (replay)", restamped, sig],
    ["key substitution: attacker key, attacker key id", receipt, await signActionReceipt(evil, receipt)],
    ["key substitution: attacker key claiming the trusted key id", receipt, { ...(await signActionReceipt(evil, receipt)), key_id: p.key_id }],
    ["signature for another purpose over the same digest", receipt, await signSubject(p, "evidence-bundle", actionReceiptSubject(receipt))],
    ["signature over another subject", receipt, await signSubject(p, "action-receipt", D)],
    ["garbage signature object", receipt, { value: "x" }],
    ["signature string", receipt, "sig"],
  ];
  for (const [name, r, s] of cases) {
    const t = await toeparaVerify(env, r, null, tctx(pol), s);
    assert.equal(t.verdict.verdict, "REJECTED", name);
    assert.ok(t.verdict.reasons.includes("receipt-signature-invalid"), `${name}: ${t.verdict.reasons.join(",")}`);
    assert.equal(t.bundle, null, name);
  }
  // control for the replay case: unsigned and unrequired, the re-timestamped receipt IS verified (so the signature is what stops it)
  assert.equal((await toeparaVerify(env, restamped, null, tctx())).verdict.verdict, "VERIFIED");
  // a signature is checked whenever presented: present + no verification key => REJECTED, never ignored
  const noKey = await toeparaVerify(env, receipt, null, tctx(), sig);
  assert.equal(noKey.verdict.verdict, "REJECTED");
  assert.ok(noKey.verdict.reasons.includes("receipt-signature-invalid"));
  // required without a key (require:true, verifier none) => never VERIFIED, signed or not
  for (const s of [undefined, sig]) assert.notEqual((await toeparaVerify(env, receipt, null, tctx({ verifier: noSigningProvider, key_configured: false, require: true }), s)).verdict.verdict, "VERIFIED");
  // default (no key configured): unchanged behaviour, unsigned receipt still VERIFIED
  assert.equal((await toeparaVerify(env, receipt, null, tctx({ verifier: noSigningProvider, key_configured: false }))).verdict.verdict, "VERIFIED");
});

test("CERBERUS receipt signing: required => an unsigned receipt is never ADMITted (DENY, signature:action-receipt:UNSIGNED); signed => ADMIT with honest status; re-timestamped signed replay => DENY", async () => {
  const { env, receipt } = await genuine();
  const p = ephemeralEd25519();
  const pol = required(p);
  const ctx = tctx(pol);
  const toepara = await toeparaVerify(env, receipt, null, tctx());
  const unsigned = await cerberusDecide({ envelope: env, receipt, rastik: null, toepara }, { ...ctx, guard: new ReplayGuard() });
  assert.equal(unsigned.decision.decision, "DENY");
  assert.ok(unsigned.adapter_reasons.includes("signature:action-receipt:UNSIGNED"), unsigned.adapter_reasons.join(","));
  assert.equal(unsigned.signature_status.receipt, "UNSIGNED");

  const sig = await signActionReceipt(p, receipt);
  const t2 = await toeparaVerify(env, receipt, null, ctx, sig);
  const signed = await cerberusDecide({ envelope: env, receipt, rastik: null, toepara: t2, signatures: { receipt: sig } }, { ...ctx, guard: new ReplayGuard() });
  assert.equal(signed.decision.decision, "ADMIT", signed.decision.reasons.join(","));
  assert.equal(signed.signature_status.receipt, "SIGNED");

  const restamped = { ...receipt, timestamp: "2031-01-01T00:00:00Z" };
  const replay = await cerberusDecide({ envelope: env, receipt: restamped, rastik: null, toepara: t2, signatures: { receipt: sig } }, { ...ctx, guard: new ReplayGuard() });
  assert.equal(replay.decision.decision, "DENY");
  assert.equal(replay.signature_status.receipt, "VERIFICATION_FAILED");
  assert.ok(replay.adapter_reasons.includes("signature:action-receipt:VERIFICATION_FAILED"));

  // default (no key configured, nothing required): unsigned => ADMIT, status reported honestly as UNSIGNED
  const dflt = await cerberusDecide({ envelope: env, receipt, rastik: null, toepara }, { ...tctx(), guard: new ReplayGuard() });
  assert.equal(dflt.decision.decision, "ADMIT");
  assert.equal(dflt.signature_status.receipt, "UNSIGNED");
});

const decisionReq = (over: Partial<DecisionRequest> = {}): DecisionRequest => {
  const ref = (s: string) => ({ state: "PRESENT" as const, digest: digestJson(s) });
  return {
    task_id: "t-1",
    proposed: "DENY",
    reasons: ["policy-action-denied"],
    evidence: { envelope: ref("e"), action_receipt: ref("a"), toepara_evidence: ref("t"), evidence_bundle: ref("b"), rastik_report: { state: "NOT_APPLICABLE" }, cerberus_receipt: ref("c") },
    toepara_verdict: "VERIFIED",
    cerberus_decision: "PROCEED",
    stages: { input: "PASS", policy: "PASS", toepara: "PASS", trustGate: "PASS", artifactTrust: "PASS" },
    ...over,
  } as DecisionRequest;
};

test("DECISION RECEIPT signing: SIGNED for the exact recomputed receipt; flipped decision (re-sealed digest), stripped, foreign key, invalid receipt => never SIGNED; no signer => SIGNING_KEY_UNAVAILABLE", async () => {
  const p = ephemeralEd25519();
  const d = buildDecisionReceipt(decisionReq());
  assert.equal(d.decision, "DENY");
  const sig = await signDecisionReceipt(p, d);
  assert.equal(await decisionReceiptSignatureStatus(p, d, sig), "SIGNED");
  assert.equal(await decisionReceiptSignatureStatus(p, d, null), "UNSIGNED");
  assert.equal(await decisionReceiptSignatureStatus(p, d, undefined), "UNSIGNED");
  // edited after signing and re-sealed so the receipt is internally consistent again
  const { receipt_digest: _r, ...body } = d;
  void _r;
  const edited = { ...body, reasons: [...body.reasons, "extra"] };
  const resealed = { ...edited, receipt_digest: digestJson(edited) };
  assert.equal(await decisionReceiptSignatureStatus(p, resealed, sig), "VERIFICATION_FAILED");
  // flipped decision with stale digest => receipt invalid => VERIFICATION_FAILED
  assert.equal(await decisionReceiptSignatureStatus(p, { ...d, decision: "ADMIT" }, sig), "VERIFICATION_FAILED");
  const evil = ephemeralEd25519(p.name);
  assert.equal(await decisionReceiptSignatureStatus(p, d, await signDecisionReceipt(evil, d)), "VERIFICATION_FAILED");
  assert.equal(await decisionReceiptSignatureStatus(p, d, await signSubject(p, "action-receipt", d.receipt_digest)), "VERIFICATION_FAILED", "purpose confusion");
  assert.equal(await decisionReceiptSignatureStatus(p, { not: "a receipt" }, sig), "VERIFICATION_FAILED");
  await assert.rejects(signDecisionReceipt(noSigningProvider, d), (e: Error & { code?: string }) => e.code === SIGNING_KEY_UNAVAILABLE);
  await assert.rejects(signDecisionReceipt(p, { ...d, decision: "ADMIT" }), /decision-receipt-invalid/);
});

test("CLOSED LOOP + receipt signing: KRATT-stage signs, TÖEPÄRA and CERBERUS verify => ADMIT/SIGNED; key configured but no signer => refused SIGNING_KEY_UNAVAILABLE (never ADMIT)", async () => {
  const p = ephemeralEd25519();
  const a = setup({ receiptSigning: required(p) });
  const ra = await a.stand.submit(a.stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "rsig-ok" }));
  assert.equal(ra.final_decision, "ADMIT", ra.cerberus.decision.reasons.join(","));
  assert.equal(ra.cerberus.signature_status.receipt, "SIGNED");

  const cfg = (() => {
    const dir = keyDir();
    const f = join(dir, "k.pem");
    writeFileSync(f, p.publicKeyPem());
    return resolveSigningConfig({ FACTORY_SIGNING_PUBLIC_KEY_FILE: f, FACTORY_SIGNING_KEY_ID: p.key_id, FACTORY_SIGNING_PROVIDER: p.name });
  })();
  assert.equal(cfg.status, "CONFIGURED");
  const b = setup({ receiptSigning: cfg.policy });
  const rb = await b.stand.submit(b.stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "rsig-nosigner" }));
  assert.equal(rb.final_decision, "DENY");
  assert.ok(rb.cerberus.decision.reasons.includes(SIGNING_KEY_UNAVAILABLE), rb.cerberus.decision.reasons.join(","));
});
