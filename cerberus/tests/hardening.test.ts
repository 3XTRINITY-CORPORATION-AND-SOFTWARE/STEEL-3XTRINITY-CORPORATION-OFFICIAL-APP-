import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decide, verifyReceipt, RECEIPT_VERSION } from "../core/decide.ts";
import { sha256Hex } from "../artifact-trust/artifact-trust.ts";
import { decideWithAdapters, stubAdapter } from "../integrations/verdict-adapters.ts";

const content = "artifact-bytes";
const valid = () => ({
  action: "recover",
  toepara: "ADMITTED",
  trustGate: "AUTHORIZED",
  artifact: { name: "a.bin", content, sha256: sha256Hex(content) },
});
const cyc: Record<string, unknown> = { ...valid() };
cyc.self = cyc;
const admit = { toepara: stubAdapter("toepara", "ADMITTED"), trustGate: stubAdapter("gate", "AUTHORIZED") };

describe("INPUT stage: malformed / hostile input => FAIL_CLOSED, never throws", () => {
  const proxyThrows = new Proxy({}, { getOwnPropertyDescriptor() { throw new Error("boom"); }, getPrototypeOf() { throw new Error("boom"); } });
  const cases: Array<[string, unknown]> = [
    ["undefined", undefined], ["null", null], ["string", "ADMITTED"], ["number", 1], ["bigint", 1n],
    ["symbol", Symbol("x")], ["function", () => valid()], ["array", [valid()]], ["empty object", {}],
    ["throwing proxy", proxyThrows],
    ["class instance", new (class X { action = "recover"; toepara = "ADMITTED"; trustGate = "AUTHORIZED"; })()],
  ];
  for (const [name, input] of cases) {
    it(name, () => {
      let r;
      assert.doesNotThrow(() => { r = decide(input); });
      assert.equal(r!.decision, "FAIL_CLOSED");
      assert.ok(r!.reasons.length > 0);
      assert.equal(verifyReceipt(r), true);
    });
  }
  it("BigInt / cyclic values in decision fields deny instead of throwing", () => {
    for (const bad of [1n, {}, [], () => 1, Symbol("s"), NaN, Infinity, true]) {
      const r = decide({ ...valid(), action: bad, toepara: bad, trustGate: bad });
      assert.equal(r.decision, "FAIL_CLOSED");
    }
  });
});

describe("snapshot semantics: decision and digest use the same bytes", () => {
  it("accessor properties are rejected (no per-read value changes)", () => {
    let reads = 0;
    const evil = { ...valid() };
    Object.defineProperty(evil, "toepara", { enumerable: true, get() { return reads++ === 0 ? "ADMITTED" : "REJECTED"; } });
    const r = decide(evil);
    assert.equal(r.decision, "FAIL_CLOSED");
    assert.deepEqual(r.reasons, ["input-accessor-property"]);
    assert.equal(reads, 0, "getter must never be invoked");
  });
  it("inherited verdicts are ignored (prototype-supplied ADMITTED does not count)", () => {
    const proto = { toepara: "ADMITTED", trustGate: "AUTHORIZED" };
    const sneaky = Object.assign(Object.create(proto), { action: "recover", artifact: valid().artifact });
    // non-plain prototype => rejected outright
    assert.equal(decide(sneaky).decision, "FAIL_CLOSED");
    assert.deepEqual(decide(sneaky).reasons, ["input-not-plain-object"]);
  });
  it("polluted Object.prototype cannot supply verdicts", () => {
    (Object.prototype as Record<string, unknown>).toepara = "ADMITTED";
    (Object.prototype as Record<string, unknown>).trustGate = "AUTHORIZED";
    try {
      const { toepara: _t, trustGate: _g, ...rest } = valid();
      const r = decide(rest);
      assert.equal(r.decision, "FAIL_CLOSED");
      assert.deepEqual(r.reasons, ["toepara-not-admitted", "trust-gate-not-authorized"]);
    } finally {
      delete (Object.prototype as Record<string, unknown>).toepara;
      delete (Object.prototype as Record<string, unknown>).trustGate;
    }
  });
  it("null-prototype plain objects are accepted and equal ordinary ones", () => {
    const a = Object.assign(Object.create(null), valid());
    assert.deepEqual(decide(a), decide(valid()));
  });
  it("cyclic / BigInt unknown extra keys are never read and do not change the receipt", () => {
    assert.deepEqual(decide({ ...valid(), self: cyc, big: 1n }), decide(valid()));
  });
  it("extra unknown keys do not change the receipt", () => {
    assert.deepEqual(decide({ ...valid(), note: "x", artifact: { ...valid().artifact, extra: 1 } }), decide(valid()));
  });
});

describe("verdict strictness (unknown verdict => deny)", () => {
  for (const v of ["admitted", "Admitted", " ADMITTED", "ADMITTED ", "ADMITTED\n", "ADMITTED\u0000", "AUTHORIZED", "", "UNKNOWN", "PENDING", "true", "1", null, undefined, 1, true, {}, ["ADMITTED"]]) {
    it(`toepara=${JSON.stringify(v) ?? String(v)}`, { skip: v === "ADMITTED" }, () => {
      assert.deepEqual(decide({ ...valid(), toepara: v }).reasons, ["toepara-not-admitted"]);
    });
    it(`trustGate=${JSON.stringify(v) ?? String(v)}`, { skip: v === "AUTHORIZED" }, () => {
      assert.deepEqual(decide({ ...valid(), trustGate: v }).reasons, ["trust-gate-not-authorized"]);
    });
  }
  it("action case/whitespace variants and non-strings are denied", () => {
    for (const a of ["Recover", "RECOVER", "recover ", " recover", "recover\n", "Merge", "deploy", null, undefined, 1, {}, ["recover"]]) {
      assert.deepEqual(decide({ ...valid(), action: a }).reasons, ["policy-action-denied"]);
    }
  });
  it("all allowed actions proceed", () => {
    for (const action of ["detect", "recover", "recommend"]) assert.equal(decide({ ...valid(), action }).decision, "PROCEED");
  });
});

describe("artifact trust boundaries", () => {
  const withArtifact = (artifact: unknown) => decide({ ...valid(), artifact });
  it("non-object artifacts", () => {
    for (const a of [undefined, null, "x", 1, [], () => 1]) assert.deepEqual(withArtifact(a).reasons, ["artifact-missing"]);
  });
  it("name/content/digest field validation", () => {
    const base = valid().artifact;
    assert.deepEqual(withArtifact({ ...base, name: "" }).reasons, ["artifact-name-invalid"]);
    assert.deepEqual(withArtifact({ ...base, name: 5 }).reasons, ["artifact-name-invalid"]);
    assert.deepEqual(withArtifact({ ...base, content: 5 }).reasons, ["artifact-content-invalid"]);
    for (const sha256 of [undefined, 5, "", base.sha256.toUpperCase(), base.sha256.slice(1), base.sha256 + "0", ` ${base.sha256}`, base.sha256 + "\n"]) {
      assert.deepEqual(withArtifact({ ...base, sha256 }).reasons, ["artifact-digest-malformed"], String(sha256));
    }
  });
  it("empty content is valid only with the real empty-string digest", () => {
    assert.equal(withArtifact({ name: "e", content: "", sha256: sha256Hex("") }).decision, "PROCEED");
    assert.deepEqual(withArtifact({ name: "e", content: "", sha256: sha256Hex("x") }).reasons, ["artifact-digest-mismatch"]);
  });
  it("one-character content change flips to mismatch; unicode is hashed as UTF-8", () => {
    assert.equal(withArtifact({ name: "u", content: "töepära", sha256: sha256Hex("töepära") }).decision, "PROCEED");
    assert.deepEqual(withArtifact({ name: "u", content: "toepära", sha256: sha256Hex("töepära") }).reasons, ["artifact-digest-mismatch"]);
  });
});

describe("no bypass: every stage independently blocks, all failures are reported", () => {
  it("each single failing stage => FAIL_CLOSED with exactly that stage FAIL", () => {
    const base = valid();
    const mutate = {
      policy: { ...base, action: "merge" },
      toepara: { ...base, toepara: "NO" },
      trustGate: { ...base, trustGate: "NO" },
      artifactTrust: { ...base, artifact: { ...base.artifact, content: "z" } },
    } as const;
    for (const [stage, input] of Object.entries(mutate)) {
      const r = decide(input);
      assert.equal(r.decision, "FAIL_CLOSED", stage);
      for (const [s, v] of Object.entries(r.stages)) assert.equal(v, s === stage ? "FAIL" : "PASS", `${stage}/${s}`);
    }
  });
  it("all stages failing lists all reasons in pipeline order", () => {
    assert.deepEqual(decide({ action: "merge", toepara: "x", trustGate: "y", artifact: null }).reasons, [
      "policy-action-denied", "toepara-not-admitted", "trust-gate-not-authorized", "artifact-missing",
    ]);
  });
  it("valid input passes every stage", () => {
    const r = decide(valid());
    assert.deepEqual(r.stages, { input: "PASS", policy: "PASS", toepara: "PASS", trustGate: "PASS", artifactTrust: "PASS" });
  });
});

describe("recovery receipt: determinism and evidence identification", () => {
  it("is byte-identical across repeated calls and key orders", () => {
    const a = valid();
    const b = { artifact: { sha256: a.artifact.sha256, content, name: "a.bin" }, trustGate: a.trustGate, toepara: a.toepara, action: a.action };
    assert.equal(JSON.stringify(decide(a)), JSON.stringify(decide(b)));
    assert.equal(JSON.stringify(decide(a)), JSON.stringify(decide(a)));
  });
  it("identifies the decision evidence", () => {
    const r = decide(valid());
    assert.equal(r.version, RECEIPT_VERSION);
    assert.equal(r.verdictSource, "caller-supplied");
    assert.deepEqual(r.evidence, {
      action: "recover", toepara: "ADMITTED", trustGate: "AUTHORIZED",
      artifact: { name: "a.bin", declaredSha256: sha256Hex(content), computedSha256: sha256Hex(content) },
    });
    assert.match(r.inputDigest, /^[0-9a-f]{64}$/);
    assert.match(r.receiptDigest, /^[0-9a-f]{64}$/);
  });
  it("tamper evidence shows declared != computed digest", () => {
    const v = valid(); v.artifact.content = "tampered";
    const r = decide(v);
    assert.notEqual(r.evidence.artifact!.declaredSha256, r.evidence.artifact!.computedSha256);
  });
  it("any change to any decision field changes inputDigest and receiptDigest", () => {
    const base = decide(valid());
    const variants = [
      { ...valid(), action: "detect" }, { ...valid(), toepara: "x" }, { ...valid(), trustGate: "x" },
      { ...valid(), artifact: { ...valid().artifact, name: "b.bin" } },
      { ...valid(), artifact: { ...valid().artifact, content: "other" } },
    ];
    const seen = new Set([base.inputDigest]);
    for (const v of variants) {
      const r = decide(v);
      assert.notEqual(r.inputDigest, base.inputDigest);
      assert.notEqual(r.receiptDigest, base.receiptDigest);
      seen.add(r.inputDigest);
    }
    assert.equal(seen.size, variants.length + 1);
  });
  it("verifyReceipt detects post-hoc edits", () => {
    const r = decide({ ...valid(), toepara: "NO" });
    assert.equal(verifyReceipt(r), true);
    assert.equal(verifyReceipt({ ...r, decision: "PROCEED" }), false);
    assert.equal(verifyReceipt({ ...r, reasons: [] }), false);
    assert.equal(verifyReceipt({ ...r, stages: { ...r.stages, toepara: "PASS" } }), false);
    assert.equal(verifyReceipt(null), false);
    assert.equal(verifyReceipt("x"), false);
    assert.equal(verifyReceipt({}), false);
  });
  it("malformed-input receipts are deterministic and sealed", () => {
    assert.deepEqual(decide(null), decide(undefined));
    assert.equal(verifyReceipt(decide(null)), true);
    assert.deepEqual(decide(null).stages, { input: "FAIL", policy: "NOT_EVALUATED", toepara: "NOT_EVALUATED", trustGate: "NOT_EVALUATED", artifactTrust: "NOT_EVALUATED" });
  });
});

describe("adapter seam (STUBS ONLY — not a real TÖEPÄRA / Trust Gate integration)", () => {
  it("admits when both stubs return the exact verdicts; source is recorded", () => {
    const r = decideWithAdapters(valid(), admit);
    assert.equal(r.decision, "PROCEED");
    assert.equal(r.verdictSource, "adapter");
  });
  it("caller-supplied verdict fields are ignored in adapter mode", () => {
    const r = decideWithAdapters(valid(), { toepara: stubAdapter("t", "REJECTED"), trustGate: admit.trustGate });
    assert.deepEqual(r.reasons, ["toepara-not-admitted"]);
    const { toepara: _t, trustGate: _g, ...noVerdicts } = valid();
    assert.equal(decideWithAdapters(noVerdicts, admit).decision, "PROCEED");
  });
  it("adapters never see the caller's verdict fields", () => {
    let seen: unknown;
    const spy = { name: "spy", verdict: (e: unknown) => { seen = e; return "ADMITTED"; } };
    decideWithAdapters(valid(), { toepara: spy, trustGate: admit.trustGate });
    assert.deepEqual(seen, { action: "recover", toepara: null, trustGate: null, artifact: { name: "a.bin", content, sha256: sha256Hex(content) } });
  });
  it("throwing / non-string / missing adapters => FAIL_CLOSED, never an exception", () => {
    const thrower = { name: "t", verdict: () => { throw new Error("down"); } };
    for (const bad of [thrower, stubAdapter("n", undefined), stubAdapter("n", 1), stubAdapter("n", null), undefined as never, {} as never]) {
      let r;
      assert.doesNotThrow(() => { r = decideWithAdapters(valid(), { toepara: bad, trustGate: admit.trustGate }); });
      assert.equal(r!.decision, "FAIL_CLOSED");
      assert.deepEqual(r!.reasons, ["toepara-not-admitted"]);
      assert.doesNotThrow(() => { r = decideWithAdapters(valid(), { toepara: admit.toepara, trustGate: bad }); });
      assert.deepEqual(r!.reasons, ["trust-gate-not-authorized"]);
    }
    assert.equal(decideWithAdapters(valid(), undefined as never).decision, "FAIL_CLOSED");
  });
  it("policy and artifact trust still apply in adapter mode", () => {
    assert.deepEqual(decideWithAdapters({ ...valid(), action: "deploy" }, admit).reasons, ["policy-action-denied"]);
    const v = valid(); v.artifact.content = "t";
    assert.deepEqual(decideWithAdapters(v, admit).reasons, ["artifact-digest-mismatch"]);
    assert.equal(decideWithAdapters(null, admit).decision, "FAIL_CLOSED");
  });
  it("same input + same adapters => same receipt", () => {
    assert.deepEqual(decideWithAdapters(valid(), admit), decideWithAdapters(valid(), admit));
  });
});

// ---------------------------------------------------------------------------------------------------------------------
// ASYNC adapter seam (F-P1-TG-002): timeout / rejection / sync throw / malformed / non-exact => FAIL_CLOSED, never PROCEED
// ---------------------------------------------------------------------------------------------------------------------
import { DEFAULT_ADAPTER_TIMEOUT_MS, decideWithAdaptersAsync, type AsyncVerdictAdapter } from "../integrations/verdict-adapters.ts";

const asyncOf = (name: string, f: (signal: AbortSignal) => unknown): AsyncVerdictAdapter => ({ name, verdict: (_e, signal) => f(signal) });
const later = <T>(ms: number, v: T) => new Promise<T>((res) => setTimeout(() => res(v), ms));
const asyncAdmit = { toepara: asyncOf("t", async () => "ADMITTED"), trustGate: asyncOf("g", async () => "AUTHORIZED") };

describe("async adapter seam: deny on timeout / throw / rejection / malformed (STUB adapters only)", () => {
  it("exact verdicts from async adapters => PROCEED; the sync stubAdapter is still a valid implementation", async () => {
    const a = await decideWithAdaptersAsync(valid(), asyncAdmit);
    assert.equal(a.receipt.decision, "PROCEED");
    assert.deepEqual(a.outcomes, { toepara: "ok", trustGate: "ok" });
    assert.equal(verifyReceipt(a.receipt), true);
    assert.equal((await decideWithAdaptersAsync(valid(), admit)).receipt.decision, "PROCEED");
    assert.equal(DEFAULT_ADAPTER_TIMEOUT_MS, 2000);
  });
  it("a hanging Trust Gate => FAIL_CLOSED (trust-gate-not-authorized, outcome timeout) within the deadline, and the adapter is told to abort", async () => {
    let signalSeen: AbortSignal | null = null;
    const t0 = Date.now();
    const a = await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("hang", (s) => { signalSeen = s; return new Promise(() => {}); }) }, { timeoutMs: 50 });
    assert.equal(a.receipt.decision, "FAIL_CLOSED");
    assert.deepEqual(a.receipt.reasons, ["trust-gate-not-authorized"]);
    assert.equal(a.outcomes.trustGate, "timeout");
    assert.ok(Date.now() - t0 < 1000, "decided at the deadline, not when the adapter feels like it");
    assert.equal((signalSeen as AbortSignal | null)?.aborted, true);
  });
  it("slow-then-AUTHORIZED AFTER the deadline is still FAIL_CLOSED, and the late answer changes nothing afterwards", async () => {
    const a = await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("slow", () => later(150, "AUTHORIZED")) }, { timeoutMs: 40 });
    assert.equal(a.receipt.decision, "FAIL_CLOSED");
    assert.equal(a.outcomes.trustGate, "timeout");
    const frozen = JSON.stringify(a);
    await later(200, null);
    assert.equal(JSON.stringify(a), frozen, "the late resolution did not mutate the decision");
    assert.equal(verifyReceipt(a.receipt), true);
    // control: the same slow adapter WITHIN the deadline proceeds (so the deadline, not the slowness, is what denies)
    assert.equal((await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("slow", () => later(10, "AUTHORIZED")) }, { timeoutMs: 1000 })).receipt.decision, "PROCEED");
  });
  it("sync throw and async rejection => FAIL_CLOSED with the outcome recorded; never an exception", async () => {
    const thrown = await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("t", () => { throw new Error("down"); }) });
    assert.equal(thrown.receipt.decision, "FAIL_CLOSED");
    assert.equal(thrown.outcomes.trustGate, "threw");
    const rejected = await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("r", async () => { throw new Error("down"); }) });
    assert.equal(rejected.receipt.decision, "FAIL_CLOSED");
    assert.equal(rejected.outcomes.trustGate, "rejected");
    const tRej = await decideWithAdaptersAsync(valid(), { toepara: asyncOf("r", () => Promise.reject(new Error("x"))), trustGate: admit.trustGate });
    assert.deepEqual(tRej.receipt.reasons, ["toepara-not-admitted"]);
    assert.equal(tRej.outcomes.toepara, "rejected");
  });
  it("malformed responses (non-strings, boxed strings, objects, arrays) => FAIL_CLOSED outcome malformed; non-exact strings => FAIL_CLOSED", async () => {
    for (const bad of [1, null, undefined, true, { verdict: "AUTHORIZED" }, ["AUTHORIZED"], new String("AUTHORIZED"), Symbol("AUTHORIZED"), 1n]) {
      const a = await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("m", async () => bad) });
      assert.equal(a.receipt.decision, "FAIL_CLOSED", String(bad?.toString?.() ?? bad));
      assert.equal(a.outcomes.trustGate, "malformed");
    }
    for (const near of ["authorized", " AUTHORIZED", "AUTHORIZED\n", "ADMITTED", "AUTHORIZED\u200b", ""]) {
      const a = await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("n", async () => near) });
      assert.equal(a.receipt.decision, "FAIL_CLOSED", JSON.stringify(near));
    }
  });
  it("hostile thenables (throwing then getter, then that throws after resolving, resolve called twice) => never PROCEED on a non-exact verdict, never throw", async () => {
    const getterThrows = { get then() { throw new Error("boom"); } };
    const a = await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("h", () => getterThrows) });
    assert.equal(a.receipt.decision, "FAIL_CLOSED");
    const flip = { then(res: (v: unknown) => void) { res("DENIED"); res("AUTHORIZED"); } };
    assert.equal((await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("f", () => flip) })).receipt.decision, "FAIL_CLOSED", "first settlement wins");
    const thrAfter = { then(res: (v: unknown) => void) { res("DENIED"); throw new Error("late"); } };
    assert.equal((await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("x", () => thrAfter) })).receipt.decision, "FAIL_CLOSED");
  });
  it("invalid timeouts => FAIL_CLOSED without calling any adapter", async () => {
    let called = 0;
    const counting = { toepara: asyncOf("t", async () => { called++; return "ADMITTED"; }), trustGate: asyncOf("g", async () => { called++; return "AUTHORIZED"; }) };
    for (const timeoutMs of [0, -1, 1.5, Number.NaN, Infinity, 60_001, "50" as never]) {
      const a = await decideWithAdaptersAsync(valid(), counting, { timeoutMs });
      assert.equal(a.receipt.decision, "FAIL_CLOSED", String(timeoutMs));
      assert.deepEqual(a.outcomes, { toepara: "invalid-timeout", trustGate: "invalid-timeout" });
    }
    assert.equal(called, 0);
  });
  it("missing adapters, undefined adapters and invalid input never throw and never PROCEED; caller verdict fields are ignored and blanked", async () => {
    assert.equal((await decideWithAdaptersAsync(valid(), undefined as never)).receipt.decision, "FAIL_CLOSED");
    const m = await decideWithAdaptersAsync(valid(), { toepara: admit.toepara } as never);
    assert.equal(m.receipt.decision, "FAIL_CLOSED");
    assert.equal(m.outcomes.trustGate, "missing");
    assert.equal((await decideWithAdaptersAsync(null, asyncAdmit)).receipt.decision, "FAIL_CLOSED");
    let seen: unknown;
    await decideWithAdaptersAsync(valid(), { toepara: asyncOf("spy", async () => "ADMITTED"), trustGate: { name: "spy", verdict: async (e) => { seen = e; return "AUTHORIZED"; } } });
    assert.deepEqual(seen, { action: "recover", toepara: null, trustGate: null, artifact: { name: "a.bin", content, sha256: sha256Hex(content) } });
    const r = await decideWithAdaptersAsync({ ...valid(), trustGate: "AUTHORIZED" }, { toepara: admit.toepara, trustGate: asyncOf("d", async () => "DENIED") });
    assert.equal(r.receipt.decision, "FAIL_CLOSED", "a caller-typed AUTHORIZED is ignored");
  });
  it("timers are always cleared (fast answers leave no pending deadline timer behind)", async () => {
    const timers = () => process.getActiveResourcesInfo().filter((x) => x === "Timeout").length;
    const before = timers();
    for (let i = 0; i < 5; i++) await decideWithAdaptersAsync(valid(), asyncAdmit, { timeoutMs: 60_000 });
    await decideWithAdaptersAsync(valid(), { toepara: admit.toepara, trustGate: asyncOf("t", () => { throw new Error("x"); }) }, { timeoutMs: 60_000 });
    assert.equal(timers(), before);
  });
});
