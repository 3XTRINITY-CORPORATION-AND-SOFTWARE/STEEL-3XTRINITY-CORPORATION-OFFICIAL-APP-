import test from "node:test";
import assert from "node:assert/strict";
import { ReplayGuard } from "../../kratt/evidence.ts";
import { cerberusDecide } from "../cerberus-gate.ts";
import { assembleRun } from "../rastik-attacks.ts";
import { toeparaVerify } from "../toepara.ts";
import { DEFAULT_TRUST_TIMEOUT_MS, resolveTrustGate, stubPolicyTrustGate, type AsyncTrustGate, type TrustGateRequest } from "../trust-gate.ts";
import { envelope } from "./fixtures.ts";
import { REPO, ROOT, genuine } from "./helpers.ts";

const req = (): TrustGateRequest => ({ task_id: "t-001", repository: REPO, action: "hash-files", envelope: envelope({ forbidden_actions: ["merge", "deploy"] }), host_repository: REPO });
const gate = (evaluate: AsyncTrustGate["evaluate"]): AsyncTrustGate => ({ name: "test-gate", evaluate });

test("TRUST GATE (async): only the exact strings AUTHORIZED/DENIED are accepted; AUTHORIZED passes", async () => {
  assert.deepEqual(await resolveTrustGate(gate(async () => "AUTHORIZED"), req(), 50), { verdict: "AUTHORIZED", reasons: [] });
  assert.deepEqual(await resolveTrustGate(gate(async () => "DENIED"), req(), 50), { verdict: "DENIED", reasons: ["trust-gate:denied"] });
});

test("TRUST GATE (async): malformed / unknown verdicts are DENIED", async () => {
  for (const bad of ["authorized", " AUTHORIZED", "AUTHORIZED\n", "ADMITTED", "PROCEED", "OK", "", null, undefined, true, 1, ["AUTHORIZED"], { verdict: "AUTHORIZED" }, { toString: () => "AUTHORIZED" }]) {
    const r = await resolveTrustGate(gate(async () => bad), req(), 50);
    assert.equal(r.verdict, "DENIED", JSON.stringify(bad));
    assert.deepEqual(r.reasons, ["trust-gate:malformed-verdict"]);
  }
});

test("TRUST GATE (async): a rejecting gate and a synchronously throwing gate are DENIED", async () => {
  assert.deepEqual((await resolveTrustGate(gate(() => Promise.reject(new Error("down"))), req(), 50)).reasons, ["trust-gate:threw"]);
  assert.deepEqual((await resolveTrustGate(gate(() => { throw new Error("boom"); }), req(), 50)).reasons, ["trust-gate:threw"]);
});

test("TRUST GATE (async): a gate that never answers is DENIED on timeout (fake timers), and a late answer or late rejection changes nothing", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let lateResolve: (v: unknown) => void = () => undefined;
  const p = resolveTrustGate(gate(() => new Promise((r) => (lateResolve = r))), req(), 1500);
  t.mock.timers.tick(1499);
  t.mock.timers.tick(1);
  const r = await p;
  assert.deepEqual(r, { verdict: "DENIED", reasons: ["trust-gate:timeout"] });
  lateResolve("AUTHORIZED");
  await Promise.resolve();
  const q = resolveTrustGate(gate(() => new Promise((_, rej) => setTimeout(() => rej(new Error("late")), 5000))), req(), 100);
  t.mock.timers.tick(100);
  assert.deepEqual((await q).reasons, ["trust-gate:timeout"]);
  t.mock.timers.tick(5000); // late rejection must not surface as an unhandled rejection
});

test("TRUST GATE (async): real short timeout also denies; a fast answer does not wait for the timer", async () => {
  const slow = await resolveTrustGate(gate(() => new Promise((r) => setTimeout(() => r("AUTHORIZED"), 200))), req(), 20);
  assert.deepEqual(slow.reasons, ["trust-gate:timeout"]);
  const t0 = Date.now();
  assert.equal((await resolveTrustGate(gate(async () => "AUTHORIZED"), req(), 30_000)).verdict, "AUTHORIZED");
  assert.ok(Date.now() - t0 < 1000, "timer cleared / not awaited");
});

test("TRUST GATE (async): the timeout timer is always cleared (answer, rejection and timeout paths) so nothing keeps the process alive", async (t) => {
  const clear = t.mock.method(globalThis, "clearTimeout");
  await resolveTrustGate(gate(async () => "AUTHORIZED"), req(), 30_000);
  await resolveTrustGate(gate(() => Promise.reject(new Error("x"))), req(), 30_000);
  await resolveTrustGate(gate(() => new Promise(() => undefined)), req(), 10);
  assert.equal(clear.mock.callCount(), 3);
});

test("TRUST GATE (async): invalid timeout values deny without calling the gate", async () => {
  let calls = 0;
  const g = gate(async () => (calls++, "AUTHORIZED"));
  for (const bad of [0, -1, 1.5, Number.NaN, Infinity, 60_001, "50" as never]) assert.deepEqual((await resolveTrustGate(g, req(), bad)).reasons, ["trust-gate:invalid-timeout"]);
  assert.equal(calls, 0);
  assert.equal(DEFAULT_TRUST_TIMEOUT_MS, 2000);
});

test("TRUST GATE (stub): the stub is a local policy - lax envelope (merge not forbidden) is DENIED, strict envelope AUTHORIZED", async () => {
  assert.equal(await stubPolicyTrustGate.evaluate(req()), "AUTHORIZED");
  assert.equal(await stubPolicyTrustGate.evaluate({ ...req(), envelope: envelope({ forbidden_actions: [] }) }), "DENIED");
  assert.equal(await stubPolicyTrustGate.evaluate({ ...req(), action: null }), "DENIED");
});

// ---- wired into CERBERUS ----
async function inputs() {
  const { env, receipt } = await genuine();
  const need = { ...env, required_evidence: ["source_digests", "rastik_findings"] };
  const run = assembleRun(receipt, [{ attack_id: "invalid-input/null-receipt", class: "invalid-input", agent_id: "SERPENT-052", case_id: "null-receipt", hypothesis: "h", outcome: "REPELLED", reproduced: null }], [], { probes: 0, cases_executed: 0, confirmed_findings: 0, probe_errors: 0, evidence_digest: null });
  const ctx = { root: ROOT, repository: REPO, rerun: new Map() };
  const toepara = await toeparaVerify(need, receipt, run, ctx);
  return { i: { envelope: need, receipt, rastik: run, toepara }, ctx };
}

test("TRUST GATE in CERBERUS: authorizing gate => ADMIT; timeout / throw / malformed verdict / explicit DENIED => DENY with the reason recorded", async () => {
  const { i, ctx } = await inputs();
  const ok = await cerberusDecide(i, { ...ctx, guard: new ReplayGuard(), trustGate: gate(async () => "AUTHORIZED") });
  assert.equal(ok.decision.decision, "ADMIT", ok.decision.reasons.join(","));
  const cases: [string, AsyncTrustGate][] = [
    ["trust-gate:timeout", gate(() => new Promise(() => undefined))],
    ["trust-gate:threw", gate(() => Promise.reject(new Error("x")))],
    ["trust-gate:malformed-verdict", gate(async () => "ADMITTED")],
    ["trust-gate:denied", gate(async () => "DENIED")],
  ];
  for (const [reason, g] of cases) {
    const d = await cerberusDecide(i, { ...ctx, guard: new ReplayGuard(), trustGate: g, trustGateTimeoutMs: 30 });
    assert.equal(d.decision.decision, "DENY", reason);
    assert.ok(d.adapter_reasons.includes(reason), `${reason} in ${d.adapter_reasons.join(",")}`);
  }
});

test("TRUST GATE in CERBERUS: an external gate saying AUTHORIZED cannot override local policy (merge not forbidden => DENY)", async () => {
  const { i, ctx } = await inputs();
  const lax = { ...i.envelope, forbidden_actions: ["network"] };
  const t = await toeparaVerify(lax, i.receipt, i.rastik, ctx);
  const d = await cerberusDecide({ ...i, envelope: lax, toepara: t }, { ...ctx, guard: new ReplayGuard(), trustGate: gate(async () => "AUTHORIZED") });
  assert.equal(d.decision.decision, "DENY");
  assert.ok(d.adapter_reasons.includes("policy:merge-not-forbidden"));
});
