import test from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt } from "../../cerberus/core/decide.ts";
import { ATTACK_CLASSES, CAPABILITIES, HANDLER_KEYS } from "../capabilities.ts";
import { selfCheckFinalReceipt, type ClosedLoopReceipt } from "../loop.ts";
import { validateActionReceipt, validateCerberusDecision, validateEvidenceBundle, validateToeparaVerdict } from "../protocol/types.ts";
import { countRegistry } from "../registry.ts";
import { realAttackTarget, type AttackTarget } from "../rastik-attacks.ts";
import { REPO, ROOT, SCOPE, setup } from "./helpers.ts";
import { headSha } from "../git.ts";

const WALK = "SLEEP->READY,READY->ACTIVE,ACTIVE->VERIFY,VERIFY->DONE,DONE->SLEEP";
const walk = (r: ClosedLoopReceipt, stage: number) => r.stages[stage]?.transitions.map((t) => `${t.from}->${t.to}`).join(",");

test("CLOSED LOOP (hash-files, real files at the real HEAD): envelope -> KRATT -> RÄSTIK -> TÖEPÄRA -> CERBERUS = ADMIT, with real worker transitions", async () => {
  const { stand, dispatcher } = setup({ runProbes: true });
  const env = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "e2e-hash" });
  const r = await stand.submit(env);

  assert.equal(r.caller.real_goliath, false, "the caller is a stand-in");
  assert.equal(r.final_decision, "ADMIT", JSON.stringify(r.cerberus.decision.reasons));
  assert.deepEqual(selfCheckFinalReceipt(r), []);

  // KRATT: real action, receipt carries the required fields and is UNVERIFIED
  const a = r.action_receipt!;
  assert.ok(validateActionReceipt(a).ok);
  assert.equal(a.task_id, "e2e-hash");
  assert.equal(a.repository, REPO);
  assert.equal(a.base_sha, headSha(ROOT));
  assert.equal(a.action, "hash-files");
  assert.deepEqual(a.scope, SCOPE);
  assert.equal(a.verification_state, "UNVERIFIED");
  assert.equal(a.result.ok, true);
  assert.match(a.timestamp, /^\d{4}-\d{2}-\d{2}T/);

  // RÄSTIK: attacked that exact receipt, real cases, nothing confirmed
  assert.ok(r.rastik);
  assert.equal(r.rastik.target_receipt_digest, r.toepara?.bundle?.action_receipt_digest);
  assert.ok(r.rastik.probe.cases_executed >= 100, "existing rastik probes ran for the cerberus scope");
  assert.equal(r.rastik.attacks.length >= 38, true);
  assert.deepEqual(r.rastik.findings, []);
  assert.ok(r.rastik.attacks.every((x) => x.outcome === "REPELLED"));
  assert.deepEqual([...new Set(r.rastik.attacks.map((x) => x.class))].sort(), [...ATTACK_CLASSES].sort());

  // TÖEPÄRA + CERBERUS
  assert.ok(validateToeparaVerdict(r.toepara!.verdict).ok);
  assert.equal(r.toepara?.verdict.verdict, "VERIFIED");
  assert.ok(validateEvidenceBundle(r.toepara!.bundle).ok);
  assert.ok(validateCerberusDecision(r.cerberus.decision).ok);
  assert.ok(verifyReceipt(r.cerberus.cerberus_receipt));
  assert.equal(r.cerberus.cerberus_receipt.decision, "PROCEED");

  // worker transitions: each stage walked the full legal machine, and everything returned to SLEEP
  const names = r.stages.map((s) => `${s.stage}:${s.agent_id}`);
  assert.deepEqual(names.slice(0, 2), ["KRATT:FORGE-026", "RASTIK:SERPENT-051"]);
  assert.deepEqual(names.slice(-2), ["TOEPARA:CITADEL-101", "CERBERUS:CITADEL-111"]);
  for (const s of r.stages) {
    assert.equal(s.outcome, "DONE", `${s.stage}/${s.task_id}`);
    assert.equal(s.transitions.map((t) => `${t.from}->${t.to}`).join(","), WALK, s.task_id);
    assert.ok(s.transitions.every((t) => t.accepted));
  }
  assert.equal(r.stages.length, 2 + ATTACK_CLASSES.length + 2);
  const c = dispatcher.counts();
  assert.equal(c.executed_tasks, r.stages.length);
  assert.equal(c.failed_tasks, 0);
  assert.equal(c.active, 0);
  assert.equal(c.sleeping, 150);
  assert.deepEqual(dispatcher.watchdog(), []);
  assert.equal(c.available, Object.keys(CAPABILITIES).length);
  assert.equal(walk(r, 0), WALK);
});

test("CLOSED LOOP (run-test): a real node:test file is executed by KRATT, re-executed by TÖEPÄRA, and ADMITTED", async () => {
  const { stand } = setup();
  const env = stand.issueEnvelope({ action: "run-test", scope: ["cerberus/tests/decide.test.ts"], branch: "t", task_id: "e2e-test" });
  const r = await stand.submit(env);
  assert.equal(r.final_decision, "ADMIT", JSON.stringify([r.cerberus.decision.reasons, r.toepara?.verdict.reasons]));
  assert.equal(r.action_receipt?.action, "run-test");
  assert.ok((r.action_receipt?.result.checks.pass ?? 0) >= 1);
  assert.equal(r.toepara?.bundle?.test_evidence?.reexecuted, true);
  assert.deepEqual(selfCheckFinalReceipt(r), []);
});

test("NEGATIVE: stale base_sha => KRATT BLOCKED -> SLEEP, no receipt, final DENY", async () => {
  const { stand, dispatcher } = setup();
  const env = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "neg-stale", base_sha: "1".repeat(40) });
  const r = await stand.submit(env);
  assert.equal(r.final_decision, "DENY");
  assert.equal(r.action_receipt, null);
  assert.equal(r.stages[0]?.outcome, "BLOCKED");
  assert.equal(r.stages[0]?.note, "stale-base-sha");
  assert.equal(walk(r, 0), "SLEEP->READY,READY->ACTIVE,ACTIVE->BLOCKED,BLOCKED->SLEEP");
  assert.equal(dispatcher.worker("FORGE-026").failed_tasks, 1);
  assert.equal(dispatcher.worker("FORGE-026").state, "SLEEP");
  assert.equal(r.cerberus.cerberus_receipt.decision, "FAIL_CLOSED");
});

test("NEGATIVE: wrong repository, duplicate task, incompatible protocol, scope escape, unavailable capability => DENY", async () => {
  const { stand, deps, dispatcher } = setup();
  const good = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "neg-1" });
  const wrongRepo = await stand.submit({ ...good, task_id: "neg-repo", repository: "someone/else" });
  assert.equal(wrongRepo.final_decision, "DENY");
  assert.equal(wrongRepo.stages[0]?.note, "repository-mismatch");

  const first = await stand.submit(good);
  assert.equal(first.final_decision, "ADMIT");
  const dup = await stand.submit(good);
  assert.equal(dup.final_decision, "DENY");
  assert.ok(dup.cerberus.decision.reasons.includes("duplicate-task"));

  const v2 = await stand.submit({ ...good, task_id: "neg-v2", protocol_version: 2 });
  assert.equal(v2.final_decision, "DENY");
  assert.ok(v2.cerberus.decision.reasons.some((r) => r.includes("protocol-incompatible-major:2")));

  const escape = await stand.submit({ ...good, task_id: "neg-escape", scope: ["../../etc/passwd"] });
  assert.equal(escape.final_decision, "DENY");

  const noCap = await stand.submit({ ...good, task_id: "neg-nocap", agent_id: "FORGE-027" });
  assert.equal(noCap.final_decision, "DENY");
  assert.ok(noCap.cerberus.decision.reasons.some((r) => r.startsWith("capability-not-available")));
  assert.equal(dispatcher.worker("FORGE-027").completed_tasks, 0);
  void deps;
});

test("NEGATIVE: a truthful failing action (missing file) is executed but DENIED - failure never becomes ADMIT", async () => {
  const { stand } = setup();
  const env = stand.issueEnvelope({ action: "hash-files", scope: ["cerberus/core/decide.ts", "cerberus/core/does-not-exist.ts"], branch: "t", task_id: "neg-missing" });
  const r = await stand.submit(env);
  assert.equal(r.action_receipt?.result.ok, false);
  assert.equal(r.final_decision, "DENY");
  assert.equal(r.toepara?.verdict.verdict, "REJECTED");
});

test("NEGATIVE: replayed final submission - a new task with the same evidence cannot reuse a consumed bundle", async () => {
  const { stand, deps } = setup();
  const a = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "rep-a" });
  const r1 = await stand.submit(a);
  assert.equal(r1.final_decision, "ADMIT");
  // same guard, same bundle digest: re-run Cerberus on the stored receipt/bundle
  const { cerberusDecide } = await import("../cerberus-gate.ts");
  const again = await cerberusDecide({ envelope: a, receipt: r1.action_receipt, rastik: r1.rastik, toepara: r1.toepara! }, { root: ROOT, repository: REPO, rerun: new Map(), guard: deps.guard });
  assert.equal(again.decision.decision, "DENY");
  assert.ok(again.adapter_reasons.includes("replayed-bundle"));
});

test("MUTATION-STYLE: with a weak verifier under attack, RÄSTIK confirms findings, CERBERUS QUARANTINEs the otherwise-valid receipt, and confirmed findings go back to FORGE-043 as queued (not executed) tasks", async () => {
  const weak: AttackTarget = async () => true; // admits anything
  const { stand, dispatcher } = setup({ attackTarget: weak });
  const env = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "weak-1" });
  const r = await stand.submit(env);
  assert.equal(r.toepara?.verdict.verdict, "VERIFIED", "the receipt itself is genuine");
  assert.ok((r.rastik?.findings.filter((f) => f.status === "CONFIRMED").length ?? 0) >= 38);
  assert.equal(r.final_decision, "QUARANTINE");
  assert.ok(r.cerberus.decision.unresolved_high_findings.length >= 30);
  assert.ok(r.forge_followups.length >= 38);
  const q = dispatcher.queue.find((x) => x.task_id === r.forge_followups[0]);
  assert.equal(q?.agent_id, "FORGE-043");
  assert.equal(q?.status, "QUEUED", "follow-ups are queued, never counted as executed");
  assert.equal(dispatcher.worker("FORGE-043").completed_tasks, 0);
  assert.deepEqual(selfCheckFinalReceipt(r), []);
});

test("the real attack target admits the genuine receipt (control) - sanity for the whole battery", async () => {
  const { stand } = setup();
  const env = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "ctl-1" });
  const t = realAttackTarget({ root: ROOT, repository: REPO, rerun: new Map() });
  const r = await stand.submit(env);
  assert.equal(r.final_decision, "ADMIT");
  const { ReplayGuard } = await import("../../kratt/evidence.ts");
  assert.equal(await t(r.action_receipt, env, new ReplayGuard()), true);
});

test("capability map and handler keys agree: every declared capability has a handler key and vice versa; only registered workers can run", () => {
  const declared = Object.entries(CAPABILITIES).flatMap(([id, caps]) => caps.map((c) => `${id}:${c}`)).sort();
  assert.deepEqual([...HANDLER_KEYS].sort(), declared);
  const { dispatcher } = setup();
  assert.equal(dispatcher.available().length, Object.keys(CAPABILITIES).length);
  assert.deepEqual(countRegistry(dispatcher.registry).with_capabilities, Object.keys(CAPABILITIES).length);
  assert.equal(Object.keys(CAPABILITIES).length, 20, "11 closed-loop workers + 9 handler workers (factory/handlers)");
});

test("selfCheckFinalReceipt flags tampering with a stored final receipt", async () => {
  const { stand } = setup();
  const r = await stand.submit(stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "self-1" }));
  assert.deepEqual(selfCheckFinalReceipt(r), []);
  const t = structuredClone(r);
  t.final_decision = "ADMIT";
  t.toepara!.verdict.verdict = "REJECTED";
  assert.ok(selfCheckFinalReceipt(t).includes("final_digest-mismatch"));
  assert.ok(selfCheckFinalReceipt(t).includes("admit-without-independent-verification"));
  const g = structuredClone(r);
  (g.caller as { real_goliath: boolean }).real_goliath = true;
  assert.ok(selfCheckFinalReceipt(g).includes("caller-claims-real-goliath"));
});
