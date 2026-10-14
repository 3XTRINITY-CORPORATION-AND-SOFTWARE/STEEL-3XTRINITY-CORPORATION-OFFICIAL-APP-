import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bindEvidence, buildDecisionReceipt, digestJson, verifyDecisionReceipt } from "../../cerberus/receipts/decision-receipt.ts";
import { verifyReceipt } from "../../cerberus/core/decide.ts";
import { cerberusDecide, type CerberusCtx, type GateInput } from "../cerberus-gate.ts";
import { DecisionLedger, decideIdempotent, recordProblem, replayStoresFromEnv, requestKey } from "../replay-ledger.ts";
import { FileReplayGuard, type ReplayStore } from "../replay-store.ts";
import { digestOf, type EvidenceBundle, type RastikFinding } from "../protocol/types.ts";
import { assembleRun } from "../rastik-attacks.ts";
import { toeparaVerify } from "../toepara.ts";
import { decisionReceiptForGate } from "../trust-gate-receipt.ts";
import { REPO, ROOT, genuine } from "./helpers.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "ledger-"));
const base = () => ({ root: ROOT, repository: REPO, rerun: new Map() });
const probe = { probes: 0, cases_executed: 0, confirmed_findings: 0, probe_errors: 0, evidence_digest: null };
const attack = { attack_id: "invalid-input/null-receipt", class: "invalid-input" as const, agent_id: "SERPENT-052", case_id: "null-receipt", hypothesis: "h", outcome: "REPELLED" as const, reproduced: null };
const finding = (severity: RastikFinding["severity"], status: RastikFinding["status"] = "CONFIRMED"): RastikFinding => ({
  finding_id: `F-${severity}-${status}`, target: "t", hypothesis: "h", reproduction: "r", severity, status, evidence: {}, regression_test: "x", proposed_smallest_fix: "y",
});
async function full(findings: RastikFinding[] = []) {
  const { env, receipt } = await genuine();
  const need = { ...env, required_evidence: ["source_digests", "rastik_findings"] };
  const run = assembleRun(receipt, [attack], findings, probe);
  const toepara = await toeparaVerify(need, receipt, run, base());
  assert.equal(toepara.verdict.verdict, "VERIFIED");
  return { need, receipt, run, toepara };
}
type Full = Awaited<ReturnType<typeof full>>;
const inputOf = (i: Full): GateInput => ({ envelope: i.need, receipt: i.receipt, rastik: i.run, toepara: i.toepara });
/** A guard that counts how many digests were actually consumed (= admissions burned). */
function counting(dir: string): { guard: ReplayStore; consumed: () => number; calls: () => number } {
  const g = new FileReplayGuard(dir);
  let ok = 0, calls = 0;
  return { guard: { consume: (d) => { calls++; const r = g.consume(d); if (r) ok++; return r; } }, consumed: () => ok, calls: () => calls };
}
const markers = (dir: string) => readdirSync(dir).filter((n) => n.endsWith(".consumed"));
const ctxOf = (guard: ReplayStore): CerberusCtx => ({ ...base(), guard });

// ---- decision receipts with evidence binding for ADMIT / DENY / QUARANTINE ------------------------------------------------

test("RECEIPT (ADMIT): the gate's ADMIT gets a verifying decision receipt bound to the envelope, action receipt, TÖEPÄRA verdict, bundle, RÄSTIK report and Cerberus receipt", async () => {
  const i = await full();
  const out = await cerberusDecide(inputOf(i), ctxOf(new FileReplayGuard(join(tmp(), "g"))));
  assert.equal(out.decision.decision, "ADMIT", out.decision.reasons.join(","));
  const r = decisionReceiptForGate(inputOf(i), out);
  assert.equal(r.decision, "ADMIT");
  assert.deepEqual(verifyDecisionReceipt(r), { ok: true, problems: [] });
  assert.deepEqual(bindEvidence(r, { envelope: i.need, action_receipt: i.receipt, toepara_evidence: i.toepara.verdict, evidence_bundle: i.toepara.bundle, rastik_report: i.run, cerberus_receipt: out.cerberus_receipt }, { complete: true }), { ok: true, problems: [] });
  assert.equal(r.evidence.cerberus_receipt.digest, digestJson(out.cerberus_receipt));
  assert.ok(verifyReceipt(out.cerberus_receipt));
  // binding is real: other evidence does not bind
  const other = await full();
  assert.ok(bindEvidence(r, { action_receipt: other.receipt }).problems.includes("evidence-mismatch:action_receipt"));
  assert.ok(bindEvidence(r, { evidence_bundle: { ...(i.toepara.bundle as EvidenceBundle), repository: "x/y" } }).problems.includes("evidence-mismatch:evidence_bundle"));
});

test("RECEIPT (QUARANTINE): an unresolved CONFIRMED high RÄSTIK finding yields a QUARANTINE decision receipt with the same binding; medium findings stay ADMIT", async () => {
  const q = await full([finding("high")]);
  const out = await cerberusDecide(inputOf(q), ctxOf(new FileReplayGuard(join(tmp(), "g"))));
  assert.equal(out.decision.decision, "QUARANTINE");
  const r = decisionReceiptForGate(inputOf(q), out);
  assert.equal(r.decision, "QUARANTINE");
  assert.ok(r.reasons.includes("unresolved-confirmed-high-rastik-finding"));
  assert.ok(verifyDecisionReceipt(r).ok);
  assert.ok(bindEvidence(r, { rastik_report: q.run, envelope: q.need }, { complete: false }).ok);
  assert.ok(!bindEvidence(r, { rastik_report: { ...q.run, findings: [] } }).ok, "a RÄSTIK report with the finding removed does not bind");
  const m = await full([finding("medium")]);
  const mo = await cerberusDecide(inputOf(m), ctxOf(new FileReplayGuard(join(tmp(), "g"))));
  assert.equal(decisionReceiptForGate(inputOf(m), mo).decision, "ADMIT");
});

test("RECEIPT (DENY): a denied gate run gets a verifying DENY receipt that records which evidence existed; the receipt can never be MORE permissive than the gate", async () => {
  const i = await full();
  const tampered = structuredClone(i.receipt) as any;
  tampered.evidence.artifacts[0].sha256 = "d".repeat(64);
  const inp = { ...inputOf(i), receipt: tampered };
  const out = await cerberusDecide(inp, ctxOf(new FileReplayGuard(join(tmp(), "g"))));
  assert.equal(out.decision.decision, "DENY");
  const r = decisionReceiptForGate(inp, out);
  assert.equal(r.decision, "DENY");
  assert.ok(verifyDecisionReceipt(r).ok);
  assert.equal(r.evidence.action_receipt.state, "PRESENT");
  assert.ok(bindEvidence(r, { action_receipt: tampered }).ok, "the DENY binds the (bad) receipt that was actually presented");
  // a gate output claiming ADMIT with evidence that does not support it is downgraded by the receipt builder
  const lie = { ...out, decision: { ...out.decision, decision: "ADMIT" as const } };
  const downgraded = decisionReceiptForGate(inp, lie);
  assert.equal(downgraded.decision, "DENY");
  assert.equal(downgraded.proposed_decision, "ADMIT");
  // ADMIT whose TÖEPÄRA result is not the one CERBERUS recomputed => evidence UNKNOWN => DENY
  const ok = await cerberusDecide(inputOf(i), ctxOf(new FileReplayGuard(join(tmp(), "g2"))));
  const swapped = { ...inputOf(i), toepara: { ...i.toepara, verdict: { ...i.toepara.verdict, evidence_digest: "9".repeat(64) } } };
  const rr = decisionReceiptForGate(swapped, ok);
  assert.equal(rr.decision, "DENY");
  assert.ok(rr.reasons.includes("evidence-toepara-evidence-unknown"), rr.reasons.join(","));
});

test("RECEIPT (inputs are re-checked): a tampered Cerberus pipeline receipt, a missing-but-required RÄSTIK report, or an inconsistent caller TÖEPÄRA result never yields an ADMIT receipt; a RÄSTIK report that is not required is NOT_APPLICABLE", async () => {
  const i = await full();
  const out = await cerberusDecide(inputOf(i), ctxOf(new FileReplayGuard(join(tmp(), "g"))));
  assert.equal(out.decision.decision, "ADMIT");
  assert.equal(decisionReceiptForGate(inputOf(i), out).decision, "ADMIT", "control");
  const forgedRc = { ...out, cerberus_receipt: { ...out.cerberus_receipt, reasons: ["edited"] } };
  const a = decisionReceiptForGate(inputOf(i), forgedRc);
  assert.equal(a.decision, "DENY");
  assert.ok(a.reasons.includes("evidence-cerberus-receipt-unknown"), a.reasons.join(","));
  const b = decisionReceiptForGate({ ...inputOf(i), rastik: null }, out);
  assert.equal(b.decision, "DENY");
  assert.ok(b.reasons.includes("evidence-rastik-report-missing"), b.reasons.join(","));
  const lax = { ...i.need, required_evidence: ["source_digests"] };
  const c = decisionReceiptForGate({ ...inputOf(i), envelope: lax, rastik: null }, out);
  assert.equal(c.evidence.rastik_report.state, "NOT_APPLICABLE");
  assert.equal(c.decision, "ADMIT");
});

// ---- idempotency + restart persistence --------------------------------------------------------------------------------------

test("IDEMPOTENT: the same receipt presented twice returns the SAME decision and receipt (byte-identical); the second call does not evaluate, consume or admit again", async () => {
  const i = await full();
  const dir = join(tmp(), "store");
  const g = counting(dir);
  const ledger = new DecisionLedger(join(dir, "decisions"));
  const a = await decideIdempotent(inputOf(i), ctxOf(g.guard), ledger);
  assert.equal(a.decision.decision, "ADMIT", a.decision.reasons.join(","));
  assert.equal(a.idempotent_replay, false);
  const callsAfterFirst = g.calls();
  const b = await decideIdempotent(inputOf(i), ctxOf(g.guard), ledger);
  assert.equal(b.idempotent_replay, true);
  assert.equal(b.decision.decision, "ADMIT");
  assert.equal(JSON.stringify(b.decision), JSON.stringify(a.decision));
  assert.equal(JSON.stringify(b.receipt), JSON.stringify(a.receipt));
  assert.equal(g.calls(), callsAfterFirst, "the replay guard was not even consulted the second time");
  assert.equal(g.consumed(), 1, "exactly one admission burned");
  assert.equal(markers(dir).length, 1);
  assert.equal(readdirSync(join(dir, "decisions")).filter((n) => n.endsWith(".decision.json")).length, 1);
  assert.equal(readdirSync(join(dir, "decisions")).filter((n) => n.startsWith(".tmp-")).length, 0, "no temp files left behind");
});

test("IDEMPOTENT (restart): new guard + new ledger objects on the same directory (process restart) still return the stored ADMIT and consume nothing", async () => {
  const i = await full();
  const dir = join(tmp(), "store");
  const first = await decideIdempotent(inputOf(i), ctxOf(new FileReplayGuard(dir)), new DecisionLedger(join(dir, "decisions")));
  assert.equal(first.decision.decision, "ADMIT");
  const g2 = counting(dir);
  const again = await decideIdempotent(inputOf(i), ctxOf(g2.guard), new DecisionLedger(join(dir, "decisions")));
  assert.equal(again.idempotent_replay, true);
  assert.equal(JSON.stringify(again.receipt), JSON.stringify(first.receipt));
  assert.equal(g2.calls(), 0);
  // and the replay guard on its own also survived the restart: a DIFFERENT request carrying the same bundle is refused
  const g3 = counting(dir);
  const other = await decideIdempotent({ ...inputOf(i), signatures: { bundle: "x" } as never }, ctxOf(g3.guard), new DecisionLedger(join(dir, "decisions")));
  assert.equal(other.decision.decision, "DENY");
  assert.ok(other.decision.reasons.includes("replayed-bundle"), other.decision.reasons.join(","));
  assert.equal(other.receipt.decision, "DENY");
  assert.equal(g3.consumed(), 0);
});

test("IDEMPOTENT (QUARANTINE and DENY): every outcome is stored and replayed identically; a replayed DENY is not turned into ADMIT", async () => {
  const q = await full([finding("critical")]);
  const dir = join(tmp(), "store");
  const L = () => new DecisionLedger(join(dir, "decisions"));
  const q1 = await decideIdempotent(inputOf(q), ctxOf(new FileReplayGuard(dir)), L());
  const q2 = await decideIdempotent(inputOf(q), ctxOf(new FileReplayGuard(dir)), L());
  assert.equal(q1.decision.decision, "QUARANTINE");
  assert.equal(q2.idempotent_replay, true);
  assert.equal(JSON.stringify(q2.decision), JSON.stringify(q1.decision));

  const d = await full();
  const bad = { ...inputOf(d), receipt: { ...(d.receipt as object), task_id: "someone-else" } };
  const d1 = await decideIdempotent(bad, ctxOf(new FileReplayGuard(dir)), L());
  const d2 = await decideIdempotent(bad, ctxOf(new FileReplayGuard(dir)), L());
  assert.equal(d1.decision.decision, "DENY");
  assert.equal(d2.idempotent_replay, true);
  assert.equal(d2.decision.decision, "DENY");
  assert.equal(JSON.stringify(d2.receipt), JSON.stringify(d1.receipt));
  // the genuine request is a different request: still evaluated (and admitted) normally
  const ok = await decideIdempotent(inputOf(d), ctxOf(new FileReplayGuard(dir)), L());
  assert.equal(ok.decision.decision, "ADMIT");
  assert.equal(ok.idempotent_replay, false);
});

test("IDEMPOTENT (receipt can only tighten): the gate would ADMIT, but the presented TÖEPÄRA result disagrees with the recomputed digest => the stored decision is DENY (decision digest re-sealed, replayed identically)", async () => {
  const i = await full();
  const dir = join(tmp(), "store");
  const swapped = { ...inputOf(i), toepara: { ...i.toepara, verdict: { ...i.toepara.verdict, evidence_digest: "9".repeat(64) } } };
  const L = () => new DecisionLedger(join(dir, "decisions"));
  const r = await decideIdempotent(swapped, ctxOf(new FileReplayGuard(dir)), L());
  assert.equal(r.decision.decision, "DENY");
  assert.equal(r.receipt.decision, "DENY");
  assert.equal(r.receipt.proposed_decision, "ADMIT");
  assert.ok(r.decision.reasons.includes("downgraded-to-deny") && r.decision.reasons.includes("evidence-toepara-evidence-unknown"), r.decision.reasons.join(","));
  const { decision_digest, ...body } = r.decision;
  assert.equal(digestOf(body), decision_digest);
  const again = await decideIdempotent(swapped, ctxOf(new FileReplayGuard(dir)), L());
  assert.equal(again.idempotent_replay, true);
  assert.equal(again.decision.decision, "DENY");
});

test("IDEMPOTENT (request identity): any change to envelope, receipt, RÄSTIK report, bundle or signatures is a different request; the toepara diagnostics field is not part of the identity", async () => {
  const i = await full();
  const k = requestKey(inputOf(i));
  assert.match(k ?? "", /^[0-9a-f]{64}$/);
  assert.equal(requestKey(inputOf(i)), k, "stable");
  assert.equal(requestKey({ ...inputOf(i), toepara: { ...i.toepara, verdict: { ...i.toepara.verdict, reasons: ["note"] } } }), k, "caller-supplied verdict is diagnostics only");
  for (const [name, v] of Object.entries({
    envelope: { ...inputOf(i), envelope: { ...i.need, branch: "other" } },
    receipt: { ...inputOf(i), receipt: { ...(i.receipt as object), agent_id: "X" } },
    rastik: { ...inputOf(i), rastik: null },
    bundle: { ...inputOf(i), toepara: { ...i.toepara, bundle: null } },
    signatures: { ...inputOf(i), signatures: { bundle: "s" } as never },
  })) assert.notEqual(requestKey(v as GateInput), k, name);
  const cyclic: any = { a: 1 }; cyclic.self = cyclic;
  assert.equal(requestKey({ ...inputOf(i), envelope: cyclic }), null);
});

// ---- ledger integrity / fail closed ------------------------------------------------------------------------------------------

test("LEDGER (tamper): an edited, re-sealed, foreign or corrupt stored record is DENY ledger-record-invalid - never replayed as ADMIT", async () => {
  const i = await full();
  const dir = join(tmp(), "store");
  const ldir = join(dir, "decisions");
  const first = await decideIdempotent(inputOf(i), ctxOf(new FileReplayGuard(dir)), new DecisionLedger(ldir));
  assert.equal(first.decision.decision, "ADMIT");
  const key = requestKey(inputOf(i)) as string;
  const file = join(ldir, `${key}.decision.json`);
  const orig = readFileSync(file, "utf8");
  const record = JSON.parse(orig);
  const attempts: Array<[string, string]> = [
    ["receipt reasons edited", JSON.stringify({ ...record, receipt: { ...record.receipt, reasons: ["x"] } })],
    ["decision flipped in the decision only", JSON.stringify({ ...record, decision: { ...record.decision, decision: "DENY" } })],
    ["evidence ref removed and receipt re-sealed", (() => {
      const r = structuredClone(record);
      r.receipt.evidence.evidence_bundle = { state: "MISSING", digest: null };
      r.receipt.evidence_binding_digest = digestJson(r.receipt.evidence);
      const { receipt_digest: _x, ...b } = r.receipt; void _x;
      r.receipt.receipt_digest = digestJson(b);
      return JSON.stringify(r);
    })()],
    ["decision reasons edited, decision_digest stale", JSON.stringify({ ...record, decision: { ...record.decision, reasons: ["x"] } })],
    ["decision flipped to DENY and re-sealed, receipt still ADMIT", (() => {
      const r = structuredClone(record);
      r.decision.decision = "DENY";
      const { decision_digest: _x, ...b } = r.decision; void _x;
      r.decision.decision_digest = digestOf(b);
      return JSON.stringify(r);
    })()],
    ["truncated", orig.slice(0, 40)],
    ["not json", "ADMIT\n"],
    ["empty", ""],
    ["extra key", JSON.stringify({ ...record, extra: 1 })],
  ];
  for (const [name, content] of attempts) {
    writeFileSync(file, content);
    const g = counting(dir);
    const r = await decideIdempotent(inputOf(i), ctxOf(g.guard), new DecisionLedger(ldir));
    assert.equal(r.decision.decision, "DENY", name);
    assert.ok(r.decision.reasons.some((x) => x.startsWith("ledger-record-invalid")), `${name}: ${r.decision.reasons.join(",")}`);
    assert.equal(r.receipt.decision, "DENY");
    assert.equal(g.calls(), 0, `${name}: the gate was not re-run`);
  }
  // a record stored under a DIFFERENT key (copied file) is rejected too
  const j = await full();
  const otherKey = requestKey(inputOf(j)) as string;
  writeFileSync(join(ldir, `${otherKey}.decision.json`), orig);
  const foreign = await decideIdempotent(inputOf(j), ctxOf(new FileReplayGuard(dir)), new DecisionLedger(ldir));
  assert.equal(foreign.decision.decision, "DENY");
  assert.ok(foreign.decision.reasons.includes("ledger-record-invalid:request-key-mismatch"), foreign.decision.reasons.join(","));
  assert.equal(recordProblem(key, JSON.parse(orig)), null, "control: the untouched record is valid");
});

test("LEDGER (crash between claim and publish): the request is DENY idempotency-incomplete, not stored, never ADMIT, and nothing is consumed", async () => {
  const i = await full();
  const dir = join(tmp(), "store");
  const ldir = join(dir, "decisions");
  const key = requestKey(inputOf(i)) as string;
  const ledger = new DecisionLedger(ldir);
  assert.equal(ledger.claim(key), "won");
  assert.equal(ledger.claim(key), "exists");
  const g = counting(dir);
  const r = await decideIdempotent(inputOf(i), ctxOf(g.guard), ledger, { waitMs: 120, pollMs: 10 });
  assert.equal(r.decision.decision, "DENY");
  assert.deepEqual(r.decision.reasons, ["idempotency-incomplete"]);
  assert.equal(g.calls(), 0);
  assert.equal(existsSync(join(ldir, `${key}.decision.json`)), false, "an incomplete result is not recorded as final");
});

test("LEDGER (fail closed): unwritable / hostile ledger directory, publish failure and unhashable input all end in DENY - an admission is never returned without a durable record", async () => {
  const i = await full();
  // ledger path is a regular file
  const base0 = tmp();
  const f = join(base0, "afile");
  writeFileSync(f, "x");
  const g1 = counting(join(base0, "store"));
  const r1 = await decideIdempotent(inputOf(i), ctxOf(g1.guard), new DecisionLedger(f));
  assert.equal(r1.decision.decision, "DENY");
  assert.ok(r1.decision.reasons[0]?.startsWith("ledger-unavailable"), r1.decision.reasons.join(","));
  assert.equal(g1.calls(), 0, "the bundle is not burned when the ledger cannot record");
  // read-only ledger directory
  if (process.getuid?.() !== 0) {
    const d = join(tmp(), "ro");
    const l = new DecisionLedger(d);
    assert.equal(l.claim("a".repeat(64)), "won");
    chmodSync(d, 0o500);
    try {
      const g = counting(join(tmp(), "store"));
      const r = await decideIdempotent(inputOf(i), ctxOf(g.guard), l);
      assert.equal(r.decision.decision, "DENY");
      assert.equal(g.calls(), 0);
    } finally {
      chmodSync(d, 0o700);
    }
  }
  // publish fails AFTER the gate decided ADMIT: the caller gets DENY, not an unrecorded ADMIT
  class NoPublish extends DecisionLedger {
    override publish(): boolean {
      this.lastError = "forced";
      return false;
    }
  }
  const dir = join(tmp(), "store");
  const r2 = await decideIdempotent(inputOf(i), ctxOf(new FileReplayGuard(dir)), new NoPublish(join(dir, "decisions")));
  assert.equal(r2.decision.decision, "DENY");
  assert.ok(r2.decision.reasons[0]?.startsWith("ledger-publish-failed"));
  assert.equal(r2.receipt.decision, "DENY");
  // unhashable (cyclic) input
  const cyclic: any = {}; cyclic.self = cyclic;
  const r3 = await decideIdempotent({ ...inputOf(i), envelope: cyclic }, ctxOf(new FileReplayGuard(join(tmp(), "s"))), new DecisionLedger(join(tmp(), "l")));
  assert.equal(r3.decision.decision, "DENY");
  assert.deepEqual(r3.decision.reasons, ["ledger-request-key-unavailable"]);
});

test("LEDGER: replayStoresFromEnv honours FACTORY_REPLAY_DIR (guard markers in the dir, ledger in <dir>/decisions) and is null when unset or empty", () => {
  assert.equal(replayStoresFromEnv({}), null);
  assert.equal(replayStoresFromEnv({ FACTORY_REPLAY_DIR: "" }), null);
  const dir = tmp();
  const s = replayStoresFromEnv({ FACTORY_REPLAY_DIR: dir });
  assert.ok(s !== null);
  assert.equal(s.guard.dir, dir);
  assert.equal(s.ledger.dir, join(dir, "decisions"));
});

// ---- fail closed on missing / UNKNOWN evidence; NOT_IMPLEMENTED is never PASS ---------------------------------------------------

test("FAIL CLOSED (gate): missing, null, UNKNOWN or NOT_IMPLEMENTED evidence/verdicts never ADMIT, and the decision receipt agrees", async () => {
  const i = await full();
  const sev = (r: { decision: { decision: string }; receipt: { decision: string } }) => {
    assert.equal(r.decision.decision, "DENY");
    assert.equal(r.receipt.decision, "DENY");
    assert.ok(verifyDecisionReceipt(r.receipt).ok);
  };
  const run = async (inp: unknown, c: Partial<CerberusCtx> = {}) => decideIdempotent(inp as GateInput, { ...ctxOf(new FileReplayGuard(join(tmp(), "g"))), ...c }, new DecisionLedger(join(tmp(), "l")));
  const good = inputOf(i);
  sev(await run({ ...good, receipt: null }));
  sev(await run({ ...good, receipt: undefined }));
  sev(await run({ ...good, envelope: undefined }));
  sev(await run({ ...good, envelope: null }));
  sev(await run({ ...good, rastik: null }), /* envelope requires rastik_findings */);
  sev(await run({ ...good, toepara: null }));
  sev(await run({ ...good, toepara: { verdict: { ...i.toepara.verdict, verdict: "UNKNOWN" }, bundle: null } }));
  sev(await run({ ...good, toepara: { verdict: { ...i.toepara.verdict, verdict: "NOT_IMPLEMENTED" }, bundle: null } }));
  sev(await run({ ...good, toepara: { ...i.toepara, bundle: null } }));
  sev(await run({}));
  sev(await run(null));
  sev(await run("ADMIT"));
  // the Trust Gate answers UNKNOWN / NOT_IMPLEMENTED / nothing / the wrong word => DENIED => DENY
  for (const answer of ["UNKNOWN", "NOT_IMPLEMENTED", undefined, null, "ADMITTED", "authorized", "AUTHORIZED "]) {
    const r = await run(good, { trustGate: { name: "x", evaluate: async () => answer } });
    sev(r);
    assert.ok(r.decision.reasons.includes("trust-gate:malformed-verdict"), `${String(answer)}: ${r.decision.reasons.join(",")}`);
  }
  // control: the same input with the real stub gate is ADMIT (the matrix above is not vacuous)
  const ok = await run(good);
  assert.equal(ok.decision.decision, "ADMIT");
});

test("FAIL CLOSED (receipt level): a stage reported NOT_IMPLEMENTED / UNKNOWN / NOT_EVALUATED can never PASS into an ADMIT or QUARANTINE receipt, even when the evidence is complete", () => {
  const present = (s: unknown) => ({ state: "PRESENT", digest: digestJson(s) });
  const ev = { envelope: present("e"), action_receipt: present("a"), toepara_evidence: present("t"), evidence_bundle: present("b"), rastik_report: present("r"), cerberus_receipt: present("c") };
  const stages = { input: "PASS", policy: "PASS", toepara: "PASS", trustGate: "PASS", artifactTrust: "PASS" };
  assert.equal(buildDecisionReceipt({ task_id: "t-1", proposed: "ADMIT", evidence: ev, toepara_verdict: "VERIFIED", cerberus_decision: "PROCEED", stages }).decision, "ADMIT");
  for (const v of ["NOT_IMPLEMENTED", "UNKNOWN", "NOT_EVALUATED"]) {
    for (const s of Object.keys(stages)) {
      for (const proposed of ["ADMIT", "QUARANTINE"]) {
        assert.equal(buildDecisionReceipt({ task_id: "t-1", proposed, evidence: ev, toepara_verdict: "VERIFIED", cerberus_decision: "PROCEED", stages: { ...stages, [s]: v } }).decision, "DENY", `${proposed}/${s}=${v}`);
      }
    }
  }
  assert.equal(digestOf({ a: 1 }), digestOf({ a: 1 }));
});
