import test from "node:test";
import assert from "node:assert/strict";
import { ATTACK_CLASSES } from "../capabilities.ts";
import { execFileSync } from "node:child_process";
import {
  caseCount,
  configCaseCount,
  configCollisionViolations,
  configureParentLookup,
  jsonDuplicateKeys,
  readConfigDeclarations,
  realAttackTarget,
  runAttackClass,
  runConfigCollisionAttacks,
  type AttackTarget,
  type ConfigDeclarations,
} from "../rastik-attacks.ts";
import { toeparaVerify } from "../toepara.ts";
import { runKrattStage } from "../kratt-stage.ts";
import { validateRastikFinding, type ActionReceipt } from "../protocol/types.ts";
import { ROOT, REPO, genuine, tempRepo } from "./helpers.ts";

configureParentLookup(ROOT);
const real = () => realAttackTarget({ root: ROOT, repository: REPO, rerun: new Map() });

test("RÄSTIK: against the real verifier every receipt attack is REPELLED (after a control receipt was ADMITTED), 0 findings", async () => {
  const { env, receipt } = await genuine();
  let executed = 0;
  for (const cls of ATTACK_CLASSES) {
    const r = await runAttackClass(cls, receipt, env, { target: real() });
    assert.equal(r.control_admitted, true, `${cls}: control receipt must be admitted or "all repelled" proves nothing`);
    assert.ok(r.records.length >= caseCount(cls) - 1, cls);
    assert.deepEqual(r.records.filter((x) => x.outcome !== "REPELLED").map((x) => x.attack_id), [], cls);
    assert.deepEqual(r.findings, []);
    executed += r.records.length;
  }
  assert.ok(executed >= 38, `executed ${executed}`);
});

test("RÄSTIK: the battery is not vacuous - a verifier that admits everything is attacked successfully (every case CONFIRMED with a schema-valid finding)", async () => {
  const { env, receipt } = await genuine();
  const admitAll: AttackTarget = async () => true;
  let confirmed = 0;
  for (const cls of ATTACK_CLASSES) {
    const r = await runAttackClass(cls, receipt, env, { target: admitAll });
    assert.equal(r.findings.length, r.records.length);
    for (const f of r.findings) {
      assert.equal(f.status, "CONFIRMED");
      assert.ok(validateRastikFinding(f).ok, f.finding_id);
      assert.match(f.regression_test, /^test\(/);
      confirmed++;
    }
  }
  assert.ok(confirmed >= 38);
});

test("RÄSTIK: a realistic weak verifier that trusts KRATT's own verdict + digest is caught on the right classes only", async () => {
  const { env, receipt } = await genuine();
  const trustingKratt: AttackTarget = async (c) => {
    const r = c as { evidence?: { verdict?: string }; verification_state?: string } | null;
    return r?.evidence?.verdict === "ADMITTED";
  };
  const hits = new Map<string, boolean>();
  for (const cls of ATTACK_CLASSES) {
    const r = await runAttackClass(cls, receipt, env, { target: trustingKratt });
    for (const f of r.findings) hits.set(f.finding_id, f.status === "CONFIRMED");
  }
  assert.equal(hits.get("RASTIK-RCPT-malformed-receipt-self-verified-by-kratt"), true);
  assert.equal(hits.get("RASTIK-RCPT-tampered-evidence-self-consistent-forgery-wrong-source-digest"), true);
  assert.equal(hits.get("RASTIK-RCPT-unauthorized-action-action-deploy"), true);
  assert.equal(hits.has("RASTIK-RCPT-invalid-input-null-receipt"), false, "null receipt has no evidence.verdict: repelled even by the weak verifier");
  assert.equal(hits.has("RASTIK-RCPT-missing-evidence-evidence-deleted"), false);
});

test("RÄSTIK: UNCONFIRMED when the bypass does not reproduce on the independent re-run (flaky acceptance is not a finding)", async () => {
  const { env, receipt } = await genuine();
  let n = 0;
  const flaky: AttackTarget = async () => {
    n++;
    return n === 2; // control is call 1 (rejected) -> would block; make control pass: see below
  };
  // control (call 1) must pass, case first attempt (call 2) admitted, re-run (call 3) refused
  const seq = [true, true, false];
  let i = 0;
  const target: AttackTarget = async () => seq[i++] ?? false;
  void flaky;
  const r = await runAttackClass("invalid-input", receipt, env, { target });
  assert.equal(r.records[0]?.outcome, "SUCCEEDED");
  assert.equal(r.records[0]?.reproduced, false);
  assert.equal(r.findings[0]?.status, "UNCONFIRMED");
});

test("RÄSTIK: if the control receipt is not admitted, no attack results are reported (no false 'all repelled')", async () => {
  const { env, receipt } = await genuine();
  const r = await runAttackClass("boundary", receipt, env, { target: async () => false });
  assert.equal(r.control_admitted, false);
  assert.deepEqual(r.records, []);
});

test("RÄSTIK: a throwing verifier is treated as fail-closed (repelled), never as a bypass", async () => {
  const { env, receipt } = await genuine();
  let calls = 0;
  const target: AttackTarget = async () => {
    if (++calls === 1) return true; // control
    throw new Error("boom");
  };
  const r = await runAttackClass("replay", receipt, env, { target });
  assert.equal(r.records[0]?.outcome, "REPELLED");
});

// ---------------------------------------------------------------------------------------------
// RÄSTIK v2: adversarial expansion
// ---------------------------------------------------------------------------------------------
import { ReplayGuard, parseEvidence } from "../../kratt/evidence.ts";
import { canonicalize } from "../../cerberus/core/decide.ts";
import { selfCheckFinalReceipt } from "../loop.ts";
import { describeCases, finalReceiptCaseCount, openDefectCases, runFinalReceiptAttacks } from "../rastik-attacks.ts";
import { SCOPE, setup } from "./helpers.ts";

/**
 * Attacks that currently SUCCEED against the verifier because of a defect in a file RÄSTIK does not
 * own (reported with the smallest fix in docs/factory/MUTATION-CHECKS.md and the PR). The pin is
 * strict on purpose: when a defect is fixed this test fails with "FIXED", and the fix PR must delete
 * the `openDefect` flag of that case in factory/rastik-attacks.ts (the case then joins the default
 * battery and guards the fix) and the id below.
 */
const OPEN_RECEIPT_DEFECTS = [
  "boundary/timestamp-impossible-calendar-date",
  "replay/replay-reordered-retimestamped",
  "replay/replay-retimestamped",
  "unauthorized-action/forged-role-cerberus-commander-produces-kratt-receipt",
  "unauthorized-action/forged-role-rastik-commander-produces-kratt-receipt",
  "unauthorized-action/forged-role-toepara-commander-produces-kratt-receipt",
];
const OPEN_FINAL_DEFECTS = [
  "final-receipt/action-receipt-swapped-after-verification",
  "final-receipt/decision-body-tampered-decision-digest-stale",
  "final-receipt/decision-bound-to-other-toepara-evidence",
  "final-receipt/rastik-report-tampered-evidence-digest-stale",
  "final-receipt/toepara-bundle-body-tampered",
];

test("RÄSTIK v2: default battery (malformed, prototype pollution, confusables, traversal, substitution, forged trust, replay) is REPELLED by the real verifier, with >= 90 cases and no pollution", async () => {
  const { env, receipt } = await genuine();
  let executed = 0;
  for (const cls of ATTACK_CLASSES) {
    const r = await runAttackClass(cls, receipt, env, { target: real() });
    assert.equal(r.control_admitted, true, cls);
    assert.deepEqual(r.records.filter((x) => x.outcome !== "REPELLED").map((x) => x.attack_id), [], cls);
    executed += r.records.length;
  }
  assert.ok(executed >= 90, `executed ${executed}`);
  assert.equal(({} as Record<string, unknown>).admin, undefined, "Object.prototype was not polluted by any attack");
  assert.equal(Object.prototype.hasOwnProperty.call(Object.prototype, "admin"), false);
});

test("RÄSTIK v2: real bypasses are CONFIRMED against the current verifier and match the pinned open-defect list EXACTLY (FIXED => remove the openDefect flag)", async () => {
  const { env, receipt } = await genuine();
  const succeeded: string[] = [];
  const findings = [];
  for (const cls of ATTACK_CLASSES) {
    const r = await runAttackClass(cls, receipt, env, { target: real(), includeOpenDefects: true });
    succeeded.push(...r.records.filter((x) => x.outcome === "SUCCEEDED").map((x) => x.attack_id));
    findings.push(...r.findings);
  }
  const declared = openDefectCases().map((d) => d.attack_id).sort();
  assert.deepEqual([...OPEN_RECEIPT_DEFECTS].sort(), declared, "every openDefect case is pinned here and vice versa");
  assert.deepEqual(succeeded.sort(), [...OPEN_RECEIPT_DEFECTS].sort(), "FIXED defects must have their openDefect flag removed; NEW bypasses are a failure");
  for (const f of findings) {
    assert.equal(f.status, "CONFIRMED", f.finding_id);
    assert.ok(validateRastikFinding(f).ok, f.finding_id);
    // RISK, REPRODUCTION, AFFECTED COMPONENT, SMALLEST FIX, REGRESSION TEST are all present and specific
    assert.ok(f.hypothesis.length > 20 && f.reproduction.includes("digest") && f.target.includes("factory/") && f.proposed_smallest_fix.length > 20, f.finding_id);
    assert.match(f.regression_test, /^test\("RASTIK [a-z-]+\/[a-z0-9-]+: must not be ADMITted"/);
    assert.match(f.regression_test, /only: "/);
  }
});

test("RÄSTIK v2: the generated regression test for a confirmed finding really fails today (only + includeOpenDefects reproduces the bypass)", async () => {
  const { env, receipt } = await genuine();
  const r = await runAttackClass("replay", receipt, env, { target: real(), includeOpenDefects: true, only: "replay-retimestamped" });
  assert.equal(r.control_admitted, true);
  assert.deepEqual(r.findings.map((f) => f.finding_id), ["RASTIK-RCPT-replay-replay-retimestamped"]);
  assert.match(r.findings[0]?.reproduction ?? "", /on two independent runs/);
  assert.equal(r.findings[0]?.severity, "high");
});

test("RÄSTIK v2: evidence-substitution cases are well-formed - a verifier that only checks the producer's own digest consistency admits them (so 'repelled' by the real verifier is meaningful)", async () => {
  const { env, receipt } = await genuine();
  const digestOnly: AttackTarget = async (c, e) => {
    const r = c as { task_id?: unknown; evidence?: unknown } | null;
    if (r === null || typeof r !== "object" || typeof r.evidence !== "object" || r.evidence === null) return false;
    return parseEvidence(canonicalize(r.evidence)).ok && r.task_id === (e as { task_id?: unknown }).task_id;
  };
  const res = await runAttackClass("tampered-evidence", receipt, env, { target: digestOnly });
  const confirmed = new Set(res.findings.map((f) => f.finding_id));
  for (const id of [
    "evidence-substitution-swap-artifact-hashes",
    "evidence-substitution-swap-artifact-bytes",
    "evidence-substitution-from-other-task",
    "evidence-substitution-from-other-action",
    "evidence-substitution-foreign-real-artifact",
    "self-consistent-forgery-wrong-source-digest",
  ])
    assert.ok(confirmed.has(`RASTIK-RCPT-tampered-evidence-${id}`), id);
  assert.ok(!confirmed.has("RASTIK-RCPT-tampered-evidence-evidence-substitution-swap-artifact-names"), "swapped names break KRATT's own sorted-artifact parse, so even the weak verifier repels it");
  assert.ok(!confirmed.has("RASTIK-RCPT-tampered-evidence-evidence-substitution-duplicate-artifact"), "a duplicated artifact breaks KRATT's own strictly-sorted parse, so even the weak verifier repels it");
  assert.ok(!confirmed.has("RASTIK-RCPT-tampered-evidence-artifact-sha-flipped"), "an un-resealed digest is caught even by the weak verifier");
});

test("RÄSTIK v2: cross-task evidence substitution with a SECOND genuine receipt (real evidence of another task) is REPELLED", async () => {
  const a = await genuine("hash-files");
  const b = await genuine("run-test");
  const t = real();
  const swapped = { ...structuredClone(a.receipt), evidence: structuredClone(b.receipt.evidence) };
  assert.equal(await t(a.receipt, a.env, new ReplayGuard()), true, "control A");
  assert.equal(await t(swapped, a.env, new ReplayGuard()), false, "evidence of task B inside the receipt of task A");
  const hashSwap = structuredClone(a.receipt) as unknown as { evidence: { artifacts: { sha256: string }[] } };
  hashSwap.evidence.artifacts[0] = { ...hashSwap.evidence.artifacts[0]!, sha256: (b.receipt.evidence as { artifacts: { sha256: string }[] }).artifacts[0]!.sha256 };
  assert.equal(await t(hashSwap, a.env, new ReplayGuard()), false, "artifact hash taken from task B");
});

test("RÄSTIK v2: trust bypass on the stored final receipt - controls are flagged; unchecked inner digests/links are CONFIRMED and match the pinned list EXACTLY", async () => {
  const { stand } = setup({ runProbes: false });
  const final = await stand.submit(stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "v2-final-receipt" }));
  assert.equal(final.final_decision, "ADMIT");
  const dflt = runFinalReceiptAttacks(final, selfCheckFinalReceipt);
  assert.equal(dflt.control_clean, true);
  assert.equal(dflt.records.length, finalReceiptCaseCount());
  assert.deepEqual(dflt.findings, []);
  const detail = new Map(dflt.records.map((r) => [r.case_id, r.detail]));
  assert.match(detail.get("final-digest-not-resealed") ?? "", /final_digest-mismatch/);
  assert.match(detail.get("final-decision-flipped") ?? "", /final-decision-differs-from-cerberus/);
  assert.match(detail.get("admit-with-toepara-removed") ?? "", /admit-without-independent-verification/);
  assert.match(detail.get("caller-claims-real-goliath") ?? "", /caller-claims-real-goliath/);
  assert.match(detail.get("kratt-receipt-claims-verified") ?? "", /admit-without-independent-verification/);
  // a missing CERBERUS decision never passes (it is fail-closed by exception today, which is a hardening gap, not a bypass)
  for (const id of ["cerberus-decision-deleted", "cerberus-decision-null", "cerberus-receipt-deleted"]) assert.match(detail.get(id) ?? "", /^(threw:|violations:)/, id);

  const all = runFinalReceiptAttacks(final, selfCheckFinalReceipt, { includeOpenDefects: true });
  assert.deepEqual(all.records.filter((r) => r.outcome === "SUCCEEDED").map((r) => r.attack_id).sort(), [...OPEN_FINAL_DEFECTS].sort(), "FIXED => remove the openDefect flag; NEW bypass => failure");
  for (const f of all.findings) {
    assert.equal(f.status, "CONFIRMED", f.finding_id);
    assert.ok(validateRastikFinding(f).ok, f.finding_id);
    assert.match(f.proposed_smallest_fix, /decision_digest|digest|bound|violation/i);
  }
});

test("RÄSTIK v2: final-receipt battery is not vacuous - a self-check that accepts everything is attacked successfully on EVERY case", async () => {
  const { stand } = setup({ runProbes: false });
  const final = await stand.submit(stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "v2-final-vacuous" }));
  const r = runFinalReceiptAttacks(final, () => [], { includeOpenDefects: true });
  assert.equal(r.findings.length, finalReceiptCaseCount({ includeOpenDefects: true }));
  assert.ok(r.findings.every((f) => f.status === "CONFIRMED"));
  const broken = runFinalReceiptAttacks(final, () => ["always-broken"]);
  assert.equal(broken.control_clean, false, "a control that does not pass means no results are reported");
  assert.deepEqual(broken.records, []);
});

test("RÄSTIK v2: no case is a no-op mutation (a no-op would be 'admitted' for the wrong reason and become a false finding) - checked on hash-files AND run-test fixtures with different task ids", async () => {
  for (const action of ["hash-files", "run-test"] as const) {
    const { env, receipt } = await genuine(action);
    const shortId = { ...structuredClone(env), task_id: "dbg" };
    const shortReceipt = { ...structuredClone(receipt), task_id: "dbg" };
    for (const [e, r] of [[env, receipt], [shortId, shortReceipt]] as const) {
      const d = describeCases(r, e, { includeOpenDefects: true });
      assert.ok(d.length >= 100, `cases ${d.length}`);
      assert.deepEqual(d.filter((x) => x.applicable && !x.changed).map((x) => x.attack_id), [], `${action}/${e.task_id}`);
      const inapplicable = d.filter((x) => !x.applicable).map((x) => x.attack_id);
      // hash-files: only the HEAD~1 case may be inapplicable (CI clones are shallow, depth 1: there is no parent).
      // run-test has a single artifact, so the five multi-artifact cases are also inapplicable.
      const allowed = new Set(["stale-base-sha/base-sha-parent-commit", ...(action === "run-test" ? ["tampered-evidence/evidence-substitution-swap-artifact-hashes", "tampered-evidence/evidence-substitution-swap-artifact-names", "tampered-evidence/evidence-substitution-swap-artifact-bytes", "tampered-evidence/evidence-artifact-dropped-resealed", "tampered-evidence/evidence-substitution-duplicate-artifact"] : [])]);
      assert.deepEqual(inapplicable.filter((x) => !allowed.has(x)), [], `${action}: unexpected inapplicable cases`);
    }
  }
});

test("RÄSTIK v2: the whole battery also runs on a run-test (single-artifact) receipt: nothing throws, everything REPELLED except the pinned open defects", async () => {
  const { env, receipt } = await genuine("run-test");
  const succeeded: string[] = [];
  for (const cls of ATTACK_CLASSES) {
    const r = await runAttackClass(cls, receipt, env, { target: real(), includeOpenDefects: true });
    assert.equal(r.control_admitted, true, cls);
    succeeded.push(...r.records.filter((x) => x.outcome === "SUCCEEDED").map((x) => x.attack_id));
  }
  assert.deepEqual(succeeded.sort(), [...OPEN_RECEIPT_DEFECTS].sort());
});

// ---------------------------------------------------------------------------------------------
// Runtime drift: local Node != declared engines / .nvmrc != CI node
// ---------------------------------------------------------------------------------------------
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SPECS } from "../protocol/types.ts";
import { readRuntimeDeclarations, runRuntimeDriftAttacks, runtimeCaseCount, runtimeDriftViolations, type RuntimeDeclarations } from "../rastik-attacks.ts";

test("RÄSTIK runtime drift: the real declarations (.nvmrc, engines, devcontainer, every CI node-version) and the RUNNING interpreter name one Node major", () => {
  const d = readRuntimeDeclarations(ROOT);
  assert.ok(d.ci_node_versions.length >= 1, "CI pins a node version");
  assert.deepEqual(runtimeDriftViolations(d), [], JSON.stringify(d));
});

test("RÄSTIK runtime drift: all bounded drift mutations are REPELLED with a specific reason (21 cases)", () => {
  const d = readRuntimeDeclarations(ROOT);
  const r = runRuntimeDriftAttacks(d);
  assert.equal(r.control_clean, true);
  assert.equal(r.records.length, runtimeCaseCount());
  assert.equal(r.records.length, 21);
  assert.deepEqual(r.findings, []);
  const reason = new Map(r.records.map((x) => [x.case_id, x.detail]));
  const expect: Record<string, RegExp> = {
    "nvmrc-other-major": /engines-major-differs|devcontainer-major-differs|ci-major-differs|actual-major-differs/,
    "nvmrc-lts-alias": /nvmrc-not-a-numeric-version/,
    "nvmrc-empty": /nvmrc-not-a-numeric-version/,
    "nvmrc-missing": /nvmrc-not-a-numeric-version/,
    "nvmrc-two-lines": /nvmrc-not-a-numeric-version/,
    "nvmrc-trailing-text": /nvmrc-not-a-numeric-version/,
    "engines-open-range": /engines-not-exact-major-x/,
    "engines-caret-union": /engines-not-exact-major-x/,
    "engines-other-major": /engines-major-differs-from-nvmrc/,
    "engines-missing": /engines-not-exact-major-x/,
    "devcontainer-other-major": /devcontainer-major-differs-from-nvmrc/,
    "devcontainer-lts": /devcontainer-node-not-numeric/,
    "ci-other-major": /ci-major-differs-from-nvmrc:20/,
    "ci-floating-lts": /ci-node-not-numeric:lts/,
    "ci-floating-latest": /ci-node-not-numeric:latest/,
    "ci-floating-node-alias": /ci-node-not-numeric:node/,
    "ci-second-setup-node-drifts": /ci-major-differs-from-nvmrc:20/,
    "ci-pins-nothing": /ci-pins-no-node/,
    "actual-older-major": /actual-major-differs-from-nvmrc/,
    "actual-newer-major": /actual-major-differs-from-nvmrc/,
    "actual-unreadable": /actual-node-unreadable/,
  };
  for (const [id, re] of Object.entries(expect)) assert.match(reason.get(id) ?? "", re, id);
});

test("RÄSTIK runtime drift: the battery is not vacuous - a checker that accepts everything, and the existing node-pin style check (first CI match only, no runtime check), are attacked successfully", () => {
  const d = readRuntimeDeclarations(ROOT);
  const all = runRuntimeDriftAttacks(d, () => []);
  assert.equal(all.findings.length, runtimeCaseCount());
  assert.ok(all.findings.every((f) => f.status === "CONFIRMED" && validateRastikFinding(f).ok));
  assert.match(all.findings[0]?.regression_test ?? "", /^test\("RASTIK runtime-drift\//);
  // scripts/node-pin.test.mjs semantics re-implemented as a checker: nvmrc major vs engines vs devcontainer vs FIRST ci match
  const nodePin = (x: RuntimeDeclarations): string[] => {
    const major = (x.nvmrc ?? "").trim().replace(/^v/, "").split(".")[0] ?? "";
    const why: string[] = [];
    if (!/^\d+$/.test(major)) why.push("nvmrc");
    if (x.engines_node !== `${major}.x`) why.push("engines");
    if (x.devcontainer_node === null || String(x.devcontainer_node) !== major) why.push("devcontainer");
    const first = x.ci_node_versions[0]?.match(/^(\d+)/);
    if (!first || first[1] !== major) why.push("ci");
    return why;
  };
  assert.deepEqual(nodePin(d), [], "the existing check is green on the real declarations");
  const weak = runRuntimeDriftAttacks(d, nodePin);
  const confirmed = weak.findings.map((f) => f.finding_id.replace("RASTIK-RUNTIME-", "")).sort();
  for (const id of ["ci-second-setup-node-drifts", "actual-older-major", "actual-newer-major", "actual-unreadable"]) assert.ok(confirmed.includes(id), `${id} is invisible to a node-pin style check; got ${confirmed.join()}`);
  const broken = runRuntimeDriftAttacks(d, () => ["always-broken"]);
  assert.equal(broken.control_clean, false);
  assert.deepEqual(broken.records, []);
  const throwing = runRuntimeDriftAttacks(d, () => { throw new Error("boom"); });
  assert.equal(throwing.control_clean, false, "a throwing checker is fail-closed, never 'clean'");
});

test("RÄSTIK runtime drift: KNOWN OPEN (hardening) - the protocol carries no runtime fact, so a receipt produced under another Node major cannot be told apart (FIXED => update this pin)", () => {
  const keys = (s: { k: string; shape?: Record<string, unknown> }) => Object.keys(s.shape ?? {});
  for (const name of ["ActionReceipt", "EvidenceBundle"] as const) assert.deepEqual(keys(SPECS[name] as never).filter((k) => /node|runtime|engine/i.test(k)), [], name);
});

test("RÄSTIK runtime drift: readRuntimeDeclarations reads EVERY workflow node-version (all files, all jobs), engines, devcontainer and .nvmrc from a fixture tree", () => {
  const dir = mkdtempSync(join(tmpdir(), "rd-fixture-"));
  try {
    mkdirSync(join(dir, ".github/workflows"), { recursive: true });
    mkdirSync(join(dir, ".devcontainer"));
    writeFileSync(join(dir, ".nvmrc"), "22\n");
    writeFileSync(join(dir, "package.json"), JSON.stringify({ engines: { node: "22.x" } }));
    writeFileSync(join(dir, ".devcontainer/devcontainer.json"), JSON.stringify({ features: { "ghcr.io/devcontainers/features/node:1": { version: "22" } } }));
    writeFileSync(join(dir, ".github/workflows/a.yml"), 'jobs:\n  x:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: "22"\n  y:\n    steps:\n      - with:\n          node-version: \'20\' # drift\n');
    writeFileSync(join(dir, ".github/workflows/b.yaml"), "          node-version: lts/*\n");
    writeFileSync(join(dir, ".github/workflows/readme.txt"), "          node-version: 18\n");
    const d = readRuntimeDeclarations(dir);
    assert.deepEqual(d.ci_node_versions, ["22", "20", "lts/*"]);
    assert.equal(d.nvmrc, "22");
    assert.equal(d.engines_node, "22.x");
    assert.equal(d.devcontainer_node, "22");
    assert.equal(d.actual, process.versions.node);
    assert.deepEqual(runtimeDriftViolations({ ...d, actual: "22.1.0" }), ["ci-major-differs-from-nvmrc:20", "ci-node-not-numeric:lts/*"]);
    assert.deepEqual(readRuntimeDeclarations(join(dir, "does-not-exist")), { nvmrc: null, engines_node: null, devcontainer_node: null, ci_node_versions: [], actual: process.versions.node });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------------
// STACKED_CONFIG_COLLISION
// ---------------------------------------------------------------------------------------------
test("RÄSTIK config collision: jsonDuplicateKeys finds duplicates at every depth and rejects non-JSON", () => {
  assert.deepEqual(jsonDuplicateKeys('{"a":1,"b":{"c":1}}'), []);
  assert.deepEqual(jsonDuplicateKeys('{"a":1,"a":2}'), ["a"]);
  assert.deepEqual(jsonDuplicateKeys('{"s":{"test":"x","lint":"y","test":"z"}}'), ["s.test"]);
  assert.deepEqual(jsonDuplicateKeys('{"s":[{"k":1,"k":2}]}'), ["s[].k"]);
  assert.deepEqual(jsonDuplicateKeys('{"a":"x\\"y","a":"q"}'), ["a"], "escaped quotes do not end a string");
  assert.deepEqual(jsonDuplicateKeys('{"a":{"x":1},"b":{"x":2}}'), [], "same key in different objects is fine");
  for (const bad of ["", "{", '{"a":1,}', "{'a':1}", '{"a":1} x', "<<<<<<< HEAD\n{}", "[1,]", '{"a" 1}']) assert.equal(jsonDuplicateKeys(bad), null, JSON.stringify(bad));
  assert.equal(jsonDuplicateKeys("[".repeat(100) + "]".repeat(100)), null, "depth bound");
});

test("RÄSTIK config collision: the real repo configuration is clean and every collision (22 cases) is REPELLED with a specific reason", () => {
  const decl = readConfigDeclarations(ROOT);
  assert.deepEqual(configCollisionViolations(decl), [], "package.json must hold ONE test script that names/imports every test file; no gate bypass");
  assert.ok(decl.test_files.length >= 18 && decl.workflows.length >= 1);
  const r = runConfigCollisionAttacks(decl);
  assert.equal(r.control_clean, true);
  assert.equal(r.records.length, configCaseCount());
  assert.equal(configCaseCount(), 22);
  assert.deepEqual(r.records.filter((x) => x.outcome !== "REPELLED").map((x) => `${x.case_id}:${x.outcome}`), []);
  assert.deepEqual(r.findings, []);
  const reason = (id: string) => r.records.find((x) => x.case_id === id)?.detail ?? "";
  assert.match(reason("stacked-duplicate-test-line"), /duplicate-key:scripts\.test/);
  assert.match(reason("stacked-triple-test-line"), /duplicate-key:scripts\.test,duplicate-key:scripts\.test/);
  assert.match(reason("stacked-duplicate-scripts-block"), /duplicate-key:scripts/);
  assert.match(reason("stacked-duplicate-engines-block"), /duplicate-key:engines/);
  assert.match(reason("merge-conflict-markers-in-package-json"), /package-json-conflict-marker/);
  assert.match(reason("merge-conflict-markers-in-workflow"), /workflow-conflict-marker/);
  assert.match(reason("package-json-trailing-comma"), /package-json-invalid-json/);
  assert.match(reason("test-script-deleted"), /test-script-missing/);
  assert.match(reason("test-script-or-true"), /test-script-gate-bypass/);
  assert.match(reason("test-script-semicolon-true"), /test-script-gate-bypass/);
  assert.match(reason("test-script-drops-a-registered-test"), /unregistered-test:factory\/tests\/trust-gate\.test\.ts/);
  assert.match(reason("test-runner-deleted"), /test-runner-missing/);
  assert.match(reason("test-runner-excludes-a-security-test"), /unregistered-test:factory\/tests\/trust-gate\.test\.ts/);
  assert.match(reason("test-runner-skips-the-factory-dir"), /unregistered-test:factory\/tests\/trust-gate\.test\.ts/);
  assert.match(reason("test-runner-drops-the-exit-code"), /test-runner-exit-code-dropped/);
  assert.match(reason("test-runner-narrows-the-test-pattern"), /test-runner-test-pattern-changed/);
  assert.match(reason("new-test-file-registered-nowhere"), /unregistered-test:factory\/tests\/new-security\.test\.ts/);
  assert.match(reason("workflow-continue-on-error"), /workflow-continue-on-error:/);
  assert.match(reason("workflow-run-or-true"), /workflow-run-gate-bypass:/);
});

test("RÄSTIK config collision: under the discovery runner a NEW test file is registered by discovery (no list to forget), but a missing/skipping/excluding runner is not", () => {
  const decl = readConfigDeclarations(ROOT);
  assert.match(decl.package_json as string, /"test": "node scripts\/run-tests\.mjs"/);
  assert.ok(decl.runner !== null);
  const withNew = { ...decl, test_files: [...decl.test_files, "factory/tests/brand-new.test.ts"], test_imports: { ...decl.test_imports, "factory/tests/brand-new.test.ts": [] } };
  assert.deepEqual(configCollisionViolations(withNew), []);
  assert.deepEqual(configCollisionViolations({ ...decl, runner: null }), ["test-runner-missing"]);
  assert.deepEqual(configCollisionViolations({ ...decl, runner: `${decl.runner}\n<<<<<<< HEAD\n` }), ["test-runner-conflict-marker"]);
});

test("RÄSTIK config collision: not vacuous - an accept-all checker and a JSON.parse-only checker (what `npm` effectively does: last key wins) are attacked successfully, each finding CONFIRMED + schema-valid", () => {
  const decl = readConfigDeclarations(ROOT);
  const acceptAll = runConfigCollisionAttacks(decl, () => []);
  assert.equal(acceptAll.findings.length, configCaseCount());
  for (const f of acceptAll.findings) {
    assert.equal(f.status, "CONFIRMED");
    assert.ok(validateRastikFinding(f).ok, f.finding_id);
    assert.match(f.regression_test, /^test\(/);
  }
  const parseOnly = (d: ConfigDeclarations): string[] => {
    try {
      JSON.parse(d.package_json ?? "");
      return [];
    } catch {
      return ["invalid-json"];
    }
  };
  const weak = runConfigCollisionAttacks(decl, parseOnly);
  const succeeded = weak.records.filter((x) => x.outcome === "SUCCEEDED").map((x) => x.case_id);
  for (const id of ["stacked-duplicate-test-line", "stacked-duplicate-test-line-union-conflict", "stacked-triple-test-line", "stacked-duplicate-lint-script", "stacked-duplicate-scripts-block", "stacked-duplicate-engines-block", "test-script-or-true", "test-script-drops-a-registered-test", "workflow-continue-on-error"]) {
    assert.ok(succeeded.includes(id), `a parse-only check misses ${id}`);
  }
  assert.ok(!succeeded.includes("package-json-trailing-comma"), "parse-only DOES catch invalid JSON");
  // a throwing checker is fail-closed
  assert.deepEqual(runConfigCollisionAttacks(decl, () => { throw new Error("boom"); }).control_clean, false);
});

test("RÄSTIK config collision: reproduction of the main f429a20 defect - three stacked `test` keys; the last silently wins and the effective script does not run six existing test files", () => {
  const decl = readConfigDeclarations(ROOT);
  const line = /^[ \t]*"test": .*$/m.exec(decl.package_json as string)?.[0] as string;
  const stacked = { ...decl, package_json: (decl.package_json as string).replace(line, `${line.replace("factory/tests/trust-gate.test.ts ", "")}\n${line.replace(/ factory\/tests\/signing\.test\.ts/, "")}\n${line}`) };
  const v = configCollisionViolations(stacked);
  assert.equal(v.filter((x) => x === "duplicate-key:scripts.test").length, 2);
  assert.equal(JSON.parse(stacked.package_json).scripts.test, line.replace(/^[^:]*:\s*"/, "").replace(/",?$/, ""), "JSON.parse keeps only the LAST key");
});

// ---------------------------------------------------------------------------------------------
// Workspace attacks against the existing TÖEPÄRA: stale SHA, dirty tree, TOCTOU
// ---------------------------------------------------------------------------------------------
const gitIn = (dir: string, ...a: string[]) => execFileSync("git", a, { cwd: dir, encoding: "utf8", env: { PATH: process.env.PATH ?? "", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t", HOME: dir } }).trim();
const FILES = { "a.txt": "alpha\n", "b/c.txt": "beta\n" };
async function genuineAt(dir: string, sha: string, scope: string[], id: string) {
  const { stand, clock } = setup({ root: dir });
  const env = { ...stand.issueEnvelope({ action: "hash-files", branch: "t", scope, base_sha: sha, task_id: id }), required_evidence: ["source_digests"] };
  const r = await runKrattStage(env, dir, clock);
  assert.ok(r.ok, r.ok ? "" : r.reason);
  return { env, receipt: (r as unknown as { receipt: ActionReceipt }).receipt };
}
const tctx = (root: string) => ({ root, repository: REPO, rerun: new Map() });

test("RÄSTIK workspace attack (stale SHA): a genuine receipt bound to base_sha is no longer VERIFIED once the branch moved on (new commit), reason stale-base-sha", async () => {
  const { dir, sha } = tempRepo(FILES);
  const { env, receipt } = await genuineAt(dir, sha, ["a.txt"], "ws-stale");
  assert.equal((await toeparaVerify(env, receipt, null, tctx(dir))).verdict.verdict, "VERIFIED", "control");
  writeFileSync(join(dir, "z.txt"), "later\n");
  gitIn(dir, "add", "-A");
  gitIn(dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "later");
  const t = await toeparaVerify(env, receipt, null, tctx(dir));
  assert.notEqual(t.verdict.verdict, "VERIFIED");
  assert.ok(t.verdict.reasons.includes("stale-base-sha"), t.verdict.reasons.join(","));
  assert.equal(t.bundle, null);
});

test("RÄSTIK workspace attack (dirty tree, TOCTOU): editing a scoped file in the working tree AFTER KRATT hashed it is REJECTED (working-tree-differs-from-base-sha, no bundle), reverting restores VERIFIED; an UNTRACKED scope file is never VERIFIED", async () => {
  const { dir, sha } = tempRepo(FILES);
  const { env, receipt } = await genuineAt(dir, sha, ["a.txt", "b/c.txt"], "ws-toctou");
  const clean = await toeparaVerify(env, receipt, null, tctx(dir));
  assert.equal(clean.verdict.verdict, "VERIFIED");
  writeFileSync(join(dir, "a.txt"), "alpha-EDITED-AFTER-KRATT\n"); // swap between KRATT's read and TÖEPÄRA's check
  const dirty = await toeparaVerify(env, receipt, null, tctx(dir));
  assert.equal(dirty.verdict.verdict, "REJECTED");
  assert.ok(dirty.verdict.reasons.includes("working-tree-differs-from-base-sha"), dirty.verdict.reasons.join(","));
  assert.equal(dirty.bundle, null);
  writeFileSync(join(dir, "a.txt"), "alpha\n"); // swapped back: nothing was committed, the check is per call
  const restored = await toeparaVerify(env, receipt, null, tctx(dir));
  assert.equal(restored.verdict.verdict, "VERIFIED", restored.verdict.reasons.join(","));
  assert.deepEqual(restored.bundle?.source_digests, clean.bundle?.source_digests);
  // scope file that exists only in the working tree (never committed)
  writeFileSync(join(dir, "new-untracked.txt"), "x\n");
  const { stand, clock } = setup({ root: dir });
  const env2 = { ...stand.issueEnvelope({ action: "hash-files", branch: "t", scope: ["new-untracked.txt"], base_sha: sha, task_id: "ws-untracked" }), required_evidence: ["source_digests"] };
  const r2 = await runKrattStage(env2, dir, clock);
  if (r2.ok) assert.notEqual((await toeparaVerify(env2, (r2 as unknown as { receipt: ActionReceipt }).receipt, null, tctx(dir))).verdict.verdict, "VERIFIED", "KRATT hashed a file git does not have at base_sha");
});

test("RÄSTIK config collision (direct rules): an empty test script is test-script-missing by itself; a test file is registered through a registered file's side-effect import (transitively) and only then", () => {
  const mk = (test: string, files: string[], imports: Record<string, string[]>): ConfigDeclarations => ({
    package_json: JSON.stringify({ scripts: { test } }),
    workflows: [],
    test_files: files,
    test_imports: imports,
    runner: null,
  });
  assert.deepEqual(configCollisionViolations(mk("", [], {})), ["test-script-missing"], "empty script, nothing else to blame");
  assert.deepEqual(configCollisionViolations(mk("node scripts/run-tests.mjs", ["factory/tests/a.test.ts"], {})), ["test-runner-missing"], "the runner command registers nothing when the runner file is absent");
  assert.deepEqual(configCollisionViolations(mk("node scripts/run-tests.mjs || true", [], {})), ["test-script-gate-bypass"], "a bypassed runner command is not the runner command, so it is judged as a named list");
  assert.deepEqual(configCollisionViolations(mk("   ", [], {})), ["test-script-missing"]);
  assert.deepEqual(configCollisionViolations(mk("node --test factory/tests/a.test.ts", ["factory/tests/a.test.ts", "factory/tests/b.test.ts", "factory/tests/c.test.ts"], { "factory/tests/a.test.ts": ["factory/tests/b.test.ts"], "factory/tests/b.test.ts": ["factory/tests/c.test.ts"], "factory/tests/c.test.ts": [] })), [], "a -> b -> c");
  assert.deepEqual(configCollisionViolations(mk("node --test factory/tests/a.test.ts", ["factory/tests/a.test.ts", "factory/tests/b.test.ts"], { "factory/tests/a.test.ts": [], "factory/tests/b.test.ts": [] })), ["unregistered-test:factory/tests/b.test.ts"]);
});
