/* eslint-disable @typescript-eslint/ban-ts-comment -- the harness is untyped JS over dynamic target modules; tsconfig.cerberus.json type-checks factory/ with checkJs */
// @ts-nocheck
// KRATT/TOEPARA domain, adversarial + factory part (slots 130-150): rastik/run.ts, rastik/probes.ts, rastik/changed.ts, factory/*.
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";

const RUN = "rastik/run.ts";
const PRB = "rastik/probes.ts";
const CHG = "rastik/changed.ts";
const KST = "factory/kratt-stage.ts";
const DSP = "factory/dispatcher.ts";
const tree = (files) => { const r = mkdtempSync(join(tmpdir(), "m-rastik-")); for (const [rel, c] of Object.entries(files)) { mkdirSync(dirname(join(r, rel)), { recursive: true }); writeFileSync(join(r, rel), c); } return r; };
const probe = (over = {}) => ({ id: "p1", category: "fail-open", component: "comp", smallestFix: "fix it", applies: () => true, run: async () => ({ cases: 3, violations: [] }), ...over });
const env = (over = {}) => ({ task_id: "e1", allowed_actions: ["hash-files"], forbidden_actions: ["merge"], scope: ["a.txt", "b.txt"], resource_budget: { max_wall_ms: 1000, max_output_bytes: 2048, max_files: 4 }, ...over });
const ROOT = process.cwd();

export const SPECS = [
  { slot: 130, target: RUN, expected: { probes: [], findings: [], casesExecuted: 0, digestLen: 64 },
    run: async (m) => { const r = await m.runRastik({ root: ROOT, files: ["README.md"], probes: [] }); return { probes: r.probes, findings: r.findings, casesExecuted: r.casesExecuted, digestLen: r.evidence.evidenceDigest.length }; },
    claim: "zero applicable probes is reported as zero executed cases and no findings - never as a pass with cases" },
  { slot: 131, target: RUN, expected: { cerberusCore: ["cerberus-hostile-input", "cerberus-adapter-failopen", "cerberus-receipt-integrity", "stale-import"], readme: [], workflowOnly: ["workflow-gate-weakening"] },
    run: async (m) => { const { allProbes } = await import("../../../rastik/probes.ts"); const ids = (files) => m.selectProbes(files, allProbes(), false).map((p) => p.id); return { cerberusCore: ids(["cerberus/core/decide.ts"]), readme: ids(["README.md"]), workflowOnly: ids([".github/workflows/ci.yml"]) }; },
    claim: "probe selection follows the changed files: cerberus/core pulls four probes, README none, a workflow file only the gate probe" },
  { slot: 132, target: PRB, expected: "factory/registry.ts", run: (m) => relative(ROOT, m.resolveSpecifier(ROOT, "factory/loop.ts", "./registry.ts")),
    claim: "a relative specifier with an explicit .ts extension resolves to the sibling file" },
  { slot: 133, target: PRB, expected: "src/lib/auth/sign-in-gate.ts", run: (m) => relative(ROOT, m.resolveSpecifier(ROOT, "src/routes/index.tsx", "@/lib/auth/sign-in-gate")),
    claim: "an @/ alias resolves under src/ and tries the .ts extension" },
  { slot: 134, target: PRB, expected: "scripts/with-app-env.mjs", run: (m) => relative(ROOT, m.resolveSpecifier(ROOT, "factory/x.ts", "../scripts/with-app-env.mjs?raw#frag")),
    claim: "Vite ?raw and #hash suffixes are stripped before resolving" },
  { slot: 135, target: PRB, fn: "resolveSpecifier", input: [ROOT, "factory/loop.ts", "./does-not-exist"], expected: null, claim: "a specifier that matches no file or index resolves to null (the stale-import signal)" },
  { slot: 136, target: PRB, expected: "kratt/task.ts", run: (m) => relative(ROOT, m.resolveSpecifier(ROOT, "kratt/run.ts", "./task.js")),
    claim: "a .js specifier falls back to the .ts source file" },
  { slot: 137, target: CHG, expected: { option: "invalid-base-ref", range: "invalid-base-ref", empty: "invalid-base-ref" },
    run: (m) => { const e = (b) => { try { m.changedFiles(b, ROOT); return "no-throw"; } catch (x) { return x.message; } }; return { option: e("--upload-pack=x"), range: e("a..b"), empty: e("") }; },
    claim: "a base ref that could be parsed as an option, a range, or is empty is refused before git runs" },
  { slot: 138, target: RUN, expected: { ids: ["RASTIK-p1-bad-case"], status: "CONFIRMED", category: "fail-open", component: "comp", fix: "fix it", hasRegression: true, failing: true },
    run: async (m) => { const p = probe({ run: async () => ({ cases: 3, violations: [{ caseId: "bad case!", expected: "E", observed: "o", reproduction: "R", recheck: () => true }] }) }); const r = await m.runRastik({ root: ROOT, files: ["x.ts"], probes: [p] }); const f = r.findings[0]; return { ids: r.findings.map((x) => x.id), status: f.status, category: f.category, component: f.affectedComponent, fix: f.smallestFix, hasRegression: f.regressionTest.includes("RASTIK p1: bad case!"), failing: m.hasFailures(r) }; },
    claim: "a violation that reproduces on re-run becomes one CONFIRMED finding with slugged id, component, fix and a regression test skeleton" },
  { slot: 139, target: RUN, expected: { findings: 0, unconfirmed: 1, failing: false },
    run: async (m) => { const p = probe({ run: async () => ({ cases: 1, violations: [{ caseId: "flaky", expected: "E", observed: "o", reproduction: "R", recheck: () => false }] }) }); const r = await m.runRastik({ root: ROOT, files: ["x.ts"], probes: [p] }); return { findings: r.findings.length, unconfirmed: r.probes[0].unconfirmed, failing: m.hasFailures(r) }; },
    claim: "a violation that does not reproduce is counted unconfirmed and is not a finding" },
  { slot: 140, target: RUN, expected: { error: "probe-threw:boom", findings: 0, failing: true },
    run: async (m) => { const p = probe({ run: async () => { throw new Error("boom"); } }); const r = await m.runRastik({ root: ROOT, files: ["x.ts"], probes: [p] }); return { error: r.probes[0].error, findings: r.findings.length, failing: m.hasFailures(r) }; },
    claim: "a probe that throws is recorded as an error and fails the run - never counted as a pass" },
  { slot: 141, target: RUN, expected: { sameDigest: true, digestChangesWithFiles: true, hex: true },
    run: async (m) => { const a = await m.runRastik({ root: ROOT, files: ["x.ts"], probes: [probe()] }); const b = await m.runRastik({ root: ROOT, files: ["x.ts"], probes: [probe()] }); const c = await m.runRastik({ root: ROOT, files: ["y.ts"], probes: [probe()] }); return { sameDigest: a.evidence.evidenceDigest === b.evidence.evidenceDigest, digestChangesWithFiles: a.evidence.evidenceDigest !== c.evidence.evidenceDigest, hex: /^[0-9a-f]{64}$/.test(a.evidence.evidenceDigest) }; },
    claim: "RASTIK evidence is deterministic for identical inputs and changes when the changed-file set changes" },
  { slot: 142, target: RUN, expected: { probeIds: ["cerberus-hostile-input", "cerberus-adapter-failopen", "cerberus-receipt-integrity", "stale-import"], findings: 0, errors: 0, hundredsOfCases: true },
    run: async (m) => { const r = await m.runRastik({ root: ROOT, files: ["cerberus/core/decide.ts"] }); return { probeIds: r.probes.map((p) => p.probe), findings: r.findings.length, errors: r.probes.filter((p) => p.error).length, hundredsOfCases: r.casesExecuted >= 100 }; },
    claim: "the real battery run against the real cerberus/core selects four probes, executes >=100 cases, and finds 0 confirmed findings and 0 probe errors" },
  { slot: 143, target: PRB, expected: { violations: [".github/workflows/x.yml:3"], cases: 15 },
    run: async (m) => { const root = tree({ ".github/workflows/x.yml": "name: x\n# continue-on-error: true is only a comment\n    continue-on-error: true\n" }); const out = await m.probeWorkflowGates.run({ root, files: [".github/workflows/x.yml"] }); return { violations: out.violations.map((v) => v.caseId), cases: out.cases }; },
    claim: "the workflow probe flags the real 'continue-on-error: true' line 3, ignores the commented line 2, and runs 5 patterns x 3 lines = 15 cases" },
  { slot: 144, target: PRB, expected: { violations: ["a.ts -> ./missing"], cases: 2 },
    run: async (m) => { const root = tree({ "a.ts": 'import x from "./b";\nimport y from "./missing";\nimport z from "react";\n', "b.ts": "export default 1;\n" }); const out = await m.probeStaleImport.run({ root, files: ["a.ts"] }); return { violations: out.violations.map((v) => v.caseId), cases: out.cases }; },
    claim: "the stale-import probe flags exactly the specifier that resolves to nothing, accepts ./b, and skips the bare package import" },

  { slot: 145, target: KST, expected: { ok: true, action: "hash-files", task: { taskId: "e1", action: "hash-files", files: ["a.txt", "b.txt"] } },
    run: (m) => { const r = m.envelopeToKrattTask(env()); return { ok: r.ok, action: r.action, task: r.task }; },
    claim: "an envelope allowing only hash-files maps its scope onto a closed KRATT hash-files task" },
  { slot: 146, target: KST, expected: { ok: true, task: { taskId: "e1", action: "run-test", testFile: "kratt/tests/x.test.ts", timeoutMs: 60000, maxOutputBytes: 2048 } },
    run: (m) => { const r = m.envelopeToKrattTask(env({ allowed_actions: ["run-test"], scope: ["kratt/tests/x.test.ts"], resource_budget: { max_wall_ms: 90000, max_output_bytes: 2048, max_files: 1 } })); return { ok: r.ok, task: r.task }; },
    claim: "a run-test envelope clamps a 90 s wall budget to KRATT's 60 s maximum and carries the output cap through" },
  { slot: 147, target: KST, fn: "envelopeToKrattTask", input: [env({ allowed_actions: ["hash-files", "run-test"] })], expected: { ok: false, reason: "envelope-must-allow-exactly-one-kratt-action" },
    claim: "an envelope authorising two KRATT actions is refused (one task = one authorised action)" },
  { slot: 148, target: KST, fn: "envelopeToKrattTask", input: [env({ forbidden_actions: ["hash-files"] })], expected: { ok: false, reason: "action-forbidden" },
    claim: "an action that is both allowed and forbidden is forbidden (forbidden wins)" },
  { slot: 149, target: DSP, expected: { code: "illegal-transition:SLEEP->ACTIVE", state: "SLEEP", log: [{ seq: 1, from: "SLEEP", to: "ACTIVE", accepted: false, reason: "illegal-transition:SLEEP->ACTIVE" }] },
    run: async (m) => { const { buildInitialRegistry } = await import("../../../factory/registry.ts"); const d = new m.Dispatcher(buildInitialRegistry({}), { clock: () => "T" }); let code = null; try { d.transition("FORGE-026", "ACTIVE"); } catch (e) { code = e.code; } return { code, state: d.worker("FORGE-026").state, log: d.log.map((l) => ({ seq: l.seq, from: l.from, to: l.to, accepted: l.accepted, reason: l.reason })) }; },
    claim: "a sleeping worker cannot jump to ACTIVE: the edge is rejected, the worker stays SLEEP, and the rejected attempt is logged" },
  { slot: 150, target: DSP, expected: { code: "no-task-no-wake", state: "SLEEP", logged: { accepted: false, reason: "no-task-no-wake" } },
    run: async (m) => { const { buildInitialRegistry } = await import("../../../factory/registry.ts"); const d = new m.Dispatcher(buildInitialRegistry({}), { clock: () => "T" }); let code = null; try { d.transition("FORGE-026", "READY"); } catch (e) { code = e.code; } return { code, state: d.worker("FORGE-026").state, logged: { accepted: d.log[0].accepted, reason: d.log[0].reason } }; },
    claim: "waking a worker with no task bound to it is refused ('no task, no wake') and logged" },
];
