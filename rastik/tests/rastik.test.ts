import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { decide } from "../../cerberus/core/decide.ts";
import { decideWithAdapters } from "../../cerberus/integrations/verdict-adapters.ts";
import { parseEvidence } from "../../kratt/evidence.ts";
import { validateTask } from "../../kratt/task.ts";
import { changedFiles } from "../changed.ts";
import {
  probeCerberusAdapters, probeCerberusHostileInput, probeKrattEvidence, probeKrattTask, probeReceiptIntegrity,
  probeStaleImport, probeWorkflowGates, REAL_TARGETS, resolveSpecifier, type Targets,
} from "../probes.ts";
import { hasFailures, renderReport, runRastik, selectProbes } from "../run.ts";
import type { Probe } from "../types.ts";

const temps: string[] = [];
after(() => temps.forEach((t) => rmSync(t, { recursive: true, force: true })));
function tree(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "rastik-t-"));
  temps.push(root);
  for (const [rel, c] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), c);
  }
  return root;
}
const ids = async (probe: Probe, root = ".", files: string[] = []) =>
  (await runRastik({ root, files, probes: [probe], all: true })).findings.map((f) => f.id);

describe("RÄSTIK against the real KRATT/CERBERUS code", () => {
  it("runs all selected probes: hundreds of cases, 0 confirmed findings, 0 probe errors", async () => {
    const r = await runRastik({ root: process.cwd(), files: ["cerberus/core/decide.ts", "kratt/task.ts"], base: "test", head: "test" });
    assert.deepEqual(r.findings, []);
    assert.equal(r.probes.filter((p) => p.error).length, 0);
    assert.ok(r.casesExecuted >= 300, `cases=${r.casesExecuted}`);
    assert.equal(hasFailures(r), false);
    assert.match(r.evidence.evidenceDigest, /^[0-9a-f]{64}$/);
    assert.match(renderReport(r), /0 CONFIRMED findings/);
  });

  it("evidence is deterministic for identical inputs", async () => {
    const run = () => runRastik({ root: process.cwd(), files: ["kratt/task.ts"], base: "b", head: "h" });
    assert.equal((await run()).evidence.evidenceDigest, (await run()).evidence.evidenceDigest);
  });
});

describe("probes detect planted defects (mutation check of RÄSTIK itself)", () => {
  const withT = (over: Partial<Targets>): Targets => ({ ...REAL_TARGETS, ...over });

  it("cerberus-hostile-input: case-insensitive verdict (fail-open)", async () => {
    const t = withT({
      decide: (i) => {
        const o = i as { toepara?: unknown };
        return typeof o?.toepara === "string" && o.toepara === "admitted" ? { decision: "PROCEED" } : decide(i);
      },
    });
    assert.ok((await ids(probeCerberusHostileInput(t))).some((f) => f.endsWith("toepara-lowercase")));
  });

  it("cerberus-hostile-input: decide() that throws on hostile input", async () => {
    const t = withT({ decide: (i) => { if (typeof i === "bigint") throw new Error("boom"); return decide(i); } });
    assert.ok((await ids(probeCerberusHostileInput(t))).some((f) => f.endsWith("bigint")));
  });

  it("cerberus-adapter-failopen: adapters ignored / caller verdicts honoured", async () => {
    const t = withT({ decideWithAdapters: ((i: unknown, _a: unknown) => decide({ ...(i as object), toepara: "ADMITTED", trustGate: "AUTHORIZED" })) as typeof decideWithAdapters });
    const f = await ids(probeCerberusAdapters(t));
    assert.ok(f.some((x) => x.endsWith("caller-verdicts-ignored")));
    assert.ok(f.some((x) => x.includes("toepara-null")));
  });

  it("cerberus-receipt-integrity: verifyReceipt that always says true", async () => {
    const f = await ids(probeReceiptIntegrity(withT({ verifyReceipt: () => true })));
    assert.ok(f.length > 20);
  });

  it("kratt-task-schema: NaN accepted, boundary off-by-one", async () => {
    const t = withT({
      validateTask: (i) => {
        const o = i as { timeoutMs?: number };
        return Number.isNaN(o?.timeoutMs) ? { ok: true } : validateTask(i);
      },
    });
    assert.ok((await ids(probeKrattTask(t))).some((f) => f.includes("timeoutMs-NaN")));
    const off = withT({
      validateTask: (i) => {
        const o = i as { timeoutMs?: number };
        return o?.timeoutMs === 60_001 ? { ok: true } : validateTask(i);
      },
    });
    assert.ok((await ids(probeKrattTask(off))).some((f) => f.includes("boundary-timeoutMs-60001")));
  });

  it("kratt-evidence-mutation: parser that skips the digest check", async () => {
    const t = withT({ parseEvidence: (c) => { const r = parseEvidence(c); return r.ok || (typeof c === "string" && c.startsWith("{") && c.includes('"evidenceDigest"')) ? { ok: true } : r; } });
    const f = await ids(probeKrattEvidence(t));
    assert.ok(f.some((x) => x.includes("stale-digest")));
  });

  it("every confirmed finding carries RISK / REPRODUCTION / COMPONENT / FIX / REGRESSION TEST", async () => {
    const r = await runRastik({ root: ".", files: [], all: true, probes: [probeReceiptIntegrity(withT({ verifyReceipt: () => true }))] });
    assert.ok(r.findings.length > 0);
    for (const f of r.findings) {
      assert.equal(f.status, "CONFIRMED");
      for (const k of ["risk", "reproduction", "affectedComponent", "smallestFix", "regressionTest"] as const) assert.ok(f[k].length > 10, k);
    }
    assert.equal(hasFailures(r), true);
    assert.match(renderReport(r), /REGRESSION TEST:/);
  });
});

describe("stale-import probe", () => {
  it("flags an import that resolves to nothing; accepts real, index, .js->.ts and alias imports", async () => {
    const root = tree({
      "src/a.ts": 'import x from "./gone.ts";\nimport y from "./b";\nimport z from "./dir";\nimport w from "./c.js";\nimport q from "@/lib/q";\nimport "node:fs";\nimport pkg from "react";',
      "src/b.ts": "export {}", "src/dir/index.ts": "export {}", "src/c.ts": "export {}", "src/lib/q.ts": "export {}",
    });
    const f = await ids(probeStaleImport, root, ["src/a.ts"]);
    assert.deepEqual(f, ["RASTIK-stale-import-src-a-ts-gone-ts"]);
  });

  it("REGRESSION (defect in RÄSTIK found on real repo): Vite ?raw / ?url / #hash suffixes are not stale", async () => {
    const root = tree({ "src/a.ts": 'import u from "./s.css?url";\nimport r from "../p/i.html?raw";\nimport h from "./s.css#x";', "src/s.css": "", "p/i.html": "" });
    assert.deepEqual(await ids(probeStaleImport, root, ["src/a.ts"]), []);
    assert.ok(resolveSpecifier(root, "src/a.ts", "./s.css?url"));
    assert.equal(resolveSpecifier(root, "src/a.ts", "./nope.css?url"), null);
  });
});

describe("workflow-gate probe", () => {
  it("flags continue-on-error / || true / audit fix --force; ignores comments and clean files", async () => {
    const root = tree({
      ".github/workflows/bad.yml": "jobs:\n  a:\n    steps:\n      - run: npm test || true\n        continue-on-error: true\n      - run: npm audit fix --force\n      # continue-on-error: true\n",
      ".github/workflows/ok.yml": "jobs:\n  a:\n    steps:\n      - run: npm test\n",
    });
    const f = await ids(probeWorkflowGates, root, [".github/workflows/bad.yml", ".github/workflows/ok.yml"]);
    assert.equal(f.length, 3);
    assert.ok(f.every((x) => x.includes("bad-yml")));
  });
});

describe("runner semantics", () => {
  it("a probe that throws is an error that fails the run (never a pass); no applicable probe => 0 cases", async () => {
    const boom: Probe = { id: "boom", category: "fail-open", component: "x", smallestFix: "x", applies: () => true, run: async () => { throw new Error("kaput"); } };
    const r = await runRastik({ root: ".", files: ["a.ts"], probes: [boom] });
    assert.match(r.probes[0].error ?? "", /probe-threw:kaput/);
    assert.equal(hasFailures(r), true);
    const none = await runRastik({ root: ".", files: ["README.md"], probes: [boom] });
    assert.equal(selectProbes(["README.md"], [boom], false).length, 1); // boom.applies is always true
    assert.equal((await runRastik({ root: ".", files: ["README.md"], probes: [probeStaleImport] })).casesExecuted, 0);
    assert.equal(none.probes.length, 1);
  });

  it("a violation that does not reproduce on re-run is unconfirmed, not a finding", async () => {
    let n = 0;
    const flaky: Probe = { id: "flaky", category: "boundary", component: "x", smallestFix: "x", applies: () => true,
      run: async () => ({ cases: 1, violations: [{ caseId: "c", expected: "e", observed: "o", reproduction: "r", recheck: () => ++n < 0 }] }) };
    const r = await runRastik({ root: ".", files: [], probes: [flaky], all: true });
    assert.equal(r.findings.length, 0);
    assert.equal(r.probes[0].unconfirmed, 1);
  });
});

describe("changedFiles (git diff, fixed argv)", () => {
  it("rejects refs that could be parsed as options or ranges", () => {
    for (const ref of ["", "--upload-pack=x", "-x", "a..b", "a b", "a;id", "$(id)", "x".repeat(101)])
      assert.throws(() => changedFiles(ref, "."), /invalid-base-ref/, ref);
  });

  it("lists added/modified files between base and HEAD in a throwaway repo", () => {
    const root = tree({ "a.txt": "1" });
    const env = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
    const g = (...a: string[]) => assert.equal(spawnSync("git", a, { cwd: root, env, encoding: "utf8" }).status, 0, a.join(" "));
    g("init", "-q", "-b", "base"); g("add", "."); g("commit", "-q", "-m", "1");
    g("checkout", "-q", "-b", "feat");
    writeFileSync(join(root, "b.txt"), "2"); writeFileSync(join(root, "a.txt"), "changed");
    g("add", "."); g("commit", "-q", "-m", "2");
    assert.deepEqual(changedFiles("base", root), ["a.txt", "b.txt"]);
    assert.throws(() => changedFiles("nonexistent-ref", root), /git-diff-failed/);
  });
});

