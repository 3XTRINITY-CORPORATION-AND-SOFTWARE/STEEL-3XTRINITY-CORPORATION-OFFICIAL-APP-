// 250x validation matrix harness. 250 means 250 SLOTS (checks), not 250 edits.
// A slot is PASS only if every check registered for it actually ran and succeeded.
// Everything else stays NOT_IMPLEMENTED; NOT_IMPLEMENTED is never counted as PASS.
//
// TWO different things are measured and must never be conflated (definitions: docs/factory/MATRIX.md):
//   PASS            = the slot's check(s) ran and succeeded. For a slot with no spec this is only "one named, existing
//                     test passed" - a generic mapping that says nothing about the slot's own behaviour.
//   SPECIFIED_SLOTS = slots with their OWN unique assertion spec (factory/matrix/specs/*): unique assertion
//                     fingerprint and unique behaviour fingerprint across all slots.
//   DOMAIN_VERIFIED = SPECIFIED slots whose assertion, in this run, called real domain code and matched the written
//                     expected value (evidence: spec:<slot>:<target>:<result digest>).
import { runSpecs, EMPTY_SPEC_RUN } from "./specs.mjs";
import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { TEST_REGISTRY } from "./test-registry.mjs";

export const STATES = ["PASS", "FAIL", "BLOCKED", "NOT_IMPLEMENTED"];

export const GROUPS = [
  { from: 1, to: 50, name: "BUILD/RUNTIME", owner: "TESTER" },
  { from: 51, to: 100, name: "SECURITY/TRUST", owner: "SECURITY" },
  { from: 101, to: 150, name: "KRATT/TOEPARA", owner: "KRATT" },
  { from: 151, to: 200, name: "CERBERUS/RECOVERY", owner: "CERBERUS" },
  { from: 201, to: 250, name: "PWA/ASSET/INTEGRATION", owner: "INTEGRATOR" },
];

const json = (p) => JSON.parse(readFileSync(p, "utf8"));

// slot number -> { input, expected, run() } ; run() returns an evidence string or throws.
export const CHECKS = {
  1: {
    input: ".devcontainer/devcontainer.json",
    expected: "parses as one JSON document",
    run: () => (json(".devcontainer/devcontainer.json"), "JSON.parse ok"),
  },
  2: {
    input: "package.json",
    expected: "parses and defines typecheck, build and test scripts",
    run: () => {
      const s = json("package.json").scripts ?? {};
      for (const k of ["typecheck", "build", "test"]) if (!s[k]) throw new Error(`missing script ${k}`);
      return "scripts typecheck/build/test present";
    },
  },
  3: {
    input: "package-lock.json",
    expected: "lockfile exists and parses",
    run: () => `lockfileVersion=${json("package-lock.json").lockfileVersion}`,
  },
  4: {
    input: ".github/workflows/ci.yml",
    expected: "CI validates devcontainer JSON",
    run: () => {
      if (!readFileSync(".github/workflows/ci.yml", "utf8").includes("Validate devcontainer JSON")) throw new Error("gate missing");
      return "devcontainer gate step present";
    },
  },
  51: {
    input: ".github/workflows",
    expected: "no workflow uses continue-on-error",
    run: () => {
      for (const f of ["ci.yml", "codeql.yml", "security-deception.yml"]) {
        const p = `.github/workflows/${f}`;
        if (existsSync(p) && readFileSync(p, "utf8").includes("continue-on-error")) throw new Error(`${f} uses continue-on-error`);
      }
      return "no continue-on-error in ci/codeql/security-deception";
    },
  },
};


/**
 * Parse node:test TAP output into name -> verdict. A test is "ok" only when it is a plain
 * `ok` line; `# SKIP` / `# TODO` are reported separately so they can never count as PASS.
 * Duplicate names are kept as a list so ambiguity can be detected.
 */
export function parseTap(stdout) {
  const results = new Map();
  for (const line of stdout.split("\n")) {
    const m = line.match(/^\s*(not ok|ok) \d+ - (.*?)(?: # (SKIP|TODO)\b.*)?$/);
    if (!m) continue;
    const name = m[2].replace(/\\([\\#])/g, "$1");
    const verdict = m[3] ? m[3].toLowerCase() : m[1] === "ok" ? "ok" : "fail";
    if (!results.has(name)) results.set(name, []);
    results.get(name).push(verdict);
  }
  return results;
}

/** Run one test file once per runMatrix call; returns parsed TAP or an error description. */
export function makeFileRunner(spawn = spawnSync) {
  const cache = new Map();
  return (file) => {
    if (!cache.has(file)) {
      const args = ["--test", "--test-reporter=tap", file];
      if (file.endsWith(".ts")) args.unshift("--experimental-strip-types");
      // When this runs inside a parent `node --test`, NODE_TEST_CONTEXT makes a nested `--test`
      // emit in the parent's child-process protocol instead of TAP. Strip it so the child is standalone.
      const env = { ...process.env };
      delete env.NODE_TEST_CONTEXT;
      const r = spawn(process.execPath, args, { encoding: "utf8", timeout: 120_000, env });
      cache.set(file, r.error || r.stdout == null ? { error: String(r.error?.message ?? "no output") } : { results: parseTap(r.stdout) });
    }
    return cache.get(file);
  };
}

/** A slot whose evidence is one specific, already-existing named test case. */
export function testCheck(file, name, runFile, expected) {
  return {
    input: `${file} :: ${name}`,
    expected: typeof expected === "string" && expected.trim() !== "" ? expected : "named test case runs and reports ok (not skipped, not todo)",
    run: () => {
      const r = runFile(file);
      if (r.error) throw new Error(`could not run ${file}: ${r.error}`);
      const verdicts = r.results.get(name);
      if (!verdicts) throw new Error(`test not found in ${file}: ${name}`);
      if (verdicts.length !== 1) throw new Error(`ambiguous: ${verdicts.length} tests named "${name}" in ${file}`);
      if (verdicts[0] === "skip" || verdicts[0] === "todo") return { blocked: `test is ${verdicts[0].toUpperCase()}ped/pending in ${file}` };
      if (verdicts[0] !== "ok") throw new Error(`test failed: ${name}`);
      return "ok";
    },
    evidence: `test:${file}::${name}`,
  };
}

export function registryChecks(registry = TEST_REGISTRY, runFile = makeFileRunner()) {
  const out = {};
  for (const [slot, file, name, expected] of registry) {
    if (out[slot]) throw new Error(`duplicate registry slot ${slot}`);
    out[slot] = testCheck(file, name, runFile, expected);
  }
  return out;
}

export function allChecks(registry = TEST_REGISTRY) {
  const reg = registryChecks(registry);
  for (const k of Object.keys(reg)) if (CHECKS[k]) throw new Error(`slot ${k} registered twice (static + test registry)`);
  return { ...CHECKS, ...reg };
}

export function slotId(n) {
  return String(n).padStart(3, "0");
}

/**
 * Run all 250 slots. `specRun` carries the per-slot specification results (see specs.mjs). When `checks` is passed
 * explicitly (unit tests with synthetic checks) and no `specRun`, no real specs are run.
 * A slot's status combines every check registered for it: any FAIL => FAIL, any BLOCKED => BLOCKED,
 * otherwise PASS if at least one check ran, otherwise NOT_IMPLEMENTED.
 */
export function runMatrix(checks, specRun) {
  const useDefaults = checks === undefined;
  const cks = checks ?? allChecks();
  const spec = specRun ?? (useDefaults ? runSpecs() : EMPTY_SPEC_RUN);
  const byslot = new Map(spec.entries.map((e) => [e.slot, e]));
  const slots = [];
  for (let n = 1; n <= 250; n++) {
    const g = GROUPS.find((x) => n >= x.from && n <= x.to);
    const c = cks[n];
    const e = byslot.get(n);
    const base = { id: slotId(n), group: g.name, domain: g.name, owner: g.owner, blocker: "-", specified: false, domain_verified: false, named_test: "-", spec: "-" };
    if (!c && !e) {
      slots.push({ ...base, status: "NOT_IMPLEMENTED", input: "-", expected: "-", actual: "no check registered", evidence: "-" });
      continue;
    }
    // 1. the legacy mapping to one named, existing test (or static check)
    let legacy = null; // { status, actual, evidence }
    if (c) {
      const evidence = c.evidence ?? `check:${slotId(n)}`;
      try {
        const actual = c.run();
        legacy = actual && typeof actual === "object" && "blocked" in actual ? { status: "BLOCKED", actual: String(actual.blocked), evidence } : { status: "PASS", actual: String(actual), evidence };
      } catch (err) {
        legacy = { status: "FAIL", actual: String(err.message), evidence };
      }
    }
    // 2. the slot's own spec
    const isSpecified = spec.specified.has(n);
    const r = e?.result ?? null;
    const specStatus = !e ? null : r && r.ok ? "PASS" : "FAIL";
    const specEvidence = e && r && r.ok ? `spec:${slotId(n)}:${e.target}${e.fn ? `#${e.fn}` : ""}:${r.digest}` : null;

    const parts = [legacy?.status, specStatus].filter(Boolean);
    const status = parts.includes("FAIL") ? "FAIL" : parts.includes("BLOCKED") ? "BLOCKED" : "PASS";
    const rec = {
      ...base,
      status,
      specified: isSpecified,
      domain_verified: status === "PASS" && spec.domainVerified.has(n),
      named_test: legacy ? legacy.evidence : "-",
      spec: e ? e.claim : "-",
    };
    if (status === "BLOCKED") {
      slots.push({ ...rec, blocker: legacy.actual, input: c.input, expected: c.expected, actual: "not executed to a verdict", evidence: "-" });
    } else if (status === "FAIL") {
      const why = [legacy?.status === "FAIL" ? `named test: ${legacy.actual}` : null, specStatus === "FAIL" ? `spec: ${r?.error ?? "spec produced no result"}` : null].filter(Boolean).join(" | ");
      slots.push({ ...rec, input: e ? `${e.target}${e.fn ? `#${e.fn}` : ""}` : c.input, expected: e ? e.claim : c.expected, actual: why, evidence: specEvidence ?? legacy?.evidence ?? `spec:${slotId(n)}:failed` });
    } else if (e) {
      slots.push({ ...rec, input: `${e.target}${e.fn ? `#${e.fn}` : ""}`, expected: e.claim, actual: `matched expected; ${r.calls} call(s) into target; result digest ${r.digest}${legacy ? `; named test also ok (${legacy.evidence})` : ""}`, evidence: specEvidence });
    } else {
      slots.push({ ...rec, input: c.input, expected: c.expected, actual: legacy.actual, evidence: legacy.evidence });
    }
  }
  return slots;
}

/**
 * Integrity rules for a matrix. Returns a list of violation strings (empty = well-formed).
 * Says nothing about whether the checks are meaningful, only that the record is consistent.
 */
export function validateMatrix(slots) {
  const v = [];
  if (!Array.isArray(slots)) return ["matrix is not an array"];
  if (slots.length !== 250) v.push(`expected exactly 250 slots, got ${slots.length}`);
  const seen = new Set();
  const isText = (x) => typeof x === "string" && x.trim() !== "";
  slots.forEach((s, i) => {
    const where = `slot[${i}]${s && s.id ? ` ${s.id}` : ""}`;
    if (!s || typeof s !== "object") return v.push(`${where}: not an object`);
    for (const f of ["id", "domain", "owner", "input", "expected", "actual", "status", "evidence"]) {
      if (!isText(s[f])) v.push(`${where}: missing required field ${f}`);
    }
    if (isText(s.id)) {
      if (!/^\d{3}$/.test(s.id) || +s.id < 1 || +s.id > 250) v.push(`${where}: id must be 001..250`);
      else if (+s.id !== i + 1) v.push(`${where}: id out of order (expected ${slotId(i + 1)})`);
      if (seen.has(s.id)) v.push(`${where}: duplicate id`);
      seen.add(s.id);
    }
    if (!STATES.includes(s.status)) return v.push(`${where}: illegal status ${JSON.stringify(s.status)}`);
    const hasEvidence = isText(s.evidence) && s.evidence !== "-";
    if (s.status === "PASS") {
      if (!hasEvidence) v.push(`${where}: PASS requires evidence`);
      else if (!/^(check|test|spec):/.test(s.evidence)) v.push(`${where}: PASS evidence must be a check:/test:/spec: reference`);
    }
    if (s.status === "FAIL" && (!isText(s.actual) || s.actual === "-")) v.push(`${where}: FAIL requires actual`);
    if (s.status === "BLOCKED" && (!isText(s.blocker) || s.blocker === "-")) v.push(`${where}: BLOCKED requires blocker`);
    if (s.status === "BLOCKED" && hasEvidence) v.push(`${where}: BLOCKED cannot carry PASS evidence`);
    if (s.status === "NOT_IMPLEMENTED" && hasEvidence) v.push(`${where}: NOT_IMPLEMENTED cannot carry evidence`);
    if (s.domain_verified === true && !(s.status === "PASS" && s.specified === true && /^spec:/.test(String(s.evidence)))) v.push(`${where}: domain_verified requires a PASS, specified slot with spec: evidence`);
    if (s.specified === true && (!isText(s.spec) || s.spec.trim().length < 20)) v.push(`${where}: specified slot needs its written claim`);
  });
  return v;
}

export function summarize(slots) {
  const s = { PASS: 0, FAIL: 0, BLOCKED: 0, NOT_IMPLEMENTED: 0 };
  for (const x of slots) s[x.status]++;
  return { total: slots.length, ...s, SPECIFIED: slots.filter((x) => x.specified === true).length, DOMAIN_VERIFIED: slots.filter((x) => x.domain_verified === true).length };
}

/**
 * Machine-readable results. `executed` counts slots whose check actually ran to a verdict (PASS + FAIL);
 * BLOCKED and NOT_IMPLEMENTED were not executed. The invariant pass+fail+blocked+not_implemented === total is
 * checked by validateResults, never assumed.
 * `specified_slots` and `domain_verified` are the strict metrics (see docs/factory/MATRIX.md). `pass` alone is NOT
 * evidence of per-slot behaviour: `named_test_only_pass` is the part of `pass` that rests solely on a generic
 * "one named existing test passed" mapping.
 */
export function toResults(slots) {
  const s = summarize(slots);
  return {
    total: s.total,
    executed: s.PASS + s.FAIL,
    pass: s.PASS,
    fail: s.FAIL,
    blocked: s.BLOCKED,
    not_implemented: s.NOT_IMPLEMENTED,
    specified_slots: s.SPECIFIED,
    domain_verified: s.DOMAIN_VERIFIED,
    named_test_only_pass: slots.filter((x) => x.status === "PASS" && x.specified !== true).length,
  };
}

/**
 * The only sentence the harness is allowed to use about its own numbers. It prints measured counts, and it can only
 * say "250/250" for a figure that is exactly 250 (the figure is never rounded, defaulted or carried over).
 */
export function headline(r) {
  return `executed ${r.executed}/${r.total}; PASS ${r.pass}/${r.total} (of which ${r.named_test_only_pass} rest only on a generic named-test mapping); SPECIFIED_SLOTS ${r.specified_slots}/${r.total}; DOMAIN_VERIFIED ${r.domain_verified}/${r.total}`;
}

/** Slots whose evidence comes from factory/ tests (or the registry-v3 slot 050), plus the real closed-loop task ids. */
export const FACTORY_SLOTS = [50, 145, 146, 147, 148, 149, 150];
export function toFactoryMatrix(slots, receipts) {
  const loops = Array.isArray(receipts?.closed_loops) ? receipts.closed_loops.filter((r) => r && typeof r.task_id === "string") : [];
  const results = toResults(slots);
  return {
    matrix_version: 3,
    note:
      "PASS means every check registered for the slot ran and succeeded; for a slot without its own spec that is only 'one named, already-existing test passed'. SPECIFIED_SLOTS counts slots with their own unique assertion spec (factory/matrix/specs); DOMAIN_VERIFIED counts those whose assertion ran against real domain code and matched with evidence. Counts come from scripts/matrix250/matrix.mjs, never from documentation.",
    headline: headline(results),
    summary: results,
    by_group: GROUPS.map((g) => {
      const inG = slots.filter((x) => x.group === g.name);
      return { group: g.name, slots: inG.length, pass: inG.filter((x) => x.status === "PASS").length, specified: inG.filter((x) => x.specified).length, domain_verified: inG.filter((x) => x.domain_verified).length };
    }),
    unspecified_slots: slots.filter((x) => !x.specified).map((x) => x.id),
    factory_slots: FACTORY_SLOTS.map((n) => {
      const s = slots[n - 1];
      return { id: s.id, status: s.status, specified: s.specified, domain_verified: s.domain_verified, expected: s.expected, evidence: s.evidence, named_test: s.named_test };
    }),
    closed_loops: loops.map((r) => ({ task_id: r.task_id, base_sha: r.base_sha, cerberus_decision: r.cerberus?.decision?.decision ?? null })),
  };
}

const RESULT_KEYS = ["total", "executed", "pass", "fail", "blocked", "not_implemented", "specified_slots", "domain_verified", "named_test_only_pass"];

/** Violations of a matrix-results object (empty = well-formed). Does not compare against a fresh run. */
export function validateResults(r) {
  const v = [];
  if (!r || typeof r !== "object" || Array.isArray(r)) return ["results is not an object"];
  const keys = Object.keys(r).sort();
  if (JSON.stringify(keys) !== JSON.stringify([...RESULT_KEYS].sort())) v.push(`keys must be exactly ${RESULT_KEYS.join(",")}, got ${Object.keys(r).join(",")}`);
  for (const k of RESULT_KEYS) if (!Number.isInteger(r[k]) || r[k] < 0) v.push(`${k} must be a non-negative integer`);
  if (v.length) return v;
  if (r.total !== 250) v.push(`total must be 250, got ${r.total}`);
  if (r.pass + r.fail + r.blocked + r.not_implemented !== r.total) v.push("pass+fail+blocked+not_implemented !== total");
  if (r.executed !== r.pass + r.fail) v.push("executed must equal pass+fail");
  if (r.domain_verified > r.specified_slots) v.push("domain_verified cannot exceed specified_slots");
  if (r.specified_slots > r.total) v.push("specified_slots cannot exceed total");
  if (r.domain_verified > r.pass) v.push("domain_verified cannot exceed pass");
  if (r.named_test_only_pass > r.pass) v.push("named_test_only_pass cannot exceed pass");
  if (r.named_test_only_pass + r.domain_verified > r.pass) v.push("named_test_only_pass + domain_verified cannot exceed pass");
  return v;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const specRun = runSpecs();
  const slots = runMatrix(allChecks(), specRun);
  const sum = summarize(slots);
  const problems = [...validateMatrix(slots), ...specRun.violations.map((x) => `spec: ${x}`)];
  console.log(JSON.stringify(sum));
  console.log(headline(toResults(slots)));
  if (problems.length) console.error(`INTEGRITY VIOLATIONS (${problems.length}):\n` + problems.join("\n"));
  if (process.argv.includes("--json")) console.log(JSON.stringify(slots, null, 2));
  const ei = process.argv.indexOf("--emit");
  if (ei !== -1) {
    const out = process.argv[ei + 1];
    if (!out || out.startsWith("--")) throw new Error("--emit needs an output path");
    const results = toResults(slots);
    const bad = validateResults(results);
    if (bad.length) throw new Error(`refusing to emit malformed results: ${bad.join("; ")}`);
    writeFileSync(out, JSON.stringify(results, null, 2) + "\n");
    console.log(`emitted ${out}`);
  }
  const fi = process.argv.indexOf("--emit-factory");
  if (fi !== -1) {
    const out = process.argv[fi + 1];
    if (!out || out.startsWith("--")) throw new Error("--emit-factory needs an output path");
    writeFileSync(out, JSON.stringify(toFactoryMatrix(slots, existsSync("factory/factory-receipts.json") ? json("factory/factory-receipts.json") : null), null, 2) + "\n");
    console.log(`emitted ${out}`);
  }
  process.exit(sum.FAIL > 0 || problems.length ? 1 : 0);
}
