// 250x validation matrix harness. 250 means 250 SLOTS (checks), not 250 edits.
// A slot is PASS only if a registered check actually ran and succeeded.
// Everything else stays NOT_IMPLEMENTED; NOT_IMPLEMENTED is never counted as PASS.
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

export function runMatrix(checks = allChecks()) {
  const slots = [];
  for (let n = 1; n <= 250; n++) {
    const g = GROUPS.find((x) => n >= x.from && n <= x.to);
    const c = checks[n];
    const base = { id: slotId(n), group: g.name, domain: g.name, owner: g.owner, blocker: "-" };
    if (!c) {
      slots.push({ ...base, status: "NOT_IMPLEMENTED", input: "-", expected: "-", actual: "no check registered", evidence: "-" });
      continue;
    }
    const evidence = c.evidence ?? `check:${slotId(n)}`;
    try {
      const actual = c.run();
      if (actual && typeof actual === "object" && "blocked" in actual) {
        slots.push({ ...base, status: "BLOCKED", blocker: String(actual.blocked), input: c.input, expected: c.expected, actual: "not executed to a verdict", evidence: "-" });
      } else {
        slots.push({ ...base, status: "PASS", input: c.input, expected: c.expected, actual: String(actual), evidence });
      }
    } catch (e) {
      slots.push({ ...base, status: "FAIL", input: c.input, expected: c.expected, actual: String(e.message), evidence });
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
      else if (!/^(check|test):/.test(s.evidence)) v.push(`${where}: PASS evidence must be check:/test: reference`);
    }
    if (s.status === "FAIL" && (!isText(s.actual) || s.actual === "-")) v.push(`${where}: FAIL requires actual`);
    if (s.status === "BLOCKED" && (!isText(s.blocker) || s.blocker === "-")) v.push(`${where}: BLOCKED requires blocker`);
    if (s.status === "BLOCKED" && hasEvidence) v.push(`${where}: BLOCKED cannot carry PASS evidence`);
    if (s.status === "NOT_IMPLEMENTED" && hasEvidence) v.push(`${where}: NOT_IMPLEMENTED cannot carry evidence`);
  });
  return v;
}

export function summarize(slots) {
  const s = { PASS: 0, FAIL: 0, BLOCKED: 0, NOT_IMPLEMENTED: 0 };
  for (const x of slots) s[x.status]++;
  return { total: slots.length, ...s };
}

/**
 * Machine-readable results. `executed` counts slots whose check actually ran to a verdict (PASS + FAIL);
 * BLOCKED and NOT_IMPLEMENTED were not executed. The invariant pass+fail+blocked+not_implemented === total is
 * checked by validateResults, never assumed.
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
  };
}

/** Slots whose evidence comes from factory/ tests (or the registry-v3 slot 050), plus the real closed-loop task ids. */
export const FACTORY_SLOTS = [50, 145, 146, 147, 148, 149, 150];
export function toFactoryMatrix(slots, receipts) {
  const loops = Array.isArray(receipts?.closed_loops) ? receipts.closed_loops.filter((r) => r && typeof r.task_id === "string") : [];
  return {
    matrix_version: 2,
    note:
      "PASS means exactly one named, already-existing test passed in this run; per-slot specifications for most slots do not exist, so the counts are provisional and do not prove each slot's whole domain. Counts come from scripts/matrix250/matrix.mjs, never from documentation.",
    summary: toResults(slots),
    factory_slots: FACTORY_SLOTS.map((n) => {
      const s = slots[n - 1];
      return { id: s.id, status: s.status, expected: s.expected, evidence: s.evidence };
    }),
    closed_loops: loops.map((r) => ({ task_id: r.task_id, base_sha: r.base_sha, cerberus_decision: r.cerberus?.decision?.decision ?? null })),
  };
}

const RESULT_KEYS = ["total", "executed", "pass", "fail", "blocked", "not_implemented"];

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
  return v;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const slots = runMatrix();
  const sum = summarize(slots);
  const problems = validateMatrix(slots);
  console.log(JSON.stringify(sum));
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
