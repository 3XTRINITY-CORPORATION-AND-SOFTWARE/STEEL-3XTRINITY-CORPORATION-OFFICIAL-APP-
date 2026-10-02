// 250x validation matrix harness. 250 means 250 SLOTS (checks), not 250 edits.
// A slot is PASS only if a registered check actually ran and succeeded.
// Everything else stays NOT_IMPLEMENTED; NOT_IMPLEMENTED is never counted as PASS.
import { readFileSync, existsSync } from "node:fs";

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

export function slotId(n) {
  return String(n).padStart(3, "0");
}

export function runMatrix(checks = CHECKS) {
  const slots = [];
  for (let n = 1; n <= 250; n++) {
    const g = GROUPS.find((x) => n >= x.from && n <= x.to);
    const c = checks[n];
    const base = { id: slotId(n), group: g.name, owner: g.owner };
    if (!c) {
      slots.push({ ...base, status: "NOT_IMPLEMENTED", input: "-", expected: "-", actual: "no check registered", evidence: "-" });
      continue;
    }
    try {
      const actual = c.run();
      slots.push({ ...base, status: "PASS", input: c.input, expected: c.expected, actual: String(actual), evidence: `check:${slotId(n)}` });
    } catch (e) {
      slots.push({ ...base, status: "FAIL", input: c.input, expected: c.expected, actual: String(e.message), evidence: `check:${slotId(n)}` });
    }
  }
  return slots;
}

export function summarize(slots) {
  const s = { PASS: 0, FAIL: 0, BLOCKED: 0, NOT_IMPLEMENTED: 0 };
  for (const x of slots) s[x.status]++;
  return { total: slots.length, ...s };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const slots = runMatrix();
  const sum = summarize(slots);
  console.log(JSON.stringify(sum));
  if (process.argv.includes("--json")) console.log(JSON.stringify(slots, null, 2));
  process.exit(sum.FAIL > 0 ? 1 : 0);
}
