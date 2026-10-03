// BUILD/RUNTIME configuration slots (1-4, 50, 51): the real config artefacts are the domain code under test.
const lines = (/** @type {any} */ t) => t.split("\n");
const stepNames = (/** @type {any} */ yml) => lines(yml).map((/** @type {any} */ l) => l.match(/^\s*- name:\s*(.+?)\s*$/)).filter(Boolean).map((/** @type {any} */ m) => m[1]);

/** @type {import("../types.d.ts").Spec[]} */
export const SPECS = [
  { slot: 1, target: ".devcontainer/devcontainer.json", expected: { name: "STEEL", nodeFeature: "22", singleDocument: true },
    run: (m) => { const j = JSON.parse(m.text); return { name: j.name, nodeFeature: j.features["ghcr.io/devcontainers/features/node:1"].version, singleDocument: m.text.trim().startsWith("{") && m.text.trim().endsWith("}") }; },
    claim: "the devcontainer parses as one JSON document named STEEL pinning the Node 22 feature" },
  { slot: 2, target: "package.json", expected: { typecheckRunsTsc: true, testRunsNodeTest: true, buildUsesVite: true, type: "module" },
    run: (m) => { const j = JSON.parse(m.text); return { typecheckRunsTsc: j.scripts.typecheck.startsWith("tsc --noEmit"), testRunsNodeTest: j.scripts.test.startsWith("node --test"), buildUsesVite: j.scripts.build.includes("vite build"), type: j.type }; },
    claim: "package.json typecheck starts with tsc --noEmit, test starts node --test, build runs vite build, and the package is ESM" },
  { slot: 3, target: "package-lock.json", expected: { lockfileVersion: 3, rootNameMatchesPackage: true },
    run: async (m) => { const { readFileSync } = await import("node:fs"); const lock = JSON.parse(m.text); const pkg = JSON.parse(readFileSync("package.json", "utf8")); return { lockfileVersion: lock.lockfileVersion, rootNameMatchesPackage: lock.packages[""].name === pkg.name }; },
    claim: "the lockfile is lockfileVersion 3 and its root package is the same package as package.json" },
  { slot: 4, target: ".github/workflows/ci.yml", expected: { gateOrder: true, usesNpmCi: true, devcontainerFirst: true },
    run: (m) => { const n = stepNames(m.text); const idx = (/** @type {any} */ s) => n.indexOf(s); const order = ["Validate devcontainer JSON", "Install", "Typecheck", "Build", "Test"].map(idx); return { gateOrder: order.every((i, k) => i >= 0 && (k === 0 || i > order[k - 1])), usesNpmCi: /run:\s*npm ci\b/.test(m.text), devcontainerFirst: n[0] === "Validate devcontainer JSON" }; },
    claim: "CI runs validate-devcontainer, install, typecheck, build, test in that order, installs with npm ci, and the devcontainer gate is the first step" },
  { slot: 50, target: ".nvmrc", expected: { nvmrcMajorEqualsFirstCiNode: true, numeric: true },
    run: async (m) => { const { readFileSync } = await import("node:fs"); const nv = m.text.trim().replace(/^v/, "").split(".")[0]; const ci = readFileSync(".github/workflows/ci.yml", "utf8").match(/node-version:\s*["']?(\d+)/); return { nvmrcMajorEqualsFirstCiNode: ci !== null && ci[1] === nv, numeric: /^\d+$/.test(nv) }; },
    claim: "the .nvmrc Node major equals the first node-version in ci.yml (the runtime pin cannot drift from CI)" },
  { slot: 51, target: ".github/workflows/ci.yml", expected: { ciHasGateSteps: true, "ci.yml": false, "codeql.yml": false, "security-deception.yml": false },
    run: async (m) => { const { readFileSync } = await import("node:fs"); const has = (/** @type {any} */ t) => lines(t).some((/** @type {any} */ l) => !l.trim().startsWith("#") && /continue-on-error/.test(l)); return { ciHasGateSteps: stepNames(m.text).length >= 5, "ci.yml": has(m.text), "codeql.yml": has(readFileSync(".github/workflows/codeql.yml", "utf8")), "security-deception.yml": has(readFileSync(".github/workflows/security-deception.yml", "utf8")) }; },
    claim: "no active line in ci, codeql or security-deception workflows uses continue-on-error (no gate is allowed to fail softly); ci.yml is parsed (>= 5 named steps) so the negative result is not an empty read" },
];
