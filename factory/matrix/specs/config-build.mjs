/* eslint-disable @typescript-eslint/ban-ts-comment -- the harness is untyped JS over dynamic target modules; tsconfig.cerberus.json type-checks factory/ with checkJs */
// @ts-nocheck
// BUILD/RUNTIME configuration slots (1-4, 50, 51): the real config artefacts are the domain code under test.
const lines = (t) => t.split("\n");
const stepNames = (yml) => lines(yml).map((l) => l.match(/^\s*- name:\s*(.+?)\s*$/)).filter(Boolean).map((m) => m[1]);

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
    run: (m) => { const n = stepNames(m.text); const idx = (s) => n.indexOf(s); const order = ["Validate devcontainer JSON", "Install", "Typecheck", "Build", "Test"].map(idx); return { gateOrder: order.every((i, k) => i >= 0 && (k === 0 || i > order[k - 1])), usesNpmCi: /run:\s*npm ci\b/.test(m.text), devcontainerFirst: n[0] === "Validate devcontainer JSON" }; },
    claim: "CI runs validate-devcontainer, install, typecheck, build, test in that order, installs with npm ci, and the devcontainer gate is the first step" },
  { slot: 50, target: ".nvmrc", expected: { nvmrcMajorEqualsFirstCiNode: true, numeric: true },
    run: async (m) => { const { readFileSync } = await import("node:fs"); const nv = m.text.trim().replace(/^v/, "").split(".")[0]; const ci = readFileSync(".github/workflows/ci.yml", "utf8").match(/node-version:\s*["']?(\d+)/); return { nvmrcMajorEqualsFirstCiNode: ci !== null && ci[1] === nv, numeric: /^\d+$/.test(nv) }; },
    claim: "the .nvmrc Node major equals the first node-version in ci.yml (the runtime pin cannot drift from CI)" },
  { slot: 51, target: ".github/workflows/ci.yml", expected: { "ci.yml": false, "codeql.yml": false, "security-deception.yml": false },
    run: async (m) => { const { readFileSync } = await import("node:fs"); const has = (f) => lines(readFileSync(`.github/workflows/${f}`, "utf8")).some((l) => !l.trim().startsWith("#") && /continue-on-error/.test(l)); void m; return { "ci.yml": has("ci.yml"), "codeql.yml": has("codeql.yml"), "security-deception.yml": has("security-deception.yml") }; },
    claim: "no active line in ci, codeql or security-deception workflows uses continue-on-error (no gate is allowed to fail softly)" },
];
