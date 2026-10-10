# Matrix distinctness review (base a63c632)

Scope: the slots that were still weak after the #54 audit (236/250 discriminating). On a63c632 the harness itself
reported them: `node scripts/matrix250/matrix.mjs --json` gave DOMAIN_VERIFIED 243, CONFIG_PINNED 7 (slots 1, 2, 3, 4,
10, 50, 51) and SHARED_PATH 34 slots in 13 groups. This change does not chase 250. It fixes the slots that were real
duplicates or config-only, and it records why the remaining overlaps are legitimate.

## Measured counts (command: `node scripts/matrix250/matrix.mjs --json`, first line)

| metric | a63c632 | this branch |
|---|---|---|
| EXECUTED | 250 | 250 |
| SPECIFIED | 250 | 250 |
| DOMAIN_VERIFIED | 243 | 247 |
| CONFIG_PINNED | 7 | 3 (3, 4, 10) |
| SHARED_PATH | 34 slots / 13 groups | 30 slots / 11 groups |
| PASS / FAIL / BLOCKED / NOT_IMPLEMENTED | 250 / 0 / 0 / 0 | 250 / 0 / 0 / 0 |

## Changed slots

Every changed slot has one objective, an explicit input, a literal expected value and a domain assertion. Its evidence
is the spec result in `factory/matrix-results.json` / `factory/factory-matrix.json`.

| slot | before | after (objective / input -> expected) | target |
|---|---|---|---|
| 1 | CONFIG: devcontainer JSON says STEEL / node 22 | The runtime-drift gate runs over the real repo declarations and returns `[]`. A devcontainer node feature of `20` returns `devcontainer-major-differs-from-nvmrc`; `lts` returns `devcontainer-node-not-numeric`. | `factory/rastik-attacks.ts` `runtimeDriftViolations`, `readRuntimeDeclarations` |
| 2 | CONFIG: package.json script prefixes (stale "node --test" claim) | `jsonDuplicateKeys(real package.json)` returns `[]`, and the `test` script is exactly `TEST_RUNNER_CMD`. A duplicated top-level key returns `["scripts"]`, a duplicated nested key returns `["scripts.test"]`, and invalid JSON returns `null`. | `factory/rastik-attacks.ts` |
| 36 | `restart` accepted: same path and same requirement as 35 (`stop` accepted) | `["restart","--now"]` returns `{error:"unexpected argument: --now"}`. This is the trailing-argument branch, which no other slot covered. | `scripts/preview.mjs` `parsePreviewArgs` |
| 50 | CONFIG: .nvmrc major equals the first ci.yml node-version | `verifyRuntime` on the real repo returns `RUNTIME_OK`. A fixture where only `.nvmrc` is 20 returns `RUNTIME_DRIFT`, with the drift source exactly `[".nvmrc"]`. | `scripts/runtime-verify.mjs` |
| 51 | CONFIG: text grep for continue-on-error | `configCollisionViolations(readConfigDeclarations("."))` returns `[]`. Adding `continue-on-error: true` to the ci.yml test step returns `workflow-continue-on-error:ci.yml`; adding `\|\| true` returns `workflow-run-gate-bypass:ci.yml`. | `factory/rastik-attacks.ts` |
| 52 | Exact 'false' only (4 values) | The same requirement, now also covering the 5 fail-safe values that slot 53 used to restate (unset, empty, 0, FALSE, no). | `scripts/check-auth-invariant.mjs` |
| 53 | Restated 52 on the same branch-free path | A 2xx `/__app-env` body that is JSON but not an object (`null`, `42`, `"false"`) probes as `null` (unobservable). This is the non-object branch, which no other slot covered. | `scripts/check-auth-invariant.mjs` `probeDevAuthEnabled` |

### Mutation evidence (one mutant per changed requirement)

Each mutant was run through `runSpecs` (the matrix spec run) against a63c632 specs and against this branch.

| mutant | code change | a63c632 matrix | this branch |
|---|---|---|---|
| M1 | drop the devcontainer-vs-nvmrc comparison | survives (250/250 ok) | slot 1 FAIL |
| M2 | `jsonDuplicateKeys` never records a duplicate | survives | slot 2 FAIL |
| M3 | `verifyRuntime` reports no drift | survives | slot 50 FAIL |
| M4 | drop the workflow continue-on-error check | survives | slot 51 FAIL |
| M5 | drop the workflow `\|\| true` check | survives | slot 51 FAIL |
| M6 | drop the non-object check in `probeDevAuthEnabled` | survives | slot 53 FAIL |
| M7 | drop the trailing-argument check in `parsePreviewArgs` | survives | slot 36 FAIL |
| M8 | `readRuntimeDeclarations` misses the devcontainer node feature | survives | slot 1 FAIL |
| M9 | empty string turns auth off | killed (old slot 53) | slot 52 FAIL (coverage kept after folding 53 into 52) |

## Remaining SHARED_PATH groups: reviewed and kept

These slots run the same instrumented lines with different inputs and assert different requirements. Most targets are
branch-free (string or array transforms), or delegate the decision to a library call whose options are the
requirement (jose). Merging these slots would hide requirements; giving them artificial branches would be cosmetic.

| group | why each slot is a separate requirement |
|---|---|
| 12, 13 | 12: the file value is applied. 13: an explicit process-env value wins over the file (precedence). |
| 18, 19, 22, 23 | 18: basename de-duplication across directories. 19: sort order. 22: the auth-before-steel_rows order on the real copied-up schema. 23: any iterable input, without mutating the caller's array. |
| 20, 21 | 20: non-.sql entries are filtered. 21: the real `migrations/` listing never globs `auth/`. |
| 29, 30 | 29: rename semantics (bytes replaced, staged file consumed). 30: a missing nested directory is created. |
| 55, 56 | The two divergence directions. Each one asserts its own on/off wording (a swapped-label mutant kills one), and 56 also asserts the `npm run dev` remedy. |
| 98, 99, 100 | Audience binding, required `exp`, and expiry/max-age. The library enforces them through the options the target passes. |
| 151, 153, 165, 169, 176 | PROCEED and all stages pass; digest sensitivity to the artifact; unknown keys ignored; the exact allowed-action set; receipt evidence content. |
| 157, 158, 159, 167 | The toepara stage alone; the trustGate stage alone; policy-denied actions; case/whitespace/vocabulary variants of AUTHORIZED. |
| 177, 178 | Digest independence and tamper kinds; input-digest sensitivity to each of the six fields. |
| 202, 205 | Title-casing the first label; the first entry of a forwarded list with its port removed. |
| 212, 213 | iOS triggers the install tutorial (case-insensitive); android does not (iOS-only). |

## Remaining CONFIG_PINNED (honest)

- **3** (lockfile v3, root package name) and **4** (CI step order, `npm ci`, devcontainer gate first): no repo code
  enforces these properties, so the artefact itself is what the slot asserts.
- **10**: declared `config: true`. It pins the workspace's real `.grok/app-env.json` value.
