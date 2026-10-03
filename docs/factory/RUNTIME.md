# Runtime verification (Node pin)

`npm run runtime:verify` (= `node scripts/runtime-verify.mjs`, add `--json` for machine output) checks that every place that names a Node version agrees with one contract.
It is **read-only and offline**: it only reads files; it writes nothing, spawns nothing, uses no network and installs nothing (no nvm or other version-manager installer exists in this repo; the verifier only *reports*).
Output and exit code are deterministic: sources are listed in a fixed order.

## Contract (Node major 22)

| Source | Rule |
| --- | --- |
| `local node` | the running `node` is 22.x |
| `.nvmrc` | a numeric version whose major is 22 (`22`, `v22.3.0`); `lts/*` and the like are drift |
| `package.json` `engines.node` | a range that admits **every** 22.x and **nothing else**. `22.x`, `>=22 <23`, `^22`, `~22` pass; `>=22`, `>=20 <23`, `22.1.x`, `*`, `22 \|\| 24`, `20.x` are drift. Supported syntax: comparators, x-ranges, `^`, `~`, `\|\|` (anything else is reported as drift, not guessed) |
| `.github/workflows/*.yml` | **every** `actions/setup-node` step sets `node-version` to a literal 22 (or `node-version-file` naming a file that says 22). A step without a version, a matrix or `${{ }}` expression, or no setup-node step at all is drift |
| `.devcontainer/devcontainer.json` (if present) | the `features/node` feature has `version` 22 (no version = LTS default = drift); a `node`/`javascript-node`/`typescript-node` image tag and `build.args.NODE_VERSION\|NODE_MAJOR` must be 22. JSONC comments are tolerated |
| `Dockerfile*`, `.devcontainer/Dockerfile*`, `docker/Dockerfile*` (if present) | `FROM node:<tag>` (build-arg defaults are resolved) and `ARG NODE_VERSION\|NODE_MAJOR` must be 22; an unpinned `FROM node` / `node:latest` is drift |

Today the repo has no Dockerfile and one workflow with `setup-node`; those sources are simply absent from the report.

## Output

```
RUNTIME_OK expected node major 22 (5 sources agree)
  ok       local node: 22.23.3
  ...
```
```
RUNTIME_DRIFT expected node major 22 (2 of 5 sources mismatch)
  MISMATCH .nvmrc: found "20" - major 20, expected 22
  ok       package.json engines.node: 22.x
  MISMATCH .github/workflows/ci.yml:39 setup-node: found "20" - major 20, expected 22
```
Exit code 0 for `RUNTIME_OK`, 1 for `RUNTIME_DRIFT`. Every mismatch names its exact source (file:line for workflow steps and Dockerfile lines).

## Changing the Node major
Update all sources in one change, then the contract constant `EXPECTED_MAJOR` in `scripts/runtime-verify.mjs` (and `scripts/node-pin.test.mjs` which pins `engines.node` to `<major>.x`). The verifier then proves nothing was left behind.

## Tests
`scripts/runtime-verify.test.mjs` (covered by the `scripts/**/*.test.mjs` glob in `npm test`) uses temp-directory fixtures to prove that each mismatch kind is detected and named (local, `.nvmrc`, engines too wide / too narrow / wrong / missing, workflow wrong / matrix / expression / missing version / second workflow / none, `node-version-file`, devcontainer feature / image / build arg / unparseable, Dockerfile tag / unpinned / ARG / nested), that several mismatches are reported at once, that the real repository passes, that the CLI exits 1 on a drifted copy, and that the source contains no write, spawn or network API. Each detector was also mutation-checked by hand (removing the check makes a test fail).

## Limits
- It does not install, switch or fetch Node; it only compares declared versions with the running one.
- Only the Node major is compared, not minor/patch pins.
- YAML is read line-wise (no YAML parser dependency); anchors, reusable-workflow inputs and composite actions that set up Node elsewhere are not followed.
