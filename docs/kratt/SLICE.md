# KRATT real-execution slice v1

```
task -> validateTask (closed schema, fail closed)
     -> allow-listed bounded execution (hash-files | validate-manifest | run-test)
     -> TÖEPÄRA evidence (verdict computed from facts of the run)
     -> Cerberus decideWithAdapters (policy + TÖEPÄRA + Trust Gate + artifact trust) -> receipt
```

Code: `kratt/{task,paths,actions,evidence,run}.ts`. Tests: `kratt/tests/kratt.test.ts`
(run by `npm test`; typechecked by `npm run typecheck` via `tsconfig.cerberus.json`).

## Actions (allow-list; nothing else is expressible in the schema)
| action | does | writes | network |
|---|---|---|---|
| `hash-files` | SHA-256 of 1..64 repo-relative files (8 MiB each, 32 MiB total) | none | none |
| `validate-manifest` | strict-parse a JSON manifest `{version:1, files:[{path,sha256}]}` and verify every listed hash | none | none |
| `run-test` | `node --permission --allow-fs-read=<root> --experimental-test-isolation=none --experimental-strip-types --test-reporter=tap --test <file>` | denied by Node permission model | **not blocked** (see limits) |

The task cannot carry a command, argv, env, URL or output path. `run-test` uses `spawn(process.execPath, fixedArgv, {shell:false, env:{}, cwd:root})`, a hard timeout (100 ms..60 s, SIGKILL), an output cap (1 KiB..1 MiB, SIGKILL on exceed), only test files named `*.test.ts|mjs` inside `cerberus/tests` or `kratt/tests` (host-configurable, never from the task). The test file is hashed before and after the run; a change fails the run. Exit 0 with zero real tests (including the "file reported as one pseudo-test" case) is rejected.

## Evidence (`toepara-evidence/v1`)
Canonical JSON: taskId, action, taskDigest, `command` (exact argv; node binary and root path replaced by `node` / `<root>` so evidence is machine-independent), exitCode, timedOut, truncated, outputBytes, stdout/stderr SHA-256, artifacts (name, SHA-256, bytes), checks {pass,fail}, failure, verdict, evidenceDigest. `computeVerdict` is the only place a verdict is decided: ADMITTED iff exit 0, no timeout/truncation, no failure, `fail==0`, `pass>=1`, >=1 artifact. The Cerberus `artifact` is this document; the TÖEPÄRA adapter re-parses it strictly (key set, types, finite integers, sorted unique artifacts, canonical form), recomputes `evidenceDigest`, re-derives the verdict from the facts, and consumes the digest in a `ReplayGuard` (second presentation => REJECTED).

## Cerberus link
Action is always `detect`. `decideWithAdapters` ignores any caller `toepara`/`trustGate` fields; the Trust Gate adapter is a **mandatory** `KrattDeps` field (tests use `stubAdapter`; absent/throwing/other => FAIL_CLOSED). Invalid task => `malformedInputReceipt("kratt-task-invalid:<reason>")`. Receipt determinism: same normalized evidence + same adapters + fresh guard => byte-identical receipt (no timestamps anywhere). `hash-files` and `validate-manifest` evidence is itself deterministic; `run-test` evidence contains output digests that vary run to run (TAP durations), so its receipts differ per run.

## Assumptions
- Stacked on PR #39 (needs `decideWithAdapters`); PR targets `cerberus/hardening-v1` so the diff is KRATT-only; GitHub retargets to `main` once #39 merges.
- `.ts`/`.mjs` test files in the allow-listed dirs are trusted repo code. The sandbox limits damage; it does not make hostile test code safe.

## Limits (honest)
- **Network is not restricted** (Node 22 permission model has no network control).
- **Evidence is integrity-hashed, not signed.** Anyone able to rewrite evidence and recompute all digests can forge it (test `LIMITATION ...` records this). Needs a signing key / real TÖEPÄRA service.
- `ReplayGuard` is in-memory, per process; no persistence across restarts.
- Trust Gate: only a stub exists. No real client.
- `run-test` trusts the TAP summary printed by trusted test code and the exit code.
- Linux/macOS only paths assumed (`/` separators in task paths).

## Defect found by the slice's own tests
`--experimental-test-isolation=none` reports an empty test file as one passing entry (`ok 1 - file.test.mjs`, `# pass 1`). Fixed in `isFileLevelPseudoTest`; regression: "DENIES a file that runs zero tests".
