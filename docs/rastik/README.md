# RÄSTIK execution stage v1

`npm run rastik -- --base <git-ref> [--all] [--json]` (exit 0 clean, 1 confirmed findings or probe error, 2 usage).

Flow: `git diff --name-only <base>...HEAD` (fixed argv, ref validated) -> select probes by changed path -> run probes against the real code -> **re-run every violation once** -> CONFIRMED findings (RISK, REPRODUCTION, AFFECTED COMPONENT, SMALLEST FIX, REGRESSION TEST candidate) -> `rastik-evidence/v1` (changed files, per-probe case counts, finding ids, SHA-256; no timestamps).

| probe | category | applies to | what it does |
|---|---|---|---|
| cerberus-hostile-input | fail-open | `cerberus/**` | 35 hostile/near-miss inputs to `decide` must FAIL_CLOSED without throwing |
| cerberus-adapter-failopen | fail-open | `cerberus/**` | adapter returns Promise / boxed string / throws / missing / caller-supplied verdicts => must deny |
| cerberus-receipt-integrity | evidence-bypass | `cerberus/core/decide.ts` | every receipt leaf mutated => `verifyReceipt` false; junk => false |
| kratt-task-schema | non-finite, boundary, invalid-input | `kratt/**` | NaN/Infinity/float/string numbers, inclusive limit edges, path/action/extra-key corpus |
| kratt-evidence-mutation | evidence-bypass | `kratt/**` | every single-field mutation of real evidence (stale digest) + verdict flip with re-sealed digests + replay + missing evidence |
| kratt-path-escape | invalid-input | `kratt/**` | symlink file/dir escape, symlink loop, directory, FIFO (no hang), symlinked test dir |
| stale-import | stale-import | any changed `.ts/.tsx/.js/.mjs` | relative and `@/` imports must resolve (Vite `?url`/`?raw` suffixes stripped) |
| workflow-gate-weakening | fail-open | `.github/workflows/**` | `continue-on-error: true`, `\|\| true`, `audit fix --force`, `--no-verify`, `if: false` |

Honesty rules: a probe that throws fails the run; zero applicable probes reports 0 cases (not a pass); a violation that does not reproduce is counted as `unconfirmed` and is not a finding. `rastik/tests` plant defects (mutant targets) to prove each probe class can fail.

Limits: probes target known categories only; they do not find unknown defects. Each probe is bounded and in-process; `kratt-path-escape` uses temp dirs only. Findings are not auto-fixed.
