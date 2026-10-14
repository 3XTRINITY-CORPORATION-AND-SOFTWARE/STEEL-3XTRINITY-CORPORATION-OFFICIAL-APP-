# Factory incidents

## STACKED_CONFIG_COLLISION

**Class:** two (or more) stacked PRs each edit the same single-line value in a JSON config (here the one-line `scripts.test` in `package.json`). Each PR is internally valid; the squash merge of the stack produces no conflict marker but leaves duplicate keys, so `package.json` has two or three `"test"` entries. JSON parsers silently keep the last one, so tests registered in the others stop running, and the config-json-integrity guard fails.

| # | Occurrence | Stack | Symptom | Detected by | Fixed by |
|---|---|---|---|---|---|
| 1 | main f429a20 after merging #50, #51, #56 (with the #52 line) | #50 / #51 / #52 each rewrote the `test` line | three `"test"` keys in `package.json`; Vite CI `ci` -> Test red | `scripts/config-json-integrity.test.mjs` "package.json parses without syntax errors and has no duplicate keys" | #58 (63e3332): one `test` script = union of the three, 2 unlisted tests added |
| 2 | main 1d7fb48 after merging #58, #59, #60 (Vite CI run 37106759630) | #60 was stacked on #58 and rewrote the same line (adding `factory/tests/status.test.ts`); the #59 squash had also dropped its own 7 test registrations | duplicate `"test"` at `package.json` lines 24 and 25; the 7 boundary tests from #57 were not registered, i.e. not run | same guard | this PR (`fix(main)`: `fix/main-test-dup-2`): one `test` script, the 7 files registered |
| 3 | main 6bcf1da after merging #62 (adds mutation tests to the `test` line) and #65 (adds 3 CRB-REC-01 test files; #65 was my early-pushed branch merged as pushed, based on d7793e5) | two PRs based on the same main each appended to the single-line `test` script; the second squash left a second `"test"` key | duplicate `test` at `package.json` lines 24/25 (the #61 guard) | `exec/cerberus-recovery` (CRB-REC-01): one `test` script = union (44 test files) |
| 4 | main 3af646f after merging #68 and #67 (Vite CI `ci` -> Test, duplicate-key gate) | #67 (based on an older main) and #68 each edited the single-line `test` script; the merge left two `"test"` keys at lines 24/25 (both lines identical) | the #61 guard | `fix/main-test-dup-3` (**structural**): `"test": "node scripts/run-tests.mjs"`; the runner discovers every `*.test.*` on disk, so PRs add tests without editing `package.json` |

**Cause:** stacked PRs that touch the same one-line config value; a squash merge of a stack does not conflict on separate-but-adjacent lines, and the merged result is valid text with a semantic defect (duplicate key).

**Detection (existing, unchanged):** `config-json-integrity.test.mjs` fails on duplicate keys in `package.json`, `tsconfig*.json`, `factory/*.json`. It was correct both times and was not weakened.

**Recurrence guard (this PR), in the same test file:**
1. `STACKED_CONFIG_COLLISION` test: a synthetic `package.json` with two `test` keys is rejected (exactly one duplicate-key problem, three keys give two), a clean one is accepted.
2. Coverage guard: every `*.test.*` / `*.spec.*` file in the repo (excluding `node_modules`, `.git`, `dist`, `build`, `coverage`, ...) must be run by the `test` script **exactly once** (explicit path or the `scripts/**/*.test.mjs` glob), and the script may not name a missing file. A new unregistered test file fails CI instead of silently never running. A self-check test proves the guard flags an unregistered, a doubly-registered and a glob-anchored-wrong file.
3. Verified by mutation: original main `package.json` -> fails; one registration removed -> fails; new unregistered test file -> fails; a file registered twice -> fails.

**Process rule:** when a stacked PR must edit the shared `test` line, rebase onto the base branch's merged result and re-derive the union rather than carrying its own copy; the guard above is the backstop.


## Structural fix for STACKED_CONFIG_COLLISION (after occurrence #4)
Four manual unions were not enough: any hand-maintained one-line list is a merge hotspot. `package.json` now has `"test": "node scripts/run-tests.mjs"` (short, stable, never edited again).

* `scripts/run-tests.mjs` discovers every `*.test.*` / `*.spec.*` file on disk (skipping `node_modules`, `.git`, `dist`, `build`, `coverage`, ...), sorted by code point. Runs `node --test <.mjs/.cjs/.js files>` first, then `node --experimental-strip-types --test <.ts/.mts/.cts files>` (same flags and `&&` semantics as before: a failing group's exit code is returned and the next group is not run; signal/spawn error => 1). An unsupported test extension (`.tsx`, ...) is an error, an empty suite is an error, and a nested run is refused (`RUN_TESTS_ACTIVE`). `--list` prints the plan. An explicit `EXCLUDE` map (empty) is the only opt-out and needs a reason per entry; non-test helpers/fixtures are simply not named `*.test.*`.
* `test:coverage` is unchanged (`c8 ... npm test`) and runs the same discovered set.
* Guards (`scripts/config-json-integrity.test.mjs`, strictly stronger than the former list check): duplicate-key detection (unchanged), `scripts.test` must equal the runner command, and the runner's discovery must equal an independent walk of the repo with every file run exactly once. `scripts/run-tests.test.mjs` covers discovery, order, exit propagation, fail-closed cases, end-to-end runs and the recursion guard.
* Rule for contributors: add `foo.test.ts` / `foo.test.mjs` and nothing else. Do not touch `package.json`'s `test` script.
