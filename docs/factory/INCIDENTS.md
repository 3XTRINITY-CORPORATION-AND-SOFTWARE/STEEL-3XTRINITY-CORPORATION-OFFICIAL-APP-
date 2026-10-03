# Factory incidents

## STACKED_CONFIG_COLLISION

**Class:** two (or more) stacked PRs each edit the same single-line value in a JSON config (here the one-line `scripts.test` in `package.json`). Each PR is internally valid; the squash merge of the stack produces no conflict marker but leaves duplicate keys, so `package.json` has two or three `"test"` entries. JSON parsers silently keep the last one, so tests registered in the others stop running, and the config-json-integrity guard fails.

| # | Occurrence | Stack | Symptom | Detected by | Fixed by |
|---|---|---|---|---|---|
| 1 | main f429a20 after merging #50, #51, #56 (with the #52 line) | #50 / #51 / #52 each rewrote the `test` line | three `"test"` keys in `package.json`; Vite CI `ci` -> Test red | `scripts/config-json-integrity.test.mjs` "package.json parses without syntax errors and has no duplicate keys" | #58 (63e3332): one `test` script = union of the three, 2 unlisted tests added |
| 2 | main 1d7fb48 after merging #58, #59, #60 (Vite CI run 37106759630) | #60 was stacked on #58 and rewrote the same line (adding `factory/tests/status.test.ts`); the #59 squash had also dropped its own 7 test registrations | duplicate `"test"` at `package.json` lines 24 and 25; the 7 boundary tests from #57 were not registered, i.e. not run | same guard | this PR (`fix(main)`: `fix/main-test-dup-2`): one `test` script, the 7 files registered |

**Cause:** stacked PRs that touch the same one-line config value; a squash merge of a stack does not conflict on separate-but-adjacent lines, and the merged result is valid text with a semantic defect (duplicate key).

**Detection (existing, unchanged):** `config-json-integrity.test.mjs` fails on duplicate keys in `package.json`, `tsconfig*.json`, `factory/*.json`. It was correct both times and was not weakened.

**Recurrence guard (this PR), in the same test file:**
1. `STACKED_CONFIG_COLLISION` test: a synthetic `package.json` with two `test` keys is rejected (exactly one duplicate-key problem, three keys give two), a clean one is accepted.
2. Coverage guard: every `*.test.*` / `*.spec.*` file in the repo (excluding `node_modules`, `.git`, `dist`, `build`, `coverage`, ...) must be run by the `test` script **exactly once** (explicit path or the `scripts/**/*.test.mjs` glob), and the script may not name a missing file. A new unregistered test file fails CI instead of silently never running. A self-check test proves the guard flags an unregistered, a doubly-registered and a glob-anchored-wrong file.
3. Verified by mutation: original main `package.json` -> fails; one registration removed -> fails; new unregistered test file -> fails; a file registered twice -> fails.

**Process rule:** when a stacked PR must edit the shared `test` line, rebase onto the base branch's merged result and re-derive the union rather than carrying its own copy; the guard above is the backstop.
