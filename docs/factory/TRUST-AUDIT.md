# Where trust is caller-supplied, hardcoded or mocked (cerberus / kratt / rastik)

Method: `rg -n '"ADMITTED"|"AUTHORIZED"|stubAdapter|toepara: *"|trustGate: *"|caller-supplied' cerberus kratt rastik` at the base of this PR,
plus `rg -n '\bdecide\(|decideWithAdapters\(|runKrattTask\(|gateArtifact\('` to find non-test callers.
Result of the second search: **no production caller of `decide`, `decideWithAdapters`, `runKrattTask` or `gateArtifact` existed outside tests and rastik probes** before the factory closed loop.

| # | Location | What is trusted | Class | Status in this slice |
|---|---|---|---|---|
| 1 | `cerberus/core/decide.ts:26-27,106-107,154` `decide(input)` | `input.toepara === "ADMITTED"` and `input.trustGate === "AUTHORIZED"` are plain caller strings; Cerberus cannot know where they came from | **caller-supplied trust** (by design, documented in CONTRACT.md) | Not used by the closed loop. Left in place: it is the unit-level API exercised by `cerberus/tests` and `rastik` probes. Anyone wiring `decide()` into a real path would reintroduce self-authorisation. |
| 2 | `cerberus/integrations/verdict-adapters.ts:61` `stubAdapter(name, fixed)` | returns a fixed verdict | **mock** | Legit test double. The closed loop does not call it. |
| 3 | `kratt/run.ts` `KrattDeps.trustGate` (mandatory param) + `kratt/tests/kratt.test.ts:28` `AUTH = stubAdapter("trust-gate","AUTHORIZED")` | Trust Gate verdict is whatever adapter the caller passes | **caller-supplied trust** (an honest caller passes the real client; none exists) | Closed loop replaces it with `localPolicyTrustGate`, which computes AUTHORIZED/DENIED from the envelope + receipt (read-only action set, merge/deploy forbidden, repository match). Still a local policy, not the real Trust Gate. |
| 4 | `kratt/evidence.ts:61` `computeVerdict` + `:192-193` KRATT's TÖEPÄRA adapter returns `"ADMITTED"` | The verdict is derived from facts, but the facts (artifact SHA-256s, check counts) are the producer's own report; the "TÖEPÄRA" adapter is KRATT code validating KRATT output and never re-reads a file | **self-verification** (derived, not hardcoded; origin unproven) | Closed loop: `factory/toepara.ts` recomputes digests from `git cat-file blob <base_sha>:<path>`, the diff, the task digest and (run-test) re-executes the test. KRATT's `verdict` is carried but never used as authority. |
| 5 | `rastik/probes.ts` (29, 97-124, 221, 246), `rastik/tests/rastik.test.ts:69` | literal `ADMITTED`/`AUTHORIZED` fixtures and `stubAdapter`s | **test fixtures / mocks** | Legit: they are the attack inputs and the sanity baselines. |
| 6 | `cerberus/tests/*`, `kratt/tests/*` | literal verdicts | **test fixtures / mocks** | Legit. |
| 7 | `kratt/evidence.ts` `ReplayGuard` | replay protection | in-memory, per process | Unchanged (known limit). The closed loop uses one guard per process. |

## What replaced caller-supplied trust in the closed loop (and only there)
* TÖEPÄRA verdict: Cerberus' adapter re-runs `toeparaVerify` and accepts only a byte-identical recomputed bundle (`factory/cerberus-gate.ts`); the TÖEPÄRA result handed in by the caller is used for nothing but diagnostics.
* Trust Gate verdict: computed locally from policy, never passed in.
* KRATT `verification_state` is always `UNVERIFIED`; a receipt claiming otherwise is REJECTED.

## TÖEPÄRA independence + shallow/partial checkouts (this slice, stacked on trust-hardening)
Independence evidence (`factory/tests/toepara-independence.test.ts`, 6 tests):
* Source boundary test: `factory/toepara.ts` may import only `cerberus/core/decide` (canonicalize), `kratt/actions` (executeTask, for run-test re-execution), `kratt/evidence` (`parseEvidence` + type only), `kratt/task` (taskDigest), `./git`, `./kratt-stage`, `./protocol/types`, `./rastik-types`. It must not import `kratt/run`, `computeVerdict`, `ReplayGuard`, `createToeparaAdapter`, `evidenceToArtifact`, must not read KRATT's `.verdict` field, and neither it nor `git.ts` may read files directly. `git.ts` is limited to `cat-file`, `diff`, `rev-parse`, `config`, `ls-tree`.
* Bundle `source_digests` of a VERIFIED result equal an independent `git cat-file` + sha256 computed in the test.
* Table of 11 self-consistent forgeries (evidenceDigest re-sealed): none VERIFIED. A genuine KRATT receipt with no git to recompute from is not VERIFIED.
* **Finding fixed here (R-IND-1):** for `hash-files`, KRATT's claimed `checks.pass` was not tied to anything TÖEPÄRA recomputed, so an inflated count (re-sealed) was VERIFIED. TÖEPÄRA now requires `checks.pass == |scope|` and `checks.fail == 0` (regression test: "KRATT verdict/checks inflated"). `validate-manifest` check counts are still only cross-checked KRATT-evidence vs KRATT-result, not recomputed from the committed manifest (open).

Shallow / partial checkouts (`factory/tests/git-shallow.test.ts`, 7 tests, real `git clone --depth 1` and `--filter=blob:none` over file://):
* Base commit absent and checkout is shallow => `INSUFFICIENT_EVIDENCE` (`base-commit-unavailable:shallow-checkout`), never VERIFIED; dependent checks are skipped (no derived noise). CERBERUS then FAIL_CLOSED/DENY.
* Unknown commit in a full clone => still REJECTED (`base-sha-unknown-commit`).
* Partial clone (commit present, blob object missing) => `INSUFFICIENT_EVIDENCE` (`base-blob-unavailable:<path>`). git runs with `GIT_NO_LAZY_FETCH=1`, so TÖEPÄRA never triggers a network fetch. A path absent from the commit stays REJECTED (`source-not-in-base-sha`).
* Not implemented (optional): an explicit, opt-in `fetch <sha>` to deepen a shallow checkout. Callers must deepen/fetch before invoking the loop.
* `factory/tests/snapshot.test.ts` still treats `base-commit-unavailable` as a skip; it was outside this slice's lease and not edited.

Host-trust limit (documented, not tested): `ctx.rerun` is a host-supplied cache for run-test re-execution. A poisoned cache from the host process would be trusted; TÖEPÄRA's independence is from KRATT, not from its own host.

## Still not solved (honest)
* Evidence is hashed, not signed. Whoever can rewrite a receipt, recompute every digest AND rewrite the git object database can forge it. Signing needs a key: **human gate**.
* The RÄSTIK report handed to TÖEPÄRA is integrity-checked (digest, bound to the receipt digest) but not authenticated.
* `run-test` re-execution by TÖEPÄRA reuses KRATT's bounded runner: independent invocation, not independent implementation. Node's permission model has no network control.
* `decide()` caller-supplied API still exists (item 1).
