# Matrix connection (250x)

`node scripts/matrix250/matrix.mjs --emit factory/matrix-results.json --emit-factory factory/factory-matrix.json` re-runs every check and every
spec and writes the two files. Nothing in them is typed by hand; `scripts/matrix250/matrix.test.mjs` requires the committed files to equal a fresh run.

## The numbers (never conflate them)

| Metric | Meaning |
| --- | --- |
| `pass` / `executed` | The slot's checks ran and passed. `executed = pass + fail`. For a slot that has **no** own spec, PASS only means "one named, pre-existing test (`scripts/matrix250/test-registry.mjs`) passed". That mapping is generic: it proves the named test, not the slot's behaviour. |
| **SPECIFIED_SLOTS** (`specified_slots`) | Slots that have their **own, unique assertion spec** (definition below). |
| **DOMAIN_VERIFIED** (`domain_verified`) | Specified slots whose assertion **executed real domain code, whose result fed the assertion, and passed** (definition below). Config-only slots are excluded. |
| **CONFIG_PINNED** (`config_pinned`) | Specified, passing slots whose spec pins a **configuration / data artefact** (`package.json`, lockfile, workflow, `.nvmrc`, devcontainer) or is declared `config: true`. No domain code is under test, so they are **never** DOMAIN_VERIFIED. `domain_verified + config_pinned <= specified_slots`. |
| **SHARED_PATH** (`shared_path_slots`) | Specified slots whose observed executed-code path is identical to at least one other slot's (they test different inputs/outputs through the same code). Reported, not hidden; a group larger than 8 slots is a violation. It is a transparency metric, not a credit. |
| **GUARD_PROBES** (`guard_probes`, `guard_probes_passed`) | Regression guards in `factory/matrix/guards/*.mjs` (ids 1001+). They are **not slots**: they never count towards PASS, SPECIFIED or DOMAIN_VERIFIED. They pin behaviour found by the independent audit of PR #54 that no slot asserts. |

`named_test_only_pass` = PASS slots that are not SPECIFIED, i.e. PASS resting only on the generic named-test mapping. A generic or shared named
test **never** counts towards SPECIFIED_SLOTS, DOMAIN_VERIFIED or CONFIG_PINNED.

### SPECIFIED (strict)
A slot is SPECIFIED only if all of these hold:

1. It has exactly one spec in `factory/matrix/specs/*.mjs` (`{slot, target, fn+input | run, expected, claim}`), written as a literal expected value or behaviour, never "whatever the code returns".
2. The spec is statically valid: slot is an integer 1..250 with no second spec; `target` is a repo-relative, existing file that is *domain code* (not the harness `factory/matrix`, `scripts/matrix250`, a `*.test.*` file or `node_modules`); exactly one of `fn` (with an `input` array) or `run`; `expected` present; `claim` is **a text of at least 20 characters** (that is the only check: the checker cannot judge whether it is a meaningful sentence; uniqueness of the claim text is asserted by `specs.test.mjs`, quality is review's job). Data targets (`package.json`, workflows, `.nvmrc`, ...) must use a `run` probe.
3. Its **assertion fingerprint** is unique. The fingerprint is `sha256(canonical {target, fn, input, expected, normalised run-source})`. The slot number and the claim text are *not* inputs, so renaming the id or rewording the claim of a copy-pasted assertion collides with the original. The probe source (and any function-valued input) is **normalised with the TypeScript scanner: all comments and all whitespace are dropped** and the tokens are re-joined, so adding a comment or reformatting cannot make a duplicate look unique. String, regex and template literal contents are kept verbatim.
4. Its **behaviour fingerprint** is unique. It is `sha256({target, set of repo code blocks V8 actually executed, expected})`. The set covers **all repo code executed while the assertion ran** (V8 precise block coverage), not only the target file; it excludes `node_modules`, `factory/matrix` and `scripts/matrix250`. Coverage of child processes started through `ctx.execTarget` is included (`NODE_V8_COVERAGE`), so CLI slots have an observable path too. Only the data/config slots (1, 2, 3, 4, 50, 51) have no observable path and fall back to the assertion fingerprint.

A slot whose spec is invalid, duplicated or colliding is **not** SPECIFIED and every colliding slot loses the credit (none is "the original"). Violations are listed in the CLI output and fail it (exit 1).

### DOMAIN_VERIFIED (strict)
SPECIFIED, not config-only, **and**, in this very run, the harness (`factory/matrix/runner.mjs`, a child process per spec file):

- imported the real target module (the module the probe receives has the real exports, wrapped only in counting Proxies);
- observed **>= 1 call into that module** (a probe that makes no call is rejected: "no call into the target module was observed");
- deep-compared the actual result with the written `expected` and they were equal;
- for `run` probes, passed the **dependence check**. This is real but bounded: (1) the probe is run a second time unchanged and must give the identical answer ("probe is not repeatable" otherwise); (2) it is then run against a *neutralised* target (functions return `undefined`, constructors return `{}`, exported constants are perturbed, data text is empty, `ctx.execTarget` returns an empty result without spawning) and the answer must **differ or throw**; if it is identical the result does not depend on the target (a constant returned after a call, e.g. `m.f("x"); return "CONST"`) and the spec fails with "result does not depend on the target". `fn` specs feed by construction (the result IS the call result). What the check cannot prove: that the probe exercises the *interesting* branch, which is what the mutation table below measures;
- and the slot's overall status is PASS.

Evidence is `spec:<slot>:<target>[#<fn>]:<16-hex digest of the actual result>`: the `#<fn>` part is present for `fn` specs only; `run` probes carry no function name.

If a slot's own spec fails, the slot is FAIL, even if its legacy named test passes. Failing never turns into a PASS elsewhere.

### CONFIG_PINNED
Slots 1, 2, 3, 4, 10, 50, 51 are inherently configuration pins: the artefact itself (devcontainer, `package.json` scripts, lockfile, CI workflow, `.nvmrc`, plus slot 10 declared `config: true`) is what is asserted. They are specified and pass with evidence, but they test that a file says the right thing, not that code behaves. They are reported as CONFIG_PINNED and subtracted from DOMAIN_VERIFIED.

### Regression guards (not slots)
`factory/matrix/guards/{security-trust,kratt,pwa-asset,build-runtime}.mjs` export `GUARDS` with ids 1001-1012. They run through the same runner and uniqueness rules but are never slots and never inflate a metric; all must pass and none may duplicate a slot's assertion. Covered: JWKS key type (crv Ed25519), JWT algorithm pin, issuer check, blank/padded `sub` (1001-1004); KRATT total byte budget and manifest duplicate/self-listing guard (1005-1006); brand-check size limit and `isInstallQuery` (1007-1008); preview SIGKILL escalation, `parsePgid(0)` and spawn-error exit 127 (1009, 1010, 1012); 1011 pins a known gap (below).

## Reporting rule
`headline()` prints measured counts only: `executed X/250; PASS Y/250 (of which N rest only on a generic named-test mapping); SPECIFIED_SLOTS S/250; DOMAIN_VERIFIED D/250; CONFIG_PINNED C/250; SHARED_PATH P/250 slots; GUARD_PROBES g/t`.
"250/250" can only appear for a metric whose measured value is exactly 250 (tests cover partial, empty and full runs). `matrix-results.json` has exactly
`{total, executed, pass, fail, blocked, not_implemented, specified_slots, domain_verified, config_pinned, shared_path_slots, guard_probes, guard_probes_passed, named_test_only_pass}`, validated by `validateResults`
(`pass+fail+blocked+not_implemented = total`, `domain_verified + config_pinned <= specified_slots <= total`, `domain_verified <= pass`, `config_pinned <= pass`, `named_test_only_pass + domain_verified + config_pinned <= pass`, `shared_path_slots <= specified_slots`, `guard_probes_passed <= guard_probes`).
`factory-matrix.json` is `matrix_version` 4 and adds `headline`, per-group counts (incl. `config_pinned`), `config_pinned_slots`, `shared_path_groups`, `guard_probes` and `unspecified_slots`.
Consumers of the results file must expect the four new keys.

## Uniqueness checker
`scripts/matrix250/specs.test.mjs` fails if any two slots share an assertion fingerprint (or behaviour fingerprint), if a slot has two specs, if any real spec has no
observed call or does not match, if a constant-after-call probe is accepted, and runs the whole spec set with every `expected` replaced by an impossible sentinel (`--mutate`): all 250 must fail.
**What `--mutate` shows:** only that the harness' comparison is real (a wrong expected value cannot pass). It does **not** show that specs discriminate between correct and defective code; that is what the mutation table below measures.
`validateSpecs` / `combineEntries` (in `factory/matrix/spec-lib.mjs`) are also tested with synthetic copy-paste duplicates, comment-only variations and shared-path groups.

Not caught by design: two probes that differ only in literals but drive the same code path are reported as SHARED_PATH (34 slots in 13 groups today), not rejected, up to 8 slots per path. Identical paths with different inputs are legitimate (different boundary values), so the metric makes the overlap visible instead of guessing intent.

## Spec files (by group)
`config-build.mjs` (1-4, 50, 51: node pin / scripts / CI wiring), `build-runtime.mjs` (5-49: `with-app-env`, migration plan, atomic write, preview), `security-trust.mjs` (52-100:
auth invariant, sign-out plan, sign-in gate, gate-identity JWT), `kratt.mjs` (101-129), `rastik-factory.mjs` (130-150), `cerberus.mjs` (151-200),
`pwa-asset.mjs` (201-250: PWA shared helpers, plugin, brand check). To add or change a slot: edit its spec, run the emit command, commit the regenerated JSON.
The harness is type-checked (`factory/matrix/types.d.ts` + JSDoc under `tsconfig.cerberus.json`, no `@ts-nocheck`). The one deliberate untyped boundary is the dynamically imported target module (`any`).

## Evidence that the specs bite (mutation table, one defect at a time, restored afterwards)
`factory/matrix/mutants.mjs` lists 49 mutants; `node scripts/matrix250/mutation-check.mjs [--set <set>] [--only 1,2]` applies each one to the real source, runs the group's specs and all guards, expects at least one failure and restores the file byte-identically (about 4 minutes; deliberately not part of `npm test`; `specs.test.mjs` checks every row anchors on exactly one occurrence). Sets: `builder` (the 10 defects of the original PR), `audit-targeted` (23) and `audit-subtle` (14) (the auditor's 37, of which the original PR killed 25) and `audit-slot-weakness` (2: `handOver` never renames; an always-false flag function). Last full run: **49/49 killed** (builder 10/10, audit-targeted 23/23, audit-subtle 14/14, audit-slot-weakness 2/2); the auditor's 37 are 37/37 and the builder's 10 are 10/10.

## Findings recorded
- **`stagingError` does not refuse `public/` itself as a staging source** (only paths strictly inside it): `scripts/write-atomic.mjs` is not owned by this workstream. Guard 1011 *characterises* the current behaviour (it is a pin of a known gap, not an endorsement); when the code is tightened, flip guard 1011.
- The audit's weak slots 33 (`handOver`) and 52 (flag function) were strengthened; slots 1, 2, 3, 4, 10, 50, 51 are config pins and are now labelled so instead of counted as domain verification.

## Honest limits
- The repository never defines per-slot requirements beyond the five group names (50 slots each). Slot-to-domain assignment follows the earlier sequential mapping of slots to test files. SPECIFIED therefore means *"this slot has its own unique, discriminating assertion against real code"*, not *"covers a requirement that is written elsewhere"*.
- The legacy named-test mapping (`test-registry.mjs`) is still executed on top of the specs as regression evidence; both must pass for PASS.
- Specs assert behaviour of code owned by other workstreams (read-only here). If that behaviour changes, the affected spec turns red; update the spec deliberately, never loosen it to fit.
- The dependence check is a stub-run heuristic: a probe could still read a value the stub also reproduces, and a probe that discriminates nothing important passes it. Mutation results are the stronger evidence, and 49 mutants are a sample, not a proof.
- Documentation never converts a slot.
