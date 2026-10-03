# Matrix connection (250x)

`node scripts/matrix250/matrix.mjs --emit factory/matrix-results.json --emit-factory factory/factory-matrix.json` re-runs every check and every
spec and writes the two files. Nothing in them is typed by hand; `scripts/matrix250/matrix.test.mjs` requires the committed files to equal a fresh run.

## Three different numbers (never conflate them)

| Metric | Meaning |
| --- | --- |
| `pass` / `executed` | The slot's checks ran and passed. `executed = pass + fail`. For a slot that has **no** own spec, PASS only means "one named, pre-existing test (`scripts/matrix250/test-registry.mjs`) passed". That mapping is generic: it proves the named test, not the slot's behaviour. |
| **SPECIFIED_SLOTS** (`specified_slots`) | Slots that have their **own, unique assertion spec** (definition below). |
| **DOMAIN_VERIFIED** (`domain_verified`) | Specified slots whose assertion **ran against the real domain code and passed, with evidence** (definition below). |

`named_test_only_pass` = PASS slots that are not SPECIFIED, i.e. PASS resting only on the generic named-test mapping. A generic or shared named
test **never** counts towards SPECIFIED_SLOTS or DOMAIN_VERIFIED.

### SPECIFIED (strict)
A slot is SPECIFIED only if all of these hold:

1. It has exactly one spec in `factory/matrix/specs/*.mjs` (`{slot, target, fn+input | run, expected, claim}`), written as a literal expected value or behaviour, never "whatever the code returns".
2. The spec is statically valid: slot is an integer 1..250 with no second spec; `target` is a repo-relative, existing file that is *domain code* (not the harness `factory/matrix`, `scripts/matrix250`, a `*.test.*` file or `node_modules`); exactly one of `fn` (with an `input` array) or `run`; `expected` present; `claim` is a real sentence (>= 20 chars). Data targets (`package.json`, workflows, `.nvmrc`, ...) must use a `run` probe.
3. Its **assertion fingerprint** is unique. The fingerprint is `sha256(canonical {target, fn, input, expected, normalised run-source})`. The slot number and the claim text are *not* inputs, so renaming the id or rewording the claim of a copy-pasted assertion collides with the original; whitespace-insensitive for probe source; function values are hashed by source.
4. Its **behaviour fingerprint** is unique. It is `sha256({target, set of target code blocks V8 actually executed, expected})`, so two probes that differ cosmetically but drive the same code path to the same expectation also collide (for probes that run a CLI through `ctx.execTarget`, the path is not observable in-process and the behaviour fingerprint falls back to the assertion fingerprint).

A slot whose spec is invalid, duplicated or colliding is **not** SPECIFIED and every colliding slot loses the credit (none is "the original"). Violations are listed in the CLI output and fail it (exit 1).

### DOMAIN_VERIFIED (strict)
SPECIFIED **and**, in this very run, the harness (`factory/matrix/runner.mjs`, a child process per spec file):

- imported the real target module (the instrumented module the probe receives is the real export object, wrapped only in counting Proxies);
- observed **>= 1 call into that module** (a probe that computes its answer without calling the target is rejected: "no call into the target module was observed");
- deep-compared the actual result with the written `expected` and they were equal;
- and the slot's overall status is PASS. Evidence is `spec:<slot>:<target>#<fn>:<16-hex digest of the actual result>`.

If a slot's own spec fails, the slot is FAIL, even if its legacy named test passes. Failing never turns into a PASS elsewhere.

## Reporting rule
`headline()` prints measured counts only: `executed X/250; PASS Y/250 (of which N rest only on a generic named-test mapping); SPECIFIED_SLOTS S/250; DOMAIN_VERIFIED D/250`.
"250/250" can only appear for a metric whose measured value is exactly 250 (tests cover partial, empty and full runs). `matrix-results.json` has exactly
`{total, executed, pass, fail, blocked, not_implemented, specified_slots, domain_verified, named_test_only_pass}`, validated by `validateResults`
(`pass+fail+blocked+not_implemented = total`, `domain_verified <= specified_slots <= total`, `domain_verified <= pass`, `named_test_only_pass + domain_verified <= pass`).
`factory-matrix.json` is `matrix_version` 3 and adds `headline`, per-group counts and `unspecified_slots`.

## Uniqueness checker
`scripts/matrix250/specs.test.mjs` fails if any two slots share an assertion fingerprint (or behaviour fingerprint), if a slot has two specs, if any real spec has no
observed call or does not match, and runs the whole spec set with every `expected` replaced by an impossible sentinel (`--mutate`): all 250 must fail,
proving the comparison is real. `validateSpecs` / `combineEntries` (in `factory/matrix/spec-lib.mjs`) are also tested with synthetic copy-paste duplicates.

## Spec files (by group)
`config-build.mjs` (1-4, 50, 51: node pin / scripts / CI wiring), `build-runtime.mjs` (5-49: `with-app-env`, migration plan, atomic write, preview), `security-trust.mjs` (52-100:
auth invariant, sign-out plan, sign-in gate, gate-identity JWT), `kratt.mjs` (101-129), `rastik-factory.mjs` (130-150), `cerberus.mjs` (151-200),
`pwa-asset.mjs` (201-250: PWA shared helpers, plugin, brand check). To add or change a slot: edit its spec, run the emit command, commit the regenerated JSON.

## Evidence that the specs bite (mutation experiment, one defect at a time, restored afterwards)
10 deliberate defects in real code were each caught by at least one spec: TÖEPÄRA self-verified check removed (9 slots), KRATT evidence threshold `pass>=1` (slot 125), preview `pid>1` (40),
gate-identity max-token-age removed (100), sign-out `outcome!=="ok"` (74, 75), PWA `&` escape removed (201, 219, 234, 239), policy allowlist merge (159, 175, 189, 190, 142),
KRATT path dotfile segment (105), dispatcher SLEEP->ACTIVE (149), RÄSTIK re-run guard (139).

## Honest limits
- The repository never defines per-slot requirements beyond the five group names (50 slots each). Slot-to-domain assignment follows the earlier sequential mapping of slots to test files. SPECIFIED therefore means *"this slot has its own unique, discriminating assertion against real code"*, not *"covers a requirement that is written elsewhere"*.
- The legacy named-test mapping (`test-registry.mjs`) is still executed on top of the specs as regression evidence; both must pass for PASS.
- Specs assert behaviour of code owned by other workstreams (read-only here). If that behaviour changes, the affected spec turns red; update the spec deliberately, never loosen it to fit.
- Documentation never converts a slot.
