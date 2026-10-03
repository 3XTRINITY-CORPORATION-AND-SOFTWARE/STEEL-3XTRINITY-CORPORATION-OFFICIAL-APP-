# Trust hardening (stacked on #49): persistent replay, async Trust Gate, evidence authentication

What exists after this change, what is tested, and what is still a human gate. Nothing here makes TÖEPÄRA or the Trust Gate real services.

## 1. Persistent replay guard (`factory/replay-store.ts`, `FileReplayGuard`)
* `ReplayStore { consume(digest): boolean }`; `CerberusCtx.guard` and `LoopDeps.guard` accept any store. The in-memory kratt `ReplayGuard` still works (default).
* One marker file per 64-hex digest. Content is written + fsynced to a private temp file and published with `link(2)`; `EEXIST` means replay. Exactly one of any number of concurrent processes wins; a half-written marker is never visible; directory is fsynced. Survives restart.
* Fail closed: malformed digest, store path that is a symlink / plain file, unwritable store => `false` (never `true`).
* `FACTORY_REPLAY_DIR=<dir> npm run factory -- run-loop` uses it.
* Tests (`factory/tests/replay-persistent.test.ts`): restart on same dir, hostile digests/paths, **second Node process** consuming a digest first consumed by the parent (both orders), 8 concurrent processes => exactly one TRUE, end-to-end: CERBERUS ADMITs in-process then a **second process** presenting the same consumed bundle gets `DENY replayed-bundle` (a fresh store ADMITs, so the child is not vacuous).
* LIMITS: local POSIX filesystem shared by the processes; anyone who can delete markers can reset it; `link` on network filesystems is not guaranteed. Multi-host replay protection needs an external service (human gate).

## 2. Asynchronous Trust Gate (`factory/trust-gate.ts`)
* `AsyncTrustGate.evaluate(req): Promise<unknown>`; `resolveTrustGate` accepts only the exact strings `AUTHORIZED` / `DENIED`. Timeout, rejection, synchronous throw, any other value (lowercase, padded, objects, null, "ADMITTED"...), and an invalid timeout (<1, >60000, non-integer) all give `DENIED` with a reason (`trust-gate:timeout|threw|malformed-verdict|invalid-timeout|denied`). Timers are always cleared.
* `cerberusDecide` resolves the gate before the (synchronous) Cerberus pipeline. The local policy ALWAYS also applies: an external gate saying `AUTHORIZED` cannot override `policy:merge-not-forbidden` etc.
* Only a **stub** (`stubPolicyTrustGate`, a local policy) exists. No real Trust Gate service exists in any accessible repository.

## 3. Evidence authentication: abstraction only (`factory/signing.ts`)
* `SigningProvider { sign, verify }`, statuses `UNSIGNED | SIGNED | VERIFICATION_FAILED`. Default provider `none` => everything UNSIGNED; a presented signature that the provider cannot verify is `VERIFICATION_FAILED`.
* Signatures are domain-separated (`purpose` + subject digest). CERBERUS verifies against subjects it recomputes itself (the fresh TÖEPÄRA bundle digest; the RÄSTIK report digest recomputed from the report body, bound to the attacked receipt digest), never against the digest the signature claims.
* Policy: `CerberusCtx.signing = { provider, required }`. When `required`, UNSIGNED or VERIFICATION_FAILED bundle or RÄSTIK report => DENY, checked **before** the replay guard so a rejected bundle is not burned. `GateOutput.signature_status` always reports the honest status. Default (`required:false`, provider none) leaves behaviour unchanged and reports UNSIGNED.
* RÄSTIK report authentication uses the same abstraction (`purpose: "rastik-report"`); a report edited after signing, signatures swapped between artifacts, a signature by another key, or for another bundle all give VERIFICATION_FAILED.
* Test-only provider `factory/tests/ephemeral-provider.ts`: an ed25519 key pair generated per call inside the test process, held in closure only, never written. A static test asserts no `BEGIN ... PRIVATE KEY` literal anywhere under `factory/` and that production files do not call `generateKeyPair*`/`createPrivateKey`.
* **HUMAN GATES (not done, not faked):** choosing the production signing system (KMS/HSM/Sigstore/...), generating and custodying the key (never in this repo or in evidence artifacts), registering the verification key(s) with CERBERUS, and deciding to flip `required` to true in production. Until then `EVIDENCE_AUTHENTICATED` is false.

## Mutation checks (one mutation at a time, restored byte-identical, `node --experimental-strip-types --test` on the listed files)
Replay + Trust Gate + CERBERUS wiring (`replay-persistent`, `trust-gate`, `cerberus-gate` tests): 16 of 17 mutants killed in the first run. Survivors and what was done:
* equivalence probe I wrote (R2, a no-op text change): discarded, not a real mutant.
* R5 (write failure fails open): killed after adding the unwritable-store test (skipped only when run as root).
* T6 (unhandled late rejection): equivalent, `Promise.race` already subscribes to the call; the dead line was removed.
* T7 (timer never cleared): killed after adding the `clearTimeout` call-count test.
* C2 (invalid envelope: gate verdict AUTHORIZED): equivalent by design (TÖEPÄRA recompute rejects an invalid envelope independently); recorded, not killed.

Signing + CERBERUS signing policy (`signing`, `cerberus-gate` tests): 15 mutants; first run 12 killed. S4 (claimed subject not compared) and S9 (none provider verifies everything) were killed after adding the lenient-provider test; G5 (redundant late DENY) was equivalent with the adapter-level block, so the redundant line was removed. Final: all remaining mutants killed except C2 above.
