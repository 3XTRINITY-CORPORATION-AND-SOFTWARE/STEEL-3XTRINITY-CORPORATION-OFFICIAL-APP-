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
* **HUMAN GATES (not done, not faked):** choosing the production signing system (KMS/HSM/Sigstore/...), generating and custodying the key (never in this repo or in evidence artifacts), registering the verification key(s) with CERBERUS, and deciding to flip `required` to true in production. Until then `EVIDENCE_AUTHENTICATED` is not full (see section 4: `partial`).

## 4. Receipt authentication (P2): ActionReceipt + CERBERUS decision receipts — interface + test key only

**Maturity: `EVIDENCE_AUTHENTICATED = partial`** (`factory/signing.ts`). Interface, Ed25519 verifier, fail-closed config and policy exist and are tested with an EPHEMERAL in-process key only. No production key, signer or KMS exists; key custody is a human gate. No production receipt is authenticated today.

* **Interface:** `ReceiptSigner { sign }` / `ReceiptVerifier { verify }` (`SigningProvider` = both). Detached `Signature` objects, domain-separated purposes `action-receipt` and `decision-receipt` (plus the existing `evidence-bundle`, `rastik-report`).
* **Subjects (recomputed by the verifier, never taken from the signature):** action receipt = `digestOf(validated receipt)` (timestamp included, so a re-timestamped replay invalidates the signature); decision receipt = `receipt_digest` only after `verifyDecisionReceipt` re-derived it.
* **Ed25519 via node:crypto:** `ed25519Verifier(publicKeyPem, keyId, name)` accepts only an Ed25519 SPKI public key, checks alg, key id, provider name, base64 shape and 64-byte length, then `crypto.verify`. It never signs.
* **Config (`resolveSigningConfig(env)`):** `FACTORY_SIGNING_PUBLIC_KEY_FILE` (regular file, not a symlink, <= 16 KiB, public key only: any `PRIVATE` material is refused), `FACTORY_SIGNING_KEY_ID`, `FACTORY_SIGNING_PROVIDER` (default `ed25519`). Anything missing or wrong => `SIGNING_KEY_UNAVAILABLE` and a verifier that verifies nothing. No key is generated. The resolved policy never carries a signer; `signActionReceipt` / `signDecisionReceipt` / `requireReceiptSigner` without a signer throw `SigningKeyUnavailableError` (`code: "SIGNING_KEY_UNAVAILABLE"`).
* **Policy (`ReceiptSigningPolicy`, `receiptSigningRequired`):** `require` defaults to **required exactly when a verification key is configured** (`key_configured`). No key configured => nothing required, receipts reported `UNSIGNED`, behaviour unchanged. `require: true` without a key => nothing can be VERIFIED (fail closed). `require: false` with a key => explicit opt-out.
* **TÖEPÄRA:** a presented receipt signature is always verified (even with no policy: an unverifiable signature is never ignored). Valid => the check passes (VERIFIED still needs every other check). Missing while required => `INSUFFICIENT_EVIDENCE` (`receipt-signature-missing`), never VERIFIED. Tampered / wrong key / other purpose / malformed => `REJECTED` (`receipt-signature-invalid`).
* **CERBERUS:** passes the receipt signature into its own TÖEPÄRA recomputation, so an unsigned receipt is never ADMITted while signing is required; the DENY names `signature:action-receipt:<status>`; `signature_status.receipt` always reports the honest status.
* **Loop:** `LoopDeps.receiptSigning`. The KRATT stage signs when a signer is set; required without a signer => refusal `SIGNING_KEY_UNAVAILABLE` (never continues unsigned).
* **RÄSTIK (`runReceiptSignatureAttacks`, 14 cases; `runDecisionReceiptSignatureAttacks`, 5 cases):** signature stripping (with and without re-timestamp), key substitution (attacker key, attacker key claiming the trusted key id, and the trusted provider name), payload tamper after signing (evidence re-sealed; agent_id), replay of a signed receipt with a new timestamp, signature from another receipt, purpose confusion / relabelling, bit-flipped / truncated value, extra field. All REPELLED by the real TÖEPÄRA with a required Ed25519 policy; a target that ignores signatures and a presence/key-id-only checker are both attacked successfully (non-vacuity).
* **Mutation check:** 16 mutants `AS01`-`AS16` (`factory/mutation/mutants.ts`), run with `node --experimental-strip-types factory/mutation/run.ts --only AS01,...,AS16`; results in the PR.
* **Still human gates:** production signing system (KMS/HSM/Sigstore), key generation + custody, registering the verification key, turning signing on in production, and signing at the real KRATT/CERBERUS producers.

## Mutation checks (one mutation at a time, restored byte-identical, `node --experimental-strip-types --test` on the listed files)
Replay + Trust Gate + CERBERUS wiring (`replay-persistent`, `trust-gate`, `cerberus-gate` tests): 16 of 17 mutants killed in the first run. Survivors and what was done:
* equivalence probe I wrote (R2, a no-op text change): discarded, not a real mutant.
* R5 (write failure fails open): killed after adding the unwritable-store test (skipped only when run as root).
* T6 (unhandled late rejection): equivalent, `Promise.race` already subscribes to the call; the dead line was removed.
* T7 (timer never cleared): killed after adding the `clearTimeout` call-count test.
* C2 (invalid envelope: gate verdict AUTHORIZED): equivalent by design (TÖEPÄRA recompute rejects an invalid envelope independently); recorded, not killed.

Signing + CERBERUS signing policy (`signing`, `cerberus-gate` tests): 15 mutants; first run 12 killed. S4 (claimed subject not compared) and S9 (none provider verifies everything) were killed after adding the lenient-provider test; G5 (redundant late DENY) was equivalent with the adapter-level block, so the redundant line was removed. Final: all remaining mutants killed except C2 above.
