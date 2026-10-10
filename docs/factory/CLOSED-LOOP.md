# Closed loop v1 (GOLIATH stand-in -> KRATT -> RÄSTIK -> TÖEPÄRA -> CERBERUS)

Entry point: `runClosedLoop()` in `factory/loop.ts`; CLI: `npm run factory -- run-loop`.

1. `GoliathStandIn` (typed, in-process, `real_goliath:false`) issues a TaskEnvelope. It is NOT the real GOLIATH (no spec exists in any repo).
2. Dispatcher validates the envelope (protocol v1, repo, scope, capability) and runs each stage as a task on a registered worker; every worker transition lands in the transition log.
3. KRATT (FORGE-026) executes ONE bounded action (`hash-files`, `validate-manifest`, `run-test`) and emits an ActionReceipt with `verification_state: UNVERIFIED`.
4. RÄSTIK (SERPENT-051..065) attacks that exact receipt (40 cases in 8 classes) plus the existing `rastik/` probes selected by scope. A finding is CONFIRMED only when reproduced on a fresh re-run.
5. TÖEPÄRA (CITADEL-101) re-derives digests from `git cat-file blob <base_sha>:<path>`, the scope diff, task digest, test evidence (re-execution) and the RÄSTIK report digest. KRATT output alone cannot be VERIFIED.
6. CERBERUS (CITADEL-111) re-runs TÖEPÄRA, requires a byte-identical bundle, consumes the replay guard, evaluates a locally computed policy gate, then ADMIT / DENY / QUARANTINE.
7. Final receipt returned to the caller; confirmed findings enqueue FORGE-043 regression tasks (QUEUED only).

Known limits: evidence hashed, not signed (human gate: signing key); replay guard in-memory; `localPolicyTrustGate` is not the real Trust Gate; `run-test` re-execution reuses KRATT's runner (Node permission model, no network control); RÄSTIK reports hash-checked, not authenticated; probe findings assumed severity high; GOLIATH is a stand-in; 11 of 150 workers have handler code.
See `TRUST-AUDIT.md` and `MUTATION-CHECKS.md`.
