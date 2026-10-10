# Cerberus decision contract (v1 slice)

```
INPUT -> POLICY -> TÖEPÄRA -> TRUST GATE -> ARTIFACT TRUST -> DECISION -> RECOVERY RECEIPT
```

Code: `cerberus/core/normalize.ts` (INPUT), `cerberus/policy/policy.ts`,
`cerberus/artifact-trust/artifact-trust.ts`, `cerberus/core/decide.ts` (DECISION + RECEIPT),
`cerberus/integrations/verdict-adapters.ts` (stubbed seam). Tests: `cerberus/tests/`.

## Invariants (all asserted by tests)
- Missing, malformed, hostile (accessor, Proxy, non-plain, BigInt/cyclic values) or unknown-verdict input => `FAIL_CLOSED`; `decide` never throws.
- Only the exact strings `ADMITTED` (TÖEPÄRA) and `AUTHORIZED` (Trust Gate) pass; actions limited to `detect|recover|recommend`.
- Every stage always runs; `PROCEED` requires all five stages `PASS`.
- Decision and digests come from one immutable snapshot of own data properties => same normalized input, same receipt bytes; unknown extra keys are ignored and do not affect the receipt.
- Receipt records version, verdict source, per-stage results, the evidence decided on (incl. declared vs computed artifact SHA-256), `inputDigest`, and a `receiptDigest` over everything else (`verifyReceipt`).

## What this is NOT
- `decide(input)` trusts caller-supplied TÖEPÄRA / Trust Gate strings. Cerberus cannot verify their origin.
- `decideWithAdapters` fixes the interface a real client must meet (adapter failure => deny; caller verdict fields ignored) but only stub adapters exist. No real TÖEPÄRA / Trust Gate client, no signature verification, no async/timeout handling yet.
- `receiptDigest` is an integrity hash, not a signature: anyone can recompute it. It proves nothing about who produced the receipt.
- The artifact digest check proves content matches a *declared* digest, not that the declaration is trustworthy.
