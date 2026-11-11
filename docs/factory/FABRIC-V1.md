# 3XT-FABRIC/1 ingress contract (STEEL)

Status: **IMPLEMENTED SOURCE / TESTS NOT EXECUTED HERE / NOT INTEGRATED**.

`factory/protocol/fabric-v1.ts` defines the closed event envelope and ingress pipeline. It parses bounded UTF-8 JSON, validates exact keys and nested values, recomputes SHA-256 over RFC 8785-style JCS serialization of the complete event body excluding `content_digest` and `signature`, verifies Ed25519 over `3XT-FABRIC/1\n<source_node>\n<key_id>\n<digest>`, calls a separate authorization policy, checks bounded UTC expiry, then uses a PostgreSQL inbox uniqueness constraint and transaction for deduplication and handler side effects.

The receiver does not grant authorization based on a signature. The supplied `authorize` callback must implement local policy; the `handler` is called only after it returns true and must perform side effects using the supplied transaction client. Rejected, expired, malformed, unauthenticated, or unauthorized events never enter the transaction handler.

Persistence migration: `0003_fabric_event_inbox.sql`. Uniqueness is enforced both by event ID and by `(source_node, source_sequence)`; concurrent insert attempts serialize through PostgreSQL uniqueness. Same-ID/same-digest retries return `duplicate: true` without a second handler call; conflicting ID/sequence claims fail closed.

## Compatibility and limits

- Exact major `3XT-FABRIC/1` only; no implicit downgrade or forward compatibility.
- Max serialized event: 256 KiB; max TTL: 24 hours; accepted issue-time skew: 5 minutes.
- SHA-256 is integrity only. Ed25519 identity trust requires an out-of-band resolver for `(source_node, key_id)`.
- The contract module is not a broker or deployed service. A real authenticated transport, provisioned node-key registry, database configuration/migration execution, and cross-repository task adapter remain unverified and block `INTEGRATED` / `PRODUCTION_READY`.
- RFC 8785 JCS is implemented for finite JSON primitives/arrays/plain data objects with UTF-16 key ordering and rejects unsupported values. Duplicate JSON object names are not detected by JavaScript `JSON.parse`; an upstream strict JSON parser is required if duplicate-key rejection is part of the transport threat model.

Run `node --experimental-strip-types --test factory/tests/fabric-v1.test.ts` in STEEL with its dependencies installed. No claim is made that this command was executed in this session.
