import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { Pool } from "pg";
import { authenticateEvent, canonicalizeJcs, eventContentDigest, parseFabricEvent, receiveFabricEvent, validateFabricEvent, verifyContentDigest, type FabricEventV1, type TrustedNodeKey } from "../protocol/fabric-v1.ts";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const nodeKey: TrustedNodeKey = { source_node: "kratt-prime", key_id: "node-key-1", public_key: publicKey };
function makeEvent(overrides: Partial<FabricEventV1> = {}): FabricEventV1 {
  const base: FabricEventV1 = {
    protocol: "3XT-FABRIC/1", event_id: "evt-1", event_type: "task.request", source_node: "kratt-prime",
    destination_node: "steel", source_revision: "a".repeat(40), correlation_id: "corr-1", parent_event_id: null,
    sequence: 1, issued_at: "2026-11-11T12:00:00.000Z", expires_at: "2026-11-11T12:05:00.000Z",
    scope: ["repository.read"], payload_reference: null, evidence_references: [], key_id: "node-key-1",
    payload: { task_id: "task-1" }, content_digest: "0".repeat(64), signature: "",
  };
  Object.assign(base, overrides);
  base.content_digest = eventContentDigest(base);
  base.signature = sign(null, Buffer.from(`${base.protocol}\n${base.source_node}\n${base.key_id}\n${base.content_digest}`), privateKey).toString("base64");
  return base;
}

test("JCS key order is deterministic and event digest excludes digest/signature", () => {
  assert.equal(canonicalizeJcs({ z: 1, a: 2 }), '{"a":2,"z":1}');
  assert.equal(verifyContentDigest(makeEvent()).ok, true);
});
test("event schema accepts a valid envelope and rejects missing and invalid nested fields", () => {
  assert.equal(validateFabricEvent(makeEvent()).ok, true);
  const { event_id: _omit, ...missing } = makeEvent();
  assert.equal(validateFabricEvent(missing).ok, false);
  assert.equal(validateFabricEvent(makeEvent({ scope: ["bad token"] })).ok, false);
});
test("strict UTC and supported protocol version are enforced", () => {
  assert.equal(validateFabricEvent(makeEvent({ issued_at: "2026-11-11T12:00:00+00:00" })).ok, false);
  assert.equal(validateFabricEvent(makeEvent({ expires_at: "2026-11-11T12:05:00" })).ok, false);
  assert.equal(validateFabricEvent(makeEvent({ protocol: "3XT-FABRIC/2" as FabricEventV1["protocol"] })).ok, false);
});
test("payload tampering and bad signature are rejected", async () => {
  const event = makeEvent();
  assert.equal(verifyContentDigest({ ...event, payload: { task_id: "changed" } }).ok, false);
  assert.equal((await authenticateEvent({ ...event, signature: Buffer.alloc(64).toString("base64") }, async () => nodeKey)).ok, false);
});
test("parser enforces payload bound and parse errors", () => {
  assert.equal(parseFabricEvent("{" ).ok, false);
  assert.equal(parseFabricEvent(" ".repeat(256 * 1024 + 1)).ok, false);
});
test("ingress enforces auth, authorization, expiry, and persists idempotency in PostgreSQL transaction", async () => {
  const queries: string[] = [];
  const client = { query: async (sql: string) => { queries.push(sql); if (sql.includes("INSERT INTO fabric_event_inbox")) return { rowCount: 1, rows: [{ event_id: "evt-1" }] }; return { rowCount: 1, rows: [] }; }, release() {} };
  const pool = { connect: async () => client } as unknown as Pool;
  let effects = 0;
  const result = await receiveFabricEvent(pool, JSON.stringify(makeEvent()), {
    resolveKey: async () => nodeKey, authorize: async () => true,
    now: () => Date.parse("2026-11-11T12:01:00Z"), handler: async () => ++effects,
  });
  assert.equal(result.ok, true);
  assert.equal(effects, 1);
  assert.equal(queries[0], "BEGIN");
  assert.equal(queries.at(-1), "COMMIT");
});
test("unauthorized and expired events never reach the handler", async () => {
  const pool = { connect: async () => { throw new Error("must not connect"); } } as unknown as Pool;
  const event = makeEvent();
  const base = { resolveKey: async () => nodeKey, now: () => Date.parse("2026-11-11T12:06:00Z"), handler: async () => assert.fail("handler called") };
  assert.equal((await receiveFabricEvent(pool, JSON.stringify(event), { ...base, authorize: async () => false })).ok, false);
  const expired = await receiveFabricEvent(pool, JSON.stringify(event), { ...base, authorize: async () => true });
  assert.equal(!expired.ok && expired.code, "EVENT_EXPIRED");
});
