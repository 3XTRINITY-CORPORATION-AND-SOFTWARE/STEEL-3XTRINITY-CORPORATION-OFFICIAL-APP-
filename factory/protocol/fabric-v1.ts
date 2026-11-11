import { createHash, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { types as utilTypes } from "node:util";
import type { Pool, PoolClient } from "pg";

/** Canonical event protocol. Major-only compatibility: unsupported versions fail closed. */
export const FABRIC_PROTOCOL = "3XT-FABRIC/1" as const;
export const MAX_EVENT_BYTES = 256 * 1024;
export const MAX_TTL_MS = 24 * 60 * 60 * 1000;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TOKEN = /^[a-z][a-z0-9._:-]{0,127}$/;
const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const UTC = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

export interface FabricEventV1 {
  protocol: typeof FABRIC_PROTOCOL;
  event_id: string;
  event_type: string;
  source_node: string;
  destination_node: string;
  source_revision: string;
  correlation_id: string;
  parent_event_id: string | null;
  sequence: number;
  issued_at: string;
  expires_at: string;
  scope: string[];
  payload_reference: string | null;
  evidence_references: string[];
  key_id: string;
  payload: Record<string, unknown>;
  content_digest: string;
  signature: string;
}

export type FabricErrorCode =
  | "PAYLOAD_TOO_LARGE" | "PARSE_FAILED" | "SCHEMA_INCOMPATIBLE" | "SCHEMA_INVALID"
  | "DIGEST_INVALID" | "DIGEST_MISMATCH" | "KEY_UNAVAILABLE" | "SIGNATURE_INVALID"
  | "UNAUTHORIZED" | "CLOCK_UNAVAILABLE" | "EVENT_EXPIRED" | "EVENT_NOT_YET_VALID"
  | "EVENT_TTL_INVALID" | "REPLAY_OR_DUPLICATE" | "PERSISTENCE_UNAVAILABLE" | "HANDLER_FAILED";
export type FabricResult<T = undefined> =
  | { ok: true; value: T }
  | { ok: false; code: FabricErrorCode; detail?: string };
const fail = (code: FabricErrorCode, detail?: string): FabricResult<never> => ({ ok: false, code, ...(detail ? { detail } : {}) });

const isRecord = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value) || utilTypes.isProxy(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};
const exactKeys = (value: Record<string, unknown>, expected: readonly string[]): boolean => {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length && keys.every((k) => typeof k === "string" && expected.includes(k) &&
    Object.getOwnPropertyDescriptor(value, k) !== undefined && "value" in Object.getOwnPropertyDescriptor(value, k)!);
};
const validText = (v: unknown, re: RegExp): v is string => typeof v === "string" && v.length <= 128 && re.test(v);

function strictUtcMillis(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const match = UTC.exec(value);
  if (!match) return null;
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) return null;
  const normalized = `${match[1]}.${(match[2] ?? "").padEnd(3, "0")}Z`;
  try { return new Date(millis).toISOString() === normalized ? millis : null; } catch { return null; }
}

/** RFC 8785 JCS serialization for the JSON/I-JSON subset used by this protocol. */
export function canonicalizeJcs(value: unknown): string {
  const seen = new Set<object>();
  const validUnicode = (s: string): boolean => {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const next = s.charCodeAt(i + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
        i++;
      } else if (c >= 0xdc00 && c <= 0xdfff) return false;
    }
    return true;
  };
  const encode = (v: unknown, depth: number): string => {
    if (depth > 32) throw new TypeError("JCS_DEPTH_LIMIT");
    if (v === null || typeof v === "boolean" || typeof v === "string") {
      if (typeof v === "string" && !validUnicode(v)) throw new TypeError("JCS_INVALID_UNICODE");
      return JSON.stringify(v);
    }
    if (typeof v === "number") {
      if (!Number.isFinite(v)) throw new TypeError("JCS_NON_FINITE_NUMBER");
      return JSON.stringify(Object.is(v, -0) ? 0 : v);
    }
    if (typeof v !== "object" || v === undefined || utilTypes.isProxy(v)) throw new TypeError("JCS_NON_JSON_VALUE");
    if (seen.has(v)) throw new TypeError("JCS_CYCLE");
    seen.add(v);
    try {
      if (Array.isArray(v)) {
        const parts: string[] = [];
        for (let i = 0; i < v.length; i++) {
          const d = Object.getOwnPropertyDescriptor(v, String(i));
          if (!d || !("value" in d)) throw new TypeError("JCS_ARRAY_HOLE_OR_ACCESSOR");
          parts.push(encode(d.value, depth + 1));
        }
        if (Reflect.ownKeys(v).some((k) => typeof k === "symbol")) throw new TypeError("JCS_SYMBOL_KEY");
        return `[${parts.join(",")}]`;
      }
      if (!isRecord(v)) throw new TypeError("JCS_NON_PLAIN_OBJECT");
      const keys = Reflect.ownKeys(v);
      if (keys.some((k) => typeof k !== "string")) throw new TypeError("JCS_SYMBOL_KEY");
      const sorted = (keys as string[]).sort(); // ECMAScript UTF-16 code-unit ordering, as required by JCS.
      const parts = sorted.map((key) => {
        if (!validUnicode(key)) throw new TypeError("JCS_INVALID_UNICODE");
        const d = Object.getOwnPropertyDescriptor(v, key);
        if (!d || !("value" in d) || !d.enumerable) throw new TypeError("JCS_ACCESSOR_OR_NON_ENUMERABLE");
        return `${JSON.stringify(key)}:${encode(d.value, depth + 1)}`;
      });
      return `{${parts.join(",")}}`;
    } finally { seen.delete(v); }
  };
  return encode(value, 0);
}

const digestHex = (value: unknown): string => createHash("sha256").update(canonicalizeJcs(value), "utf8").digest("hex");
const DIGEST_FIELDS = ["content_digest", "signature"] as const;
const EVENT_KEYS = ["protocol", "event_id", "event_type", "source_node", "destination_node", "source_revision", "correlation_id", "parent_event_id", "sequence", "issued_at", "expires_at", "scope", "payload_reference", "evidence_references", "key_id", "payload", "content_digest", "signature"] as const;

/** Digest covers every event field except content_digest and signature. */
export function eventContentDigest(event: FabricEventV1): string {
  const body: Record<string, unknown> = {};
  for (const key of EVENT_KEYS) if (!(DIGEST_FIELDS as readonly string[]).includes(key)) body[key] = (event as unknown as Record<string, unknown>)[key];
  return digestHex(body);
}

export function validateFabricEvent(value: unknown): FabricResult<FabricEventV1> {
  if (!isRecord(value) || !exactKeys(value, EVENT_KEYS)) return fail("SCHEMA_INVALID", "event envelope keys do not match 3XT-FABRIC/1");
  if (value.protocol !== FABRIC_PROTOCOL) return fail("SCHEMA_INCOMPATIBLE", "unsupported protocol version");
  if (!validText(value.event_id, ID) || !validText(value.source_node, ID) || !validText(value.destination_node, ID) ||
      !validText(value.correlation_id, ID) || (value.parent_event_id !== null && !validText(value.parent_event_id, ID)))
    return fail("SCHEMA_INVALID", "invalid event or node identity");
  if (!validText(value.event_type, TOKEN) || !validText(value.key_id, ID) || typeof value.source_revision !== "string" || !SHA1.test(value.source_revision))
    return fail("SCHEMA_INVALID", "invalid event type, key id, or source revision");
  if (typeof value.sequence !== "number" || !Number.isSafeInteger(value.sequence) || value.sequence < 1)
    return fail("SCHEMA_INVALID", "sequence must be a positive safe integer");
  if (strictUtcMillis(value.issued_at) === null || strictUtcMillis(value.expires_at) === null)
    return fail("SCHEMA_INVALID", "timestamps must be real UTC ISO-8601 instants");
  if (!Array.isArray(value.scope) || value.scope.length < 1 || value.scope.length > 64 || value.scope.some((x) => !validText(x, TOKEN)) || new Set(value.scope).size !== value.scope.length)
    return fail("SCHEMA_INVALID", "scope must contain 1..64 unique capability tokens");
  if (value.payload_reference !== null && (typeof value.payload_reference !== "string" || value.payload_reference.length < 1 || value.payload_reference.length > 512))
    return fail("SCHEMA_INVALID", "invalid payload reference");
  if (!Array.isArray(value.evidence_references) || value.evidence_references.length > 64 || value.evidence_references.some((x) => typeof x !== "string" || x.length < 1 || x.length > 512))
    return fail("SCHEMA_INVALID", "invalid evidence references");
  if (!isRecord(value.payload)) return fail("SCHEMA_INVALID", "payload must be a JSON object");
  if (typeof value.content_digest !== "string" || !SHA256.test(value.content_digest)) return fail("DIGEST_INVALID", "content_digest must be lowercase SHA-256 hex");
  if (typeof value.signature !== "string" || value.signature.length < 1 || value.signature.length > 128 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value.signature))
    return fail("SCHEMA_INVALID", "signature must be base64");
  try { canonicalizeJcs(value); } catch (e) { return fail("SCHEMA_INVALID", e instanceof Error ? e.message : "not JCS-compatible JSON"); }
  return { ok: true, value: value as unknown as FabricEventV1 };
}

/** Parse bytes before schema checks; payload bytes are capped before allocation/JSON parsing. */
export function parseFabricEvent(input: Uint8Array | string): FabricResult<FabricEventV1> {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
  if (bytes.byteLength > MAX_EVENT_BYTES) return fail("PAYLOAD_TOO_LARGE");
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { return fail("PARSE_FAILED", "invalid UTF-8 or JSON"); }
  return validateFabricEvent(parsed);
}

export function verifyContentDigest(event: FabricEventV1): FabricResult<string> {
  try {
    const computed = eventContentDigest(event);
    return computed === event.content_digest ? { ok: true, value: computed } : fail("DIGEST_MISMATCH");
  } catch { return fail("DIGEST_INVALID"); }
}

export interface TrustedNodeKey { source_node: string; key_id: string; public_key: string | KeyObject; }
export type ResolveNodeKey = (sourceNode: string, keyId: string) => Promise<TrustedNodeKey | null>;
/** Ed25519 over domain-separated protocol + source identity + recomputed content digest. */
export async function authenticateEvent(event: FabricEventV1, resolveKey: ResolveNodeKey): Promise<FabricResult<TrustedNodeKey>> {
  const resolved = await resolveKey(event.source_node, event.key_id).catch(() => null);
  if (!resolved || resolved.source_node !== event.source_node || resolved.key_id !== event.key_id) return fail("KEY_UNAVAILABLE");
  let sig: Buffer;
  try { sig = Buffer.from(event.signature, "base64"); } catch { return fail("SIGNATURE_INVALID"); }
  if (sig.length !== 64 || sig.toString("base64") !== event.signature) return fail("SIGNATURE_INVALID");
  const signingInput = Buffer.from(`${FABRIC_PROTOCOL}\n${event.source_node}\n${event.key_id}\n${event.content_digest}`, "utf8");
  try { return cryptoVerify(null, signingInput, resolved.public_key, sig) ? { ok: true, value: resolved } : fail("SIGNATURE_INVALID"); }
  catch { return fail("SIGNATURE_INVALID"); }
}

export type AuthorizeEvent = (event: FabricEventV1, authenticatedNode: TrustedNodeKey) => Promise<boolean>;
export interface EventTransaction { client: PoolClient; }
export type EventHandler<T> = (event: FabricEventV1, tx: EventTransaction) => Promise<T>;

/**
 * Production ingress boundary. Schema, content digest, Ed25519 identity, policy, expiry, then a
 * PostgreSQL unique inbox insert and handler work in the same transaction. The handler MUST use
 * the supplied transaction for side effects; no acknowledgement is returned before COMMIT.
 */
export async function receiveFabricEvent<T>(
  pool: Pool,
  raw: Uint8Array | string,
  deps: { resolveKey: ResolveNodeKey; authorize: AuthorizeEvent; now: () => number; handler: EventHandler<T> },
): Promise<FabricResult<{ duplicate: boolean; result?: T }>> {
  const parsed = parseFabricEvent(raw);
  if (!parsed.ok) return parsed;
  const event = parsed.value;
  const digest = verifyContentDigest(event);
  if (!digest.ok) return digest;
  const authenticated = await authenticateEvent(event, deps.resolveKey);
  if (!authenticated.ok) return authenticated;
  let permitted = false;
  try { permitted = await deps.authorize(event, authenticated.value); } catch { permitted = false; }
  if (!permitted) return fail("UNAUTHORIZED");
  const now = deps.now();
  if (!Number.isFinite(now)) return fail("CLOCK_UNAVAILABLE");
  const issued = strictUtcMillis(event.issued_at)!;
  const expires = strictUtcMillis(event.expires_at)!;
  if (expires <= issued || expires - issued > MAX_TTL_MS) return fail("EVENT_TTL_INVALID");
  if (issued > now + MAX_FUTURE_SKEW_MS) return fail("EVENT_NOT_YET_VALID");
  if (expires <= now) return fail("EVENT_EXPIRED");

  const client = await pool.connect().catch(() => null);
  if (!client) return fail("PERSISTENCE_UNAVAILABLE");
  try {
    await client.query("BEGIN");
    const inserted = await client.query(
      `INSERT INTO fabric_event_inbox (event_id, source_node, source_sequence, content_digest, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT DO NOTHING
       RETURNING event_id`,
      [event.event_id, event.source_node, event.sequence, event.content_digest, event.expires_at],
    );
    if (inserted.rowCount !== 1) {
      const sameId = await client.query("SELECT content_digest FROM fabric_event_inbox WHERE event_id = $1", [event.event_id]);
      await client.query("ROLLBACK");
      return sameId.rows.length === 1 && sameId.rows[0].content_digest === event.content_digest
        ? { ok: true, value: { duplicate: true } }
        : fail("REPLAY_OR_DUPLICATE", "event id or source sequence already consumed");
    }
    const result = await deps.handler(event, { client });
    await client.query("COMMIT");
    return { ok: true, value: { duplicate: false, result } };
  } catch {
    await client.query("ROLLBACK").catch(() => undefined);
    return fail("HANDLER_FAILED");
  } finally { client.release(); }
}
