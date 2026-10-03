/**
 * INPUT stage. Turns an untrusted value into a closed, immutable snapshot of
 * exactly the fields Cerberus decides on, or rejects it.
 *
 * Why a snapshot: the decision AND the receipt digest must be computed from the
 * same bytes. Reading properties lazily from a caller-owned object would allow
 * (a) inherited properties that the digest never covers, (b) accessors that
 * return different values per read, (c) Proxies that throw or lie, and
 * (d) cyclic / BigInt values that make canonical JSON throw instead of deny.
 * Every leaf in the snapshot is `string | null`, so downstream hashing cannot throw.
 */
export interface NormalizedArtifact {
  name: string | null;
  content: string | null;
  sha256: string | null;
}

export interface NormalizedInput {
  action: string | null;
  toepara: string | null;
  trustGate: string | null;
  /** null when absent or not a plain object. */
  artifact: NormalizedArtifact | null;
}

export type NormalizeResult =
  | { ok: true; value: Readonly<NormalizedInput> }
  | { ok: false; reason: string };

const isPlainObject = (v: unknown): v is object => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

class Malformed extends Error {}

/** Own data property as string, else null. Accessors are rejected outright. */
function ownString(obj: object, key: string): string | null {
  const d = Object.getOwnPropertyDescriptor(obj, key);
  if (d === undefined) return null;
  if (!("value" in d)) throw new Malformed("input-accessor-property");
  return typeof d.value === "string" ? d.value : null;
}

function ownObject(obj: object, key: string): object | null {
  const d = Object.getOwnPropertyDescriptor(obj, key);
  if (d === undefined) return null;
  if (!("value" in d)) throw new Malformed("input-accessor-property");
  return isPlainObject(d.value) ? d.value : null;
}

export function normalizeInput(input: unknown): NormalizeResult {
  try {
    if (!isPlainObject(input)) return { ok: false, reason: "input-not-plain-object" };
    const art = ownObject(input, "artifact");
    const value: NormalizedInput = {
      action: ownString(input, "action"),
      toepara: ownString(input, "toepara"),
      trustGate: ownString(input, "trustGate"),
      artifact:
        art === null
          ? null
          : {
              name: ownString(art, "name"),
              content: ownString(art, "content"),
              sha256: ownString(art, "sha256"),
            },
    };
    if (value.artifact) Object.freeze(value.artifact);
    return { ok: true, value: Object.freeze(value) };
  } catch (e) {
    // Proxy traps / hostile objects must deny, never throw out of Cerberus.
    return { ok: false, reason: e instanceof Malformed ? e.message : "input-unreadable" };
  }
}
