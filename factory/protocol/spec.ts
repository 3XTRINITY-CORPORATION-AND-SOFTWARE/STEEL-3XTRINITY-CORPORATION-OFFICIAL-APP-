/**
 * Tiny declarative schema DSL. ONE spec drives both the runtime validator and the generated
 * JSON Schema (factory/protocol/protocol.schema.json), so the two cannot drift apart
 * (a test regenerates the schema and compares it to the committed file).
 *
 * Validation is closed: objects must be plain, with exactly the declared own data
 * properties (no accessors, no extra keys, no symbols).
 */
export type Spec =
  | { k: "str"; re?: RegExp; min?: number; max?: number; /** timestamp must survive a Date round-trip (rejects 2026-02-30, 24:00:00, :60 ...) */ isoRoundTrip?: boolean }
  | { k: "int"; min: number; max: number }
  | { k: "bool" }
  | { k: "null" }
  | { k: "enum"; values: readonly string[] }
  | { k: "lit"; value: number | string | boolean | null }
  | { k: "arr"; item: Spec; min: number; max: number; unique?: boolean }
  | { k: "obj"; shape: Record<string, Spec> }
  | { k: "json" } // opaque plain JSON object; validated deeper by its own owner (e.g. KRATT evidence)
  | { k: "or"; any: Spec[] };

export const str = (o: { re?: RegExp; min?: number; max?: number; isoRoundTrip?: boolean } = {}): Spec => ({ k: "str", ...o });

/**
 * True when an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.f{1,3}]Z`) names a real instant: parsing it and printing it
 * again gives the same text (fraction normalised to 3 digits). The regex alone accepts 2026-02-30T25:61:61Z.
 */
export function isoRoundTrips(v: string): boolean {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/.exec(v);
  if (m === null) return false;
  const t = Date.parse(v);
  if (!Number.isFinite(t)) return false;
  try {
    return new Date(t).toISOString() === `${m[1]}.${(m[2] ?? "").padEnd(3, "0")}Z`;
  } catch {
    return false;
  }
}
export const int = (min: number, max: number): Spec => ({ k: "int", min, max });
export const bool: Spec = { k: "bool" };
export const nul: Spec = { k: "null" };
export const oneOf = (...values: string[]): Spec => ({ k: "enum", values });
export const lit = (value: number | string | boolean | null): Spec => ({ k: "lit", value });
export const arr = (item: Spec, min: number, max: number, unique = false): Spec => ({ k: "arr", item, min, max, unique });
export const obj = (shape: Record<string, Spec>): Spec => ({ k: "obj", shape });
export const json: Spec = { k: "json" };
export const or = (...any: Spec[]): Spec => ({ k: "or", any });

const isPlain = (v: unknown): v is Record<string, unknown> => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
};

/** Returns null when `v` satisfies `spec`, else a short reason (path:reason). Never throws. */
export function check(spec: Spec, v: unknown, path = "$"): string | null {
  try {
    return checkInner(spec, v, path);
  } catch {
    return `${path}:unreadable`;
  }
}

function checkInner(spec: Spec, v: unknown, path: string): string | null {
  switch (spec.k) {
    case "str":
      if (typeof v !== "string") return `${path}:not-string`;
      if (spec.min !== undefined && v.length < spec.min) return `${path}:too-short`;
      if (spec.max !== undefined && v.length > spec.max) return `${path}:too-long`;
      if (spec.re && !spec.re.test(v)) return `${path}:pattern`;
      if (spec.isoRoundTrip === true && !isoRoundTrips(v)) return `${path}:impossible-timestamp`;
      return null;
    case "int":
      if (typeof v !== "number" || !Number.isSafeInteger(v)) return `${path}:not-integer`;
      return v < spec.min || v > spec.max ? `${path}:out-of-range` : null;
    case "bool":
      return typeof v === "boolean" ? null : `${path}:not-boolean`;
    case "null":
      return v === null ? null : `${path}:not-null`;
    case "lit":
      return v === spec.value ? null : `${path}:literal-mismatch`;
    case "enum":
      return typeof v === "string" && spec.values.includes(v) ? null : `${path}:not-in-enum`;
    case "json":
      return isPlain(v) ? null : `${path}:not-plain-object`;
    case "or": {
      const reasons: string[] = [];
      for (const s of spec.any) {
        const r = checkInner(s, v, path);
        if (r === null) return null;
        reasons.push(r);
      }
      return reasons[0] ?? `${path}:no-alternative`;
    }
    case "arr": {
      if (!Array.isArray(v)) return `${path}:not-array`;
      if (v.length < spec.min || v.length > spec.max) return `${path}:length`;
      const seen = new Set<unknown>();
      for (let i = 0; i < v.length; i++) {
        const d = Object.getOwnPropertyDescriptor(v, String(i));
        if (d === undefined || !("value" in d)) return `${path}[${i}]:unreadable`;
        const r = checkInner(spec.item, d.value, `${path}[${i}]`);
        if (r) return r;
        if (spec.unique) {
          if (seen.has(d.value)) return `${path}[${i}]:duplicate`;
          seen.add(d.value);
        }
      }
      return null;
    }
    case "obj": {
      if (!isPlain(v)) return `${path}:not-plain-object`;
      const keys = Reflect.ownKeys(v);
      const want = Object.keys(spec.shape);
      if (keys.length !== want.length || !keys.every((k) => typeof k === "string" && want.includes(k)))
        return `${path}:unexpected-or-missing-keys`;
      for (const k of want) {
        const d = Object.getOwnPropertyDescriptor(v, k);
        if (d === undefined || !("value" in d)) return `${path}.${k}:accessor`;
        const r = checkInner(spec.shape[k] as Spec, d.value, `${path}.${k}`);
        if (r) return r;
      }
      return null;
    }
  }
}

/** JSON Schema (2020-12) for a spec. Every declared key is required; no additional properties. */
export function toJsonSchema(spec: Spec): Record<string, unknown> {
  switch (spec.k) {
    case "str":
      return {
        type: "string",
        ...(spec.min !== undefined ? { minLength: spec.min } : {}),
        ...(spec.max !== undefined ? { maxLength: spec.max } : {}),
        ...(spec.re ? { pattern: spec.re.source } : {}),
      };
    case "int":
      return { type: "integer", minimum: spec.min, maximum: spec.max };
    case "bool":
      return { type: "boolean" };
    case "null":
      return { type: "null" };
    case "lit":
      return { const: spec.value };
    case "enum":
      return { enum: [...spec.values] };
    case "json":
      return { type: "object" };
    case "or":
      return { anyOf: spec.any.map(toJsonSchema) };
    case "arr":
      return {
        type: "array",
        items: toJsonSchema(spec.item),
        minItems: spec.min,
        maxItems: spec.max,
        ...(spec.unique ? { uniqueItems: true } : {}),
      };
    case "obj":
      return {
        type: "object",
        properties: Object.fromEntries(Object.entries(spec.shape).map(([k, s]) => [k, toJsonSchema(s)])),
        required: Object.keys(spec.shape),
        additionalProperties: false,
      };
  }
}
