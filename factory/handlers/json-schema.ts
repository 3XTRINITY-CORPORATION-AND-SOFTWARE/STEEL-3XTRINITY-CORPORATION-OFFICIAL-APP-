/**
 * Small, fail-closed JSON Schema (draft-07 subset) validator. Pure; no I/O.
 * Any keyword outside the supported set makes the SCHEMA invalid (never silently ignored), so
 * a schema using `$ref`, `oneOf`, ... cannot produce a false "valid".
 */
const ANNOTATIONS = new Set(["$schema", "$id", "title", "description", "default", "examples", "$comment"]);
const KEYWORDS = new Set([
  "type", "enum", "const", "properties", "required", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems",
  "minLength", "maxLength", "pattern", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minProperties", "maxProperties",
]);
const TYPES = new Set(["string", "number", "integer", "boolean", "null", "array", "object"]);
const MAX_DEPTH = 32;
const MAX_ERRORS = 100;
/** A quantified group (`(a+)+`, `(x*){2}`) is the classic ReDoS shape: refuse such patterns. */
const REDOS = /\)[*+{]/;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (isObj(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
}

/** Returns reasons the schema itself is unusable (empty = ok). */
export function schemaProblems(schema: unknown, path = "#", depth = 0): string[] {
  if (depth > MAX_DEPTH) return [`${path}: schema-too-deep`];
  if (typeof schema === "boolean") return [];
  if (!isObj(schema)) return [`${path}: schema-not-object`];
  const out: string[] = [];
  for (const k of Object.keys(schema)) {
    if (ANNOTATIONS.has(k)) continue;
    if (!KEYWORDS.has(k)) out.push(`${path}: unsupported-keyword:${k}`);
  }
  const t = schema.type;
  if (t !== undefined) {
    const ts = Array.isArray(t) ? t : [t];
    if (ts.length === 0 || ts.some((x) => typeof x !== "string" || !TYPES.has(x))) out.push(`${path}: bad-type`);
  }
  if (schema.enum !== undefined && (!Array.isArray(schema.enum) || schema.enum.length === 0)) out.push(`${path}: bad-enum`);
  if (schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.some((r) => typeof r !== "string"))) out.push(`${path}: bad-required`);
  for (const k of ["minItems", "maxItems", "minLength", "maxLength", "minProperties", "maxProperties"] as const)
    if (schema[k] !== undefined && !(Number.isInteger(schema[k]) && (schema[k] as number) >= 0)) out.push(`${path}: bad-${k}`);
  for (const k of ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"] as const)
    if (schema[k] !== undefined && typeof schema[k] !== "number") out.push(`${path}: bad-${k}`);
  if (schema.uniqueItems !== undefined && typeof schema.uniqueItems !== "boolean") out.push(`${path}: bad-uniqueItems`);
  if (schema.pattern !== undefined) {
    if (typeof schema.pattern !== "string" || schema.pattern.length > 200 || REDOS.test(schema.pattern)) out.push(`${path}: bad-or-unsafe-pattern`);
    else
      try {
        new RegExp(schema.pattern, "u");
      } catch {
        out.push(`${path}: pattern-not-regexp`);
      }
  }
  if (schema.properties !== undefined) {
    if (!isObj(schema.properties)) out.push(`${path}: bad-properties`);
    else for (const [k, s] of Object.entries(schema.properties)) out.push(...schemaProblems(s, `${path}/properties/${k}`, depth + 1));
  }
  if (schema.items !== undefined) out.push(...schemaProblems(schema.items, `${path}/items`, depth + 1));
  if (schema.additionalProperties !== undefined) out.push(...schemaProblems(schema.additionalProperties, `${path}/additionalProperties`, depth + 1));
  return out;
}

const typeOf = (v: unknown): string => (v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v);
const typeMatches = (want: string, v: unknown): boolean => (want === "number" ? typeof v === "number" && Number.isFinite(v) : typeOf(v) === want);

/** Validate `data` against an already `schemaProblems`-clean schema. Returns error strings (empty = valid). */
export function validate(schema: unknown, data: unknown, at = "$", depth = 0, errors: string[] = []): string[] {
  if (errors.length >= MAX_ERRORS || depth > MAX_DEPTH) return errors;
  const err = (m: string) => {
    if (errors.length < MAX_ERRORS) errors.push(`${at}: ${m}`);
  };
  if (schema === true) return errors;
  if (schema === false) return (err("schema-false-rejects-everything"), errors);
  const s = schema as Obj;
  if (s.type !== undefined) {
    const ts = (Array.isArray(s.type) ? s.type : [s.type]) as string[];
    if (!ts.some((t) => typeMatches(t, data))) return (err(`type-mismatch:expected=${ts.join("|")}:got=${typeOf(data)}`), errors);
  }
  if (s.const !== undefined && canonical(s.const) !== canonical(data)) err("const-mismatch");
  if (Array.isArray(s.enum) && !s.enum.some((e) => canonical(e) === canonical(data))) err("not-in-enum");
  if (typeof data === "string") {
    const len = [...data].length;
    if (typeof s.minLength === "number" && len < s.minLength) err(`minLength:${s.minLength}`);
    if (typeof s.maxLength === "number" && len > s.maxLength) err(`maxLength:${s.maxLength}`);
    if (typeof s.pattern === "string" && data.length <= 10_000 && !new RegExp(s.pattern, "u").test(data)) err("pattern-mismatch");
  }
  if (typeof data === "number") {
    if (typeof s.minimum === "number" && data < s.minimum) err(`minimum:${s.minimum}`);
    if (typeof s.maximum === "number" && data > s.maximum) err(`maximum:${s.maximum}`);
    if (typeof s.exclusiveMinimum === "number" && data <= s.exclusiveMinimum) err(`exclusiveMinimum:${s.exclusiveMinimum}`);
    if (typeof s.exclusiveMaximum === "number" && data >= s.exclusiveMaximum) err(`exclusiveMaximum:${s.exclusiveMaximum}`);
  }
  if (Array.isArray(data)) {
    if (typeof s.minItems === "number" && data.length < s.minItems) err(`minItems:${s.minItems}`);
    if (typeof s.maxItems === "number" && data.length > s.maxItems) err(`maxItems:${s.maxItems}`);
    if (s.uniqueItems === true && new Set(data.map(canonical)).size !== data.length) err("uniqueItems");
    if (s.items !== undefined) data.forEach((x, i) => validate(s.items, x, `${at}[${i}]`, depth + 1, errors));
  }
  if (isObj(data)) {
    const keys = Object.keys(data);
    if (typeof s.minProperties === "number" && keys.length < s.minProperties) err(`minProperties:${s.minProperties}`);
    if (typeof s.maxProperties === "number" && keys.length > s.maxProperties) err(`maxProperties:${s.maxProperties}`);
    for (const r of (s.required as string[] | undefined) ?? []) if (!Object.hasOwn(data, r)) err(`missing-required:${r}`);
    const props = (isObj(s.properties) ? s.properties : {}) as Obj;
    for (const k of keys) {
      if (Object.hasOwn(props, k)) validate(props[k], data[k], `${at}.${k}`, depth + 1, errors);
      else if (s.additionalProperties === false) err(`additional-property:${k}`);
      else if (s.additionalProperties !== undefined && s.additionalProperties !== true) validate(s.additionalProperties, data[k], `${at}.${k}`, depth + 1, errors);
    }
  }
  return errors;
}
