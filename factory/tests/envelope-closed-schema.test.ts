import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildJsonSchema, SPECS, validateActionReceipt, validateEnvelope } from "../protocol/types.ts";
import type { Spec } from "../protocol/spec.ts";
import { envelope } from "./fixtures.ts";

/**
 * A-011: the TaskEnvelope and ActionReceipt schemas are CLOSED: an unknown key is rejected at EVERY object level
 * (top level and each nested object), a missing key is rejected, and the generated JSON Schema says the same.
 * The walker below derives its cases from SPECS itself, so a newly added nested object is covered automatically.
 */
const SHA = "a".repeat(40);
const receipt = () => ({
  task_id: "t-001",
  agent_id: "FORGE-026",
  repository: "o/r",
  base_sha: SHA,
  action: "hash-files",
  scope: ["a/b.ts"],
  result: { ok: true, exit_code: 0, checks: { pass: 1, fail: 0 }, failure: null },
  evidence: { anything: "opaque", nested: { x: 1 } },
  verification_state: "UNVERIFIED",
  timestamp: "2026-10-03T00:00:00.000Z",
  protocol_version: 1,
});

type Plain = Record<string | symbol, unknown>;
const clone = <T,>(v: T): T => structuredClone(v);

/** Every object-spec node in `spec`, with the JSON path (as the validator prints it) and a sample value at that node. */
function objectNodes(spec: Spec, sample: unknown, path = "$"): { path: string; keys: string[]; steps: (string | number)[] }[] {
  const out: { path: string; keys: string[]; steps: (string | number)[] }[] = [];
  const walk = (s: Spec, v: unknown, p: string, steps: (string | number)[]) => {
    if (s.k === "obj") {
      out.push({ path: p, keys: Object.keys(s.shape), steps });
      for (const [k, sub] of Object.entries(s.shape)) walk(sub, (v as Plain)[k], `${p}.${k}`, [...steps, k]);
    } else if (s.k === "arr" && Array.isArray(v)) {
      v.forEach((item, i) => walk(s.item, item, `${p}[${i}]`, [...steps, i]));
    } else if (s.k === "or") {
      const hit = s.any.find((a) => (a.k === "null" ? v === null : a.k === "obj" ? typeof v === "object" && v !== null : false));
      if (hit) walk(hit, v, p, steps);
    }
  };
  walk(spec, sample, path, []);
  return out;
}
const containerAt = (root: unknown, steps: (string | number)[]): Plain => steps.reduce<unknown>((o, k) => (o as Plain)[k as string], root) as Plain;

const TYPES = [
  { name: "TaskEnvelope", spec: SPECS.TaskEnvelope, sample: () => ({ ...envelope() }) as unknown, validate: (v: unknown) => validateEnvelope(v) },
  { name: "ActionReceipt", spec: SPECS.ActionReceipt, sample: () => receipt() as unknown, validate: (v: unknown) => validateActionReceipt(v) },
] as const;

for (const T of TYPES) {
  test(`${T.name}: the pristine sample validates (control for every mutation below)`, () => {
    assert.equal(T.validate(T.sample()).ok, true);
  });

  const nodes = objectNodes(T.spec, T.sample());

  test(`${T.name}: closed at every object level (${nodes.map((n) => n.path).join(", ")}) - extra key of any kind is rejected with that level's path`, () => {
    assert.ok(nodes.length >= (T.name === "TaskEnvelope" ? 2 : 3), "walker found the nested objects");
    const names = ["extra", "x", "", " ", "__proto__", "constructor", "prototype", "toString", "hasOwnProperty", "0", "protocol_version2", "Task_id", "TASK_ID", "task_id ", " task_id", "\u00e9", "a\0b"];
    for (const node of nodes) {
      for (const name of names) {
        const v = clone(T.sample());
        Object.defineProperty(containerAt(v, node.steps), name, { value: "boom", enumerable: true, writable: true, configurable: true });
        const r = T.validate(v);
        assert.equal(r.ok, false, `${node.path} + key ${JSON.stringify(name)}`);
        assert.equal(!r.ok && r.reason, `${node.path}:unexpected-or-missing-keys`, `${node.path} + key ${JSON.stringify(name)}`);
      }
    }
  });

  test(`${T.name}: unknown keys of unusual kinds (symbol, non-enumerable, accessor, value undefined) are rejected too`, () => {
    for (const node of nodes) {
      const kinds: [string, (o: Plain) => void][] = [
        ["symbol key", (o) => { o[Symbol("sneaky")] = 1; }],
        ["non-enumerable key", (o) => { Object.defineProperty(o, "hidden", { value: 1, enumerable: false }); }],
        ["accessor key", (o) => { Object.defineProperty(o, "acc", { get: () => 1, enumerable: true }); }],
        ["key present with undefined", (o) => { o.maybe = undefined; }],
        ["key present with null", (o) => { o.maybe = null; }],
        ["nested object value", (o) => { o.extra = { a: { b: 1 } }; }],
      ];
      for (const [label, mutate] of kinds) {
        const v = clone(T.sample());
        mutate(containerAt(v, node.steps));
        const r = T.validate(v);
        assert.equal(r.ok, false, `${node.path}: ${label}`);
      }
    }
  });

  test(`${T.name}: every declared key is required at every level (removing any one key is rejected)`, () => {
    let removed = 0;
    for (const node of nodes) {
      for (const key of node.keys) {
        const v = clone(T.sample());
        delete containerAt(v, node.steps)[key];
        const r = T.validate(v);
        assert.equal(r.ok, false, `${node.path} - ${key}`);
        assert.equal(!r.ok && r.reason, `${node.path}:unexpected-or-missing-keys`, `${node.path} - ${key}: rejected by the key-set check, not by a later accident`);
        removed++;
      }
    }
    assert.ok(removed >= 14, `exercised ${removed} removals`);
  });

  test(`${T.name}: a DECLARED key that is an accessor (getter) is rejected as ${"`<path>.<key>:accessor`"}, never read`, () => {
    let n = 0;
    for (const node of nodes) {
      for (const key of node.keys) {
        const v = clone(T.sample());
        const c = containerAt(v, node.steps);
        const val = c[key];
        delete c[key];
        Object.defineProperty(c, key, { get: () => val, enumerable: true, configurable: true });
        const r = T.validate(v);
        assert.equal(r.ok, false, `${node.path}.${key}`);
        assert.equal(!r.ok && r.reason, `${node.path}.${key}:accessor`, `${node.path}.${key}`);
        n++;
      }
    }
    assert.ok(n >= 14, `exercised ${n} accessors`);
  });

  test(`${T.name}: renaming a key (same key COUNT, wrong name) is rejected - the key check is by set, not by length`, () => {
    for (const node of nodes) {
      const key = node.keys[0] as string;
      const v = clone(T.sample());
      const c = containerAt(v, node.steps);
      c[`${key}_`] = c[key];
      delete c[key];
      const r = T.validate(v);
      assert.equal(r.ok, false, `${node.path} rename ${key}`);
      assert.equal(!r.ok && r.reason, `${node.path}:unexpected-or-missing-keys`);
    }
  });

  test(`${T.name}: an extra key is rejected even when everything else is perfect, and removing it again restores acceptance (it is the ONLY cause)`, () => {
    const v = clone(T.sample()) as Plain;
    v.extra = 1;
    assert.equal(T.validate(v).ok, false);
    delete v.extra;
    assert.equal(T.validate(v).ok, true);
  });

  test(`${T.name}: the generated JSON Schema is closed at every object level and requires every declared key`, () => {
    const defs = (buildJsonSchema() as { $defs: Record<string, unknown> }).$defs;
    const open: string[] = [];
    const seen = { n: 0 };
    const walk = (s: unknown, p: string) => {
      if (typeof s !== "object" || s === null) return;
      const o = s as Plain;
      if (o.type === "object" && o.properties !== undefined) {
        seen.n++;
        const props = Object.keys(o.properties as object);
        if (o.additionalProperties !== false) open.push(`${p}: additionalProperties!=false`);
        if (JSON.stringify([...(o.required as string[])].sort()) !== JSON.stringify([...props].sort())) open.push(`${p}: required!=properties`);
        for (const [k, sub] of Object.entries(o.properties as object)) walk(sub, `${p}.${k}`);
      }
      if (o.type === "array") walk(o.items, `${p}[]`);
      if (Array.isArray(o.anyOf)) o.anyOf.forEach((a, i) => walk(a, `${p}|${i}`));
    };
    walk(defs[T.name], T.name);
    assert.deepEqual(open, []);
    assert.equal(seen.n, nodes.length, "JSON Schema has exactly the object levels the validator has");
  });
}

test("committed protocol.schema.json is byte-identical to what SPECS generates (the closedness above is what ships)", () => {
  const committed = readFileSync(new URL("../protocol/protocol.schema.json", import.meta.url), "utf8");
  assert.equal(committed, JSON.stringify(buildJsonSchema(), null, 2) + "\n");
});

test("DOCUMENTED EXCEPTION: ActionReceipt.evidence is an opaque plain object by design; arbitrary keys INSIDE it are accepted, but it must still be a plain object", () => {
  const r = receipt();
  (r as Plain).evidence = { a: 1, b: { c: [1, 2, 3] }, zzz: "anything" };
  assert.equal(validateActionReceipt(r).ok, true);
  for (const bad of [null, [], "x", 1, true, new Map(), Object.create({ inherited: 1 })]) {
    const x = receipt() as Plain;
    x.evidence = bad;
    assert.equal(validateActionReceipt(x).ok, false, String(bad));
  }
  const missing = receipt() as Plain;
  delete missing.evidence;
  assert.equal(validateActionReceipt(missing).ok, false, "but the evidence key itself is required");
});
