import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { relPathFailure } from "../../kratt/paths.ts";
import { buildJsonSchema, REL_PATH, validateActionReceipt, validateEnvelope, SPECS } from "../protocol/types.ts";
import { check } from "../protocol/spec.ts";
import { envelope } from "./fixtures.ts";

test("a well-formed TaskEnvelope validates", () => {
  assert.deepEqual(validateEnvelope(envelope()).ok, true);
});

test("incompatible protocol major is rejected with a specific reason", () => {
  for (const v of [0, 2, 99]) {
    const r = validateEnvelope({ ...envelope(), protocol_version: v });
    assert.equal(r.ok, false);
    assert.equal(!r.ok && r.reason, `protocol-incompatible-major:${v}`);
  }
  for (const v of ["1", "1.0", null, 1.5, NaN, undefined]) {
    assert.equal(validateEnvelope({ ...envelope(), protocol_version: v }).ok, false, String(v));
  }
});

test("envelope: missing, extra and wrongly typed fields are rejected", () => {
  const base = envelope() as unknown as Record<string, unknown>;
  for (const k of Object.keys(base)) {
    const { [k]: _omit, ...rest } = base;
    assert.equal(validateEnvelope(rest).ok, false, `missing ${k}`);
  }
  assert.equal(validateEnvelope({ ...base, extra: 1 }).ok, false);
  assert.equal(validateEnvelope({ ...base, task_id: "Bad Id" }).ok, false);
  assert.equal(validateEnvelope({ ...base, base_sha: "abc" }).ok, false);
  assert.equal(validateEnvelope({ ...base, scope: [] }).ok, false);
  assert.equal(validateEnvelope({ ...base, scope: ["../etc/passwd"] }).ok, false);
  assert.equal(validateEnvelope({ ...base, scope: ["/abs"] }).ok, false);
  assert.equal(validateEnvelope({ ...base, scope: ["a", "a"] }).ok, false, "duplicate scope");
  assert.equal(validateEnvelope({ ...base, objective: "line\nbreak" }).ok, false);
  assert.equal(validateEnvelope({ ...base, resource_budget: { max_wall_ms: 1, max_output_bytes: 2048, max_files: 4 } }).ok, false);
  for (const hostile of [null, undefined, 0, "x", [], () => 1, 10n]) assert.equal(validateEnvelope(hostile).ok, false);
});

test("envelope: accessor properties and prototype tricks are rejected, never thrown", () => {
  const acc = { ...envelope() } as Record<string, unknown>;
  Object.defineProperty(acc, "objective", { enumerable: true, get: () => "x" });
  assert.equal(validateEnvelope(acc).ok, false);
  const proxy = new Proxy({}, { ownKeys() { throw new Error("trap"); } });
  assert.equal(validateEnvelope(proxy).ok, false);
  assert.equal(validateEnvelope(Object.create(envelope())).ok, false);
});

test("envelope: agent must belong to its factory; allowed and forbidden must not overlap; scope within budget", () => {
  assert.equal(validateEnvelope(envelope({ factory: "SERPENT" })).ok, false);
  assert.equal(validateEnvelope(envelope({ allowed_actions: ["merge"], forbidden_actions: ["merge"] })).ok, false);
  assert.equal(validateEnvelope(envelope({ scope: ["a.ts", "b.ts"], resource_budget: { max_wall_ms: 1000, max_output_bytes: 2048, max_files: 1 } })).ok, false);
});

test("ActionReceipt: closed schema, verification_state enum, strict timestamp", () => {
  const ok = {
    task_id: "t-1", agent_id: "FORGE-026", repository: "o/r", base_sha: "b".repeat(40), action: "hash-files",
    scope: ["a.ts"], result: { ok: true, exit_code: 0, checks: { pass: 1, fail: 0 }, failure: null },
    evidence: { x: 1 }, verification_state: "UNVERIFIED", timestamp: "2026-10-03T00:00:00.000Z", protocol_version: 1,
  };
  assert.equal(validateActionReceipt(ok).ok, true);
  assert.equal(validateActionReceipt({ ...ok, verification_state: "TRUSTED" }).ok, false);
  assert.equal(validateActionReceipt({ ...ok, timestamp: "yesterday" }).ok, false);
  assert.equal(validateActionReceipt({ ...ok, evidence: [] }).ok, false);
  assert.equal(validateActionReceipt({ ...ok, result: { ...ok.result, checks: { pass: -1, fail: 0 } } }).ok, false);
  assert.equal(validateActionReceipt({ ...ok, result: { ...ok.result, exit_code: NaN } }).ok, false);
  assert.equal(validateActionReceipt({ ...ok, protocol_version: 2 }).ok, false);
});

test("REL_PATH accepts exactly the language kratt/paths.ts accepts (no duplicate-but-different path rules)", () => {
  const samples = ["a", "a/b.ts", "cerberus/core/decide.ts", ".git/config", "../x", "/abs", "a//b", "a/", "", "a\\b", "a b", "a\0", "é.ts", "_x/.y", "a/.b", "-x", "a..b", "x".repeat(201), "x".repeat(200), "C:/x"];
  for (const s of samples) assert.equal(REL_PATH.test(s) && s.length >= 1 && s.length <= 200, relPathFailure(s) === null, JSON.stringify(s));
});

test("committed protocol.schema.json is exactly what the specs generate (no drift)", () => {
  const committed = JSON.parse(readFileSync(new URL("../protocol/protocol.schema.json", import.meta.url), "utf8"));
  assert.deepEqual(committed, JSON.parse(JSON.stringify(buildJsonSchema())));
  const defs = Object.keys(committed.$defs).sort();
  assert.deepEqual(defs, ["ActionReceipt", "CerberusDecision", "EvidenceBundle", "RastikFinding", "TaskEnvelope", "ToeparaVerdict"]);
  assert.deepEqual(committed.$defs.TaskEnvelope.required, Object.keys((SPECS.TaskEnvelope as { shape: object }).shape));
  assert.equal(committed.$defs.TaskEnvelope.additionalProperties, false);
});

test("spec checker: arrays with accessors/holes are rejected", () => {
  const holey = new Array(2);
  assert.notEqual(check({ k: "arr", item: { k: "int", min: 0, max: 1 }, min: 0, max: 5 }, holey), null);
});
