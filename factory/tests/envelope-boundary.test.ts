import test from "node:test";
import assert from "node:assert/strict";
import { Dispatcher, DispatchError } from "../dispatcher.ts";
import { validateEnvelope, type TaskEnvelope } from "../protocol/types.ts";
import { buildInitialRegistry } from "../registry.ts";
import { envelope, fixedClock } from "./fixtures.ts";

/**
 * A-010: boundary tests for every TaskEnvelope field. Each row states what the CURRENT validator does.
 * Rows marked ACCEPT are intentional leniencies of the schema (listed so a tightening/loosening is noticed);
 * behaviour that is unsafe is NOT asserted as expected - it lives in the `todo` tests at the bottom.
 */
const base = (): Record<string, unknown> => ({ ...envelope() });
const withField = (k: string, v: unknown) => ({ ...base(), [k]: v });
const verdict = (e: unknown): string => {
  const r = validateEnvelope(e);
  return r.ok ? "ACCEPT" : r.reason;
};
const field = (k: string, v: unknown) => verdict(withField(k, v));
const eachField = (k: string, rows: [unknown, string][]) => {
  for (const [v, want] of rows) assert.equal(field(k, v), want, `${k}=${typeof v === "string" ? JSON.stringify(v.length > 30 ? v.slice(0, 12) + `…(${v.length})` : v) : JSON.stringify(v)}`);
};
const ids = (n: number, p = "x") => Array.from({ length: n }, (_, i) => `${p}${i}`);

test("task_id: 1..64 chars of [a-z0-9-], must start alphanumeric; NUL, newline, unicode, uppercase are rejected", () => {
  eachField("task_id", [
    ["a", "ACCEPT"], ["0", "ACCEPT"], ["a-b-0", "ACCEPT"], ["a".repeat(64), "ACCEPT"],
    ["", "$.task_id:pattern"], ["a".repeat(65), "$.task_id:pattern"], ["-a", "$.task_id:pattern"], ["A", "$.task_id:pattern"], ["a_b", "$.task_id:pattern"],
    ["a b", "$.task_id:pattern"], ["a\n", "$.task_id:pattern"], ["a\0", "$.task_id:pattern"], ["\u00e9", "$.task_id:pattern"], ["e\u0301", "$.task_id:pattern"], ["\uff41", "$.task_id:pattern"],
    ["a/b", "$.task_id:pattern"], ["../a", "$.task_id:pattern"],
  ]);
});

test("agent_id: <FACTORY>-NNN exactly three digits; must belong to the stated factory", () => {
  eachField("agent_id", [
    ["FORGE-026", "ACCEPT"], ["FORGE-001", "ACCEPT"],
    ["FORGE-26", "$.agent_id:pattern"], ["FORGE-0261", "$.agent_id:pattern"], ["FORGE-026\n", "$.agent_id:pattern"], ["forge-026", "$.agent_id:pattern"], ["FORGE_026", "$.agent_id:pattern"],
    [" FORGE-026", "$.agent_id:pattern"], ["FORGE-02\u0666", "$.agent_id:pattern" /* arabic-indic digit */], ["", "$.agent_id:pattern"],
    ["CITADEL-026", "agent-not-in-factory"], ["SERPENT-026", "agent-not-in-factory"],
  ]);
});

test("CHARACTERISATION: the schema does not bound the agent number; an out-of-registry id passes validation and is stopped by the dispatcher (task-without-owner)", () => {
  for (const id of ["FORGE-000", "FORGE-999", "FORGE-051"]) assert.equal(field("agent_id", id), "ACCEPT", id);
  const d = new Dispatcher(buildInitialRegistry(), { clock: fixedClock() });
  for (const id of ["FORGE-000", "FORGE-999"]) {
    assert.throws(() => d.enqueue({ ...envelope(), agent_id: id }), (e: unknown) => e instanceof DispatchError && e.code === "task-without-owner", id);
  }
  assert.throws(() => d.enqueue({ ...envelope(), agent_id: "FORGE-051" }), (e: unknown) => e instanceof DispatchError && e.code === "task-without-owner", "FORGE-051 is a SERPENT slot: no such FORGE worker");
  assert.equal(d.queue.length, 0, "nothing was queued for any of them");
});

test("factory: exact enum, case and whitespace sensitive", () => {
  eachField("factory", [["FORGE", "ACCEPT"], ["forge", "$.factory:not-in-enum"], ["FORGE ", "$.factory:not-in-enum"], ["", "$.factory:not-in-enum"], ["FORGE\0", "$.factory:not-in-enum"], ["F0RGE", "$.factory:not-in-enum"], [null, "$.factory:not-in-enum"], [1, "$.factory:not-in-enum"]]);
});

test("objective: 1..500 UTF-16 code units, no C0 controls/DEL; length counts code units (astral chars count twice)", () => {
  eachField("objective", [
    ["x", "ACCEPT"], ["x".repeat(500), "ACCEPT"], ["x".repeat(501), "$.objective:too-long"], ["", "$.objective:too-short"],
    ["\u{1F600}".repeat(250), "ACCEPT"], ["\u{1F600}".repeat(251), "$.objective:too-long"], ["x".repeat(499) + "\u{1F600}", "$.objective:too-long"],
    ["a\0b", "$.objective:pattern"], ["\0", "$.objective:pattern"], ["a\nb", "$.objective:pattern"], ["a\rb", "$.objective:pattern"], ["a\tb", "$.objective:pattern"], ["a\x1bb", "$.objective:pattern"], ["a\x7fb", "$.objective:pattern"], ["a\x08b", "$.objective:pattern"],
  ]);
  for (let c = 0; c < 0x20; c++) assert.equal(field("objective", `a${String.fromCharCode(c)}b`), "$.objective:pattern", `U+${c.toString(16).padStart(4, "0")}`);
});

test("CHARACTERISATION objective unicode: NFC and NFD forms are both accepted and NOT normalised (distinct strings, distinct digests)", () => {
  const nfc = "\u00e9";
  const nfd = "e\u0301";
  assert.notEqual(nfc, nfd);
  assert.equal(field("objective", nfc), "ACCEPT");
  assert.equal(field("objective", nfd), "ACCEPT");
  const a = validateEnvelope(withField("objective", nfc));
  const b = validateEnvelope(withField("objective", nfd));
  assert.ok(a.ok && b.ok);
  assert.equal(a.value.objective, nfc, "value is returned verbatim");
  assert.equal(b.value.objective, nfd);
});

test("repository: owner/name, [A-Za-z0-9_.-]{1,100} each side; exactly one slash", () => {
  eachField("repository", [
    ["o/r", "ACCEPT"], ["O-w_n.er/R.e-p_o", "ACCEPT"], [`${"a".repeat(100)}/${"b".repeat(100)}`, "ACCEPT"],
    [`${"a".repeat(101)}/b`, "$.repository:pattern"], [`a/${"b".repeat(101)}`, "$.repository:pattern"],
    ["", "$.repository:pattern"], ["o", "$.repository:pattern"], ["/r", "$.repository:pattern"], ["o/", "$.repository:pattern"], ["o/r/x", "$.repository:pattern"], ["o//r", "$.repository:pattern"],
    ["o r/x", "$.repository:pattern"], ["o/r\n", "$.repository:pattern"], ["o/r\0", "$.repository:pattern"], ["\u00e9/r", "$.repository:pattern"], ["o/r?x=1", "$.repository:pattern"], ["o\\r", "$.repository:pattern"], ["https://x/y", "$.repository:pattern"],
  ]);
});

test("branch: starts alphanumeric, then [A-Za-z0-9._/-], 1..200; leading '-' (option injection), whitespace, '@{', unicode, control chars rejected", () => {
  eachField("branch", [
    ["main", "ACCEPT"], ["factory/handlers-and-debt", "ACCEPT"], ["v1.2.3", "ACCEPT"], ["a".repeat(200), "ACCEPT"],
    ["a".repeat(201), "$.branch:pattern"], ["", "$.branch:pattern"], ["-x", "$.branch:pattern"], ["--upload-pack=x", "$.branch:pattern"], ["/x", "$.branch:pattern"], [".x", "$.branch:pattern"], ["_x", "$.branch:pattern"],
    ["a b", "$.branch:pattern"], ["a\tb", "$.branch:pattern"], ["a\nb", "$.branch:pattern"], ["a\0b", "$.branch:pattern"], ["a@{1}", "$.branch:pattern"], ["a\u00e9", "$.branch:pattern"], ["a\u202e", "$.branch:pattern"], ["a\u2028b", "$.branch:pattern"], ["a~1", "$.branch:pattern"], ["a^", "$.branch:pattern"], ["a:b", "$.branch:pattern"], ["a\\b", "$.branch:pattern"], ["\u00e9", "$.branch:pattern"], ["a*", "$.branch:pattern"], ["a?", "$.branch:pattern"], ["a[", "$.branch:pattern"],
  ]);
});

test("base_sha: exactly 40 lowercase hex; 39, 41, uppercase, trailing newline, 0x prefix, sha256-length, non-hex are rejected", () => {
  const h = "0123456789abcdef0123456789abcdef01234567";
  eachField("base_sha", [
    [h, "ACCEPT"], ["0".repeat(40), "ACCEPT"],
    [h.slice(1), "$.base_sha:pattern"], [h + "0", "$.base_sha:pattern"], [h.toUpperCase(), "$.base_sha:pattern"], [h + "\n", "$.base_sha:pattern"], [" " + h.slice(1), "$.base_sha:pattern"],
    ["0x" + h.slice(2), "$.base_sha:pattern"], ["g" + h.slice(1), "$.base_sha:pattern"], [h + h.slice(0, 24), "$.base_sha:pattern"], ["", "$.base_sha:pattern"], ["HEAD", "$.base_sha:pattern"], ["main", "$.base_sha:pattern"], [h.slice(0, 7), "$.base_sha:pattern"],
  ]);
});

test("scope: 1..64 unique repo-relative paths; traversal/absolute/NUL/hidden/backslash/oversize elements rejected at the element index", () => {
  const lots = (n: number) => Array.from({ length: n }, (_, i) => `d/f${i}.ts`);
  const big = { ...base(), resource_budget: { max_wall_ms: 5000, max_output_bytes: 65536, max_files: 64 } };
  const v = (scope: unknown) => verdict({ ...big, scope });
  assert.equal(v(["a"]), "ACCEPT");
  assert.equal(v(lots(64)), "ACCEPT");
  assert.equal(v(lots(65)), "$.scope:length");
  assert.equal(v([]), "$.scope:length");
  assert.equal(v(["a", "a"]), "$.scope[1]:duplicate");
  assert.equal(v(["ok", "../x"]), "$.scope[1]:pattern");
  assert.equal(v(["/etc/passwd"]), "$.scope[0]:pattern");
  assert.equal(v(["a\0b"]), "$.scope[0]:pattern");
  assert.equal(v([".env"]), "$.scope[0]:pattern");
  assert.equal(v(["a\\b"]), "$.scope[0]:pattern");
  assert.equal(v(["a/"]), "$.scope[0]:pattern");
  assert.equal(v(["a//b"]), "$.scope[0]:pattern");
  assert.equal(v(["x".repeat(200)]), "ACCEPT");
  assert.equal(v(["x".repeat(201)]), "$.scope[0]:too-long");
  assert.equal(v(["\u00e9"]), "$.scope[0]:pattern");
  assert.equal(v([5]), "$.scope[0]:not-string");
  assert.equal(v([null]), "$.scope[0]:not-string");
  assert.equal(v([["a"]]), "$.scope[0]:not-string");
  assert.equal(v("a"), "$.scope:not-array");
  assert.equal(v({ 0: "a", length: 1 }), "$.scope:not-array");
  // sparse array hole and extra array properties
  assert.equal(v(["a", , "c"]), "$.scope[1]:unreadable"); // eslint-disable-line no-sparse-arrays
});

test("scope vs resource_budget.max_files: scope longer than max_files is rejected by validateEnvelope even though both fields are individually valid", () => {
  const e = (n: number, max: number) => ({ ...base(), scope: Array.from({ length: n }, (_, i) => `f${i}`), resource_budget: { max_wall_ms: 5000, max_output_bytes: 65536, max_files: max } });
  assert.equal(verdict(e(4, 4)), "ACCEPT");
  assert.equal(verdict(e(5, 4)), "scope-exceeds-max-files");
  assert.equal(verdict(e(1, 1)), "ACCEPT");
  assert.equal(verdict(e(2, 1)), "scope-exceeds-max-files");
  assert.equal(verdict(e(64, 64)), "ACCEPT");
});

test("action lists: allowed 1..16, forbidden 0..32, required_evidence 1..16, unique tokens [a-z][a-z0-9:_-]{0,63}", () => {
  assert.equal(field("allowed_actions", ids(16)), "ACCEPT");
  assert.equal(field("allowed_actions", ids(17)), "$.allowed_actions:length");
  assert.equal(field("allowed_actions", []), "$.allowed_actions:length");
  assert.equal(field("forbidden_actions", []), "ACCEPT");
  assert.equal(field("forbidden_actions", ids(32, "f")), "ACCEPT");
  assert.equal(field("forbidden_actions", ids(33, "f")), "$.forbidden_actions:length");
  assert.equal(field("required_evidence", ids(16, "e")), "ACCEPT");
  assert.equal(field("required_evidence", ids(17, "e")), "$.required_evidence:length");
  assert.equal(field("required_evidence", []), "$.required_evidence:length");
  for (const k of ["allowed_actions", "forbidden_actions", "required_evidence"]) {
    assert.equal(field(k, ["a".repeat(64)]), "ACCEPT", k);
    assert.equal(field(k, ["a".repeat(65)]), `$.${k}[0]:pattern`, k);
    assert.equal(field(k, ["a:b_c-d9"]), "ACCEPT", k);
    for (const bad of ["", "A", "1a", "-a", "a b", "a\n", "a\0", "\u00e9", "a.b", "a/b", " a"]) assert.equal(field(k, [bad]), `$.${k}[0]:pattern`, `${k} ${JSON.stringify(bad)}`);
    assert.equal(field(k, ["a", "a"]), `$.${k}[1]:duplicate`, k);
    assert.equal(field(k, [1]), `$.${k}[0]:not-string`, k);
  }
  assert.equal(verdict({ ...base(), allowed_actions: ["merge"], forbidden_actions: ["merge"] }), "action-both-allowed-and-forbidden");
  assert.equal(verdict({ ...base(), allowed_actions: ["merge", "x"], forbidden_actions: ["y", "merge"] }), "action-both-allowed-and-forbidden");
});

test("resource_budget: every bound, both sides (wall 100..600000 ms, output 1024..1048576 B, files 1..64), integers only", () => {
  const rb = (over: Record<string, unknown>) => ({ ...base(), scope: ["a"], resource_budget: { max_wall_ms: 5000, max_output_bytes: 65536, max_files: 8, ...over } });
  const rows: [string, unknown, string][] = [
    ["max_wall_ms", 99, "$.resource_budget.max_wall_ms:out-of-range"], ["max_wall_ms", 100, "ACCEPT"], ["max_wall_ms", 600_000, "ACCEPT"], ["max_wall_ms", 600_001, "$.resource_budget.max_wall_ms:out-of-range"],
    ["max_output_bytes", 1023, "$.resource_budget.max_output_bytes:out-of-range"], ["max_output_bytes", 1024, "ACCEPT"], ["max_output_bytes", 1_048_576, "ACCEPT"], ["max_output_bytes", 1_048_577, "$.resource_budget.max_output_bytes:out-of-range"],
    ["max_files", 0, "$.resource_budget.max_files:out-of-range"], ["max_files", 1, "ACCEPT"], ["max_files", 64, "ACCEPT"], ["max_files", 65, "$.resource_budget.max_files:out-of-range"],
  ];
  for (const [k, v, want] of rows) assert.equal(verdict(rb({ [k]: v })), want, `${k}=${String(v)}`);
  for (const k of ["max_wall_ms", "max_output_bytes", "max_files"]) {
    for (const v of [1.5, NaN, Infinity, -Infinity, "1000", null, true, [1000], 1000n, 2 ** 53, -0.0001, undefined]) assert.equal(verdict(rb({ [k]: v })), `$.resource_budget.${k}:not-integer`, `${k}=${String(v)}`);
  }
  assert.equal(verdict(rb({ max_files: -1 })), "$.resource_budget.max_files:out-of-range");
  assert.equal(verdict({ ...base(), resource_budget: null }), "$.resource_budget:not-plain-object");
  assert.equal(verdict({ ...base(), resource_budget: [] }), "$.resource_budget:not-plain-object");
  assert.equal(verdict({ ...base(), resource_budget: { max_wall_ms: 5000, max_output_bytes: 65536 } }), "$.resource_budget:unexpected-or-missing-keys");
});

test("wrong JSON types for every field: number, null, boolean, array, object, undefined, bigint, function are all rejected", () => {
  const wrong = [0, 1, null, true, false, [], ["x"], {}, undefined, 10n, () => "x", Symbol("s")];
  const stringFields = ["task_id", "factory", "agent_id", "objective", "repository", "branch", "base_sha"];
  for (const k of stringFields) for (const v of wrong) assert.notEqual(field(k, v), "ACCEPT", `${k}=${typeof v}`);
  for (const k of ["scope", "allowed_actions", "forbidden_actions", "required_evidence"]) for (const v of [0, null, true, "x", {}, undefined, 10n, () => []]) assert.notEqual(field(k, v), "ACCEPT", `${k}=${typeof v}`);
  for (const k of stringFields) assert.match(field(k, 123), /not-string|not-in-enum/, k);
  // No String() coercion: values that stringify to a valid token are still not strings.
  assert.equal(field("factory", ["FORGE"]), "$.factory:not-in-enum");
  assert.equal(field("factory", { toString: () => "FORGE" }), "$.factory:not-in-enum");
  assert.equal(field("task_id", ["abc"]), "$.task_id:not-string");
  assert.equal(field("base_sha", [`${"a".repeat(40)}`]), "$.base_sha:not-string");
  // protocol_version is a strict literal: no loose equality, no coercion.
  for (const pv of ["1", true, [1], ["1"], 1.0000001, "01", null, undefined]) assert.equal(field("protocol_version", pv), "$.protocol_version:literal-mismatch", `protocol_version=${String(pv)}`);
  // A different integer major gets the dedicated, machine-readable reason.
  for (const pv of [0, 2, 3, -1, 1000]) assert.equal(field("protocol_version", pv), `protocol-incompatible-major:${pv}`);
  assert.equal(field("protocol_version", 1), "ACCEPT");
});

test("hostile containers: non-objects, class instances, Proxy, accessors, symbol keys, non-enumerable and __proto__ keys all fail closed without throwing", () => {
  for (const x of [null, undefined, 0, 1, "", "x", true, [], [envelope()], () => envelope(), 10n, Symbol("s"), new Map(), new Date(0), /re/, Buffer.from("{}")]) assert.notEqual(verdict(x), "ACCEPT", String(typeof x));
  class Env { constructor(o: object) { Object.assign(this, o); } }
  assert.equal(verdict(new Env(envelope())), "$:not-plain-object");
  assert.equal(verdict(Object.create(null, Object.fromEntries(Object.entries(envelope()).map(([k, v]) => [k, { value: v, enumerable: true }])))), "ACCEPT", "null-prototype plain object is fine");
  assert.equal(verdict(Object.freeze(envelope())), "ACCEPT");
  const getter = { ...envelope() } as Record<string, unknown>;
  delete getter.objective;
  Object.defineProperty(getter, "objective", { enumerable: true, get: () => "x" });
  assert.equal(verdict(getter), "$.objective:accessor");
  const accElem = { ...envelope(), scope: [] as string[] };
  Object.defineProperty(accElem.scope, "0", { get: () => "ok.txt", enumerable: true });
  assert.equal(verdict(accElem), "$.scope[0]:unreadable", "an array element that is an accessor is never read");
  const sparse = { ...envelope(), scope: new Array<string>(1) };
  assert.equal(verdict(sparse), "$.scope[0]:unreadable", "a hole in an array is not an element");
  const sym = { ...envelope(), [Symbol("s")]: 1 };
  assert.equal(verdict(sym), "$:unexpected-or-missing-keys");
  const hidden = { ...envelope() };
  Object.defineProperty(hidden, "hidden", { value: 1, enumerable: false });
  assert.equal(verdict(hidden), "$:unexpected-or-missing-keys", "non-enumerable extra key still counts");
  assert.equal(verdict(JSON.parse(`${JSON.stringify(envelope()).slice(0, -1)},"__proto__":{"agent_id":"FORGE-001"}}`)), "$:unexpected-or-missing-keys", "own __proto__ data key from JSON.parse");
  const boom = new Proxy({}, { ownKeys() { throw new Error("boom"); }, getOwnPropertyDescriptor() { throw new Error("boom"); }, getPrototypeOf() { throw new Error("boom"); } });
  assert.equal(verdict(boom), "$:unreadable");
  const nestedBoom = { ...envelope(), resource_budget: boom };
  assert.equal(verdict(nestedBoom), "$:unreadable", "a throw anywhere is converted at the top-level check() boundary");
});

test("a valid envelope is returned by identity-preserving validation (no mutation, no coercion of the caller's object)", () => {
  const e = envelope();
  const before = JSON.stringify(e);
  const r = validateEnvelope(e);
  assert.ok(r.ok);
  assert.equal(r.value, e, "same object returned");
  assert.equal(JSON.stringify(e), before);
});

// ----------------------------------------------------------------------------------------------
// DEFECTS (reported as F2/F3 in the PR). These assert the SAFE behaviour and are `todo` so the suite
// stays green while open; remove `todo` once the validator is tightened and they must pass.
// ----------------------------------------------------------------------------------------------
test("F2: objective must not contain C1 controls, line/paragraph separators, bidi overrides/isolates or lone surrogates", { todo: "validator only forbids C0+DEL (types.ts TEXT regex); display/log spoofing risk" }, () => {
  for (const bad of ["a\u0085b", "a\u2028b", "a\u2029b", "a\u202eb", "a\u2066b", "a\u200bb", "a\ufeffb", "a\ud800b"]) assert.notEqual(field("objective", bad), "ACCEPT", JSON.stringify(bad));
});

test("F3: repository and branch must be well-formed slugs/refs (no '.'/'..' segments, no '//', no trailing '/' or '.lock', no '..')", { todo: "REPO/BRANCH regexes accept '../..', './.', 'a/../b', 'a//b', 'a/', 'a.lock', 'a..b'" }, () => {
  for (const bad of ["./.", "../..", "./..", "../."]) assert.notEqual(field("repository", bad), "ACCEPT", `repository ${bad}`);
  for (const bad of ["a/../b", "a//b", "a/", "a.lock", "a..b", "a/.b"]) assert.notEqual(field("branch", bad), "ACCEPT", `branch ${bad}`);
});

test("F4: validateEnvelope must not throw, and must not hand back an object whose reads differ from what was validated (Proxy with a hostile get trap)", { todo: "validateEnvelope validates via property descriptors but then reads e.agent_id etc. through [[Get]] and returns the original object (types.ts); a throwing/lying get trap escapes the fail-closed contract" }, () => {
  const throwing = new Proxy(envelope(), { get: () => { throw new Error("get trap"); } });
  assert.doesNotThrow(() => validateEnvelope(throwing), "a hostile input must come back as {ok:false}, not as an exception");
  const real = envelope();
  let reads = 0;
  const lying = new Proxy(real, { get: (t, k, r) => (k === "agent_id" && ++reads > 0 ? "SERPENT-099" : Reflect.get(t, k, r)) });
  const r = validateEnvelope(lying);
  assert.ok(!r.ok || r.value.agent_id === real.agent_id, "validated value and consumed value must be the same");
});

export type _Keep = TaskEnvelope;
