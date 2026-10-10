// Uniqueness checker + spec-harness tests. The real specs live in factory/matrix/specs/*.mjs.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { assertionFingerprint, combineEntries, validateSpecs, canon, canonJson, normalizeSource, MAX_SHARED_PATH_GROUP } from "../../factory/matrix/spec-lib.mjs";
import { MUTANTS } from "../../factory/matrix/mutants.mjs";
import { runSpecs, specFiles, guardFiles, execSpecFile } from "./specs.mjs";

const T = "scripts/preview.mjs";
const spec = (slot, over = {}) => ({ slot, target: T, fn: "parsePid", input: ["42"], expected: 42, claim: "parsePid reads a plain integer pid from text", ...over });
const entry = (slot, over = {}) => ({ slot, file: "f.mjs", target: T, fn: "parsePid", claim: "claim long enough to count", valid: true, fingerprint: `fp${slot}`, behaviour: `bh${slot}`, result: { ok: true, calls: 1, digest: "d", path: "p", error: null }, ...over });

describe("uniqueness checker (static, synthetic specs)", () => {
  it("accepts distinct specs", () => {
    const { valid, violations } = validateSpecs([spec(1), spec(2, { input: ["43"], expected: 43 })]);
    assert.deepEqual(violations, []);
    assert.deepEqual([...valid.keys()], [1, 2]);
  });
  it("FAILS when two slots share an assertion fingerprint (copy-paste with a renamed id / reworded claim)", () => {
    const { valid, violations } = validateSpecs([spec(1), spec(2, { claim: "a completely reworded claim, same assertion" })]);
    assert.equal(valid.size, 0, "neither duplicate may count as specified");
    assert.match(violations.join("|"), /slots 1,2 share assertion fingerprint/);
  });
  it("the fingerprint ignores the slot number, the claim text and whitespace in probe source", () => {
    const a = { slot: 1, target: T, expected: 1, claim: "x".repeat(30), run: (m) => m.parsePid("1") };
    const b = { slot: 99, target: T, expected: 1, claim: "y".repeat(40), run: (m) =>   m.parsePid( "1" ) };
    assert.equal(assertionFingerprint(a), assertionFingerprint(b));
    const { valid, violations } = validateSpecs([a, b]);
    assert.equal(valid.size, 0);
    assert.match(violations.join("|"), /share assertion fingerprint/);
  });
  it("the fingerprint DOES change with input, expected value, target, function and probe logic", () => {
    const base = assertionFingerprint(spec(1));
    for (const o of [{ input: ["43"] }, { expected: 43 }, { fn: "parsePgid" }, { target: "scripts/with-app-env.mjs" }]) assert.notEqual(assertionFingerprint(spec(1, o)), base, JSON.stringify(o));
    const r1 = assertionFingerprint({ target: T, expected: 1, run: (m) => m.parsePid("1") });
    const r2 = assertionFingerprint({ target: T, expected: 1, run: (m) => m.parsePid("2") });
    assert.notEqual(r1, r2);
    // function-valued inputs are fingerprinted by source, not dropped
    assert.notEqual(assertionFingerprint(spec(1, { input: [() => 1] })), assertionFingerprint(spec(1, { input: [() => 2] })));
  });
  it("rejects duplicate slots, bad slot numbers, missing/blank fields and non-domain targets", () => {
    const bad = (s, re) => assert.match(validateSpecs([s]).violations.join("|"), re);
    assert.match(validateSpecs([spec(1), spec(1, { input: ["9"], expected: 9 })]).violations.join("|"), /duplicate spec for slot 1/);
    bad(spec(0), /slot must be an integer 1..250/);
    bad(spec(251), /slot must be an integer 1..250/);
    bad(spec(1.5), /slot must be an integer 1..250/);
    bad(spec(1, { expected: undefined }), /expected value is required/);
    bad(spec(1, { claim: "too short" }), /claim must be a text of at least 20 characters/);
    bad(spec(1, { config: "yes" }), /config must be a boolean/);
    bad(spec(1, { fn: undefined, input: undefined }), /exactly one of fn/);
    bad(spec(1, { run: () => 1 }), /exactly one of fn/);
    bad(spec(1, { input: undefined }), /fn spec needs an input array/);
    bad(spec(1, { target: "no/such/file.mjs" }), /does not exist/);
    bad(spec(1, { target: "/etc/passwd" }), /repo-relative/);
    bad(spec(1, { target: "../x.mjs" }), /repo-relative/);
    bad(spec(1, { target: "scripts/matrix250/matrix.mjs" }), /not domain code/);
    bad(spec(1, { target: "factory/matrix/spec-lib.mjs" }), /not domain code/);
    bad(spec(1, { target: "scripts/preview.test.mjs" }), /not domain code/);
    bad(spec(1, { target: "package.json" }), /data targets need a run probe/);
  });
  it("combineEntries: slot with two specs, shared assertion fingerprint or shared behaviour fingerprint are all NOT specified", () => {
    const dupSlot = combineEntries([entry(1), entry(1, { file: "g.mjs", fingerprint: "other", behaviour: "otherb" }), entry(2)]);
    assert.deepEqual([...dupSlot.specified.keys()], [2]);
    assert.match(dupSlot.violations.join("|"), /slot 1 has 2 specs/);
    const fp = combineEntries([entry(1, { fingerprint: "same" }), entry(2, { fingerprint: "same" }), entry(3)]);
    assert.deepEqual([...fp.specified.keys()], [3]);
    assert.match(fp.violations.join("|"), /slots 1,2 share assertion fingerprint/);
    const bh = combineEntries([entry(1, { behaviour: "same" }), entry(2, { behaviour: "same" }), entry(3)]);
    assert.deepEqual([...bh.specified.keys()], [3]);
    assert.match(bh.violations.join("|"), /slots 1,2 share behaviour fingerprint/);
  });
  it("combineEntries: DOMAIN_VERIFIED needs an ok result with >= 1 observed call into the target", () => {
    const c = combineEntries([entry(1), entry(2, { result: { ok: true, calls: 0, digest: "-", path: "p", error: null } }), entry(3, { result: { ok: false, calls: 2, digest: "-", path: "p", error: "x" } }), entry(4, { result: null }), entry(5, { valid: false })]);
    assert.deepEqual([...c.specified.keys()].sort(), [1, 2, 3, 4]);
    assert.deepEqual([...c.domainVerified], [1]);
  });
  it("fingerprints ignore comments and formatting but not code: a comment-only or whitespace-only variation collides, a changed literal does not", () => {
    const mk = (run) => ({ slot: 1, target: T, expected: 1, claim: "x".repeat(30), run });
    const a = mk((m) => m.parsePid("1"));
    const b = mk((m) => /* a comment that changes nothing */ m.parsePid( // trailing
      "1"));
    assert.equal(assertionFingerprint(a), assertionFingerprint(b));
    assert.notEqual(assertionFingerprint(a), assertionFingerprint(mk((m) => m.parsePid("2"))));
    assert.equal(normalizeSource("a  +  /* c */ b // d\n"), normalizeSource("a+b"));
    assert.notEqual(normalizeSource("'a b'"), normalizeSource("'a  b'"), "string literal content is code");
    assert.equal(normalizeSource("x = /re//* not a comment */g.test(`t ${1 /* c */}`)"), normalizeSource("x=/re//* not a comment */g.test(`t ${1}`)"));
  });
  it("combineEntries: CONFIG_PINNED is split from DOMAIN_VERIFIED and a config entry never counts as domain-verified", () => {
    const c = combineEntries([entry(1), entry(2, { config: true }), entry(3, { target: "package.json" }), entry(4, { result: { ok: true, calls: 1, digest: "d", path: "p", feeds: false, error: null } })]);
    assert.deepEqual([...c.domainVerified], [1]);
    assert.deepEqual([...c.configPinned].sort(), [2, 3]);
    assert.deepEqual([...c.specified.keys()].sort(), [1, 2, 3, 4]);
  });
  it("combineEntries: SHARED_PATH groups slots whose observed path is identical, ignores unobserved paths, and flags a group above the limit", () => {
    const at = (path) => ({ ok: true, calls: 1, digest: "d", path, error: null });
    const c = combineEntries([entry(1, { result: at("A/3") }), entry(2, { result: at("A/3") }), entry(3, { result: at("B/2") }), entry(4, { result: at("-") }), entry(5, { result: at("-") })]);
    assert.deepEqual(c.sharedPathGroups, [[1, 2]]);
    assert.deepEqual([...c.sharedPathSlots], [1, 2]);
    assert.deepEqual(c.violations, []);
    const many = Array.from({ length: MAX_SHARED_PATH_GROUP + 1 }, (_, i) => entry(i + 1, { result: at("Z/9") }));
    const v = combineEntries(many);
    assert.match(v.violations.join("|"), new RegExp(`${MAX_SHARED_PATH_GROUP + 1} slots .* execute one identical code path`));
  });
  it("validateSpecs guard mode accepts ids 1001..1999 only", () => {
    assert.deepEqual(validateSpecs([spec(1001)], process.cwd(), { guard: true }).violations, []);
    assert.match(validateSpecs([spec(1)], process.cwd(), { guard: true }).violations.join("|"), /slot must be an integer 1001..1999/);
    assert.match(validateSpecs([spec(1001)]).violations.join("|"), /slot must be an integer 1..250/);
  });
  it("canon distinguishes values JSON collapses", () => {
    assert.notEqual(canonJson(undefined), canonJson(null));
    assert.notEqual(canonJson(NaN), canonJson(null));
    assert.notEqual(canonJson(1n), canonJson(1));
    assert.equal(canonJson({ b: 1, a: 2 }), canonJson({ a: 2, b: 1 }));
    assert.notEqual(canonJson(new Set([1])), canonJson([1]));
    assert.deepEqual(canon(new Error("x")), { $: "error", name: "Error", message: "x" });
  });
});

describe("the real specs (factory/matrix/specs)", () => {
  const run = runSpecs();
  const slotsWithSpecs = run.entries.map((e) => e.slot);

  it("exist for exactly slots 1..250, one spec each, in well-formed spec files", () => {
    assert.ok(specFiles().length >= 5);
    assert.deepEqual([...slotsWithSpecs].sort((a, b) => a - b), Array.from({ length: 250 }, (_, i) => i + 1));
    assert.deepEqual(run.errors, []);
  });
  it("no two slots share an assertion fingerprint or a behaviour fingerprint (uniqueness checker over the real specs)", () => {
    assert.deepEqual(run.violations, []);
    assert.equal(new Set(run.entries.map((e) => e.fingerprint)).size, 250);
    assert.equal(new Set(run.entries.map((e) => e.behaviour)).size, 250);
    assert.equal(new Set(run.entries.map((e) => e.claim)).size, 250, "every slot has its own written claim");
  });
  it("every real spec ran against real domain code (>= 1 observed call) and matched its expected value", () => {
    const failing = run.entries.filter((e) => !e.result.ok).map((e) => `${e.slot}: ${e.result.error}`);
    assert.deepEqual(failing, []);
    assert.ok(run.entries.every((e) => e.result.calls >= 1));
    assert.equal(run.specified.size, 250);
  });
  it("DOMAIN_VERIFIED and CONFIG_PINNED are split honestly: 7 config-only slots are pinned, the other 243 execute real domain code", () => {
    assert.deepEqual([...run.configPinned].sort((a, b) => a - b), [1, 2, 3, 4, 10, 50, 51]);
    assert.equal(run.domainVerified.size, 243);
    for (const n of run.configPinned) assert.ok(!run.domainVerified.has(n), `slot ${n} is config-only and must not be DOMAIN_VERIFIED`);
    assert.equal(run.domainVerified.size + run.configPinned.size, run.specified.size);
  });
  it("shared code paths are reported, not hidden: SHARED_PATH slots exist, each group is below the limit, and every slot of a group has the same observed path", () => {
    assert.ok(run.sharedPathGroups.length > 0);
    assert.equal(run.sharedPathSlots.size, run.sharedPathGroups.flat().length);
    for (const g of run.sharedPathGroups) {
      assert.ok(g.length > 1 && g.length <= MAX_SHARED_PATH_GROUP);
      assert.equal(new Set(g.map((n) => run.entries.find((e) => e.slot === n).result.path)).size, 1);
    }
  });
  it("every result carries the dependence verdict: all fn specs feed the assertion, every run probe was stub-checked", () => {
    assert.ok(run.entries.every((e) => e.result.feeds === true || (e.result.feeds === undefined && e.result.ok)));
  });
  it("targets are real domain code: none is the harness, a test file or node_modules", () => {
    for (const e of run.entries) assert.doesNotMatch(e.target, /^(factory\/matrix|scripts\/matrix250|node_modules)\/|\.test\.[cm]?[jt]sx?$/, `slot ${e.slot}`);
  });
  it("regression guards (ids 1001+) are not slots: all pass, are unique, and never enter SPECIFIED or DOMAIN_VERIFIED", () => {
    assert.ok(guardFiles().length >= 4);
    assert.equal(run.guards.total, 12);
    assert.equal(run.guards.passed, 12);
    assert.ok(run.guards.entries.every((e) => e.slot >= 1001 && !run.specified.has(e.slot) && !run.domainVerified.has(e.slot)));
    assert.equal(new Set(run.guards.entries.map((e) => e.fingerprint)).size, 12);
  });
  it("the comparison is real: with every expected value replaced by an impossible sentinel, ALL 250 specs fail", () => {
    const mutated = runSpecs({ mutate: true });
    assert.equal(mutated.entries.length, 250);
    assert.equal(mutated.entries.filter((e) => e.result.ok).length, 0);
    assert.equal(mutated.domainVerified.size, 0);
  });
  it("a probe that never touches the real module is not DOMAIN_VERIFIED (no observed call)", () => {
    const dir = mkdtempSync(join(tmpdir(), "m-spec-"));
    const f = join(dir, "fake.mjs");
    writeFileSync(f, `export const SPECS = [{ slot: 7, target: "scripts/preview.mjs", expected: 3, run: () => 1 + 2, claim: "a probe that computes without calling the target" }];\n`);
    const r = execSpecFile(f);
    assert.equal(r.entries[0].result.ok, false);
    assert.match(r.entries[0].result.error, /no call into the target module was observed/);
    const c = combineEntries(r.entries);
    assert.equal(c.domainVerified.size, 0);
  });
  it("gaming: a constant return after a call that does not feed the result is rejected (result does not depend on the target)", () => {
    const dir = mkdtempSync(join(tmpdir(), "m-spec-"));
    const f = join(dir, "const.mjs");
    writeFileSync(f, `export const SPECS = [{ slot: 7, target: "scripts/preview.mjs", expected: "CONST", run: (m) => { m.parsePid("1"); return "CONST"; }, claim: "calls the target but returns a constant" }];\n`);
    const r = execSpecFile(f);
    assert.equal(r.entries[0].result.ok, false);
    assert.match(r.entries[0].result.error, /does not depend on the target/);
    assert.equal(combineEntries(r.entries).domainVerified.size, 0);
  });
  it("a probe whose answer really comes from the target is accepted and marked as feeding the assertion", () => {
    const dir = mkdtempSync(join(tmpdir(), "m-spec-"));
    const f = join(dir, "feeds.mjs");
    writeFileSync(f, `export const SPECS = [{ slot: 7, target: "scripts/preview.mjs", expected: 42, run: (m) => m.parsePid("42"), claim: "parsePid parses a plain pid through the probe" }];\n`);
    const r = execSpecFile(f);
    assert.equal(r.entries[0].result.ok, true, String(r.entries[0].result.error));
    assert.equal(r.entries[0].result.feeds, true);
  });
  it("a spec whose real module returns something else fails with the actual value reported", () => {
    const dir = mkdtempSync(join(tmpdir(), "m-spec-"));
    const f = join(dir, "wrong.mjs");
    writeFileSync(f, `export const SPECS = [{ slot: 7, target: "scripts/preview.mjs", fn: "parsePid", input: ["42"], expected: 43, claim: "parsePid claimed to return 43 for 42 (wrong)" }];\n`);
    const r = execSpecFile(f);
    assert.equal(r.entries[0].result.ok, false);
    assert.match(r.entries[0].result.error, /expected 43 but got 42/);
  });
  it("a spec file that cannot run is a violation, never silently skipped", () => {
    const r = runSpecs({ files: ["factory/matrix/specs/does-not-exist.mjs"], exec: (f) => execSpecFile(f) });
    assert.ok(r.violations.some((v) => v.includes("did not run")));
    assert.equal(r.specified.size, 0);
  });
});

describe("mutation table (factory/matrix/mutants.mjs)", () => {
  it("has the builder's 10 and the auditor's 37 mutants, every row anchored on exactly one occurrence in an existing file", () => {
    const by = (set) => MUTANTS.filter((m) => m.set === set).length;
    assert.equal(by("builder"), 10);
    assert.equal(by("audit-targeted") + by("audit-subtle") + by("audit-slot-weakness"), 39);
    assert.equal(MUTANTS.length, 49);
    for (const m of MUTANTS) {
      const text = readFileSync(m.file, "utf8");
      assert.equal(text.split(m.from).length - 1, 1, `${m.set}/${m.desc}: "from" must occur exactly once in ${m.file}`);
      assert.notEqual(m.from, m.to);
    }
  });
});
