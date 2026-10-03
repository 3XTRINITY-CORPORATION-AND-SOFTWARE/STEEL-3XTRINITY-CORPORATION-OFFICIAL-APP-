import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { GROUPS, runMatrix, summarize } from "./matrix.mjs";
import { runSpecs } from "./specs.mjs";

// One real run (named tests + specs + guards) shared by every describe below; it is the slow part.
const REAL_RUN = runSpecs();
const REAL = runMatrix(undefined, REAL_RUN);

describe("250x matrix harness", () => {
  const slots = REAL;
  it("has exactly 250 unique, ordered slots across 5 groups of 50", () => {
    assert.equal(slots.length, 250);
    assert.equal(new Set(slots.map((s) => s.id)).size, 250);
    assert.equal(slots[0].id, "001");
    assert.equal(slots[249].id, "250");
    for (const g of GROUPS) assert.equal(slots.filter((s) => s.group === g.name).length, 50);
  });
  it("counts add up and never turn NOT_IMPLEMENTED into PASS", () => {
    const sum = summarize(slots);
    assert.equal(sum.PASS + sum.FAIL + sum.BLOCKED + sum.NOT_IMPLEMENTED, 250);
    for (const s of slots) if (s.status === "NOT_IMPLEMENTED") assert.equal(s.evidence, "-");
    for (const s of slots) if (s.status === "PASS") assert.notEqual(s.evidence, "-");
  });
  it("a throwing check is FAIL, not PASS", () => {
    const r = runMatrix({ 7: { input: "x", expected: "y", run: () => { throw new Error("boom"); } } });
    assert.equal(r[6].status, "FAIL");
    assert.equal(summarize(r).PASS, 0);
  });
  it("registered real checks currently pass on this repo", () => {
    assert.equal(summarize(slots).FAIL, 0);
  });
});

import { parseTap, testCheck, registryChecks, allChecks, validateMatrix, STATES, toResults, validateResults, toFactoryMatrix, FACTORY_SLOTS, headline } from "./matrix.mjs";
import { readFileSync } from "node:fs";
import { TEST_REGISTRY } from "./test-registry.mjs";

const fakeRunner = (results, error) => () => (error ? { error } : { results: parseTap(results) });

describe("matrix integrity validation", () => {
  const slots = REAL;
  const clone = () => structuredClone(slots);
  const firstOf = (status) => slots.findIndex((s) => s.status === status);

  it("the real matrix is well-formed", () => {
    assert.deepEqual(validateMatrix(slots), []);
  });
  it("states are exactly PASS|FAIL|BLOCKED|NOT_IMPLEMENTED", () => {
    assert.deepEqual(STATES, ["PASS", "FAIL", "BLOCKED", "NOT_IMPLEMENTED"]);
    for (const s of slots) assert.ok(STATES.includes(s.status));
  });
  it("every slot carries ID, DOMAIN, OWNER, INPUT, EXPECTED, ACTUAL, STATUS, EVIDENCE", () => {
    for (const s of slots) for (const f of ["id", "domain", "owner", "input", "expected", "actual", "status", "evidence"]) assert.equal(typeof s[f], "string", `${s.id}.${f}`);
  });
  it("rejects wrong slot count, duplicates and out-of-order ids", () => {
    assert.match(validateMatrix(slots.slice(1)).join("|"), /exactly 250/);
    assert.match(validateMatrix([...slots, slots[0]]).join("|"), /exactly 250/);
    const dup = clone(); dup[5].id = dup[4].id;
    const v = validateMatrix(dup).join("|");
    assert.match(v, /duplicate id/);
    assert.match(v, /out of order/);
    assert.match(validateMatrix(slots.map((s, i) => (i === 3 ? { ...s, id: "abc" } : s))).join("|"), /id must be 001..250/);
    assert.match(validateMatrix("nope").join("|"), /not an array/);
  });
  it("rejects missing/blank required fields", () => {
    for (const f of ["id", "domain", "owner", "input", "expected", "actual", "status", "evidence"]) {
      const m = clone(); delete m[0][f];
      assert.ok(validateMatrix(m).some((x) => x.includes(`missing required field ${f}`)), f);
      const b = clone(); b[0][f] = "  ";
      assert.ok(validateMatrix(b).some((x) => x.includes(`missing required field ${f}`)), `blank ${f}`);
    }
  });
  it("rejects illegal states", () => {
    for (const bad of ["pass", "DONE", "SKIPPED", "250x", ""]) {
      const m = clone(); m[0].status = bad;
      assert.ok(validateMatrix(m).length > 0, bad);
    }
  });
  it("PASS requires evidence (and a check:/test:/spec: reference)", () => {
    const i = firstOf("PASS");
    const m = clone(); m[i].evidence = "-";
    assert.match(validateMatrix(m).join("|"), /PASS requires evidence/);
    const n = clone(); n[i].evidence = "trust me";
    assert.match(validateMatrix(n).join("|"), /check:\/test:\/spec:/);
  });
  it("FAIL requires actual", () => {
    const m = clone(); m[0] = { ...m[0], specified: false, domain_verified: false, config_pinned: false, status: "FAIL", actual: "-" };
    assert.match(validateMatrix(m).join("|"), /FAIL requires actual/);
    const n = clone(); n[0] = { ...n[0], specified: false, domain_verified: false, config_pinned: false, status: "FAIL", actual: "boom" };
    assert.deepEqual(validateMatrix(n), []);
  });
  it("BLOCKED requires a blocker and cannot carry evidence", () => {
    const m = clone(); m[0] = { ...m[0], specified: false, domain_verified: false, config_pinned: false, status: "BLOCKED", blocker: "-", evidence: "-" };
    assert.match(validateMatrix(m).join("|"), /BLOCKED requires blocker/);
    const n = clone(); n[0] = { ...n[0], specified: false, domain_verified: false, config_pinned: false, status: "BLOCKED", blocker: "no server", evidence: "-" };
    assert.deepEqual(validateMatrix(n), []);
    const e = clone(); e[0] = { ...e[0], specified: false, domain_verified: false, config_pinned: false, status: "BLOCKED", blocker: "x" };
    assert.match(validateMatrix(e).join("|"), /BLOCKED cannot carry PASS evidence/);
  });
  it("NOT_IMPLEMENTED cannot carry PASS evidence", () => {
    // The real matrix may have no NOT_IMPLEMENTED slot left, so build one from a matrix with no checks.
    const m = runMatrix({});
    const i = 0;
    assert.equal(m[i].status, "NOT_IMPLEMENTED");
    m[i].evidence = "check:123";
    assert.match(validateMatrix(m).join("|"), /NOT_IMPLEMENTED cannot carry evidence/);
  });
});

describe("test-backed slots", () => {
  const tap = [
    "TAP version 13",
    "ok 1 - good one",
    "not ok 2 - bad one",
    "ok 3 - skipped one # SKIP",
    "ok 4 - todo one # TODO later",
    "    ok 1 - twice",
    "ok 2 - twice",
    "ok 5 - has \\# hash",
  ].join("\n");
  it("parseTap distinguishes ok / fail / skip / todo and unescapes names", () => {
    const r = parseTap(tap);
    assert.deepEqual(r.get("good one"), ["ok"]);
    assert.deepEqual(r.get("bad one"), ["fail"]);
    assert.deepEqual(r.get("skipped one"), ["skip"]);
    assert.deepEqual(r.get("todo one"), ["todo"]);
    assert.deepEqual(r.get("twice"), ["ok", "ok"]);
    assert.deepEqual(r.get("has # hash"), ["ok"]);
  });
  it("PASS only for a single plain ok", () => {
    const run = fakeRunner(tap);
    assert.equal(testCheck("f.test.mjs", "good one", run).run(), "ok");
    assert.throws(() => testCheck("f", "bad one", run).run(), /test failed/);
    assert.throws(() => testCheck("f", "absent", run).run(), /test not found/);
    assert.throws(() => testCheck("f", "twice", run).run(), /ambiguous/);
    assert.throws(() => testCheck("f", "good one", fakeRunner("", "spawn failed")).run(), /could not run/);
  });
  it("skip/todo become BLOCKED, never PASS", () => {
    const run = fakeRunner(tap);
    const slots = runMatrix({ 9: testCheck("f", "skipped one", run), 10: testCheck("f", "todo one", run), 11: testCheck("f", "bad one", run), 12: testCheck("f", "good one", run) });
    assert.deepEqual([9, 10, 11, 12].map((n) => slots[n - 1].status), ["BLOCKED", "BLOCKED", "FAIL", "PASS"]);
    assert.equal(slots[8].evidence, "-");
    assert.notEqual(slots[8].blocker, "-");
    assert.equal(slots[11].evidence, "test:f::good one");
    assert.deepEqual(validateMatrix(slots), []);
  });
  it("a failing runner output makes the slot FAIL (not NOT_IMPLEMENTED, not PASS)", () => {
    const slots = runMatrix({ 9: testCheck("f", "x", fakeRunner("", "boom")) });
    assert.equal(slots[8].status, "FAIL");
    assert.equal(summarize(slots).PASS, 0);
  });
  it("registry is well-formed: unique in-range slots, no overlap with static checks, KRATT/TOEPARA slots only backed by kratt/, rastik/ or factory/ tests", () => {
    const nums = TEST_REGISTRY.map((r) => r[0]);
    assert.equal(new Set(nums).size, nums.length);
    for (const n of nums) assert.ok(Number.isInteger(n) && n >= 1 && n <= 250);
    const names = TEST_REGISTRY.map((r) => `${r[1]}::${r[2]}`);
    assert.equal(new Set(names).size, names.length, "one test must not back two slots");
    assert.doesNotThrow(() => allChecks());
    assert.throws(() => registryChecks([[1, "f", "a"], [1, "f", "b"]]), /duplicate registry slot/);
    // KRATT/TOEPARA slots may only be backed by tests of code that exists for them (kratt/, rastik/, factory/).
    for (const [n, f] of TEST_REGISTRY) assert.ok(n < 101 || n > 150 || /^(kratt|rastik|factory)\/tests\//.test(f), `slot ${n} (${f}) is in KRATT/TOEPARA but not backed by kratt/rastik/factory tests`);
    // never back a slot with the matrix's own test file (would recurse)
    for (const [, f] of TEST_REGISTRY) assert.ok(!f.includes("matrix250"));
  });
  it("every registered test file/name exists and passes in the real run", () => {
    const real = REAL;
    for (const [n, file, name] of TEST_REGISTRY) {
      const s = real[n - 1];
      assert.equal(s.status, "PASS", `${s.id} ${file} :: ${name} => ${s.actual}`);
    }
  });
});

describe("matrix results (machine-readable) and factory connection", () => {
  const slots = REAL;
  const fresh = toResults(slots, REAL_RUN.guards);

  it("fresh results are well-formed: total 250, pass+fail+blocked+not_implemented = 250, executed = pass+fail", () => {
    assert.deepEqual(validateResults(fresh), []);
    assert.equal(fresh.total, 250);
    assert.equal(fresh.executed, fresh.pass + fresh.fail);
  });
  it("the committed factory/matrix-results.json equals a fresh run (no stale or hand-edited counts)", () => {
    const committed = JSON.parse(readFileSync("factory/matrix-results.json", "utf8"));
    assert.deepEqual(validateResults(committed), []);
    assert.deepEqual(committed, fresh);
  });
  it("validateResults rejects malformed or inconsistent results", () => {
    const bad = [
      { ...fresh, total: 249 },
      { ...fresh, pass: fresh.pass + 1 },
      { ...fresh, executed: fresh.executed - 1 },
      { ...fresh, extra: 1 },
      { ...fresh, fail: -1 },
      { ...fresh, pass: "250" },
      null,
      [],
    ];
    for (const b of bad) assert.notDeepEqual(validateResults(b), [], JSON.stringify(b));
    const missing = { ...fresh };
    delete missing.total;
    assert.notDeepEqual(validateResults(missing), []);
  });
  it("each guard fires on its own: total must be 250; the four states must sum to total; executed must be pass+fail", () => {
    const onlyTotal = { ...fresh, total: 251, not_implemented: fresh.not_implemented + 1 };
    assert.deepEqual(validateResults(onlyTotal), ["total must be 250, got 251"]);
    const onlySum = { ...fresh, pass: fresh.pass + 1, executed: fresh.executed + 1 };
    assert.deepEqual(validateResults(onlySum), ["pass+fail+blocked+not_implemented !== total"]);
    const onlyExecuted = { ...fresh, executed: fresh.executed + 1 };
    assert.deepEqual(validateResults(onlyExecuted), ["executed must equal pass+fail"]);
  });
  it("NOT_IMPLEMENTED stays NOT_IMPLEMENTED: with no check registered the factory slots are not PASS and are not executed", () => {
    const r = toResults(runMatrix({}));
    assert.deepEqual(r, { total: 250, executed: 0, pass: 0, fail: 0, blocked: 0, not_implemented: 250, specified_slots: 0, domain_verified: 0, config_pinned: 0, shared_path_slots: 0, guard_probes: 0, guard_probes_passed: 0, named_test_only_pass: 0 });
  });
  it("a failing factory check turns that slot FAIL, never PASS", () => {
    const checks = { 145: { input: "x", expected: "y", run: () => { throw new Error("factory test failed"); } } };
    const r = runMatrix(checks);
    assert.equal(r[144].status, "FAIL");
    assert.deepEqual(toResults(r), { total: 250, executed: 1, pass: 0, fail: 1, blocked: 0, not_implemented: 249, specified_slots: 0, domain_verified: 0, config_pinned: 0, shared_path_slots: 0, guard_probes: 0, guard_probes_passed: 0, named_test_only_pass: 0 });
  });
  it("slots 050 and 145-150 carry their own spec: unique claim, spec: evidence, and the old named test only as regression evidence", () => {
    for (const n of FACTORY_SLOTS) {
      const s = slots[n - 1];
      assert.equal(s.status, "PASS", `slot ${s.id}`);
      assert.equal(s.specified, true, `slot ${s.id} specified`);
      assert.equal(s.domain_verified, n !== 50, `slot ${s.id} domain_verified (slot 050 pins .nvmrc/ci.yml: CONFIG_PINNED instead)`);
      assert.equal(s.config_pinned, n === 50, `slot ${s.id} config_pinned`);
      assert.match(s.evidence, /^spec:\d{3}:.+:[0-9a-f]{16}$/);
      assert.notEqual(s.expected, "named test case runs and reports ok (not skipped, not todo)", `slot ${s.id} still has the generic expectation`);
      assert.match(s.named_test, /^test:.+::.+/);
    }
    for (const n of FACTORY_SLOTS.filter((x) => x >= 145)) assert.match(slots[n - 1].named_test, /^test:factory\/tests\//);
  });
  it("the committed factory/factory-matrix.json agrees with a fresh run and lists the real closed loops", () => {
    const committed = JSON.parse(readFileSync("factory/factory-matrix.json", "utf8"));
    const receipts = JSON.parse(readFileSync("factory/factory-receipts.json", "utf8"));
    assert.deepEqual(committed, toFactoryMatrix(slots, receipts, REAL_RUN));
    assert.equal(committed.closed_loops.length, receipts.closed_loops.length);
    assert.deepEqual(committed.summary, fresh);
  });
});

describe("strict metrics: SPECIFIED_SLOTS and DOMAIN_VERIFIED", () => {
  const slots = REAL;
  const fresh = toResults(slots, REAL_RUN.guards);
  const entry = (slot, over = {}) => ({ slot, file: "f.mjs", target: "scripts/preview.mjs", fn: "parsePid", claim: "synthetic claim for the test", valid: true, fingerprint: `fp${slot}`, behaviour: `bh${slot}`, result: { ok: true, calls: 1, digest: "abcdabcdabcdabcd", path: "p", error: null }, ...over });
  const specRun = (entries, over = {}) => ({ entries, specified: new Map(entries.filter((e) => e.valid).map((e) => [e.slot, e])), domainVerified: new Set(entries.filter((e) => e.valid && e.result?.ok).map((e) => e.slot)), violations: [], errors: [], ...over });

  it("the real run: every counted slot is backed by its own spec and the numbers are internally consistent", () => {
    assert.deepEqual(validateResults(fresh), []);
    assert.equal(fresh.specified_slots, slots.filter((s) => s.specified).length);
    assert.equal(fresh.domain_verified, slots.filter((s) => s.domain_verified).length);
    assert.equal(fresh.named_test_only_pass, slots.filter((s) => s.status === "PASS" && !s.specified).length);
    for (const s of slots.filter((x) => x.domain_verified)) {
      assert.equal(s.status, "PASS");
      assert.equal(s.specified, true);
      assert.match(s.evidence, /^spec:\d{3}:.+:[0-9a-f]{16}$/);
      assert.ok(s.spec.length >= 20);
    }
  });
  it("a generic named test alone is never SPECIFIED or DOMAIN_VERIFIED", () => {
    const run = fakeRunner("TAP version 13\nok 1 - good one");
    const r = runMatrix({ 9: testCheck("f", "good one", run) });
    assert.equal(r[8].status, "PASS");
    assert.equal(r[8].specified, false);
    assert.equal(r[8].domain_verified, false);
    assert.deepEqual(toResults(r), { total: 250, executed: 1, pass: 1, fail: 0, blocked: 0, not_implemented: 249, specified_slots: 0, domain_verified: 0, config_pinned: 0, shared_path_slots: 0, guard_probes: 0, guard_probes_passed: 0, named_test_only_pass: 1 });
  });
  it("a spec result that fails turns the slot FAIL even when its named test passes, and is neither specified-verified nor PASS", () => {
    const run = fakeRunner("TAP version 13\nok 1 - good one");
    const bad = entry(9, { result: { ok: false, calls: 1, digest: "-", path: "p", error: "expected X but got Y" } });
    const r = runMatrix({ 9: testCheck("f", "good one", run) }, specRun([bad], { domainVerified: new Set() }));
    assert.equal(r[8].status, "FAIL");
    assert.equal(r[8].domain_verified, false);
    assert.match(r[8].actual, /spec: expected X but got Y/);
    assert.deepEqual(validateMatrix(r).filter((x) => x.includes("slot[8]")), []);
  });
  it("a spec-only slot is PASS with spec: evidence, SPECIFIED and DOMAIN_VERIFIED; a spec without observed domain call is not DOMAIN_VERIFIED", () => {
    const r = runMatrix({}, specRun([entry(9), entry(10)], { domainVerified: new Set([9]) }));
    assert.equal(r[8].status, "PASS");
    assert.equal(r[8].specified, true);
    assert.equal(r[8].domain_verified, true);
    assert.match(r[8].evidence, /^spec:009:scripts\/preview\.mjs#parsePid:abcdabcdabcdabcd$/);
    assert.equal(r[9].specified, true);
    assert.equal(r[9].domain_verified, false);
    assert.deepEqual(toResults(r), { total: 250, executed: 2, pass: 2, fail: 0, blocked: 0, not_implemented: 248, specified_slots: 2, domain_verified: 1, config_pinned: 0, shared_path_slots: 0, guard_probes: 0, guard_probes_passed: 0, named_test_only_pass: 0 });
  });
  it("a config-only spec is PASS and SPECIFIED but CONFIG_PINNED, never DOMAIN_VERIFIED; shared-path slots are flagged", () => {
    const run = specRun([entry(9), entry(10)], { domainVerified: new Set([9]), configPinned: new Set([10]), sharedPathSlots: new Set([9]), sharedPathGroups: [[9, 11]] });
    const r = runMatrix({}, run);
    assert.deepEqual([r[9].status, r[9].specified, r[9].config_pinned, r[9].domain_verified], ["PASS", true, true, false]);
    assert.match(r[9].actual, /CONFIG_PINNED/);
    assert.deepEqual([r[8].config_pinned, r[8].domain_verified, r[8].shared_path], [false, true, true]);
    assert.deepEqual(toResults(r), { total: 250, executed: 2, pass: 2, fail: 0, blocked: 0, not_implemented: 248, specified_slots: 2, domain_verified: 1, config_pinned: 1, shared_path_slots: 1, guard_probes: 0, guard_probes_passed: 0, named_test_only_pass: 0 });
    assert.deepEqual(validateMatrix(r).filter((x) => x.includes("slot[8]") || x.includes("slot[9]")), []);
  });
  it("validateMatrix rejects a slot that is both config_pinned and domain_verified, and a config_pinned slot without spec evidence", () => {
    const m = structuredClone(REAL);
    const i = m.findIndex((x) => x.config_pinned);
    assert.ok(i >= 0, "the real matrix has config-pinned slots");
    m[i].domain_verified = true;
    assert.match(validateMatrix(m).join("|"), /cannot be both config_pinned and domain_verified/);
    const n = structuredClone(REAL);
    n[i].evidence = "test:x::y";
    assert.match(validateMatrix(n).join("|"), /config_pinned requires a PASS, specified slot with spec: evidence/);
  });
  it("the real matrix: CONFIG_PINNED slots are exactly the data/config specs, none of them DOMAIN_VERIFIED", () => {
    const cfg = slots.filter((x) => x.config_pinned).map((x) => +x.id);
    assert.deepEqual(cfg, [1, 2, 3, 4, 10, 50, 51]);
    for (const x of slots.filter((y) => y.config_pinned)) assert.equal(x.domain_verified, false, x.id);
    assert.equal(fresh.domain_verified + fresh.config_pinned, fresh.specified_slots);
  });
  it("an invalid/non-unique spec leaves the slot unspecified", () => {
    const e = entry(9, { valid: false });
    const r = runMatrix({}, { ...specRun([e]), specified: new Map(), domainVerified: new Set() });
    assert.equal(r[8].specified, false);
    assert.equal(r[8].domain_verified, false);
  });
  it("validateMatrix rejects domain_verified without spec evidence and specified without a claim", () => {
    const m = structuredClone(slots);
    const i = m.findIndex((s) => s.domain_verified);
    m[i].evidence = "test:x::y";
    assert.match(validateMatrix(m).join("|"), /domain_verified requires a PASS, specified slot with spec: evidence/);
    const n = structuredClone(slots);
    n[i].spec = "-";
    assert.match(validateMatrix(n).join("|"), /specified slot needs its written claim/);
    const q = structuredClone(slots);
    q[i].domain_verified = false;
    q[i].spec = "-";
    assert.match(validateMatrix(q).join("|"), /specified slot needs its written claim/);
  });
  it("validateResults guards the strict metrics", () => {
    assert.notDeepEqual(validateResults({ ...fresh, domain_verified: fresh.specified_slots + 1 }), []);
    assert.notDeepEqual(validateResults({ ...fresh, specified_slots: 251 }), []);
    assert.notDeepEqual(validateResults({ ...fresh, named_test_only_pass: fresh.pass + 1 }), []);
    assert.notDeepEqual(validateResults({ total: 250, executed: 0, pass: 0, fail: 0, blocked: 0, not_implemented: 250, specified_slots: 0, domain_verified: 1, config_pinned: 0, shared_path_slots: 0, guard_probes: 0, guard_probes_passed: 0, named_test_only_pass: 0 }), []);
    const missing = { ...fresh };
    delete missing.domain_verified;
    assert.notDeepEqual(validateResults(missing), []);
  });
  it("the headline prints measured numbers only and never says 250/250 unless that many checks ran", () => {
    const part = { total: 250, executed: 249, pass: 249, fail: 0, blocked: 1, not_implemented: 0, specified_slots: 100, domain_verified: 99, config_pinned: 1, shared_path_slots: 30, guard_probes: 11, guard_probes_passed: 10, named_test_only_pass: 149 };
    assert.equal(headline(part), "executed 249/250; PASS 249/250 (of which 149 rest only on a generic named-test mapping); SPECIFIED_SLOTS 100/250; DOMAIN_VERIFIED 99/250; CONFIG_PINNED 1/250; SHARED_PATH 30/250 slots; GUARD_PROBES 10/11");
    assert.ok(!headline(part).includes("250/250"));
    const none = toResults(runMatrix({}));
    assert.ok(!/(executed|PASS|SPECIFIED_SLOTS|DOMAIN_VERIFIED) 250\/250/.test(headline(none)));
    assert.match(headline(fresh), new RegExp(`^executed ${fresh.executed}/250; PASS ${fresh.pass}/250 `));
    // a claim of 250/250 is only possible when the measured figure is exactly 250
    for (const k of ["executed", "pass", "specified_slots", "domain_verified"]) if (fresh[k] !== 250) assert.ok(!new RegExp(`${k === "executed" ? "executed" : k === "pass" ? "PASS" : k === "specified_slots" ? "SPECIFIED_SLOTS" : "DOMAIN_VERIFIED"} 250/250`).test(headline(fresh)));
  });
  it("the committed factory-matrix headline equals the computed one", () => {
    const committed = JSON.parse(readFileSync("factory/factory-matrix.json", "utf8"));
    assert.equal(committed.headline, headline(fresh));
    assert.deepEqual(committed.unspecified_slots, slots.filter((s) => !s.specified).map((s) => s.id));
  });
  it("docs/factory/MATRIX.md carries the strict definitions", () => {
    const md = readFileSync("docs/factory/MATRIX.md", "utf8");
    assert.match(md, /SPECIFIED_SLOTS/);
    assert.match(md, /DOMAIN_VERIFIED/);
    assert.match(md, /assertion fingerprint/i);
    assert.match(md, /behaviour fingerprint/i);
  });
});
