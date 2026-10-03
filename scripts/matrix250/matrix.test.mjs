import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { GROUPS, runMatrix, summarize } from "./matrix.mjs";

describe("250x matrix harness", () => {
  const slots = runMatrix();
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

import { parseTap, testCheck, registryChecks, allChecks, validateMatrix, STATES, toResults, validateResults, toFactoryMatrix, FACTORY_SLOTS } from "./matrix.mjs";
import { readFileSync } from "node:fs";
import { TEST_REGISTRY } from "./test-registry.mjs";

const fakeRunner = (results, error) => () => (error ? { error } : { results: parseTap(results) });

describe("matrix integrity validation", () => {
  const slots = runMatrix();
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
  it("PASS requires evidence (and a check:/test: reference)", () => {
    const i = firstOf("PASS");
    const m = clone(); m[i].evidence = "-";
    assert.match(validateMatrix(m).join("|"), /PASS requires evidence/);
    const n = clone(); n[i].evidence = "trust me";
    assert.match(validateMatrix(n).join("|"), /check:\/test:/);
  });
  it("FAIL requires actual", () => {
    const m = clone(); m[0] = { ...m[0], status: "FAIL", actual: "-" };
    assert.match(validateMatrix(m).join("|"), /FAIL requires actual/);
    const n = clone(); n[0] = { ...n[0], status: "FAIL", actual: "boom" };
    assert.deepEqual(validateMatrix(n), []);
  });
  it("BLOCKED requires a blocker and cannot carry evidence", () => {
    const m = clone(); m[0] = { ...m[0], status: "BLOCKED", blocker: "-", evidence: "-" };
    assert.match(validateMatrix(m).join("|"), /BLOCKED requires blocker/);
    const n = clone(); n[0] = { ...n[0], status: "BLOCKED", blocker: "no server", evidence: "-" };
    assert.deepEqual(validateMatrix(n), []);
    const e = clone(); e[0] = { ...e[0], status: "BLOCKED", blocker: "x" };
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
    const real = runMatrix();
    for (const [n, file, name] of TEST_REGISTRY) {
      const s = real[n - 1];
      assert.equal(s.status, "PASS", `${s.id} ${file} :: ${name} => ${s.actual}`);
    }
  });
});

describe("matrix results (machine-readable) and factory connection", () => {
  const slots = runMatrix();
  const fresh = toResults(slots);

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
    assert.deepEqual(r, { total: 250, executed: 0, pass: 0, fail: 0, blocked: 0, not_implemented: 250 });
  });
  it("a failing factory check turns that slot FAIL, never PASS", () => {
    const checks = { 145: { input: "x", expected: "y", run: () => { throw new Error("factory test failed"); } } };
    const r = runMatrix(checks);
    assert.equal(r[144].status, "FAIL");
    assert.deepEqual(toResults(r), { total: 250, executed: 1, pass: 0, fail: 1, blocked: 0, not_implemented: 249 });
  });
  it("slots 050 and 145-150 carry a written per-slot expectation and a real test reference as evidence", () => {
    for (const n of FACTORY_SLOTS) {
      const s = slots[n - 1];
      assert.equal(s.status, "PASS", `slot ${s.id}`);
      assert.match(s.evidence, /^test:.+::.+/);
      assert.notEqual(s.expected, "named test case runs and reports ok (not skipped, not todo)", `slot ${s.id} still has the generic expectation`);
    }
    for (const n of FACTORY_SLOTS.filter((x) => x >= 145)) assert.match(slots[n - 1].evidence, /^test:factory\/tests\//);
  });
  it("the committed factory/factory-matrix.json agrees with a fresh run and lists the real closed loops", () => {
    const committed = JSON.parse(readFileSync("factory/factory-matrix.json", "utf8"));
    const receipts = JSON.parse(readFileSync("factory/factory-receipts.json", "utf8"));
    assert.deepEqual(committed, toFactoryMatrix(slots, receipts));
    assert.equal(committed.closed_loops.length, receipts.closed_loops.length);
    assert.deepEqual(committed.summary, fresh);
  });
});
