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
