import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { WORKSPACE_TABS, workspaceTab } from "./workspace-tabs.ts";

describe("workspace slug -> tab", () => {
  it("maps every declared slug to its tab (command is the console)", () => {
    assert.deepEqual(
      Object.keys(WORKSPACE_TABS).map((s) => [s, workspaceTab(s)]),
      [["studio", "studio"], ["aura", "aura"], ["command", "console"], ["kernel", "kernel"], ["audit", "audit"], ["desk", "desk"], ["pipeline", "pipeline"], ["hosts", "hosts"]],
    );
  });
  it("inherited Object.prototype names are not workspace modules (404, never a function handed to setTab)", () => {
    for (const s of ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf", "isPrototypeOf"]) assert.equal(workspaceTab(s), null, s);
  });
  it("unknown, empty and case/whitespace variants are not workspace modules", () => {
    for (const s of ["", "console", "Studio", " studio", "studio/", "fleet"]) assert.equal(workspaceTab(s), null, JSON.stringify(s));
  });
});
