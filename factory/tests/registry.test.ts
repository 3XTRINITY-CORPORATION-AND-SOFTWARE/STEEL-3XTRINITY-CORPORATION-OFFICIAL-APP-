import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { FORGE_ROLES, SERPENT_ROLES, CITADEL_ROLES } from "../roles.ts";
import { buildInitialRegistry, countRegistry, validateInitialRegistry, validateRegistryShape } from "../registry.ts";

const committed = () => JSON.parse(readFileSync(new URL("../factory-registry.json", import.meta.url), "utf8"));

test("role lists are 50/50/50 with the exact boundary roles", () => {
  assert.equal(FORGE_ROLES.length, 50);
  assert.equal(SERPENT_ROLES.length, 50);
  assert.equal(CITADEL_ROLES.length, 50);
  assert.equal(FORGE_ROLES[0], "Architect");
  assert.equal(FORGE_ROLES[25], "KRATT Engineer"); // 026
  assert.equal(FORGE_ROLES[26], "TÖEPÄRA Engineer"); // 027
  assert.equal(FORGE_ROLES[49], "FORGE FOREMAN");
  assert.equal(SERPENT_ROLES[0], "RÄSTIK Commander"); // 051
  assert.equal(SERPENT_ROLES[48], "Matrix Auditor"); // 099
  assert.equal(SERPENT_ROLES[49], "SERPENT FOREMAN");
  assert.equal(CITADEL_ROLES[0], "TÖEPÄRA Commander"); // 101
  assert.equal(CITADEL_ROLES[10], "CERBERUS Commander"); // 111
  assert.equal(CITADEL_ROLES[49], "CITADEL FOREMAN");
  assert.equal(new Set([...FORGE_ROLES, ...SERPENT_ROLES, ...CITADEL_ROLES].map((r) => r.toLowerCase())).size, 150 - 0, "role names are unique across factories");
});

test("initial registry: DEFINED 150, FORGE/SERPENT/CITADEL 50 each, ACTIVE 0, SLEEPING 150, zero completed tasks", () => {
  const reg = buildInitialRegistry();
  assert.deepEqual(validateInitialRegistry(reg), []);
  const c = countRegistry(reg);
  assert.equal(c.defined, 150);
  assert.equal(c.forge, 50);
  assert.equal(c.serpent, 50);
  assert.equal(c.citadel, 50);
  assert.equal(c.active, 0);
  assert.equal(c.sleeping, 150);
  assert.equal(c.executed_tasks, 0);
  assert.ok(reg.workers.every((w) => w.state === "SLEEP" && w.completed_tasks === 0 && w.current_task === null && w.evidence.length === 0));
  assert.equal(reg.workers[0]?.id, "FORGE-001");
  assert.equal(reg.workers[149]?.id, "CITADEL-150");
});

test("validator rejects each broken initial invariant", () => {
  const mut = (f: (r: ReturnType<typeof buildInitialRegistry>) => void) => {
    const r = buildInitialRegistry();
    f(r);
    return validateInitialRegistry(r);
  };
  assert.ok(mut((r) => r.workers.pop()).length > 0, "149 workers");
  assert.ok(mut((r) => { r.workers[0]!.state = "ACTIVE"; r.workers[0]!.current_task = "x"; }).some((x) => x.includes("ACTIVE!=0")));
  assert.ok(mut((r) => { r.workers[3]!.completed_tasks = 1; }).some((x) => x.includes("completed_tasks!=0")));
  assert.ok(mut((r) => { r.workers[60]!.factory = "FORGE"; }).some((x) => x.includes("identity-mismatch")));
  assert.ok(mut((r) => { r.workers[5]!.role = "Hacker"; }).some((x) => x.includes("identity-mismatch")));
  assert.ok(mut((r) => { r.workers[7]!.id = "FORGE-001"; }).length > 0, "duplicate id");
  assert.ok(mut((r) => { r.workers[9]!.state = "SLEEP"; r.workers[9]!.current_task = "t"; }).some((x) => x.includes("sleeping-with-task")));
  assert.ok(mut((r) => { r.workers[9]!.evidence.push("e"); }).some((x) => x.includes("evidence-not-empty")));
  assert.deepEqual(validateInitialRegistry(null), ["registry-not-object"]);
});

test("committed factory-registry.json is structurally valid and consistent with the role definitions", () => {
  assert.deepEqual(validateRegistryShape(committed()), []);
});

test("factory-baseline.json: every repo is classified, SHAs are 40-hex or null, GitLab is recorded as blocked and never as data", () => {
  const b = JSON.parse(readFileSync(new URL("../factory-baseline.json", import.meta.url), "utf8"));
  assert.equal(b.gitlab.status, "EXTERNAL_CONNECTOR_BLOCKED");
  assert.ok(b.repositories.length >= 2);
  for (const r of b.repositories) {
    assert.ok(["VERIFIED", "PARTIAL", "BLOCKED_EXTERNAL", "NOT_IMPLEMENTED"].includes(r.classification), r.repository);
    assert.ok(r.head_sha === null || /^[0-9a-f]{40}$/.test(r.head_sha), r.repository);
    assert.equal(r.open_mrs.status, "BLOCKED_EXTERNAL");
    for (const k of ["repository", "default_branch", "runtime", "package_manager", "build_command", "test_command", "open_prs", "ci_state", "known_blockers", "last_verified_at"]) assert.ok(k in r, `${r.repository}: ${k}`);
    assert.ok(r.classification !== "VERIFIED" || (r.verified_by && r.head_sha), `${r.repository}: VERIFIED needs head_sha and verified_by`);
  }
});
