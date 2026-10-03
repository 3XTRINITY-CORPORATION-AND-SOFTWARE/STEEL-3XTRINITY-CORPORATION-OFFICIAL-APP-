import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { CAPABILITIES, HANDLER_KEYS, LOOP_CAPABILITIES } from "../capabilities.ts";
import { HANDLERS, HANDLER_CAPABILITIES, checkEnvelope, handlerFor } from "../handlers/index.ts";
import { makeDispatcher } from "../loop.ts";
import { TOKEN } from "../protocol/types.ts";
import { buildInitialRegistry } from "../registry.ts";
import { ROLES } from "../roles.ts";

const HANDLER_DIR = new URL("../handlers/", import.meta.url);

test("every handler has a complete, honest contract that matches the frozen registry row", () => {
  const reg = buildInitialRegistry();
  const seen = new Set<string>();
  for (const h of HANDLERS) {
    const c = h.contract;
    const w = reg.workers.find((x) => x.id === c.agent_id);
    assert.ok(w, `${c.agent_id} exists in the registry`);
    assert.equal(w.role, c.role, `${c.agent_id} role`);
    assert.ok(ROLES[w.factory].includes(c.role));
    assert.match(c.capability, TOKEN);
    assert.ok(!seen.has(`${c.agent_id}:${c.capability}`), "unique (agent, capability)");
    seen.add(`${c.agent_id}:${c.capability}`);
    assert.equal(c.contract_version, 1);
    assert.ok(c.summary.length > 20);
    assert.deepEqual(c.permissions, { read: "git-objects-at-base_sha", write: false, network: false, env: false, spawn: "git-readonly-argv-in-repo-view-only" });
    assert.ok(c.scope.min >= 1 && c.scope.max >= c.scope.min && c.scope.max <= 64);
    assert.ok(c.limits.max_file_bytes > 0 && c.limits.max_total_bytes >= c.limits.max_file_bytes && c.limits.max_findings > 0 && c.limits.max_findings <= 100);
    assert.ok(c.summary_keys.length > 0);
  }
  assert.equal(HANDLERS.length, 9);
  assert.equal(new Set(HANDLERS.map((h) => h.contract.capability)).size, 9, "no two handlers share a capability token");
});

test("AVAILABLE accounting: capability map == closed-loop workers + contract-backed handler workers, nothing else", () => {
  assert.deepEqual(Object.keys(LOOP_CAPABILITIES).filter((id) => id in HANDLER_CAPABILITIES), []);
  assert.deepEqual(Object.keys(CAPABILITIES).sort(), [...Object.keys(LOOP_CAPABILITIES), ...Object.keys(HANDLER_CAPABILITIES)].sort());
  assert.equal(Object.keys(CAPABILITIES).length, 20);
  const d = makeDispatcher(() => "2026-10-03T00:00:00.000Z");
  assert.equal(d.available().length, 20);
  assert.equal(d.counts().available, 20);
  assert.equal(d.counts().sleeping, 150);
  assert.equal(d.counts().executed_tasks, 0, "a definition or a handler existing is worth zero executed tasks");
  for (const h of HANDLERS) assert.ok(HANDLER_KEYS.includes(`${h.contract.agent_id}:${h.contract.capability}`));
  // a handler key without a declared capability on the worker is NOT available (dispatcher cross-check)
  const reg = buildInitialRegistry({});
  const bare = new (d.constructor as new (r: typeof reg, o: { handlers: readonly string[] }) => typeof d)(reg, { handlers: HANDLER_KEYS });
  assert.equal(bare.available().length, 0, "handler code without a registry capability does not make a worker available");
});

test("capability-to-handler lookup is exact (no wildcard, wrong owner or wrong token => undefined)", () => {
  assert.ok(handlerFor("FORGE-002", "repo:map-tree"));
  assert.equal(handlerFor("FORGE-003", "repo:map-tree"), undefined);
  assert.equal(handlerFor("FORGE-002", "repo:*"), undefined);
  assert.equal(handlerFor("FORGE-026", "kratt:hash-files"), undefined, "closed-loop capabilities are not handler capabilities");
});

test("checkEnvelope enforces owner, single allowed action, forbidden list, scope bounds and uniqueness", () => {
  const h = handlerFor("FORGE-014", "schema:validate-json")!;
  const base = {
    task_id: "t-1", factory: "FORGE" as const, agent_id: "FORGE-014", objective: "x", repository: "o/r", branch: "b", base_sha: "a".repeat(40),
    scope: ["s.json", "i.json"], allowed_actions: ["schema:validate-json"], forbidden_actions: ["network"], required_evidence: ["x"],
    resource_budget: { max_wall_ms: 1000, max_output_bytes: 65536, max_files: 8 }, protocol_version: 1 as const,
  };
  assert.equal(checkEnvelope(h, base), null);
  assert.equal(checkEnvelope(h, { ...base, agent_id: "FORGE-015" }), "agent-not-handler-owner");
  assert.match(checkEnvelope(h, { ...base, allowed_actions: ["schema:validate-json", "merge"] })!, /exactly/);
  assert.match(checkEnvelope(h, { ...base, allowed_actions: ["merge"] })!, /exactly/);
  assert.equal(checkEnvelope(h, { ...base, forbidden_actions: ["schema:validate-json"] }), "capability-forbidden");
  assert.match(checkEnvelope(h, { ...base, scope: ["only-schema.json"] })!, /scope-size-out-of-contract/);
  assert.equal(checkEnvelope(h, { ...base, scope: ["s.json", "s.json"] }), "scope-has-duplicates");
});

test("BOUNDED PERMISSIONS (static): handler sources have no write/network/env/eval; only repo-view.ts spawns, and only read-only git subcommands", () => {
  const files = readdirSync(HANDLER_DIR).filter((f) => f.endsWith(".ts"));
  assert.ok(files.includes("repo-view.ts") && files.length >= 11);
  const forbiddenEverywhere: [string, RegExp][] = [
    ["fs import", /from\s+["']node:fs/],
    ["fs require", /require\(\s*["'](node:)?fs/],
    ["network import", /from\s+["']node:(net|http|https|http2|dns|tls|dgram)["']/],
    ["fetch", /\bfetch\s*\(/],
    ["worker/vm", /from\s+["']node:(worker_threads|vm|cluster)["']/],
    ["eval", /\beval\s*\(|new\s+Function\s*\(/],
    ["dynamic import", /\bimport\s*\(/],
    ["write api", /\b(writeFile|appendFile|unlink|rmSync|mkdirSync|rename|chmod|createWriteStream)\w*\s*\(/],
    ["env access beyond PATH", /process\.env\.(?!PATH\b)/],
    ["process.exit", /process\.exit/],
  ];
  for (const f of files) {
    const src = readFileSync(new URL(f, HANDLER_DIR), "utf8");
    for (const [name, re] of forbiddenEverywhere) assert.ok(!re.test(src), `${f}: ${name}`);
    if (f !== "repo-view.ts") assert.ok(!/child_process|(^|[^.\w])(spawn|exec|execFile)(Sync)?\s*\(/.test(src), `${f}: spawns a process`);
  }
  const rv = readFileSync(new URL("repo-view.ts", HANDLER_DIR), "utf8");
  const subcommands = [...rv.matchAll(/git\(\s*(?:this\.)?root,\s*\[\s*"([a-z-]+)"/g)].map((m) => m[1]);
  assert.ok(subcommands.length >= 3);
  for (const s of subcommands) assert.ok(["ls-tree", "cat-file", "rev-parse"].includes(s!), `git subcommand ${s}`);
  assert.ok(/shell:\s*false/.test(rv));
});
