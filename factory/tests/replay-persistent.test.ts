import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cerberusDecide } from "../cerberus-gate.ts";
import { FileReplayGuard } from "../replay-store.ts";
import { assembleRun } from "../rastik-attacks.ts";
import { toeparaVerify } from "../toepara.ts";
import { REPO, ROOT, genuine } from "./helpers.ts";

const CHILD = join(import.meta.dirname, "replay-child.ts");
const D1 = "a".repeat(64);
const D2 = "b".repeat(64);
const tmp = () => mkdtempSync(join(tmpdir(), "replay-"));
const runChild = (...args: string[]) => {
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", CHILD, ...args], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
};

test("REPLAY (persistent): a digest is consumable once; a NEW guard object on the same directory (process restart) still refuses it", () => {
  const dir = join(tmp(), "store");
  const g = new FileReplayGuard(dir);
  assert.equal(g.consume(D1), true);
  assert.equal(g.consume(D1), false);
  assert.equal(g.lastDenyReason, "replayed");
  assert.equal(new FileReplayGuard(dir).consume(D1), false, "survives a restart");
  assert.equal(new FileReplayGuard(dir).has(D1), true);
  assert.equal(g.consume(D2), true, "other digests are unaffected");
  assert.deepEqual(readdirSync(dir).sort(), [`${D1}.consumed`, `${D2}.consumed`], "no temp files left behind");
});

test("REPLAY (persistent): malformed digests and hostile store paths fail closed (never true), and write nothing outside the store", () => {
  const base = tmp();
  const dir = join(base, "store");
  const g = new FileReplayGuard(dir);
  for (const bad of ["", "x", "A".repeat(64), "a".repeat(63), "a".repeat(65), `../${"a".repeat(61)}`, `${"a".repeat(64)}/../x`, "a".repeat(63) + "\n"]) assert.equal(g.consume(bad), false, JSON.stringify(bad));
  assert.equal(g.consume(undefined as never), false);
  assert.equal(g.consume({ toString: () => D1 } as never), false);
  assert.equal(existsSync(dir) ? readdirSync(dir).length : 0, 0, "nothing written for invalid digests");
  // store path is a regular file
  const file = join(base, "afile");
  writeFileSync(file, "x");
  const f = new FileReplayGuard(file);
  assert.equal(f.consume(D1), false);
  assert.equal(f.lastDenyReason, "store-unavailable");
  // store path is a symlink to a directory
  const real = join(base, "real");
  new FileReplayGuard(real).consume(D2);
  const link = join(base, "link");
  symlinkSync(real, link);
  const l = new FileReplayGuard(link);
  assert.equal(l.consume(D1), false);
  assert.equal(l.lastDenyReason, "store-not-a-plain-directory");
  assert.equal(readdirSync(real).includes(`${D1}.consumed`), false);
});

test("REPLAY (persistent): when the store cannot be written, consume returns false (fail closed), never true", { skip: process.getuid?.() === 0 ? "running as root: permission bits do not apply" : false }, () => {
  const dir = join(tmp(), "store");
  const g = new FileReplayGuard(dir);
  assert.equal(g.consume(D2), true);
  chmodSync(dir, 0o500);
  try {
    assert.equal(g.consume(D1), false);
    assert.equal(g.lastDenyReason, "store-write-failed");
    assert.equal(g.has(D1), false);
  } finally {
    chmodSync(dir, 0o700);
  }
  assert.equal(g.consume(D1), true, "after the fault is cleared the digest was never marked consumed");
});

test("REPLAY (cross-process): a digest consumed by one Node process is refused by a second Node process, in both orders", () => {
  const dir = join(tmp(), "store");
  assert.equal(runChild("consume", dir, D1), "TRUE");
  assert.equal(runChild("consume", dir, D1), "FALSE");
  assert.equal(new FileReplayGuard(dir).consume(D1), false, "parent sees the child's consumption");
  assert.equal(new FileReplayGuard(dir).consume(D2), true);
  assert.equal(runChild("consume", dir, D2), "FALSE", "child sees the parent's consumption");
});

test("REPLAY (concurrent): 8 simultaneous processes racing for one digest => exactly one wins", async () => {
  const dir = join(tmp(), "store");
  new FileReplayGuard(dir).consume(D2); // create the store first so the race is on the marker only
  const one = () =>
    new Promise<string>((resolve, reject) => {
      const c = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", CHILD, "consume", dir, D1], { stdio: ["ignore", "pipe", "inherit"] });
      let out = "";
      c.stdout.on("data", (d) => (out += d));
      c.on("error", reject);
      c.on("close", (code) => (code === 0 ? resolve(out.trim()) : reject(new Error(`exit ${code}`))));
    });
  const results = await Promise.all(Array.from({ length: 8 }, one));
  assert.equal(results.filter((r) => r === "TRUE").length, 1, results.join(","));
  assert.equal(results.filter((r) => r === "FALSE").length, 7);
});

test("REPLAY (end-to-end): CERBERUS ADMITs a genuine bundle once; a SECOND PROCESS presenting the same consumed receipt gets DENY replayed-bundle; a fresh store ADMITs (child is not vacuous)", async () => {
  const { env, receipt } = await genuine();
  const need = { ...env, required_evidence: ["source_digests", "rastik_findings"] };
  const run = assembleRun(receipt, [{ attack_id: "invalid-input/null-receipt", class: "invalid-input", agent_id: "SERPENT-052", case_id: "null-receipt", hypothesis: "h", outcome: "REPELLED", reproduced: null }], [], { probes: 0, cases_executed: 0, confirmed_findings: 0, probe_errors: 0, evidence_digest: null });
  const ctx = { root: ROOT, repository: REPO, rerun: new Map() };
  const toepara = await toeparaVerify(need, receipt, run, ctx);
  assert.equal(toepara.verdict.verdict, "VERIFIED");
  const dir = join(tmp(), "store");
  const first = await cerberusDecide({ envelope: need, receipt, rastik: run, toepara }, { ...ctx, guard: new FileReplayGuard(dir) });
  assert.equal(first.decision.decision, "ADMIT", first.decision.reasons.join(","));
  const inputs = join(tmp(), "inputs.json");
  writeFileSync(inputs, JSON.stringify({ root: ROOT, repository: REPO, envelope: need, receipt, rastik: run, toepara }));
  const replay = runChild("gate", dir, inputs);
  assert.match(replay, /^DENY .*replayed-bundle/);
  assert.match(runChild("gate", join(tmp(), "fresh"), inputs), /^ADMIT/);
});
