import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DecisionLedger, decideIdempotent, requestKey } from "../replay-ledger.ts";
import { FileReplayGuard } from "../replay-store.ts";
import { assembleRun } from "../rastik-attacks.ts";
import { toeparaVerify } from "../toepara.ts";
import { REPO, ROOT, genuine } from "./helpers.ts";

const CHILD = join(import.meta.dirname, "ledger-child.ts");
const tmp = () => mkdtempSync(join(tmpdir(), "xproc-"));
const probe = { probes: 0, cases_executed: 0, confirmed_findings: 0, probe_errors: 0, evidence_digest: null };
const attack = { attack_id: "invalid-input/null-receipt", class: "invalid-input" as const, agent_id: "SERPENT-052", case_id: "null-receipt", hypothesis: "h", outcome: "REPELLED" as const, reproduced: null };

async function inputs(extra: Record<string, unknown> = {}) {
  const { env, receipt } = await genuine();
  const need = { ...env, required_evidence: ["source_digests", "rastik_findings"] };
  const rastik = assembleRun(receipt, [attack], [], probe);
  const toepara = await toeparaVerify(need, receipt, rastik, { root: ROOT, repository: REPO, rerun: new Map() });
  assert.equal(toepara.verdict.verdict, "VERIFIED");
  const file = join(tmp(), "inputs.json");
  const body = { root: ROOT, repository: REPO, envelope: need, receipt, rastik, toepara, ...extra };
  writeFileSync(file, JSON.stringify(body));
  return { file, body };
}

type Out = { decision: string; receipt_digest: string; decision_digest: string; replay: boolean; consumed: number; reasons: string[] };
/** One Node process sharing the replay directory ONLY through the FACTORY_REPLAY_DIR environment variable. */
const child = (dir: string, file: string, waitMs = 5000) =>
  new Promise<Out>((resolve, reject) => {
    const c = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", CHILD, "decide", file], {
      stdio: ["ignore", "pipe", "inherit"],
      env: { PATH: process.env.PATH ?? "", FACTORY_REPLAY_DIR: dir, LEDGER_WAIT_MS: String(waitMs) },
    });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.on("error", reject);
    c.on("close", (code) => {
      if (code !== 0) return reject(new Error(`child exit ${code}: ${out}`));
      try {
        resolve(JSON.parse(out.trim()) as Out);
      } catch {
        reject(new Error(`child output: ${out}`));
      }
    });
  });
const markers = (dir: string) => readdirSync(dir).filter((n) => n.endsWith(".consumed"));
const records = (dir: string) => readdirSync(join(dir, "decisions")).filter((n) => n.endsWith(".decision.json"));

test("CROSS-PROCESS (sequential): process A admits; process B (separate Node process, same FACTORY_REPLAY_DIR) gets the SAME decision and receipt as a stored replay - no second admit", async () => {
  const dir = join(tmp(), "store");
  const { file } = await inputs();
  const a = await child(dir, file);
  assert.equal(a.decision, "ADMIT", a.reasons.join(","));
  assert.equal(a.replay, false);
  assert.equal(a.consumed, 1);
  const b = await child(dir, file);
  assert.equal(b.decision, "ADMIT");
  assert.equal(b.replay, true);
  assert.equal(b.consumed, 0, "B consumed nothing");
  assert.equal(b.receipt_digest, a.receipt_digest);
  assert.equal(b.decision_digest, a.decision_digest);
  assert.equal(markers(dir).length, 1, "exactly one admission burned across both processes");
  assert.equal(records(dir).length, 1);
});

test("CROSS-PROCESS (restart): after every process has exited, a new process and the parent still return the stored ADMIT; a fresh directory evaluates anew (the child is not vacuous)", async () => {
  const dir = join(tmp(), "store");
  const { file, body } = await inputs();
  const a = await child(dir, file);
  assert.equal(a.decision, "ADMIT");
  const r = await decideIdempotent(
    { envelope: body.envelope, receipt: body.receipt, rastik: body.rastik, toepara: body.toepara },
    { root: ROOT, repository: REPO, rerun: new Map(), guard: new FileReplayGuard(dir) },
    new DecisionLedger(join(dir, "decisions")),
  );
  assert.equal(r.idempotent_replay, true);
  assert.equal(r.decision.decision_digest, a.decision_digest);
  assert.equal(r.receipt.receipt_digest, a.receipt_digest);
  const fresh = await child(join(tmp(), "other-store"), file);
  assert.equal(fresh.replay, false);
  assert.equal(fresh.decision, "ADMIT");
  assert.equal(fresh.consumed, 1);
});

test("CROSS-PROCESS (concurrent): 5 processes racing the SAME request => all return the same ADMIT, exactly one evaluates, exactly one marker and one record", async () => {
  const dir = join(tmp(), "store");
  const { file } = await inputs();
  const results = await Promise.all(Array.from({ length: 5 }, () => child(dir, file)));
  assert.ok(results.every((r) => r.decision === "ADMIT"), JSON.stringify(results.map((r) => [r.decision, r.reasons])));
  assert.equal(results.filter((r) => !r.replay).length, 1, "exactly one process evaluated");
  assert.equal(results.reduce((n, r) => n + r.consumed, 0), 1, "exactly one admission burned");
  assert.equal(new Set(results.map((r) => r.receipt_digest)).size, 1);
  assert.equal(new Set(results.map((r) => r.decision_digest)).size, 1);
  assert.equal(markers(dir).length, 1);
  assert.equal(records(dir).length, 1);
});

test("CROSS-PROCESS (negative): a DIFFERENT request carrying the same consumed bundle is DENY replayed-bundle in another process - idempotency does not become a replay loophole", async () => {
  const dir = join(tmp(), "store");
  const { file, body } = await inputs();
  const a = await child(dir, file);
  assert.equal(a.decision, "ADMIT");
  const variant = join(tmp(), "variant.json");
  writeFileSync(variant, JSON.stringify({ ...body, signatures: { bundle: "tampered-sig" } }));
  const b = await child(dir, variant);
  assert.equal(b.decision, "DENY");
  assert.equal(b.replay, false);
  assert.ok(b.reasons.includes("replayed-bundle"), b.reasons.join(","));
  assert.equal(b.consumed, 0);
  assert.equal(markers(dir).length, 1);
  assert.equal(records(dir).length, 2, "the DENY is recorded under its own request key");
});

test("CROSS-PROCESS (negative): a request whose claim was left behind by a crashed evaluator is DENY idempotency-incomplete in another process - never ADMIT, nothing consumed", async () => {
  const dir = join(tmp(), "store");
  const { file, body } = await inputs();
  const key = requestKey({ envelope: body.envelope, receipt: body.receipt, rastik: body.rastik, toepara: body.toepara }) as string;
  assert.equal(new DecisionLedger(join(dir, "decisions")).claim(key), "won");
  const r = await child(dir, file, 150);
  assert.equal(r.decision, "DENY");
  assert.deepEqual(r.reasons, ["idempotency-incomplete"]);
  assert.equal(r.consumed, 0);
  assert.equal(markers(dir).length, 0);
});

test("CROSS-PROCESS (negative): FACTORY_REPLAY_DIR unset => the child refuses to run (no silent in-memory fallback that would hide replays)", async () => {
  const { file } = await inputs();
  const out = await new Promise<string>((resolve) => {
    const c = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", CHILD, "decide", file], { stdio: ["ignore", "pipe", "inherit"], env: { PATH: process.env.PATH ?? "" } });
    let s = "";
    c.stdout.on("data", (d) => (s += d));
    c.on("close", () => resolve(s.trim()));
  });
  assert.equal(out, "BAD-MODE");
});
