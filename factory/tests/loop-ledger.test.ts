import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfCheckFinalReceipt } from "../loop.ts";
import { DecisionLedger, replayStoresFromEnv } from "../replay-ledger.ts";
import { SCOPE, setup } from "./helpers.ts";

// decideIdempotent wired into the closed loop (LoopDeps.ledger; factory/cli.ts via FACTORY_REPLAY_DIR).
// Scope of the claim: local-POSIX file ledger, records hashed not signed, REAL_GOLIATH_CONNECTED=false.

const submit = (deps: Parameters<typeof setup>[0], task: string) => {
  const { stand } = setup(deps);
  return stand.submit(stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: task }));
};
const records = (dir: string) => readdirSync(join(dir, "decisions")).filter((f) => f.endsWith(".decision.json"));

test("loop + ledger: the first submission is evaluated by decideIdempotent, ADMITs, passes the self-check, and its decision is stored", async () => {
  const dir = mkdtempSync(join(tmpdir(), "loop-ledger-"));
  try {
    const stores = replayStoresFromEnv({ FACTORY_REPLAY_DIR: dir });
    assert.ok(stores);
    const r = await submit({ guard: stores.guard, ledger: stores.ledger }, "ledger-first");
    assert.equal(r.final_decision, "ADMIT", r.cerberus.decision.reasons.join(","));
    assert.deepEqual(selfCheckFinalReceipt(r), []);
    assert.equal(records(dir).length, 1, "exactly one stored decision");
    // no ledger => nothing is written and the result is the same ADMIT (the ledger is opt-in)
    const plain = await submit({}, "ledger-none");
    assert.equal(plain.final_decision, "ADMIT");
    assert.equal(records(dir).length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loop + ledger: submitting the same work again (after a 'restart': fresh dispatcher + fresh stores on the same directory) is never ADMITted twice", async () => {
  const dir = mkdtempSync(join(tmpdir(), "loop-ledger-"));
  try {
    const a = replayStoresFromEnv({ FACTORY_REPLAY_DIR: dir });
    const first = await submit({ guard: a!.guard, ledger: a!.ledger }, "ledger-twice");
    assert.equal(first.final_decision, "ADMIT");
    const b = replayStoresFromEnv({ FACTORY_REPLAY_DIR: dir });
    const second = await submit({ guard: b!.guard, ledger: b!.ledger }, "ledger-twice");
    assert.equal(second.final_decision, "DENY", "second presentation is never an ADMIT");
    assert.ok(second.cerberus.decision.reasons.some((x) => x.startsWith(`idempotent-replay-stored-decision:ADMIT:${first.cerberus.decision.decision_digest}`)), second.cerberus.decision.reasons.join(","));
    assert.deepEqual(selfCheckFinalReceipt(second), [], "and the DENY receipt is itself self-consistent");
    assert.ok(records(dir).length >= 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loop + ledger: an unusable ledger fails closed - DENY refusal, no ADMIT, no fabricated gate receipt", async () => {
  const dir = mkdtempSync(join(tmpdir(), "loop-ledger-"));
  try {
    const notADir = join(dir, "file");
    writeFileSync(notADir, "x");
    const r = await submit({ ledger: new DecisionLedger(join(notADir, "decisions")) }, "ledger-broken");
    assert.equal(r.final_decision, "DENY");
    assert.equal(r.toepara, null, "a refusal carries no TÖEPÄRA/bundle");
    assert.ok(r.cerberus.decision.reasons.some((x) => x.startsWith("ledger-fail-closed:DENY")), r.cerberus.decision.reasons.join(","));
    assert.deepEqual(selfCheckFinalReceipt(r), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
