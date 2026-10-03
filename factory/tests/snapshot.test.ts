import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CAPABILITIES } from "../capabilities.ts";
import { blobDigest, commitExists } from "../git.ts";
import { selfCheckFinalReceipt, type ClosedLoopReceipt } from "../loop.ts";
import { validateActionReceipt, validateCerberusDecision, validateEvidenceBundle, validateToeparaVerdict, validateEnvelope } from "../protocol/types.ts";
import { countRegistry, validateRegistryShape, type Registry } from "../registry.ts";
import { ROOT } from "./helpers.ts";

const read = (n: string) => JSON.parse(readFileSync(new URL(`../${n}`, import.meta.url), "utf8"));
const reg = read("factory-registry.json") as Registry;
const queue = read("factory-queue.json") as { tasks: { task_id: string; agent_id: string; status: string; envelope: unknown; envelope_digest: string }[]; transitions: { seq: number; agent_id: string; from: string; to: string; task_id: string | null; accepted: boolean }[] };
const loops = (read("factory-receipts.json") as { closed_loops: ClosedLoopReceipt[] }).closed_loops;

test("committed snapshot: registry shape is valid, 150 defined, nothing ACTIVE/READY/VERIFY/BLOCKED left behind", () => {
  assert.deepEqual(validateRegistryShape(reg, CAPABILITIES), []);
  const c = countRegistry(reg);
  assert.equal(c.defined, 150);
  assert.equal(c.active + c.by_state.READY + c.by_state.VERIFY + c.by_state.DONE + c.by_state.BLOCKED, 0);
  assert.equal(c.sleeping, 150);
});

test("committed snapshot: executed/failed task counters equal what the queue and the transition log independently say", () => {
  const done = queue.tasks.filter((t) => t.status === "DONE");
  const blocked = queue.tasks.filter((t) => t.status === "BLOCKED");
  const c = countRegistry(reg);
  assert.equal(c.executed_tasks, done.length);
  assert.equal(c.failed_tasks, blocked.length);
  assert.equal(queue.transitions.filter((t) => t.accepted && t.to === "DONE").length, done.length);
  for (const w of reg.workers) {
    assert.equal(w.completed_tasks, done.filter((t) => t.agent_id === w.id).length, w.id);
    assert.equal(w.evidence.length, w.completed_tasks, w.id);
    if (w.completed_tasks > 0) assert.ok(w.capabilities.length > 0, `${w.id} executed work without a declared capability`);
  }
  queue.transitions.forEach((t, i) => assert.equal(t.seq, i + 1));
  for (const t of queue.tasks) assert.ok(validateEnvelope(t.envelope).ok, t.task_id);
  assert.equal(new Set(queue.tasks.map((t) => t.task_id)).size, queue.tasks.length);
});

test("committed receipts: every recorded closed loop is internally consistent, schema-valid, and honest about the caller", () => {
  assert.ok(loops.length >= 1);
  for (const r of loops) {
    assert.deepEqual(selfCheckFinalReceipt(r), [], String(r.task_id));
    assert.equal(r.caller.real_goliath, false);
    if (r.action_receipt) assert.ok(validateActionReceipt(r.action_receipt).ok);
    assert.ok(validateCerberusDecision(r.cerberus.decision).ok);
    if (r.toepara) {
      assert.ok(validateToeparaVerdict(r.toepara.verdict).ok);
      if (r.toepara.bundle) assert.ok(validateEvidenceBundle(r.toepara.bundle).ok);
    }
    for (const s of r.stages) {
      assert.ok(queue.tasks.some((t) => t.task_id === s.task_id && t.agent_id === s.agent_id), `stage task ${s.task_id} must exist in the queue`);
      const logged = queue.transitions.filter((t) => t.task_id === s.task_id).map((t) => `${t.from}->${t.to}`);
      assert.deepEqual(s.transitions.map((t) => `${t.from}->${t.to}`), logged, `${s.task_id}: receipt transitions == dispatcher log`);
    }
    if (r.final_decision === "ADMIT") assert.equal(r.toepara?.verdict.verdict, "VERIFIED");
  }
});

test("committed receipts: where the base commit is present locally, the recorded source digests are re-derived from git (independent of the stored evidence)", () => {
  let reverified = 0;
  let unavailable = 0;
  for (const r of loops) {
    if (!r.toepara?.bundle) continue;
    if (!commitExists(ROOT, r.toepara.bundle.base_sha)) {
      unavailable++; // shallow clone: structural checks above still ran; this independent re-derivation did not
      continue;
    }
    for (const s of r.toepara.bundle.source_digests) {
      const d = blobDigest(ROOT, r.toepara.bundle.base_sha, s.path);
      assert.deepEqual(d, { sha256: s.sha256, bytes: s.bytes }, `${r.task_id}:${s.path}`);
    }
    reverified++;
  }
  console.log(`# snapshot re-derivation: reverified=${reverified} base-commit-unavailable=${unavailable}`);
  assert.equal(reverified + unavailable, loops.filter((l) => l.toepara?.bundle).length);
});
