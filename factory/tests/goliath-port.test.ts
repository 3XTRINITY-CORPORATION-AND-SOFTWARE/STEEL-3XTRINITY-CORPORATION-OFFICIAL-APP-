import test from "node:test";
import assert from "node:assert/strict";
import { GoliathPortError, StandInGoliathPort, assertAdapterHonest, type GoliathPort } from "../goliath-port.ts";
import { headSha } from "../git.ts";
import { validateActionReceipt } from "../protocol/types.ts";
import { envelope } from "./fixtures.ts";
import { REPO, ROOT, SCOPE, setup } from "./helpers.ts";

const mk = () => {
  const { stand, deps } = setup();
  return { stand, port: new StandInGoliathPort({ root: ROOT, repository: REPO, clock: deps.clock }) };
};
const rejects = async (p: Promise<unknown>, code: string) => {
  await assert.rejects(p, (e: unknown) => e instanceof GoliathPortError && e.code === code, `expected ${code}`);
};

test("GoliathPort: stand-in submit(TaskEnvelope) returns a protocol-valid UNVERIFIED ActionReceipt from real KRATT work", async () => {
  const { stand, port } = mk();
  const env = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "port-ok" });
  const r = await port.submit(env);
  assert.ok(validateActionReceipt(r).ok);
  assert.equal(r.verification_state, "UNVERIFIED");
  assert.equal(r.task_id, "port-ok");
  assert.equal(r.base_sha, headSha(ROOT));
  assert.equal(r.result.ok, true);
  assert.equal(port.identity.real_goliath, false);
});

test("GoliathPort: invalid envelope, wrong repository, stale base_sha and unsupported action are typed rejections, never a receipt; a failing action yields a truthful ok=false receipt", async () => {
  const { stand, port } = mk();
  const good = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "port-bad" });
  await rejects(port.submit({ ...good, protocol_version: 2 } as never), "envelope-invalid");
  await rejects(port.submit({ ...good, scope: ["../etc/passwd"] }), "envelope-invalid");
  await rejects(port.submit({ ...good, repository: "evil/other" }), "repository-mismatch");
  await rejects(port.submit({ ...good, base_sha: "b".repeat(40) }), "stale-base-sha");
  await rejects(port.submit({ ...good, allowed_actions: ["open-pr"] }), "action-refused");
  // a failing action is still a truthful receipt (result.ok=false, UNVERIFIED), not a rejection and not a fake success
  const missing = await port.submit(envelope({ repository: REPO, base_sha: headSha(ROOT)!, scope: ["does/not/exist.ts"] }));
  assert.equal(missing.result.ok, false);
  assert.equal(missing.verification_state, "UNVERIFIED");
});

test("GoliathPort: a stage that returns a self-VERIFIED or schema-invalid receipt is rejected as receipt-invalid; a throwing stage is unavailable", async () => {
  const { stand, deps } = setup();
  const env = stand.issueEnvelope({ action: "hash-files", scope: [...SCOPE], branch: "t", task_id: "port-self" });
  const good = await new StandInGoliathPort({ root: ROOT, repository: REPO, clock: deps.clock }).submit(env);
  const via = (stage: never) => new StandInGoliathPort({ root: ROOT, repository: REPO, clock: deps.clock, stage }).submit(env);
  await rejects(via((async () => ({ ok: true, receipt: { ...good, verification_state: "VERIFIED" } })) as never), "receipt-invalid");
  await rejects(via((async () => ({ ok: true, receipt: { ...good, base_sha: "zz" } })) as never), "receipt-invalid");
  await rejects(via((async () => { throw new Error("boom"); }) as never), "unavailable");
});

test("GoliathPort: honesty guard rejects a stand-in or unattested port that claims to be the real GOLIATH", () => {
  const { port } = mk();
  assert.doesNotThrow(() => assertAdapterHonest(port));
  const fake = (over: Partial<GoliathPort["identity"]>): GoliathPort => ({ identity: { name: "X", real_goliath: false, transport: "in-process", ...over }, submit: () => Promise.reject(new Error("n/a")) });
  assert.throws(() => assertAdapterHonest(fake({ real_goliath: true })), /without-attestation/);
  assert.throws(() => assertAdapterHonest(fake({ real_goliath: true, name: "GOLIATH-STAND-IN-2", attestation: "signed" })), /stand-in-claims-real/);
  assert.doesNotThrow(() => assertAdapterHonest(fake({ real_goliath: true, attestation: "operator-attested:2026-10-03" })));
});
