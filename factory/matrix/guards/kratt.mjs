// REGRESSION GUARDS for kratt/actions.ts byte-budget and manifest guards that no matrix slot asserts (not slots; see guards/security-trust.mjs).
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const ACT = "kratt/actions.ts";
const sha = (/** @type {any} */ s) => createHash("sha256").update(s).digest("hex");
function root(files = {}) {
  const r = mkdtempSync(join(tmpdir(), "g-kratt-"));
  for (const [rel, c] of Object.entries(files)) { mkdirSync(dirname(join(r, rel)), { recursive: true }); writeFileSync(join(r, rel), c); }
  return r;
}
const MB7 = 7 * 1024 * 1024;

/** @type {import("../types.d.ts").Spec[]} */
export const GUARDS = [
  { slot: 1005, target: ACT, expected: { four: { exitCode: 0, artifacts: 4 }, five: { exitCode: 1, failure: "total-size-budget-exceeded:f4.bin", artifactsBeforeStop: 4 } },
    run: async (m) => {
      const files = Object.fromEntries([0, 1, 2, 3, 4].map((i) => [`f${i}.bin`, Buffer.alloc(MB7, i + 1)]));
      const dir = root(files);
      const run = (/** @type {any} */ list) => m.executeTask(dir, { taskId: "b1", action: "hash-files", files: list });
      const four = await run(["f0.bin", "f1.bin", "f2.bin", "f3.bin"]);
      const five = await run(["f0.bin", "f1.bin", "f2.bin", "f3.bin", "f4.bin"]);
      return { four: { exitCode: four.exitCode, artifacts: four.artifacts.length }, five: { exitCode: five.exitCode, failure: five.failure, artifactsBeforeStop: five.artifacts.length } };
    },
    claim: "hash-files shares one 32 MiB byte budget across the task: four 7 MiB files pass, the fifth is refused as total-size-budget-exceeded naming it (not merely file-too-large)" },
  { slot: 1006, target: ACT, expected: { duplicate: { exitCode: 1, failure: "manifest-lists-itself-or-duplicate:a.txt", checks: { pass: 1, fail: 1 } }, selfListed: { exitCode: 1, failure: "manifest-lists-itself-or-duplicate:m.json" } },
    run: async (m) => {
      const entry = (/** @type {any} */ path, /** @type {any} */ digest) => ({ path, sha256: digest });
      const man = (/** @type {any} */ files) => JSON.stringify({ version: 1, files });
      const go = async (/** @type {any} */ files) => { const r = await m.executeTask(root({ "a.txt": "hello", "m.json": man(files) }), { taskId: "m", action: "validate-manifest", manifest: "m.json" }); return r; };
      const dup = await go([entry("a.txt", sha("hello")), entry("a.txt", sha("hello"))]);
      const self = await go([entry("m.json", sha("anything"))]);
      return { duplicate: { exitCode: dup.exitCode, failure: dup.failure, checks: dup.checks }, selfListed: { exitCode: self.exitCode, failure: self.failure } };
    },
    claim: "a manifest that lists the same file twice, or lists itself, is refused with manifest-lists-itself-or-duplicate (a duplicate never double-counts as a passed check)" },
];
