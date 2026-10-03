import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { executeTask, MAX_FILE_BYTES, MAX_MANIFEST_BYTES } from "../actions.ts";
import { LIMITS, validateTask } from "../task.ts";

/**
 * A-014: every KRATT limit is tested on BOTH sides: the last accepted value and the first rejected value.
 *  - schema bounds (validateTask): files 1..64, timeoutMs 100..60000, maxOutputBytes 1024..1048576
 *  - execution bounds (executeTask): 8 MiB per file, 32 MiB total, 256 KiB manifest, 64 manifest entries,
 *    timeout enforcement, output-cap enforcement.
 */
const MiB = 1024 * 1024;
const temps: string[] = [];
after(() => temps.forEach((t) => rmSync(t, { recursive: true, force: true })));
function root(files: Record<string, string | Buffer>): string {
  const r = realpathSync(mkdtempSync(join(tmpdir(), "kratt-lb-")));
  temps.push(r);
  for (const [rel, c] of Object.entries(files)) {
    mkdirSync(dirname(join(r, rel)), { recursive: true });
    writeFileSync(join(r, rel), c);
  }
  return r;
}
const hashTask = (files: string[]) => {
  const v = validateTask({ taskId: "lb", action: "hash-files", files });
  assert.ok(v.ok, JSON.stringify(v));
  return v.task;
};
const rt = (over: Record<string, unknown> = {}) => ({ taskId: "lb", action: "run-test", testFile: "kratt/tests/x.test.mjs", timeoutMs: 1000, maxOutputBytes: 1024, ...over });
const reason = (t: unknown) => {
  const r = validateTask(t);
  return r.ok ? "ok" : r.reason;
};

describe("declared limits are the documented ones", () => {
  it("LIMITS constants and exported byte caps", () => {
    assert.deepEqual({ ...LIMITS }, { maxFiles: 64, minTimeoutMs: 100, maxTimeoutMs: 60_000, minOutputBytes: 1024, maxOutputBytes: 1_048_576 });
    assert.equal(MAX_FILE_BYTES, 8 * MiB);
    assert.equal(MAX_MANIFEST_BYTES, 256 * 1024);
  });
});

describe("schema bounds: last-accepted / first-rejected", () => {
  it("hash-files file count: 0 rejected, 1 and 64 accepted, 65 rejected", () => {
    const mk = (n: number) => Array.from({ length: n }, (_, i) => `f${i}.txt`);
    assert.equal(reason({ taskId: "t", action: "hash-files", files: mk(0) }), "files-count-invalid");
    assert.equal(reason({ taskId: "t", action: "hash-files", files: mk(1) }), "ok");
    assert.equal(reason({ taskId: "t", action: "hash-files", files: mk(63) }), "ok");
    assert.equal(reason({ taskId: "t", action: "hash-files", files: mk(64) }), "ok");
    assert.equal(reason({ taskId: "t", action: "hash-files", files: mk(65) }), "files-count-invalid");
  });

  it("run-test timeoutMs: 99 rejected, 100 accepted, 60000 accepted, 60001 rejected", () => {
    assert.equal(reason(rt({ timeoutMs: 99 })), "timeoutMs-out-of-range");
    assert.equal(reason(rt({ timeoutMs: 100 })), "ok");
    assert.equal(reason(rt({ timeoutMs: 101 })), "ok");
    assert.equal(reason(rt({ timeoutMs: 59_999 })), "ok");
    assert.equal(reason(rt({ timeoutMs: 60_000 })), "ok");
    assert.equal(reason(rt({ timeoutMs: 60_001 })), "timeoutMs-out-of-range");
  });

  it("run-test maxOutputBytes: 1023 rejected, 1024 accepted, 1048576 accepted, 1048577 rejected", () => {
    assert.equal(reason(rt({ maxOutputBytes: 1023 })), "maxOutputBytes-out-of-range");
    assert.equal(reason(rt({ maxOutputBytes: 1024 })), "ok");
    assert.equal(reason(rt({ maxOutputBytes: 1025 })), "ok");
    assert.equal(reason(rt({ maxOutputBytes: 1_048_575 })), "ok");
    assert.equal(reason(rt({ maxOutputBytes: 1_048_576 })), "ok");
    assert.equal(reason(rt({ maxOutputBytes: 1_048_577 })), "maxOutputBytes-out-of-range");
  });

  it("numeric type edge cases are rejected as not-integer (never coerced into range)", () => {
    for (const v of [100.5, NaN, Infinity, "1000", null, true, [1000], 1000n, Number.MAX_SAFE_INTEGER + 1])
      assert.match(reason(rt({ timeoutMs: v })), /^timeoutMs-not-integer$/, String(v));
    for (const v of [1024.5, NaN, -Infinity, "2048", null, false, 2048n])
      assert.match(reason(rt({ maxOutputBytes: v })), /^maxOutputBytes-not-integer$/, String(v));
    assert.equal(reason(rt({ timeoutMs: -0 })), "timeoutMs-out-of-range", "-0 is an integer but below the minimum");
    assert.equal(reason(rt({ timeoutMs: -0.5 })), "timeoutMs-not-integer");
    assert.equal(reason(rt({ timeoutMs: undefined })), "timeoutMs-not-integer", "own property present with undefined value");
  });

  it("no defaults: omitting a bound is a rejection, not 'use the maximum'", () => {
    const { timeoutMs: _t, ...noTimeout } = rt();
    const { maxOutputBytes: _m, ...noCap } = rt();
    assert.equal(reason(noTimeout), "unexpected-keys");
    assert.equal(reason(noCap), "unexpected-keys");
  });
});

describe("hash-files execution bounds (8 MiB per file, 32 MiB total)", () => {
  it("per-file: exactly 8 MiB is hashed; 8 MiB + 1 byte is refused as file-too-large:<name>", async () => {
    const r = root({ "ok.bin": Buffer.alloc(8 * MiB, 1), "big.bin": Buffer.alloc(8 * MiB + 1, 1), "just-under.bin": Buffer.alloc(8 * MiB - 1, 1) });
    const ok = await executeTask(r, hashTask(["ok.bin"]));
    assert.equal(ok.failure, null);
    assert.equal(ok.artifacts[0]?.bytes, 8 * MiB);
    assert.equal((await executeTask(r, hashTask(["just-under.bin"]))).failure, null);
    const big = await executeTask(r, hashTask(["big.bin"]));
    assert.equal(big.failure, "file-too-large:big.bin");
    assert.equal(big.exitCode, 1);
    assert.deepEqual(big.artifacts, []);
  });

  it("total: four files of exactly 8 MiB (= 32 MiB) pass; adding even one more byte fails with total-size-budget-exceeded on that file", async () => {
    const files: Record<string, Buffer> = { "a.bin": Buffer.alloc(8 * MiB, 1), "b.bin": Buffer.alloc(8 * MiB, 2), "c.bin": Buffer.alloc(8 * MiB, 3), "d.bin": Buffer.alloc(8 * MiB, 4), "one.bin": Buffer.alloc(1, 5) };
    const r = root(files);
    const exact = await executeTask(r, hashTask(["a.bin", "b.bin", "c.bin", "d.bin"]));
    assert.equal(exact.failure, null);
    assert.equal(exact.artifacts.reduce((n, a) => n + a.bytes, 0), 32 * MiB);
    const over = await executeTask(r, hashTask(["a.bin", "b.bin", "c.bin", "d.bin", "one.bin"]));
    assert.equal(over.failure, "total-size-budget-exceeded:one.bin");
    assert.deepEqual(over.artifacts.map((a) => a.name), ["a.bin", "b.bin", "c.bin", "d.bin"], "files hashed before the budget ran out are still reported");
    const reordered = await executeTask(r, hashTask(["one.bin", "a.bin", "b.bin", "c.bin", "d.bin"]));
    assert.equal(reordered.failure, "total-size-budget-exceeded:d.bin", "the budget is consumed in task order");
  });

  it("64 files is executable end to end (the schema maximum)", async () => {
    const r = root(Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`f${i}.txt`, `c${i}`])));
    const res = await executeTask(r, hashTask(Array.from({ length: 64 }, (_, i) => `f${i}.txt`)));
    assert.equal(res.failure, null);
    assert.deepEqual(res.checks, { pass: 64, fail: 0 });
  });
});

describe("validate-manifest execution bounds (256 KiB manifest, 64 entries)", () => {
  const sha0 = "0".repeat(64);
  const padded = (bytes: number): string => {
    const body = JSON.stringify({ version: 1, files: [{ path: "a.txt", sha256: sha0 }] });
    return body + " ".repeat(bytes - Buffer.byteLength(body));
  };
  const run = async (manifest: string, extra: Record<string, string> = {}) => {
    const r = root({ "a.txt": "x", "m.json": manifest, ...extra });
    const v = validateTask({ taskId: "lb", action: "validate-manifest", manifest: "m.json" });
    assert.ok(v.ok);
    return executeTask(r, v.task);
  };

  it("manifest of exactly 256 KiB is parsed; 256 KiB + 1 byte is refused as manifest-file-too-large before parsing", async () => {
    const at = await run(padded(MAX_MANIFEST_BYTES));
    assert.equal(at.failure, "sha256-mismatch:a.txt", "parsed and verified (the digest is deliberately wrong)");
    const over = await run(padded(MAX_MANIFEST_BYTES + 1));
    assert.equal(over.failure, "manifest-file-too-large");
    assert.deepEqual(over.artifacts, []);
    assert.equal((await run(padded(MAX_MANIFEST_BYTES - 1))).failure, "sha256-mismatch:a.txt");
  });

  it("64 entries accepted, 65 refused", async () => {
    const mk = (n: number) => JSON.stringify({ version: 1, files: Array.from({ length: n }, (_, i) => ({ path: `f${i}.txt`, sha256: sha0 })) });
    const files = Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`f${i}.txt`, "x"]));
    assert.equal((await run(mk(64), files)).checks.fail, 64, "all 64 entries were examined (all wrong digests)");
    assert.equal((await run(mk(65), files)).failure, "manifest-files-invalid");
  });
});

describe("run-test enforcement of timeout and output cap (real subprocesses)", () => {
  const T = "kratt/tests/";
  const exec = (r: string, name: string, over: { timeoutMs?: number; maxOutputBytes?: number }) => {
    const v = validateTask(rt({ testFile: `${T}${name}`, ...over }));
    assert.ok(v.ok, JSON.stringify(v));
    return executeTask(r, v.task);
  };
  const HANG = `import { test } from "node:test"; test("hang", async () => { await new Promise((r) => setTimeout(r, 30_000)); });`;
  const noisy = (bytes: number, stream: "stdout" | "stderr") =>
    `import { test } from "node:test"; test("noisy", () => { process.${stream}.write("x".repeat(${bytes})); });`;

  it("timeoutMs=100 (schema minimum) kills a hanging test: failure=timeout, timedOut, returns long before the test would", async () => {
    const r = root({ [`${T}hang.test.mjs`]: HANG });
    const t0 = Date.now();
    const res = await exec(r, "hang.test.mjs", { timeoutMs: 100 });
    assert.equal(res.failure, "timeout");
    assert.equal(res.timedOut, true);
    assert.ok(Date.now() - t0 < 10_000, "killed by SIGKILL, not allowed to run for 30 s");
    assert.equal(res.checks.fail >= 1, true);
  });

  it("a generous timeout does not trigger on a quick test (other side of the bound)", async () => {
    const r = root({ [`${T}quick.test.mjs`]: `import { test } from "node:test"; test("q", () => {});` });
    const res = await exec(r, "quick.test.mjs", { timeoutMs: 20_000, maxOutputBytes: 65_536 });
    assert.equal(res.failure, null);
    assert.equal(res.timedOut, false);
  });

  it("maxOutputBytes=1024 (schema minimum): output above the cap => output-cap-exceeded, truncated, and stored bytes never exceed the cap", async () => {
    const r = root({ [`${T}loud.test.mjs`]: noisy(5000, "stdout") });
    const res = await exec(r, "loud.test.mjs", { timeoutMs: 20_000, maxOutputBytes: 1024 });
    assert.equal(res.failure, "output-cap-exceeded");
    assert.equal(res.truncated, true);
    assert.equal(res.outputBytes, 1024, "exactly the cap is retained");
  });

  it("stderr counts against the same cap", async () => {
    const r = root({ [`${T}loud-err.test.mjs`]: noisy(5000, "stderr") });
    const res = await exec(r, "loud-err.test.mjs", { timeoutMs: 20_000, maxOutputBytes: 1024 });
    assert.equal(res.failure, "output-cap-exceeded");
    assert.ok(res.outputBytes <= 1024);
  });

  it("the same noise below the cap passes (cap 8 KiB vs 2000 noise bytes): truncation is caused by the cap, not by the noise", async () => {
    const r = root({ [`${T}ok.test.mjs`]: noisy(2000, "stdout") });
    const res = await exec(r, "ok.test.mjs", { timeoutMs: 20_000, maxOutputBytes: 8192 });
    assert.equal(res.failure, null);
    assert.equal(res.truncated, false);
    assert.ok(res.outputBytes >= 2000 && res.outputBytes <= 8192);
  });

  it("maxOutputBytes=1048576 (schema maximum): 2 MiB of output is cut at exactly 1 MiB", async () => {
    const r = root({ [`${T}huge.test.mjs`]: `import { test } from "node:test"; test("huge", () => { process.stdout.write(Buffer.alloc(2 * 1024 * 1024, 120)); });` });
    const res = await exec(r, "huge.test.mjs", { timeoutMs: 20_000, maxOutputBytes: 1_048_576 });
    assert.equal(res.failure, "output-cap-exceeded");
    assert.equal(res.outputBytes, 1_048_576);
  });

  it("precedence: when both timeout and cap would apply the run is still a failure and never a pass", async () => {
    const r = root({ [`${T}both.test.mjs`]: `import { test } from "node:test"; test("b", async () => { process.stdout.write("x".repeat(4000)); await new Promise((r) => setTimeout(r, 30_000)); });` });
    const res = await exec(r, "both.test.mjs", { timeoutMs: 3000, maxOutputBytes: 1024 });
    assert.notEqual(res.failure, null);
    assert.ok(["timeout", "output-cap-exceeded"].includes(res.failure ?? ""));
    assert.equal(res.exitCode === 0, false);
  });
});
