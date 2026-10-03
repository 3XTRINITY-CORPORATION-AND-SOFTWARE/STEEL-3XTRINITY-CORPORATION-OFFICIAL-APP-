import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants, fstatSync, mkdirSync, mkdtempSync, openSync, closeSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { relPathFailure, resolveRegularFile } from "./paths.ts";
import type { KrattTask } from "./task.ts";

/**
 * Bounded execution of the three allow-listed KRATT actions. No action accepts a
 * command, an environment, a URL or an output path from the task. The only subprocess
 * is `node --test <one allow-listed test file>` with a fixed argv, shell:false, an empty
 * environment, a hard timeout and an output cap, under Node's permission model
 * (no writes, no child processes, reads limited to the repo root).
 *
 * LIMITATION: Node 22's permission model does NOT restrict network access. "No network"
 * is therefore enforced only by (a) the allow-listed test directories and (b) code review
 * of those tests; it is not a sandbox guarantee.
 */
export interface Artifact {
  name: string;
  sha256: string;
  bytes: number;
}

export interface ActionResult {
  command: string[];
  exitCode: number;
  timedOut: boolean;
  truncated: boolean;
  outputBytes: number;
  stdoutSha256: string;
  stderrSha256: string;
  artifacts: Artifact[];
  checks: { pass: number; fail: number };
  failure: string | null;
}

export const DEFAULT_ALLOWED_TEST_DIRS: readonly string[] = ["cerberus/tests", "kratt/tests"];
export const MAX_FILE_BYTES = 8 * 1024 * 1024;
export const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_TOTAL_HASH_BYTES = 32 * 1024 * 1024;

const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const EMPTY = sha("");

export interface ActionOptions {
  /** Host-controlled (never taken from the task). */
  allowedTestDirs?: readonly string[];
}

const failResult = (command: string[], failure: string, artifacts: Artifact[] = []): ActionResult => ({
  command,
  exitCode: 1,
  timedOut: false,
  truncated: false,
  outputBytes: 0,
  stdoutSha256: EMPTY,
  stderrSha256: EMPTY,
  artifacts: sortArtifacts(artifacts),
  checks: { pass: 0, fail: 1 },
  failure,
});

function sortArtifacts(a: Artifact[]): Artifact[] {
  return [...a].sort((x, y) => (x.name < y.name ? -1 : x.name > y.name ? 1 : 0));
}

/** Hash a repo file, enforcing a shared byte budget. */
function hashFile(realRoot: string, rel: string, budget: { left: number }): Artifact | string {
  const r = resolveRegularFile(realRoot, rel, MAX_FILE_BYTES);
  if (!r.ok) return r.reason;
  if (r.bytes > budget.left) return "total-size-budget-exceeded";
  const buf = readFileSync(r.abs);
  if (buf.length > MAX_FILE_BYTES || buf.length > budget.left) return "file-too-large";
  budget.left -= buf.length;
  return { name: rel, sha256: sha(buf), bytes: buf.length };
}

function hashFiles(realRoot: string, files: readonly string[]): ActionResult {
  const command = ["in-process:hash-files"];
  const budget = { left: MAX_TOTAL_HASH_BYTES };
  const artifacts: Artifact[] = [];
  for (const f of files) {
    const h = hashFile(realRoot, f, budget);
    if (typeof h === "string") return failResult(command, `${h}:${f}`, artifacts);
    artifacts.push(h);
  }
  return { ...failResult(command, "", artifacts), exitCode: 0, checks: { pass: artifacts.length, fail: 0 }, failure: null };
}

const HEX64 = /^[0-9a-f]{64}$/;

function validateManifest(realRoot: string, manifestRel: string): ActionResult {
  const command = ["in-process:validate-manifest"];
  const budget = { left: MAX_TOTAL_HASH_BYTES };
  const m = resolveRegularFile(realRoot, manifestRel, MAX_MANIFEST_BYTES);
  if (!m.ok) return failResult(command, `manifest-${m.reason}`);
  const raw = readFileSync(m.abs);
  if (raw.length > MAX_MANIFEST_BYTES) return failResult(command, "manifest-file-too-large");
  const artifacts: Artifact[] = [{ name: manifestRel, sha256: sha(raw), bytes: raw.length }];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    return failResult(command, "manifest-invalid-json", artifacts);
  }
  const files = manifestEntries(parsed);
  if (typeof files === "string") return failResult(command, files, artifacts);
  let pass = 0;
  let mismatch = 0;
  let firstFailure: string | null = null;
  for (const e of files) {
    const h = hashFile(realRoot, e.path, budget);
    if (typeof h === "string") {
      mismatch++;
      firstFailure ??= `${h}:${e.path}`;
      continue;
    }
    if (artifacts.some((a) => a.name === h.name)) {
      mismatch++;
      firstFailure ??= `manifest-lists-itself-or-duplicate:${e.path}`;
      continue;
    }
    artifacts.push(h);
    if (h.sha256 === e.sha256) pass++;
    else {
      mismatch++;
      firstFailure ??= `sha256-mismatch:${e.path}`;
    }
  }
  return {
    command,
    exitCode: mismatch === 0 ? 0 : 1,
    timedOut: false,
    truncated: false,
    outputBytes: 0,
    stdoutSha256: EMPTY,
    stderrSha256: EMPTY,
    artifacts: sortArtifacts(artifacts),
    checks: { pass, fail: mismatch },
    failure: firstFailure,
  };
}

/** Manifest schema: { "version": 1, "files": [ { "path": <rel>, "sha256": <hex64> } ... ] } — closed. */
function manifestEntries(v: unknown): { path: string; sha256: string }[] | string {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return "manifest-not-object";
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(",");
  if (keys !== "files,version") return "manifest-unexpected-keys";
  if (o.version !== 1) return "manifest-version-unsupported";
  const files = o.files;
  if (!Array.isArray(files) || files.length < 1 || files.length > 64) return "manifest-files-invalid";
  const out: { path: string; sha256: string }[] = [];
  for (const f of files) {
    if (typeof f !== "object" || f === null || Array.isArray(f)) return "manifest-entry-invalid";
    const e = f as Record<string, unknown>;
    if (Object.keys(e).sort().join(",") !== "path,sha256") return "manifest-entry-invalid";
    if (relPathFailure(e.path) !== null) return "manifest-entry-path-invalid";
    if (typeof e.sha256 !== "string" || !HEX64.test(e.sha256)) return "manifest-entry-digest-malformed";
    out.push({ path: e.path as string, sha256: e.sha256 });
  }
  return out;
}

function lastCount(text: string, label: "pass" | "fail"): number | null {
  const all = [...text.matchAll(new RegExp(`^# ${label} (\\d+)\\s*$`, "gm"))];
  if (all.length === 0) return null;
  const n = Number(all[all.length - 1][1]);
  return Number.isSafeInteger(n) ? n : null;
}

/**
 * With --experimental-test-isolation=none a test file that registers no tests is still
 * reported as ONE passing top-level entry named after the file ("ok 1 - z.test.mjs"),
 * which would otherwise look like a real passing test (found by KRATT's own zero-test case).
 */
function isFileLevelPseudoTest(tap: string, testFile: string, snapshotBase: string): boolean {
  const base = testFile.split("/").pop() as string;
  return tap.split("\n").some((l) => /^ok \d+ - /.test(l) && (l.endsWith(` - ${testFile}`) || l.endsWith(` - ${base}`) || l.endsWith(` - ${snapshotBase}`)));
}

/** True when the real (symlink-resolved) path lies under the real path of one of the allowed directories. */
function realPathAllowed(realRoot: string, realFile: string, dirs: readonly string[]): boolean {
  for (const d of dirs) {
    let realDir: string;
    try {
      realDir = realpathSync(join(realRoot, d));
    } catch {
      continue; // an allowed directory that does not exist allows nothing
    }
    if (realDir !== realRoot && realDir.startsWith(realRoot + sep) && realFile.startsWith(realDir + sep)) return true;
  }
  return false;
}

/**
 * Read the validated test file ONCE through a file descriptor and prove that the inode we hold is the file the allow-list
 * judged: opened with O_NOFOLLOW (the last component cannot be a swapped-in symlink), a single regular file (nlink 1, so
 * no hardlink into another directory), and the path still resolves to the same real path and the same inode afterwards.
 * Returns the bytes that will be executed, or a failure reason.
 */
function pinTestFile(realFile: string): { bytes: Buffer } | string {
  let fd: number | undefined;
  try {
    fd = openSync(realFile, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const st = fstatSync(fd);
    if (!st.isFile()) return "not-regular-file";
    if (st.nlink > 1) return "test-file-hardlinked";
    if (st.size > MAX_FILE_BYTES) return "file-too-large";
    const bytes = readFileSync(fd);
    if (bytes.length > MAX_FILE_BYTES) return "file-too-large";
    if (realpathSync(realFile) !== realFile) return "test-file-swapped-before-run";
    const now = statSync(realFile);
    if (now.ino !== st.ino || now.dev !== st.dev) return "test-file-swapped-before-run";
    return { bytes };
  } catch {
    return "test-file-swapped-before-run";
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

const MAX_SNAPSHOT_ENTRIES = 20_000;

/**
 * Private, immutable-to-others copy of the pinned bytes. The directory is 0700 under the OS temp dir and the file 0400, so
 * nothing the repo (or an attacker holding only repo write access) can do afterwards changes what node executes.
 * Relative imports must keep working, so the file sits at its REAL repo-relative location inside a mirror tree whose
 * other entries are symlinks to the real siblings (only the test file itself is pinned, not the modules it imports).
 */
function createSnapshot(realRoot: string, realFile: string, bytes: Buffer): { dir: string; file: string } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "kratt-snap-")));
  try {
    const parts = relative(realRoot, realFile).split(sep);
    let realDir = realRoot;
    let snapDir = dir;
    let entries = 0;
    for (let i = 0; i < parts.length; i++) {
      const name = parts[i] as string;
      for (const e of readdirSync(realDir)) {
        if (e === name) continue;
        if (++entries > MAX_SNAPSHOT_ENTRIES) throw new Error("too-many-entries");
        symlinkSync(join(realDir, e), join(snapDir, e));
      }
      if (i === parts.length - 1) {
        const file = join(snapDir, name);
        writeFileSync(file, bytes, { flag: "wx", mode: 0o400 });
        return { dir, file };
      }
      mkdirSync(join(snapDir, name), { mode: 0o700 });
      realDir = join(realDir, name);
      snapDir = join(snapDir, name);
    }
    throw new Error("empty-path");
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
}

async function runTest(
  realRoot: string,
  t: Extract<KrattTask, { action: "run-test" }>,
  opts: ActionOptions,
): Promise<ActionResult> {
  const argv = [
    "--permission",
    `--allow-fs-read=${realRoot}`,
    "--experimental-test-isolation=none",
    "--experimental-strip-types",
    "--test-reporter=tap",
    "--test",
    t.testFile,
  ];
  // Exact command, with the two machine-specific values replaced by fixed placeholders.
  const command = ["node", ...argv.map((a) => a.replace(realRoot, "<root>"))];
  const dirs = opts.allowedTestDirs ?? DEFAULT_ALLOWED_TEST_DIRS;
  if (!dirs.some((d) => t.testFile.startsWith(`${d}/`))) return failResult(command, "test-dir-not-allowed");
  // The allow-list must also hold for where the file REALLY is: a symlink (or symlinked directory)
  // inside an allowed directory must not make node execute a file from a directory that is not allowed.
  const resolved = resolveRegularFile(realRoot, t.testFile, MAX_FILE_BYTES);
  if (!resolved.ok) return failResult(command, resolved.reason);
  if (!realPathAllowed(realRoot, resolved.abs, dirs)) return failResult(command, "test-dir-not-allowed");
  // TOCTOU: never execute a path that can be re-resolved. Pin the validated bytes, copy them to a private snapshot, and run THAT.
  const pinned = pinTestFile(resolved.abs);
  if (typeof pinned === "string") return failResult(command, pinned);
  if (pinned.bytes.length > MAX_TOTAL_HASH_BYTES) return failResult(command, "total-size-budget-exceeded");
  const before: Artifact = { name: t.testFile, sha256: sha(pinned.bytes), bytes: pinned.bytes.length };
  let snap: { dir: string; file: string };
  try {
    snap = createSnapshot(realRoot, resolved.abs, pinned.bytes);
  } catch {
    return failResult(command, "snapshot-failed");
  }
  // The command that actually runs differs from the reported one only in the test path (the snapshot) and its extra read grant.
  const runArgv = [argv[0] as string, argv[1] as string, `--allow-fs-read=${snap.dir}`, ...argv.slice(2, -1), relative(snap.dir, snap.file)];
  let snapshotIntact = true;

  const run = await new Promise<{
    code: number | null;
    timedOut: boolean;
    truncated: boolean;
    out: Buffer;
    err: Buffer;
    spawnError: boolean;
  }>((resolve) => {
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let total = 0;
    let timedOut = false;
    let truncated = false;
    let settled = false;
    const child = spawn(process.execPath, runArgv, {
      cwd: snap.dir, // mirror of the repo root (see createSnapshot); node's test runner cannot glob an absolute path under --permission
      env: {},
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const done = (code: number | null, spawnError = false) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, timedOut, truncated, out: Buffer.concat(out), err: Buffer.concat(err), spawnError });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, t.timeoutMs);
    const collect = (sink: Buffer[]) => (chunk: Buffer) => {
      if (truncated) return;
      const room = t.maxOutputBytes - total;
      if (chunk.length > room) {
        if (room > 0) sink.push(chunk.subarray(0, room));
        total = t.maxOutputBytes;
        truncated = true;
        child.kill("SIGKILL");
        return;
      }
      sink.push(chunk);
      total += chunk.length;
    };
    child.stdout.on("data", collect(out));
    child.stderr.on("data", collect(err));
    child.on("error", () => done(null, true));
    child.on("close", (code) => done(code));
  }).finally(() => {
    try {
      snapshotIntact = sha(readFileSync(snap.file)) === before.sha256;
    } catch {
      snapshotIntact = false;
    }
    rmSync(snap.dir, { recursive: true, force: true });
  });

  const after = hashFile(realRoot, t.testFile, { left: MAX_TOTAL_HASH_BYTES });
  // Tampering = content changed, unreadable afterwards, or the name now resolves to a different real file.
  const resolvedAfter = resolveRegularFile(realRoot, t.testFile, MAX_FILE_BYTES);
  const tampered =
    !snapshotIntact ||
    typeof after === "string" ||
    after.sha256 !== before.sha256 ||
    !resolvedAfter.ok ||
    resolvedAfter.abs !== resolved.abs;
  const text = run.out.toString("utf8");
  const pass = lastCount(text, "pass");
  const fail = lastCount(text, "fail");
  let failure: string | null = null;
  if (run.spawnError) failure = "spawn-failed";
  else if (run.timedOut) failure = "timeout";
  else if (run.truncated) failure = "output-cap-exceeded";
  else if (tampered) failure = "test-file-changed-during-run";
  else if (pass === null || fail === null) failure = "tap-summary-missing";
  else if (run.code !== 0) failure = "nonzero-exit";
  else if (fail > 0) failure = "tests-failed";
  else if (pass < 1 || isFileLevelPseudoTest(text, t.testFile, snap.file.split(sep).pop() as string)) failure = "no-tests-ran";
  return {
    command,
    exitCode: run.code ?? -1,
    timedOut: run.timedOut,
    truncated: run.truncated,
    outputBytes: run.out.length + run.err.length,
    stdoutSha256: sha(run.out),
    stderrSha256: sha(run.err),
    artifacts: [before],
    checks: { pass: pass ?? 0, fail: failure === null ? 0 : Math.max(fail ?? 0, 1) },
    failure,
  };
}

/** Never throws; any unexpected error becomes a failed (=> REJECTED) result. */
export async function executeTask(root: string, task: KrattTask, opts: ActionOptions = {}): Promise<ActionResult> {
  try {
    const realRoot = realpathSync(root);
    switch (task.action) {
      case "hash-files":
        return hashFiles(realRoot, task.files);
      case "validate-manifest":
        return validateManifest(realRoot, task.manifest);
      case "run-test":
        return await runTest(realRoot, task, opts);
    }
  } catch {
    return failResult([`in-process:${task.action}`], "internal-error");
  }
}
