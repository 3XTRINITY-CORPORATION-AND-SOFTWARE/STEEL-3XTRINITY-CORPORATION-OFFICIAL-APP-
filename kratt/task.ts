import { createHash } from "node:crypto";
import { canonicalize } from "../cerberus/core/decide.ts";
import { relPathFailure } from "./paths.ts";

/**
 * KRATT task schema. Closed: exact key set per action, own data properties only,
 * no defaults (every bound must be stated), integers only. Anything else => reject.
 */
export const KRATT_ACTIONS = ["hash-files", "validate-manifest", "run-test"] as const;
export type KrattAction = (typeof KRATT_ACTIONS)[number];

export const LIMITS = {
  maxFiles: 64,
  minTimeoutMs: 100,
  maxTimeoutMs: 60_000,
  minOutputBytes: 1024,
  maxOutputBytes: 1_048_576,
} as const;

export type KrattTask =
  | { taskId: string; action: "hash-files"; files: string[] }
  | { taskId: string; action: "validate-manifest"; manifest: string }
  | { taskId: string; action: "run-test"; testFile: string; timeoutMs: number; maxOutputBytes: number };

export type TaskResult = { ok: true; task: Readonly<KrattTask> } | { ok: false; reason: string };

const TASK_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const TEST_FILE = /\.test\.(ts|mjs)$/;

class Invalid extends Error {}
const fail = (reason: string): never => {
  throw new Invalid(reason);
};

function isPlain(v: unknown): v is object {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

/** Own data property value; accessors and missing keys are rejected. */
function own(obj: object, key: string): unknown {
  const d = Object.getOwnPropertyDescriptor(obj, key);
  if (d === undefined) return fail(`missing-${key}`);
  if (!("value" in d)) return fail("accessor-property");
  return d.value;
}

function exactKeys(obj: object, keys: readonly string[]): void {
  const actual = Reflect.ownKeys(obj);
  if (actual.length !== keys.length || !actual.every((k) => typeof k === "string" && keys.includes(k)))
    fail("unexpected-keys");
}

function boundedInt(v: unknown, lo: number, hi: number, name: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v)) return fail(`${name}-not-integer`);
  if (v < lo || v > hi) return fail(`${name}-out-of-range`);
  return v;
}

function relPath(v: unknown): string {
  const bad = relPathFailure(v);
  if (bad) fail(bad);
  return v as string;
}

export function validateTask(input: unknown): TaskResult {
  try {
    if (!isPlain(input)) return { ok: false, reason: "task-not-plain-object" };
    const taskId = own(input, "taskId");
    if (typeof taskId !== "string" || !TASK_ID.test(taskId)) fail("taskId-invalid");
    const action = own(input, "action");
    if (typeof action !== "string" || !(KRATT_ACTIONS as readonly string[]).includes(action)) fail("action-not-allowed");
    let task: KrattTask;
    switch (action as KrattAction) {
      case "hash-files": {
        exactKeys(input, ["taskId", "action", "files"]);
        const files = own(input, "files");
        if (!Array.isArray(files)) return fail("files-not-array");
        if (files.length < 1 || files.length > LIMITS.maxFiles) fail("files-count-invalid");
        const out: string[] = [];
        for (let i = 0; i < files.length; i++) {
          const d = Object.getOwnPropertyDescriptor(files, String(i));
          if (d === undefined || !("value" in d)) return fail("files-element-invalid");
          out.push(relPath(d.value));
        }
        if (new Set(out).size !== out.length) fail("files-duplicate");
        task = { taskId: taskId as string, action: "hash-files", files: out };
        break;
      }
      case "validate-manifest": {
        exactKeys(input, ["taskId", "action", "manifest"]);
        task = { taskId: taskId as string, action: "validate-manifest", manifest: relPath(own(input, "manifest")) };
        break;
      }
      case "run-test": {
        exactKeys(input, ["taskId", "action", "testFile", "timeoutMs", "maxOutputBytes"]);
        const testFile = relPath(own(input, "testFile"));
        if (!TEST_FILE.test(testFile)) fail("testFile-not-test");
        task = {
          taskId: taskId as string,
          action: "run-test",
          testFile,
          timeoutMs: boundedInt(own(input, "timeoutMs"), LIMITS.minTimeoutMs, LIMITS.maxTimeoutMs, "timeoutMs"),
          maxOutputBytes: boundedInt(own(input, "maxOutputBytes"), LIMITS.minOutputBytes, LIMITS.maxOutputBytes, "maxOutputBytes"),
        };
        break;
      }
    }
    return { ok: true, task: Object.freeze(task) };
  } catch (e) {
    return { ok: false, reason: e instanceof Invalid ? e.message : "task-unreadable" };
  }
}

export const taskDigest = (task: KrattTask): string =>
  createHash("sha256").update(canonicalize(task), "utf8").digest("hex");
