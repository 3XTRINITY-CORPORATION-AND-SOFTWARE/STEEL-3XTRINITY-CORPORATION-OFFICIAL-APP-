import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { canonicalize, decide, verifyReceipt } from "../cerberus/core/decide.ts";
import { decideWithAdapters, stubAdapter } from "../cerberus/integrations/verdict-adapters.ts";
import { executeTask } from "../kratt/actions.ts";
import { parseEvidence, produceEvidence, ReplayGuard } from "../kratt/evidence.ts";
import { gateArtifact } from "../kratt/run.ts";
import { LIMITS, validateTask } from "../kratt/task.ts";
import type { Probe, ProbeOutcome, Violation } from "./types.ts";

/**
 * Targets under test. Real modules by default; tests inject defective mutants to prove
 * each probe can actually detect the defect class it claims to cover.
 */
export interface Targets {
  decide: (input: unknown) => { decision: string };
  decideWithAdapters: typeof decideWithAdapters;
  verifyReceipt: (r: unknown) => boolean;
  validateTask: (t: unknown) => { ok: boolean };
  parseEvidence: (c: unknown) => { ok: boolean };
}
export const REAL_TARGETS: Targets = { decide, decideWithAdapters, verifyReceipt, validateTask, parseEvidence };

const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const ART = { name: "a.txt", content: "hello", sha256: sha("hello") };
const VALID = { action: "detect", toepara: "ADMITTED", trustGate: "AUTHORIZED", artifact: ART };

class Collector {
  cases = 0;
  violations: Violation[] = [];
  /** Expect `check()` to be true. Exceptions count as violations (a guard must not throw). */
  expect(caseId: string, expected: string, reproduction: string, check: () => boolean) {
    this.cases++;
    const run = () => {
      try {
        return !check();
      } catch (e) {
        void e;
        return true;
      }
    };
    if (run()) this.violations.push({ caseId, expected, observed: "expectation violated or threw", reproduction, recheck: run });
  }
  out(): ProbeOutcome {
    return { cases: this.cases, violations: this.violations };
  }
}

function hostileValues(): [string, unknown][] {
  const cyc: Record<string, unknown> = { action: "detect" };
  cyc.self = cyc;
  const accessor: Record<string, unknown> = { ...VALID };
  Object.defineProperty(accessor, "action", { enumerable: true, get: () => "detect" });
  const inherited = Object.create({ ...VALID });
  const proxy = new Proxy({}, { get() { throw new Error("trap"); }, getOwnPropertyDescriptor() { throw new Error("trap"); } });
  return [
    ["undefined", undefined], ["null", null], ["zero", 0], ["NaN", NaN], ["empty-string", ""], ["array", []],
    ["function", () => 1], ["symbol", Symbol("x")], ["bigint", 10n], ["cyclic", cyc], ["accessor", accessor],
    ["inherited-props", inherited], ["throwing-proxy", proxy], ["string-valid-json", JSON.stringify(VALID)],
    ["empty-object", {}], ["artifact-array", { ...VALID, artifact: [ART] }], ["artifact-string", { ...VALID, artifact: "x" }],
    ["artifact-bigint-content", { ...VALID, artifact: { ...ART, content: 1n } }],
    ["action-uppercase", { ...VALID, action: "DETECT" }], ["action-trailing-space", { ...VALID, action: "detect " }],
    ["action-nul", { ...VALID, action: "detect\0" }], ["action-array", { ...VALID, action: ["detect"] }],
    ["action-deploy", { ...VALID, action: "deploy" }], ["action-merge", { ...VALID, action: "merge" }],
    ["toepara-lowercase", { ...VALID, toepara: "admitted" }], ["toepara-trailing-nl", { ...VALID, toepara: "ADMITTED\n" }],
    ["toepara-true", { ...VALID, toepara: true }], ["toepara-object", { ...VALID, toepara: new String("ADMITTED") }],
    ["trustgate-lowercase", { ...VALID, trustGate: "authorized" }], ["trustgate-1", { ...VALID, trustGate: 1 }],
    ["sha-uppercase", { ...VALID, artifact: { ...ART, sha256: ART.sha256.toUpperCase() } }],
    ["sha-trailing-nl", { ...VALID, artifact: { ...ART, sha256: ART.sha256 + "\n" } }],
    ["content-changed", { ...VALID, artifact: { ...ART, content: "hellO" } }],
    ["name-empty", { ...VALID, artifact: { ...ART, name: "" } }],
  ];
}

export function probeCerberusHostileInput(t: Targets): Probe {
  return {
    id: "cerberus-hostile-input",
    category: "fail-open",
    component: "cerberus/core (decide, normalize, policy, artifact-trust)",
    smallestFix: "Make the failing stage return FAIL (never skip it) and keep decide() total: normalize into an immutable snapshot of own data properties and deny on any exception.",
    applies: (f) => f.some((x) => x.startsWith("cerberus/") && !x.startsWith("cerberus/tests/")) || f.some((x) => x.startsWith("rastik/")),
    async run() {
      const c = new Collector();
      c.expect("baseline", "valid input PROCEEDs (probe sanity)", "decide(VALID)", () => t.decide(VALID).decision === "PROCEED");
      for (const [name, v] of hostileValues()) {
        c.expect(`decide:${name}`, "FAIL_CLOSED and no throw", `decide(<${name}>)`, () => t.decide(v).decision === "FAIL_CLOSED");
      }
      return c.out();
    },
  };
}

export function probeCerberusAdapters(t: Targets): Probe {
  const good = stubAdapter("g", "AUTHORIZED");
  const adm = stubAdapter("t", "ADMITTED");
  const throwing = { name: "throws", verdict: () => { throw new Error("down"); } };
  return {
    id: "cerberus-adapter-failopen",
    category: "fail-open",
    component: "cerberus/integrations/verdict-adapters.ts",
    smallestFix: "Treat any adapter result that is not the exact string 'ADMITTED'/'AUTHORIZED' (throw, Promise, boxed String, missing adapter) as no verdict => FAIL_CLOSED.",
    applies: (f) => f.some((x) => x.startsWith("cerberus/integrations/") || x.startsWith("cerberus/core/")) || f.some((x) => x.startsWith("rastik/")),
    async run() {
      const c = new Collector();
      const input = { action: "detect", artifact: ART };
      c.expect("baseline", "both adapters ok PROCEEDs (probe sanity)", "decideWithAdapters(valid, ok adapters)", () => t.decideWithAdapters(input, { toepara: adm, trustGate: good }).decision === "PROCEED");
      const bad: [string, unknown][] = [
        ["undefined", undefined], ["null", null], ["promise-resolved", Promise.resolve("ADMITTED")], ["boxed-string", new String("ADMITTED")],
        ["trailing-space", "ADMITTED "], ["lowercase", "admitted"], ["true", true], ["object", { verdict: "ADMITTED" }], ["number", 1],
      ];
      for (const [n, v] of bad) {
        c.expect(`toepara:${n}`, "FAIL_CLOSED", `adapter returns <${n}>`, () => t.decideWithAdapters(input, { toepara: stubAdapter("x", v), trustGate: good }).decision === "FAIL_CLOSED");
        c.expect(`trustGate:${n}`, "FAIL_CLOSED", `trust gate returns <${n}>`, () => t.decideWithAdapters(input, { toepara: adm, trustGate: stubAdapter("x", v) }).decision === "FAIL_CLOSED");
      }
      c.expect("toepara-throws", "FAIL_CLOSED", "adapter throws", () => t.decideWithAdapters(input, { toepara: throwing, trustGate: good }).decision === "FAIL_CLOSED");
      c.expect("trustgate-throws", "FAIL_CLOSED", "trust gate throws", () => t.decideWithAdapters(input, { toepara: adm, trustGate: throwing }).decision === "FAIL_CLOSED");
      c.expect("adapters-missing", "FAIL_CLOSED", "adapters undefined", () => t.decideWithAdapters(input, undefined as never).decision === "FAIL_CLOSED");
      c.expect("adapters-empty", "FAIL_CLOSED", "adapters {}", () => t.decideWithAdapters(input, {} as never).decision === "FAIL_CLOSED");
      c.expect("trustgate-missing", "FAIL_CLOSED", "no trust gate", () => t.decideWithAdapters(input, { toepara: adm } as never).decision === "FAIL_CLOSED");
      c.expect("caller-verdicts-ignored", "FAIL_CLOSED when adapters deny even if caller says ADMITTED/AUTHORIZED", "caller toepara/trustGate fields + denying adapters",
        () => t.decideWithAdapters({ ...input, toepara: "ADMITTED", trustGate: "AUTHORIZED" }, { toepara: stubAdapter("d", "DENIED"), trustGate: stubAdapter("d", "DENIED") }).decision === "FAIL_CLOSED");
      return c.out();
    },
  };
}

export function probeReceiptIntegrity(t: Targets): Probe {
  return {
    id: "cerberus-receipt-integrity",
    category: "evidence-bypass",
    component: "cerberus/core/decide.ts verifyReceipt",
    smallestFix: "Hash every receipt field (canonical form) and make verifyReceipt total: false for any non-object or any altered field.",
    applies: (f) => f.some((x) => x === "cerberus/core/decide.ts") || f.some((x) => x.startsWith("rastik/")),
    async run() {
      const c = new Collector();
      const receipt = decide(VALID) as unknown as Record<string, unknown>;
      c.expect("baseline", "untouched receipt verifies (probe sanity)", "verifyReceipt(decide(VALID))", () => t.verifyReceipt(receipt) === true);
      const flat: [string, string[]][] = [];
      const walk = (o: unknown, path: string[]) => {
        if (o !== null && typeof o === "object") for (const k of Object.keys(o)) walk((o as Record<string, unknown>)[k], [...path, k]);
        else flat.push([path.join("."), path]);
      };
      walk(receipt, []);
      for (const [name, path] of flat) {
        if (name === "receiptDigest") continue;
        for (const v of ["FAIL_CLOSED_x", null, 0, true]) {
          const copy = JSON.parse(JSON.stringify(receipt)) as Record<string, unknown>;
          let o: Record<string, unknown> = copy;
          for (const p of path.slice(0, -1)) o = o[p] as Record<string, unknown>;
          const last = path[path.length - 1];
          if (o[last] === v) continue;
          o[last] = v;
          c.expect(`mutate:${name}=${String(v)}`, "verifyReceipt false", `verifyReceipt(receipt with ${name}=${String(v)})`, () => t.verifyReceipt(copy) === false);
        }
      }
      for (const [n, v] of [["null", null], ["number", 1], ["array", []], ["string", "x"], ["empty", {}], ["bigint-leaf", { ...receipt, x: 1n }]] as [string, unknown][])
        c.expect(`junk:${n}`, "false, no throw", `verifyReceipt(<${n}>)`, () => t.verifyReceipt(v) === false);
      return c.out();
    },
  };
}

export function probeKrattTask(t: Targets): Probe {
  const base = { taskId: "t", action: "run-test", testFile: "kratt/tests/x.test.ts", timeoutMs: 1000, maxOutputBytes: 4096 };
  const h = (files: unknown) => ({ taskId: "t", action: "hash-files", files });
  return {
    id: "kratt-task-schema",
    category: "non-finite",
    component: "kratt/task.ts validateTask",
    smallestFix: "Validate with Number.isSafeInteger + inclusive LIMITS bounds, allow-list path segments by regex, and require exact key sets.",
    applies: (f) => f.some((x) => x.startsWith("kratt/") && !x.startsWith("kratt/tests/")) || f.some((x) => x.startsWith("rastik/")),
    async run() {
      const c = new Collector();
      c.expect("baseline", "valid task accepted (probe sanity)", "validateTask(base)", () => t.validateTask(base).ok === true);
      const nums: [string, unknown][] = [["NaN", NaN], ["Infinity", Infinity], ["-Infinity", -Infinity], ["-0.5", -0.5], ["1e21", 1e21], ["2^53", 2 ** 53], ["float", 100.5], ["numeric-string", "1000"], ["null", null], ["boxed", new Number(1000)], ["bigint", 1000n]];
      for (const k of ["timeoutMs", "maxOutputBytes"])
        for (const [n, v] of nums) c.expect(`${k}:${n}`, "rejected", `validateTask({...,${k}:${n}})`, () => t.validateTask({ ...base, [k]: v }).ok === false);
      const edge = (k: "timeoutMs" | "maxOutputBytes", lo: number, hi: number) => {
        for (const [v, ok] of [[lo - 1, false], [lo, true], [hi, true], [hi + 1, false]] as [number, boolean][])
          c.expect(`boundary:${k}=${v}`, ok ? "accepted" : "rejected", `validateTask({...,${k}:${v}})`, () => t.validateTask({ ...base, [k]: v }).ok === ok);
      };
      edge("timeoutMs", LIMITS.minTimeoutMs, LIMITS.maxTimeoutMs);
      edge("maxOutputBytes", LIMITS.minOutputBytes, LIMITS.maxOutputBytes);
      const files = (n: number) => Array.from({ length: n }, (_, i) => `f${i}.txt`);
      c.expect("boundary:files=0", "rejected", "files []", () => t.validateTask(h([])).ok === false);
      c.expect(`boundary:files=${LIMITS.maxFiles}`, "accepted", "max files", () => t.validateTask(h(files(LIMITS.maxFiles))).ok === true);
      c.expect(`boundary:files=${LIMITS.maxFiles + 1}`, "rejected", "max files + 1", () => t.validateTask(h(files(LIMITS.maxFiles + 1))).ok === false);
      c.expect("boundary:path=200", "accepted", "200-char path", () => t.validateTask(h(["a".repeat(200)])).ok === true);
      c.expect("boundary:path=201", "rejected", "201-char path", () => t.validateTask(h(["a".repeat(201)])).ok === false);
      const paths = ["../x", "a/../../x", "/etc/passwd", "//x", "a\\..\\b", "a\0.txt", ".env", ".git/HEAD", "a/./b", "a/", "%2e%2e/x", "a%00", "..", ".", "~/x", "$HOME/x", "a b", "a\nb", "a.txt\n", "\u0430.txt", "\uff0e\uff0e/x", "a:b", "-rf", "x".repeat(5000)];
      for (const p of paths) c.expect(`path:${JSON.stringify(p).slice(0, 40)}`, "rejected", `hash-files [${JSON.stringify(p).slice(0, 40)}]`, () => t.validateTask(h([p])).ok === false);
      const actions = ["exec", "shell", "sh", "bash", "node", "npm", "git", "curl", "write", "delete", "HASH-FILES", " hash-files", "hash-files\0", "__proto__", "constructor", "toString"];
      for (const a of actions) c.expect(`action:${a}`, "rejected", `action ${JSON.stringify(a)}`, () => t.validateTask({ taskId: "t", action: a, files: ["a"] }).ok === false);
      for (const extra of [["cmd", "id"], ["args", ["-e"]], ["env", {}], ["cwd", "/"], ["__proto__", { x: 1 }], ["url", "http://x"]])
        c.expect(`extra-key:${extra[0]}`, "rejected", `extra key ${extra[0]}`, () => t.validateTask(Object.defineProperty({ ...base }, extra[0] as string, { value: extra[1], enumerable: true, configurable: true, writable: true })).ok === false);
      return c.out();
    },
  };
}

export function probeKrattEvidence(t: Targets): Probe {
  return {
    id: "kratt-evidence-mutation",
    category: "evidence-bypass",
    component: "kratt/evidence.ts (parseEvidence, createToeparaAdapter) + kratt/run.ts gateArtifact",
    smallestFix: "Re-derive digest and verdict from the facts inside the evidence; reject on any difference, non-canonical form, unknown key or non-finite number; consume digests once.",
    applies: (f) => f.some((x) => x.startsWith("kratt/") && !x.startsWith("kratt/tests/")) || f.some((x) => x.startsWith("rastik/")),
    async run() {
      const c = new Collector();
      const tmp = mkdtempSync(join(tmpdir(), "rastik-ev-"));
      try {
        writeFileSync(join(tmp, "a.txt"), "A");
        const task = { taskId: "ev", action: "hash-files" as const, files: ["a.txt"] };
        const good = produceEvidence(task, await executeTask(tmp, task));
        const bad = produceEvidence(task, await executeTask(tmp, { ...task, files: ["missing.txt"] }));
        const goodText = canonicalize(good);
        c.expect("baseline", "genuine evidence parses and is ADMITTED (probe sanity)", "parseEvidence(good)", () => t.parseEvidence(goodText).ok === true && good.verdict === "ADMITTED");
        const gate = (content: string) => gateArtifact({ name: "toepara-evidence-ev.json", content, sha256: sha(content) }, { trustGate: stubAdapter("tg", "AUTHORIZED"), guard: new ReplayGuard() });
        // 1. every single-field mutation with a stale evidenceDigest must be rejected
        const values: [string, unknown | undefined][] = [["null", null], ["deleted", undefined], ["empty", ""], ["-1", -1], ["NaN", NaN], ["Infinity", Infinity], ["true", true], ["array", []], ["object", {}], ["x", "x"]];
        for (const key of Object.keys(good)) {
          if (key === "evidenceDigest") continue;
          for (const [vn, v] of values) {
            const e = { ...good } as Record<string, unknown>;
            if (v === undefined) delete e[key];
            else e[key] = v;
            if (canonicalize(e[key]) === canonicalize((good as unknown as Record<string, unknown>)[key]) && v !== undefined) continue;
            const text = canonicalize(e);
            c.expect(`stale-digest:${key}=${vn}`, "parseEvidence rejects and gate FAIL_CLOSED", `evidence.${key}=${vn}, evidenceDigest unchanged`,
              () => t.parseEvidence(text).ok === false && gate(text).receipt.decision === "FAIL_CLOSED");
          }
        }
        // 2. verdict flip with all digests recomputed must still be rejected (verdict must derive from facts)
        const flipped = { ...bad, verdict: "ADMITTED" } as Record<string, unknown>;
        const { evidenceDigest: _d, ...body } = flipped;
        flipped.evidenceDigest = sha(canonicalize(body));
        const flipText = canonicalize(flipped);
        c.expect("verdict-flip-resealed", "rejected", "REJECTED evidence with verdict=ADMITTED, digests recomputed", () => t.parseEvidence(flipText).ok === false && gate(flipText).receipt.decision === "FAIL_CLOSED");
        // 3. REJECTED evidence never reaches PROCEED
        c.expect("rejected-evidence", "FAIL_CLOSED", "genuine failing evidence", () => gate(canonicalize(bad)).receipt.decision === "FAIL_CLOSED");
        // 4. replay
        c.expect("replay", "second presentation FAIL_CLOSED", "same evidence twice, same guard", () => {
          const d = { trustGate: stubAdapter("tg", "AUTHORIZED"), guard: new ReplayGuard() };
          const a = { name: "toepara-evidence-ev.json", content: goodText, sha256: sha(goodText) };
          return gateArtifact(a, d).receipt.decision === "PROCEED" && gateArtifact(a, d).receipt.decision === "FAIL_CLOSED";
        });
        // 5. no evidence at all
        for (const [n, content] of [["empty", ""], ["json-null", "null"], ["array", "[]"], ["huge", "x".repeat(300_000)]] as [string, string][])
          c.expect(`no-evidence:${n}`, "FAIL_CLOSED", `artifact content ${n}`, () => gate(content).receipt.decision === "FAIL_CLOSED");
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return c.out();
    },
  };
}

export function probeKrattPathEscape(): Probe {
  return {
    id: "kratt-path-escape",
    category: "invalid-input",
    component: "kratt/paths.ts + kratt/actions.ts",
    smallestFix: "realpath every target, require it to stay inside the real root, stat it as a regular file BEFORE reading, and reject otherwise.",
    applies: (f) => f.some((x) => x.startsWith("kratt/") && !x.startsWith("kratt/tests/")) || f.some((x) => x.startsWith("rastik/")),
    async run() {
      const c = new Collector();
      const root = mkdtempSync(join(tmpdir(), "rastik-root-"));
      const outside = mkdtempSync(join(tmpdir(), "rastik-out-"));
      try {
        writeFileSync(join(outside, "secret.txt"), "secret");
        writeFileSync(join(outside, "x.test.mjs"), 'import {test} from "node:test"; test("t",()=>{});');
        writeFileSync(join(root, "ok.txt"), "ok");
        symlinkSync(join(outside, "secret.txt"), join(root, "link.txt"));
        symlinkSync(outside, join(root, "dirlink"));
        mkdirSync(join(root, "kratt/tests"), { recursive: true });
        symlinkSync(outside, join(root, "kratt/tests/ext"));
        symlinkSync(join(root, "loop2"), join(root, "loop1"));
        symlinkSync(join(root, "loop1"), join(root, "loop2"));
        const fifoOk = spawnSync("mkfifo", [join(root, "fifo")]).status === 0;
        mkdirSync(join(root, "adir"));
        const denied = async (name: string, task: Parameters<typeof executeTask>[1]) => {
          c.cases++;
          const run = async () => {
            const r = await Promise.race([executeTask(root, task), new Promise<null>((res) => setTimeout(() => res(null), 8000))]);
            return r === null || r.exitCode === 0; // true => violation (hung or succeeded)
          };
          if (await run()) c.violations.push({ caseId: name, expected: "failed result, no hang", observed: "succeeded or hung", reproduction: `executeTask(root, ${JSON.stringify(task)})`, recheck: run });
        };
        await denied("file-symlink-escape", { taskId: "p", action: "hash-files", files: ["link.txt"] });
        await denied("dir-symlink-escape", { taskId: "p", action: "hash-files", files: ["dirlink/secret.txt"] });
        await denied("symlink-loop", { taskId: "p", action: "hash-files", files: ["loop1"] });
        await denied("directory-as-file", { taskId: "p", action: "hash-files", files: ["adir"] });
        await denied("manifest-symlink-escape", { taskId: "p", action: "validate-manifest", manifest: "link.txt" });
        await denied("test-via-symlinked-dir", { taskId: "p", action: "run-test", testFile: "kratt/tests/ext/x.test.mjs", timeoutMs: 3000, maxOutputBytes: 4096 });
        if (fifoOk) await denied("fifo", { taskId: "p", action: "hash-files", files: ["fifo"] });
        c.expect("ok-file-still-works", "control: legit file hashes (probe sanity)", "hash-files ok.txt", () => existsSync(join(root, "ok.txt")));
        await (async () => {
          c.cases++;
          const r = await executeTask(root, { taskId: "p", action: "hash-files", files: ["ok.txt"] });
          if (r.exitCode !== 0) c.violations.push({ caseId: "control", expected: "ok.txt hashes", observed: "failed", reproduction: "hash-files ok.txt", recheck: async () => (await executeTask(root, { taskId: "p", action: "hash-files", files: ["ok.txt"] })).exitCode !== 0 });
        })();
      } finally {
        rmSync(root, { recursive: true, force: true });
        rmSync(outside, { recursive: true, force: true });
      }
      return c.out();
    },
  };
}

const IMPORT_RE = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["']([^"']+)["']/g;
const EXTS = [".ts", ".tsx", ".mjs", ".js", ".json"];

export function resolveSpecifier(root: string, fromFile: string, rawSpec: string): string | null {
  // Vite-style suffixes (`./x.css?url`, `./x.html?raw`, `#hash`) are not part of the file name.
  const spec = rawSpec.replace(/[?#].*$/, "");
  const base = spec.startsWith("@/") ? resolve(root, "src", spec.slice(2)) : resolve(root, dirname(fromFile), spec);
  const cands = [base, ...EXTS.map((e) => base + e), ...EXTS.map((e) => join(base, "index" + e))];
  if (/\.(js|mjs)$/.test(base)) cands.push(base.replace(/\.(js|mjs)$/, ".ts"), base.replace(/\.js$/, ".tsx"));
  const hit = cands.find((p) => existsSync(p) && !p.endsWith("/"));
  return hit ?? null;
}

/** Static: every relative / `@/` import in a changed source file must resolve to a file at HEAD. */
export const probeStaleImport: Probe = {
  id: "stale-import",
  category: "stale-import",
  component: "all changed .ts/.tsx/.js/.mjs files",
  smallestFix: "Update the import path to the file's new location (or restore the file); do not leave a specifier that resolves to nothing.",
  applies: (f) => f.some((x) => /\.(ts|tsx|js|mjs)$/.test(x)),
  async run({ root, files }) {
    const c = new Collector();
    for (const f of files.filter((x) => /\.(ts|tsx|js|mjs)$/.test(x))) {
      const p = join(root, f);
      if (!existsSync(p)) continue;
      const text = readFileSync(p, "utf8");
      for (const m of text.matchAll(IMPORT_RE)) {
        const spec = m[1];
        if (!(spec.startsWith("./") || spec.startsWith("../") || spec.startsWith("@/"))) continue;
        c.expect(`${f} -> ${spec}`, "specifier resolves to an existing file", `${f} imports "${spec}"`, () => resolveSpecifier(root, f, spec) !== null);
      }
    }
    return c.out();
  },
};

const GATE_WEAKENING: [RegExp, string][] = [
  [/continue-on-error:\s*true/i, "continue-on-error: true"],
  [/\|\|\s*true\b/, "'|| true' swallows a failing step"],
  [/npm audit fix\s+--force/, "npm audit fix --force"],
  [/--no-verify\b/, "--no-verify"],
  [/if:\s*false\b/, "disabled job/step (if: false)"],
];

/** Static: changed workflow files must not weaken a gate. */
export const probeWorkflowGates: Probe = {
  id: "workflow-gate-weakening",
  category: "fail-open",
  component: ".github/workflows",
  smallestFix: "Remove the construct so the step fails the job when the check fails.",
  applies: (f) => f.some((x) => x.startsWith(".github/workflows/")),
  async run({ root, files }) {
    const c = new Collector();
    for (const f of files.filter((x) => x.startsWith(".github/workflows/") && /\.ya?ml$/.test(x))) {
      const p = join(root, f);
      if (!existsSync(p)) continue;
      const lines = readFileSync(p, "utf8").split("\n");
      for (const [re, why] of GATE_WEAKENING)
        lines.forEach((l, i) => {
          if (l.trim().startsWith("#")) return;
          c.expect(`${f}:${i + 1}`, "no gate-weakening construct", `${f}:${i + 1}: ${why}`, () => !re.test(l));
        });
    }
    return c.out();
  },
};

export function allProbes(t: Targets = REAL_TARGETS): Probe[] {
  return [
    probeCerberusHostileInput(t), probeCerberusAdapters(t), probeReceiptIntegrity(t),
    probeKrattTask(t), probeKrattEvidence(t), probeKrattPathEscape(),
    probeStaleImport, probeWorkflowGates,
  ];
}
