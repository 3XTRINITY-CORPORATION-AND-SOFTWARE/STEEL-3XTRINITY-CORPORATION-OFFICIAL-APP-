// Child-process spec executor. Usage: node [--experimental-strip-types] factory/matrix/runner.mjs <specFile> [--mutate]
// Imports each spec's REAL target module, records calls into its exports, runs the assertion and prints one line:
//   MATRIX_SPEC_RESULTS:<json array of {slot, ok, calls, digest, error}>
// --mutate replaces every expected value with an impossible sentinel: every spec must then FAIL (proves the comparison is real).
import { copyFileSync, existsSync, readdirSync, symlinkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import inspector from "node:inspector";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { assertionFingerprint, behaviourFingerprint, canonJson, sha256, isDataTarget, validateSpecs } from "./spec-lib.mjs";

const ROOT = process.cwd();

/** Perturb a plain value (used on constants exported by the target when the target is neutralised). */
/** @param {any} v @returns {any} */
export function perturb(v) {
  if (typeof v === "string") return `\u0001perturbed:${v}`;
  if (typeof v === "number") return Number.isFinite(v) ? v + 1 : 0;
  if (typeof v === "boolean") return !v;
  if (typeof v === "bigint") return v + 1n;
  if (v === null || v === undefined) return "perturbed";
  if (Array.isArray(v)) return v.length === 0 ? ["perturbed"] : v.map(perturb);
  if (typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
    const keys = Object.keys(v);
    return keys.length === 0 ? { perturbed: 1 } : Object.fromEntries(keys.map((k) => [k, perturb(v[k])]));
  }
  return v;
}

/**
 * Wrap function exports (and methods of object exports such as probe descriptors) so calls made through the harness are counted.
 * In `counter.stub` mode (the dependence check) the target is NEUTRALISED instead: no real code runs, functions return undefined
 * (constructors return {}) and exported constants are perturbed. A probe whose answer survives that was not derived from the target.
 */
function counted(/** @type {any} */ fn, /** @type {any} */ counter) {
  return new Proxy(fn, {
    apply: (t, th, a) => (counter.n++, counter.stub ? undefined : Reflect.apply(t, th, a)),
    construct: (t, a, nt) => (counter.n++, counter.stub ? {} : Reflect.construct(t, a, nt)),
  });
}
function instrument(/** @type {any} */ mod, /** @type {any} */ counter) {
  /** @type {Record<string, any>} */
  const out = {};
  for (const k of Object.keys(mod)) {
    const v = mod[k];
    if (typeof v === "function") out[k] = counted(v, counter);
    else if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      out[k] = new Proxy(v, { get: (t, p, r) => { const x = Reflect.get(t, p, r); return typeof x === "function" ? counted(x.bind(t), counter) : counter.stub ? perturb(x) : x; } });
    } else out[k] = counter.stub ? perturb(v) : v;
  }
  return out;
}

/** V8 precise block coverage of repo code (excluding harness, specs, node_modules) -> a stable path fingerprint. */
class PathProbe {
  /** @type {import("node:inspector").Session | null} */
  static session = null;
  static on = false;
  constructor() {
    const session = PathProbe.session ??= (() => { const x = new inspector.Session(); x.connect(); return x; })();
    this.session = session;
    /** @type {(m: string, p?: object) => Promise<any>} */
    this.post = (m, p) => new Promise((res, rej) => session.post(m, p ?? {}, (e, r) => (e ? rej(e) : res(r))));
  }
  async start() {
    if (!PathProbe.on) {
      await this.post("Profiler.enable");
      await this.post("Profiler.startPreciseCoverage", { callCount: true, detailed: true });
      PathProbe.on = true;
    }
    await this.post("Profiler.takePreciseCoverage"); // reset counters: only the assertion itself is measured
  }
  async stop(/** @type {any} */ extraHits = []) {
    const { result } = await this.post("Profiler.takePreciseCoverage");
    const rootUrl = pathToFileURL(ROOT + "/").href;
    const hit = [...extraHits];
    for (const sc of result) {
      if (!sc.url.startsWith(rootUrl)) continue;
      const rel = sc.url.slice(rootUrl.length);
      if (/^(node_modules|factory\/matrix|scripts\/matrix250)\//.test(rel)) continue;
      for (const f of sc.functions) for (const r of f.ranges) hit.push(`${rel}:${r.startOffset}-${r.endOffset}:${r.count > 0 ? 1 : 0}`);
    }
    return sha256([...new Set(hit)].sort().join("\n")).slice(0, 16) + `/${hit.filter((h) => h.endsWith(":1")).length}`;
  }
}

async function load(/** @type {any} */ spec, /** @type {any} */ counter) {
  if (isDataTarget(spec.target)) {
    counter.n++; // the file read is the call into the domain artefact
    const text = readFileSync(join(ROOT, spec.target), "utf8");
    return { path: spec.target, text: counter.stub ? "" : text };
  }
  return instrument(await import(pathToFileURL(resolve(ROOT, spec.target)).href), counter);
}

/** Executed-code ranges of a CLI child (NODE_V8_COVERAGE): repo files by relative path, the staged copy under the temp root as `staged:<rel>`. */
function childCoverage(/** @type {any} */ dir, /** @type {any} */ tmp) {
  const hit = [];
  const rootUrl = pathToFileURL(ROOT + "/").href;
  const tmpUrl = pathToFileURL(tmp + "/").href;
  for (const f of readdirSync(dir)) {
    let doc;
    try { doc = JSON.parse(readFileSync(join(dir, f), "utf8")); } catch { continue; }
    for (const sc of doc.result ?? []) {
      let rel = null;
      if (sc.url.startsWith(tmpUrl)) rel = `staged:${sc.url.slice(tmpUrl.length)}`;
      else if (sc.url.startsWith(rootUrl)) rel = sc.url.slice(rootUrl.length);
      if (rel === null || /^(node_modules|factory\/matrix|scripts\/matrix250)\//.test(rel)) continue;
      for (const fn of sc.functions) for (const r of fn.ranges) hit.push(`${rel}:${r.startOffset}-${r.endOffset}:${r.count > 0 ? 1 : 0}`);
    }
  }
  return hit;
}

/**
 * ctx.execTarget(): run the REAL target script as a CLI (counts as a call into the target).
 * `files` are written into a fresh temp root first; with `stageAs` the target is copied to <tmp>/<stageAs>
 * (needed when the script derives its root from its own location) - otherwise the repo file runs in place.
 */
function makeCtx(/** @type {any} */ spec, /** @type {any} */ counter) {
  return {
    root: ROOT,
    /** `collect`: temp-root-relative paths whose content (or null if absent) is returned after the run as `files`. */
    /** @param {import("./types.d.ts").ExecOptions} [opts] */
    execTarget({ args = [], files = {}, stageAs, env = {}, cwd, input, nodeArgs = [], linkAs, collect = [] } = {}) {
      counter.n++;
      if (counter.stub) return { status: null, signal: null, stdout: "", stderr: "", files: Object.fromEntries(collect.map((rel) => [rel, null])) };
      const tmp = mkdtempSync(join(tmpdir(), "matrix-spec-"));
      const cov = mkdtempSync(join(tmpdir(), "matrix-cov-"));
      try {
        for (const [rel, text] of Object.entries(files)) {
          mkdirSync(dirname(join(tmp, rel)), { recursive: true });
          writeFileSync(join(tmp, rel), text);
        }
        let script = resolve(ROOT, spec.target);
        if (stageAs) {
          script = join(tmp, stageAs);
          mkdirSync(dirname(script), { recursive: true });
          copyFileSync(resolve(ROOT, spec.target), script);
        }
        if (linkAs) {
          const link = join(tmp, linkAs);
          mkdirSync(dirname(link), { recursive: true });
          symlinkSync(script, link);
          script = link;
        }
        /** @type {Record<string, string | undefined>} */
        const childEnv = { ...process.env, ...env, NODE_V8_COVERAGE: cov };
        delete childEnv.NODE_TEST_CONTEXT;
        const r = spawnSync(process.execPath, [...nodeArgs, script, ...args], { encoding: "utf8", cwd: cwd ?? tmp, env: childEnv, input, timeout: 60_000 });
        counter.extraHits.push(...childCoverage(cov, tmp));
        return { status: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr, files: Object.fromEntries(collect.map((rel) => [rel, existsSync(join(tmp, rel)) ? readFileSync(join(tmp, rel), "utf8") : null])) };
      } finally {
        rmSync(tmp, { recursive: true, force: true });
        rmSync(cov, { recursive: true, force: true });
      }
    },
  };
}

/** One execution of a spec's assertion against the real target. `measure` records the executed code path. */
async function execute(/** @type {any} */ spec, /** @type {any} */ counter, /** @type {any} */ measure) {
  /** @type {any} */
  const mod = await load(spec, counter);
  let probe = null;
  if (measure) {
    probe = new PathProbe();
    await probe.start();
  }
  let actual;
  if (spec.fn) {
    if (typeof mod[spec.fn] !== "function") throw new Error(`${spec.target} does not export function ${spec.fn}`);
    actual = await mod[spec.fn](...spec.input);
  } else {
    actual = await spec.run(mod, makeCtx(spec, counter));
  }
  const path = probe ? await probe.stop(counter.extraHits) : "-";
  return { actual, path };
}

const fresh = (stub = false) => ({ n: 0, stub, extraHits: [] });

export async function runSpec(/** @type {any} */ spec, { mutate = false } = {}) {
  const counter = fresh();
  let path = "-";
  try {
    const first = await execute(spec, counter, true);
    path = first.path;
    const got = canonJson(first.actual);
    const want = mutate ? canonJson({ $mutated: "impossible" }) : canonJson(spec.expected);
    const digest = sha256(got).slice(0, 16);
    if (counter.n < 1) return { slot: spec.slot, ok: false, calls: 0, digest: "-", path, feeds: null, error: "no call into the target module was observed" };
    if (got !== want) return { slot: spec.slot, ok: false, calls: counter.n, digest, path, feeds: null, error: `expected ${want.slice(0, 300)} but got ${got.slice(0, 300)}` };
    let feeds = true; // a fn spec's result IS the call's result
    if (!spec.fn && !mutate) {
      // repeatability: the probe must give the same answer when run again unchanged
      const again = await execute(spec, fresh(), false);
      if (canonJson(again.actual) !== got) return { slot: spec.slot, ok: false, calls: counter.n, digest, path, feeds: null, error: "probe is not repeatable: a second unchanged run gave a different result" };
      // dependence: the answer must change (or the probe must throw) when the target is neutralised
      let changed = true;
      try {
        const p = await execute(spec, fresh(true), false);
        changed = canonJson(p.actual) !== got;
      } catch {
        changed = true;
      }
      if (!changed) return { slot: spec.slot, ok: false, calls: counter.n, digest, path, feeds: false, error: "result does not depend on the target: the probe returned the same value with the target neutralised (a constant after a call)" };
      feeds = true;
    }
    return { slot: spec.slot, ok: true, calls: counter.n, digest, path, feeds, error: null };
  } catch (e) {
    return { slot: spec.slot, ok: false, calls: counter.n, digest: "-", path, feeds: null, error: String(/** @type {any} */ (e)?.stack ? /** @type {any} */ (e).message : e).slice(0, 300) };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const file = process.argv[2];
  const mutate = process.argv.includes("--mutate");
  const mod = await import(pathToFileURL(resolve(ROOT, file)).href);
  const guard = Array.isArray(mod.GUARDS);
  const SPECS = guard ? mod.GUARDS : mod.SPECS;
  const { valid, violations } = validateSpecs(SPECS, ROOT, { guard });
  const entries = [];
  for (const s of SPECS) {
    const result = await runSpec(s, { mutate });
    const isValid = valid.has(s.slot);
    entries.push({
      slot: s.slot, file, target: s.target, fn: s.fn ?? null, claim: s.claim, config: s.config === true, guard, valid: isValid,
      fingerprint: isValid ? assertionFingerprint(s) : null,
      behaviour: isValid ? behaviourFingerprint(s, result.path) : null,
      result,
    });
  }
  process.stdout.write(`\nMATRIX_SPEC_RESULTS:${JSON.stringify({ entries, violations })}\n`);
}
