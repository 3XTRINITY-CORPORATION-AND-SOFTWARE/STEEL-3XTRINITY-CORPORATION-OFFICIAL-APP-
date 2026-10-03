/* eslint-disable @typescript-eslint/ban-ts-comment -- the harness is untyped JS over dynamic target modules; tsconfig.cerberus.json type-checks factory/ with checkJs */
// @ts-nocheck
// Child-process spec executor. Usage: node [--experimental-strip-types] factory/matrix/runner.mjs <specFile> [--mutate]
// Imports each spec's REAL target module, records calls into its exports, runs the assertion and prints one line:
//   MATRIX_SPEC_RESULTS:<json array of {slot, ok, calls, digest, error}>
// --mutate replaces every expected value with an impossible sentinel: every spec must then FAIL (proves the comparison is real).
import { copyFileSync, symlinkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import inspector from "node:inspector";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { assertionFingerprint, behaviourFingerprint, canonJson, sha256, isDataTarget, validateSpecs } from "./spec-lib.mjs";

const ROOT = process.cwd();

/** Wrap function exports (and methods of object exports such as probe descriptors) so calls made through the harness are counted. */
function counted(fn, counter) {
  return new Proxy(fn, { apply: (t, th, a) => (counter.n++, Reflect.apply(t, th, a)), construct: (t, a, nt) => (counter.n++, Reflect.construct(t, a, nt)) });
}
function instrument(mod, counter) {
  const out = {};
  for (const k of Object.keys(mod)) {
    const v = mod[k];
    if (typeof v === "function") out[k] = counted(v, counter);
    else if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      out[k] = new Proxy(v, { get: (t, p, r) => { const x = Reflect.get(t, p, r); return typeof x === "function" ? counted(x.bind(t), counter) : x; } });
    } else out[k] = v;
  }
  return out;
}

/** V8 precise block coverage of repo code (excluding harness, specs, node_modules) -> a stable path fingerprint. */
class PathProbe {
  static session = null;
  static on = false;
  constructor() {
    this.session = PathProbe.session ??= (() => { const x = new inspector.Session(); x.connect(); return x; })();
    this.post = (m, p) => new Promise((res, rej) => this.session.post(m, p, (e, r) => (e ? rej(e) : res(r))));
  }
  async start() {
    if (!PathProbe.on) {
      await this.post("Profiler.enable");
      await this.post("Profiler.startPreciseCoverage", { callCount: true, detailed: true });
      PathProbe.on = true;
    }
    await this.post("Profiler.takePreciseCoverage"); // reset counters: only the assertion itself is measured
  }
  async stop() {
    const { result } = await this.post("Profiler.takePreciseCoverage");
    const rootUrl = pathToFileURL(ROOT + "/").href;
    const hit = [];
    for (const sc of result) {
      if (!sc.url.startsWith(rootUrl)) continue;
      const rel = sc.url.slice(rootUrl.length);
      if (/^(node_modules|factory\/matrix|scripts\/matrix250)\//.test(rel)) continue;
      for (const f of sc.functions) for (const r of f.ranges) hit.push(`${rel}:${r.startOffset}-${r.endOffset}:${r.count > 0 ? 1 : 0}`);
    }
    return sha256([...new Set(hit)].sort().join("\n")).slice(0, 16) + `/${hit.filter((h) => h.endsWith(":1")).length}`;
  }
}

async function load(spec, counter) {
  if (isDataTarget(spec.target)) {
    counter.n++; // the file read is the call into the domain artefact
    return { path: spec.target, text: readFileSync(join(ROOT, spec.target), "utf8") };
  }
  return instrument(await import(pathToFileURL(resolve(ROOT, spec.target)).href), counter);
}

/**
 * ctx.execTarget(): run the REAL target script as a CLI (counts as a call into the target).
 * `files` are written into a fresh temp root first; with `stageAs` the target is copied to <tmp>/<stageAs>
 * (needed when the script derives its root from its own location) - otherwise the repo file runs in place.
 */
function makeCtx(spec, counter) {
  return {
    root: ROOT,
    execTarget({ args = [], files = {}, stageAs, env = {}, cwd, input, nodeArgs = [], linkAs } = {}) {
      counter.n++;
      const tmp = mkdtempSync(join(tmpdir(), "matrix-spec-"));
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
        const childEnv = { ...process.env, ...env };
        delete childEnv.NODE_TEST_CONTEXT;
        const r = spawnSync(process.execPath, [...nodeArgs, script, ...args], { encoding: "utf8", cwd: cwd ?? tmp, env: childEnv, input, timeout: 60_000 });
        return { status: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr, tmp: tmp.length > 0 ? "<tmp>" : "" };
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
    },
  };
}

export async function runSpec(spec, { mutate = false } = {}) {
  const counter = { n: 0 };
  let probe = null;
  let path = "-";
  try {
    const mod = await load(spec, counter);
    probe = new PathProbe();
    await probe.start();
    let actual;
    if (spec.fn) {
      if (typeof mod[spec.fn] !== "function") throw new Error(`${spec.target} does not export function ${spec.fn}`);
      actual = await mod[spec.fn](...spec.input);
    } else {
      actual = await spec.run(mod, makeCtx(spec, counter));
    }
    path = await probe.stop();
    probe = null;
    const got = canonJson(actual);
    const want = mutate ? canonJson({ $mutated: "impossible" }) : canonJson(spec.expected);
    if (counter.n < 1) return { slot: spec.slot, ok: false, calls: 0, digest: "-", path, error: "no call into the target module was observed" };
    if (got !== want) return { slot: spec.slot, ok: false, calls: counter.n, digest: sha256(got).slice(0, 16), path, error: `expected ${want.slice(0, 300)} but got ${got.slice(0, 300)}` };
    return { slot: spec.slot, ok: true, calls: counter.n, digest: sha256(got).slice(0, 16), path, error: null };
  } catch (e) {
    return { slot: spec.slot, ok: false, calls: counter.n, digest: "-", path, error: String(e?.stack ? e.message : e).slice(0, 300) };
  } finally {
    probe = null;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const file = process.argv[2];
  const mutate = process.argv.includes("--mutate");
  const { SPECS } = await import(pathToFileURL(resolve(ROOT, file)).href);
  const { valid, violations } = validateSpecs(SPECS, ROOT);
  const entries = [];
  for (const s of SPECS) {
    const result = await runSpec(s, { mutate });
    const isValid = valid.has(s.slot);
    entries.push({
      slot: s.slot, file, target: s.target, fn: s.fn ?? null, claim: s.claim, valid: isValid,
      fingerprint: isValid ? assertionFingerprint(s) : null,
      behaviour: isValid ? behaviourFingerprint(s, result.path) : null,
      result,
    });
  }
  process.stdout.write(`\nMATRIX_SPEC_RESULTS:${JSON.stringify({ entries, violations })}\n`);
}
