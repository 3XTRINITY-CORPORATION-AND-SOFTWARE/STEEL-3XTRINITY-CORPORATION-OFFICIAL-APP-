// Deterministic, read-only runtime verifier: every place that names a Node version must agree with the contract.
//
//   node scripts/runtime-verify.mjs [--json]
//
// Contract (single Node major, currently 22):
//   .nvmrc                  = 22 (or 22.x.y)
//   package.json engines    = a range that admits EVERY 22.x and nothing else (e.g. "22.x", ">=22 <23")
//   workflows               = every actions/setup-node step sets node-version 22 (or node-version-file pointing at a file that says 22)
//   .devcontainer           = node feature version 22 / node image tag 22 (where present)
//   Dockerfile*             = FROM node:22... / ARG NODE_VERSION=22 (where present)
//   local                   = the running `node` is 22.x
// Output: RUNTIME_OK, or RUNTIME_DRIFT followed by one MISMATCH line per offending source (exit 1).
// Read-only: only reads files, never writes, spawns nothing, uses no network, installs nothing.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const EXPECTED_MAJOR = 22;

/** Major of "22", "v22.1.0", "22.x" -> 22; null when it is not a plain numeric version. */
export function parseMajor(text) {
  const m = /^v?(\d+)(?:\.(?:\d+|x|X|\*)){0,2}$/.exec(String(text).trim());
  return m ? Number(m[1]) : null;
}

const parseVer = (s) => s.split(".").map(Number);
function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}
/** One semver comparator -> predicate over [maj,min,pat]. Throws on anything it does not understand. */
function comparator(tok) {
  const m = /^(>=|<=|>|<|=|\^|~)?v?(\d+|x|X|\*)(?:\.(\d+|x|X|\*))?(?:\.(\d+|x|X|\*))?$/.exec(tok);
  if (!m) throw new Error(`unsupported range token "${tok}"`);
  const op = m[1] ?? "";
  const raw = [m[2], m[3], m[4]];
  const wild = (x) => x === undefined || /^[xX*]$/.test(x);
  let given = 0;
  while (given < 3 && !wild(raw[given])) given++;
  for (let i = given; i < 3; i++) if (!wild(raw[i])) throw new Error(`unsupported range token "${tok}"`);
  const lo = [0, 1, 2].map((i) => (i < given ? Number(raw[i]) : 0));
  const nextUp = (n) => { const v = lo.slice(); if (n === 0) return [Infinity, 0, 0]; v[n - 1] += 1; for (let i = n; i < 3; i++) v[i] = 0; return v; };
  if (given === 0) { // bare "*" / "x"
    if (op === "" || op === "=" || op === ">=") return () => true;
    throw new Error(`unsupported range token "${tok}"`);
  }
  if (op === "" || op === "=") return (v) => cmp(v, lo) >= 0 && cmp(v, nextUp(given)) < 0;
  if (op === ">=") return (v) => cmp(v, lo) >= 0;
  if (op === "<") return (v) => cmp(v, lo) < 0;
  if (op === ">") return given === 3 ? (v) => cmp(v, lo) > 0 : (v) => cmp(v, nextUp(given)) >= 0;
  if (op === "<=") return given === 3 ? (v) => cmp(v, lo) <= 0 : (v) => cmp(v, nextUp(given)) < 0;
  if (op === "^") { if (lo[0] === 0) throw new Error(`unsupported range token "${tok}"`); return (v) => cmp(v, lo) >= 0 && cmp(v, [lo[0] + 1, 0, 0]) < 0; }
  /* "~" */ { const up = given === 1 ? [lo[0] + 1, 0, 0] : [lo[0], lo[1] + 1, 0]; return (v) => cmp(v, lo) >= 0 && cmp(v, up) < 0; }
}
/** Does `range` (npm syntax subset: comparators, x-ranges, ^, ~, ||) admit `version`? */
export function satisfies(version, range) {
  const v = parseVer(version);
  const sets = String(range).split("||").map((s) => s.trim());
  return sets.some((set) => {
    const toks = set === "" ? ["*"] : set.split(/\s+/);
    if (toks.includes("-")) throw new Error("unsupported hyphen range");
    return toks.map(comparator).every((p) => p(v));
  });
}
const INSIDE = ["22.0.0", "22.0.1", "22.12.3", "22.99.99"];
const OUTSIDE = ["0.0.0", "20.99.99", "21.99.99", "23.0.0", "24.0.0"];
/** The contract for engines: admits every 22.x and nothing outside major 22. */
export function rangePinsMajor(range, major = EXPECTED_MAJOR) {
  const shift = (list) => list.map((v) => v.replace(/^22\./, `${major}.`));
  const missing = shift(INSIDE).filter((v) => !satisfies(v, range));
  const leaked = [...new Set([...shift(OUTSIDE), `${major - 1}.99.99`, `${major + 1}.0.0`])].filter((v) => satisfies(v, range));
  return { ok: missing.length === 0 && leaked.length === 0, missing, leaked };
}

const read = (root, rel) => readFileSync(join(root, rel), "utf8");
const result = (source, found, ok, reason) => ({ source, found, ok, ...(ok ? {} : { reason }) });

function checkVersionText(source, text, expected) {
  const major = parseMajor(text);
  if (major === null) return result(source, String(text).trim(), false, `not a numeric Node version (expected major ${expected})`);
  return major === expected ? result(source, String(text).trim(), true) : result(source, String(text).trim(), false, `major ${major}, expected ${expected}`);
}
function missing(source, what) { return result(source, "(missing)", false, what); }

function fromLocal(localVersion, expected) {
  return checkVersionText("local node", localVersion, expected);
}
function fromNvmrc(root, expected) {
  if (!existsSync(join(root, ".nvmrc"))) return missing(".nvmrc", ".nvmrc not found");
  return checkVersionText(".nvmrc", read(root, ".nvmrc").trim(), expected);
}
function fromEngines(root, expected) {
  const src = "package.json engines.node";
  if (!existsSync(join(root, "package.json"))) return missing(src, "package.json not found");
  let pkg;
  try { pkg = JSON.parse(read(root, "package.json")); } catch (e) { return result(src, "(unparseable)", false, `package.json is not valid JSON: ${e.message}`); }
  const range = pkg?.engines?.node;
  if (typeof range !== "string") return missing(src, "engines.node is not set");
  try {
    const r = rangePinsMajor(range, expected);
    if (r.ok) return result(src, range, true);
    const why = [r.missing.length ? `does not admit ${r.missing.join(", ")}` : null, r.leaked.length ? `also admits ${r.leaked.join(", ")}` : null].filter(Boolean).join("; ");
    return result(src, range, false, `range must admit every ${expected}.x and nothing else: ${why}`);
  } catch (e) { return result(src, range, false, e.message); }
}

/** One result per `uses: actions/setup-node` step in every workflow file. */
function fromWorkflows(root, expected) {
  const dir = join(root, ".github/workflows");
  const out = [];
  const files = existsSync(dir) ? readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort() : [];
  for (const f of files) {
    const rel = `.github/workflows/${f}`;
    const lines = read(root, rel).split("\n");
    lines.forEach((line, i) => {
      if (/^\s*#/.test(line) || !/\buses:\s*["']?actions\/setup-node@/.test(line)) return;
      const keyCol = line.indexOf("uses:");
      const source = `${rel}:${i + 1} setup-node`;
      let version = null, file = null;
      for (let j = i + 1; j < lines.length; j++) {
        const l = lines[j];
        if (l.trim() === "" || /^\s*#/.test(l)) continue;
        if (l.search(/\S/) < keyCol) break;
        const mv = /^\s*node-version:\s*(.*?)\s*(?:#.*)?$/.exec(l);
        const mf = /^\s*node-version-file:\s*(.*?)\s*(?:#.*)?$/.exec(l);
        if (mv) version = mv[1].replace(/^["']|["']$/g, "");
        if (mf) file = mf[1].replace(/^["']|["']$/g, "");
      }
      if (version === null && file === null) { out.push(missing(source, "setup-node step has no node-version (it would use the runner's default Node)")); return; }
      if (file !== null && version === null) {
        const p = file.replace(/^\.\//, "");
        if (!existsSync(join(root, p))) { out.push(result(source, `node-version-file: ${file}`, false, `${file} not found`)); return; }
        const r = checkVersionText(source, read(root, p).trim().replace(/^(?:node|v)\s*/, ""), expected);
        out.push({ ...r, found: `node-version-file: ${file} -> ${r.found}` });
        return;
      }
      if (/\$\{\{/.test(version) || /^\[/.test(version)) {
        const nums = [...version.matchAll(/\d+(?:\.[\dxX*]+)*/g)].map((m) => m[0]);
        const bad = /\$\{\{/.test(version) || nums.length === 0 || nums.some((n) => parseMajor(n) !== expected);
        out.push(bad ? result(source, version, false, `node-version must be a literal ${expected} (matrix or expression found)`) : result(source, version, true));
        return;
      }
      out.push(checkVersionText(source, version, expected));
    });
  }
  return out;
}

/** Strip // and /* *\/ comments (string-aware) so JSONC devcontainer files parse. */
export function stripJsonc(text) {
  let out = "", i = 0, str = false;
  while (i < text.length) {
    const c = text[i], d = text[i + 1];
    if (str) { out += c; if (c === "\\") { out += d ?? ""; i += 2; continue; } if (c === '"') str = false; i++; continue; }
    if (c === '"') { str = true; out += c; i++; continue; }
    if (c === "/" && d === "/") { while (i < text.length && text[i] !== "\n") i++; continue; }
    if (c === "/" && d === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i += 2; continue; }
    out += c; i++;
  }
  return out;
}
function imageNodeTag(image) {
  const m = /(?:^|\/)(?:javascript-node|typescript-node|node):([^\s@]+)/.exec(image);
  return m ? m[1] : null;
}
function fromDevcontainer(root, expected) {
  const rel = ".devcontainer/devcontainer.json";
  if (!existsSync(join(root, rel))) return [];
  let dc;
  try { dc = JSON.parse(stripJsonc(read(root, rel))); } catch (e) { return [result(rel, "(unparseable)", false, `not valid JSON(C): ${e.message}`)]; }
  const out = [];
  for (const [key, cfg] of Object.entries(dc?.features ?? {}).sort(([a], [b]) => a.localeCompare(b))) {
    if (!/\/features\/node(?::|$)/.test(key)) continue;
    const v = cfg?.version;
    out.push(typeof v === "string" ? checkVersionText(`${rel} feature ${key}`, v, expected) : missing(`${rel} feature ${key}`, "no version set (the feature default is the LTS, not a pinned major)"));
  }
  if (typeof dc?.image === "string") {
    const tag = imageNodeTag(dc.image);
    if (tag !== null) out.push({ ...checkVersionText(`${rel} image`, tag.replace(/^(\d+)(?:[.-].*)?$/, "$1"), expected), found: dc.image });
  }
  for (const [k, v] of Object.entries(dc?.build?.args ?? {}).sort(([a], [b]) => a.localeCompare(b))) {
    if (/^NODE_(VERSION|MAJOR)$/.test(k)) out.push(checkVersionText(`${rel} build.args.${k}`, String(v), expected));
  }
  return out;
}

function dockerfiles(root) {
  const out = [];
  for (const d of ["", ".devcontainer", "docker"]) {
    const dir = join(root, d);
    if (!existsSync(dir) || !statSync(dir).isDirectory()) continue;
    for (const f of readdirSync(dir).sort()) if (/^Dockerfile(\..+)?$|\.Dockerfile$/.test(f) && statSync(join(dir, f)).isFile()) out.push(d ? `${d}/${f}` : f);
  }
  return out;
}
function fromDockerfiles(root, expected) {
  const out = [];
  for (const rel of dockerfiles(root)) {
    const lines = read(root, rel).split("\n");
    const args = {};
    lines.forEach((line) => { const m = /^\s*ARG\s+([A-Z0-9_]+)=["']?([^\s"']*)/.exec(line); if (m && !(m[1] in args)) args[m[1]] = m[2]; });
    lines.forEach((line, i) => {
      const source = `${rel}:${i + 1}`;
      const from = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i.exec(line);
      if (from) {
        const image = from[1];
        const m = /(?:^|\/)node(?::([^\s@]+)|@\S+)?$/.exec(image);
        if (m) {
          if (m[1] === undefined) { out.push(result(source, image, false, "node image is not pinned to a major tag")); return; }
          let tag = m[1];
          const ref = /^\$\{?([A-Z0-9_]+)\}?(.*)$/.exec(tag);
          if (ref) { if (!(ref[1] in args)) { out.push(result(source, image, false, `build arg ${ref[1]} has no default`)); return; } tag = args[ref[1]] + ref[2]; }
          const r = checkVersionText(source, tag.replace(/^(\d+)(?:[.-].*)?$/, "$1"), expected);
          out.push({ ...r, found: image });
        }
        return;
      }
      const arg = /^\s*ARG\s+(NODE_(?:VERSION|MAJOR))=["']?([^\s"']*)/.exec(line);
      if (arg) out.push(checkVersionText(`${source} ARG ${arg[1]}`, arg[2], expected));
    });
  }
  return out;
}

/** Pure verifier. `localVersion` is injectable so fixtures are deterministic. */
export function verifyRuntime({ root = process.cwd(), localVersion = process.versions.node, expected = EXPECTED_MAJOR } = {}) {
  const sources = [
    fromLocal(localVersion, expected),
    fromNvmrc(root, expected),
    fromEngines(root, expected),
    ...fromWorkflows(root, expected),
    ...fromDevcontainer(root, expected),
    ...fromDockerfiles(root, expected),
  ];
  if (!sources.some((s) => s.source.includes("setup-node"))) sources.push(missing(".github/workflows", "no actions/setup-node step found"));
  const drift = sources.filter((s) => !s.ok);
  return { status: drift.length ? "RUNTIME_DRIFT" : "RUNTIME_OK", expected, sources, drift };
}

export function render(r) {
  const head = r.status === "RUNTIME_OK" ? `RUNTIME_OK expected node major ${r.expected} (${r.sources.length} sources agree)` : `RUNTIME_DRIFT expected node major ${r.expected} (${r.drift.length} of ${r.sources.length} sources mismatch)`;
  const lines = r.sources.map((s) => (s.ok ? `  ok       ${s.source}: ${s.found}` : `  MISMATCH ${s.source}: found ${JSON.stringify(s.found)} - ${s.reason}`));
  return [head, ...lines].join("\n");
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const r = verifyRuntime({ root });
  console.log(process.argv.includes("--json") ? JSON.stringify(r, null, 2) : render(r));
  process.exit(r.status === "RUNTIME_OK" ? 0 : 1);
}
