// Slot-specification library for the 250 matrix.
//
// A SPEC is one slot's OWN assertion: a real exported function (or a small probe closure) of REAL repo code,
// called with a concrete input, whose result must deep-equal a written `expected` value. The harness - never the
// spec - performs the call and the comparison, so a spec cannot "pass" without calling real code.
//
//   { slot, target, fn, input, expected, claim }      // call target[fn](...input)
//   { slot, target, run: (mod) => actual, expected, claim }   // probe closure; must use `mod` (the real module)
//
// Definitions (also in docs/factory/MATRIX.md):
//   SPECIFIED       = the slot has a spec that passes every static rule in validateSpecs, whose assertion fingerprint is
//                     unique across all slots, and (once run) whose behaviour fingerprint is unique too.
//   DOMAIN_VERIFIED = SPECIFIED, and in this run the harness imported `target`, observed >= 1 call into it, and
//                     the actual result deep-equalled `expected`; the evidence is the digest of the actual result.
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { isAbsolute, normalize, join } from "node:path";
import ts from "typescript";

/**
 * Source normaliser for fingerprints: the TypeScript scanner drops every comment and all whitespace and the token
 * stream is re-joined with single spaces, so reformatting or adding a comment cannot make a duplicate look unique.
 * Regex literals and template literals are re-scanned so their contents are kept verbatim.
 */
export function normalizeSource(/** @type {any} */ src) {
  const sc = ts.createScanner(ts.ScriptTarget.ESNext, true, ts.LanguageVariant.Standard, String(src));
  const out = [];
  const braces = []; // true for a `${` that opened a template substitution
  let prev = ts.SyntaxKind.Unknown;
  const valueEnd = new Set([ts.SyntaxKind.Identifier, ts.SyntaxKind.NumericLiteral, ts.SyntaxKind.StringLiteral, ts.SyntaxKind.CloseParenToken, ts.SyntaxKind.CloseBracketToken, ts.SyntaxKind.CloseBraceToken, ts.SyntaxKind.RegularExpressionLiteral, ts.SyntaxKind.NoSubstitutionTemplateLiteral, ts.SyntaxKind.TemplateTail, ts.SyntaxKind.ThisKeyword, ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword, ts.SyntaxKind.NullKeyword]);
  for (let t = sc.scan(); t !== ts.SyntaxKind.EndOfFileToken; t = sc.scan()) {
    if ((t === ts.SyntaxKind.SlashToken || t === ts.SyntaxKind.SlashEqualsToken) && !valueEnd.has(prev)) t = sc.reScanSlashToken();
    else if (t === ts.SyntaxKind.CloseBraceToken && braces.length > 0 && braces[braces.length - 1]) {
      braces.pop();
      t = sc.reScanTemplateToken(false);
      if (t === ts.SyntaxKind.TemplateMiddle) braces.push(true);
    } else if (t === ts.SyntaxKind.TemplateHead) braces.push(true);
    else if (t === ts.SyntaxKind.OpenBraceToken) braces.push(false);
    else if (t === ts.SyntaxKind.CloseBraceToken) braces.pop();
    out.push(sc.getTokenText());
    prev = t;
  }
  return out.join(" ");
}

/** Deterministic, lossless-enough canonical form (sorted keys; tags for values JSON would collapse). */
/** @param {any} v @returns {any} */
export function canon(v) {
  if (typeof v === "function") return { $: "function", src: normalizeSource(v.toString()) };
  if (v === undefined) return { $: "undefined" };
  if (typeof v === "number" && !Number.isFinite(v)) return { $: "number", v: String(v) };
  if (typeof v === "bigint") return { $: "bigint", v: String(v) };
  if (v === null || typeof v !== "object") return v;
  if (v instanceof Error) return { $: "error", name: v.name, message: v.message };
  if (v instanceof Set) return { $: "set", v: [...v].map(canon).sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1)) };
  if (v instanceof Map) return { $: "map", v: [...v].map(([k, x]) => [canon(k), canon(x)]) };
  if (Array.isArray(v)) return v.map(canon);
  /** @type {Record<string, any>} */
  const out = {};
  for (const k of Object.keys(v).sort()) out[k] = canon(v[k]);
  return out;
}
export const canonJson = (/** @type {any} */ v) => JSON.stringify(canon(v));
export const sha256 = (/** @type {any} */ s) => createHash("sha256").update(s).digest("hex");
const normSrc = (/** @type {any} */ f) => (typeof f === "function" ? normalizeSource(f.toString()) : null);

/** Assertion fingerprint: everything that defines WHAT is asserted. Slot number and claim text are excluded on purpose. */
export function assertionFingerprint(/** @type {any} */ s) {
  return sha256(canonJson({ target: s.target, fn: s.fn ?? null, input: s.input ?? null, expected: s.expected, run: normSrc(s.run) }));
}
/**
 * Behaviour fingerprint (dynamic, computed by the harness after the run): the target, the exact set of code
 * ranges of repo code that executed (V8 precise block coverage) and the expected value. Two slots that drive the
 * same code path to the same expected value are the same behaviour, whatever their inputs look like.
 * Specs with no instrumented path (data targets, CLI executions) fall back to the assertion fingerprint.
 */
export function behaviourFingerprint(/** @type {any} */ s, /** @type {any} */ path) {
  const instrumented = typeof path === "string" && !path.endsWith("/0") && path !== "-";
  return sha256(canonJson({ target: s.target, path: instrumented ? path : assertionFingerprint(s), expected: s.expected }));
}

const NON_DOMAIN = [/^factory\/matrix\//, /^scripts\/matrix250\//, /\.test\.[cm]?[jt]sx?$/, /^node_modules\//];
const DATA_EXT = /(\.(json|ya?ml|md)|(^|\/)\.nvmrc)$/;

export function isDataTarget(/** @type {any} */ target) {
  return DATA_EXT.test(target);
}

/**
 * Static rules. Returns { valid: Map<slot, spec+fingerprints>, violations: string[] }.
 * A spec that breaks any rule, or shares a fingerprint with another spec, is NOT valid and is never counted SPECIFIED.
 */
export function validateSpecs(/** @type {any} */ specs, root = process.cwd(), { guard = false } = {}) {
  const lo = guard ? 1001 : 1;
  const hi = guard ? 1999 : 250;
  const violations = [];
  const bySlot = new Map();
  const byFp = new Map();
  const staged = [];
  for (const [i, s] of specs.entries()) {
    const where = `spec#${i}${s && s.slot ? ` slot ${s.slot}` : ""}`;
    const bad = (/** @type {any} */ m) => violations.push(`${where}: ${m}`);
    if (!s || typeof s !== "object") { bad("not an object"); continue; }
    if (!Number.isInteger(s.slot) || s.slot < lo || s.slot > hi) { bad(`slot must be an integer ${lo}..${hi}`); continue; }
    if (bySlot.has(s.slot)) { bad(`duplicate spec for slot ${s.slot}`); bySlot.get(s.slot).dup = true; continue; }
    const rec = { ...s, dup: false };
    bySlot.set(s.slot, rec);
    let ok = true;
    if (typeof s.target !== "string" || s.target === "" || isAbsolute(s.target) || normalize(s.target).startsWith("..")) { bad("target must be a repo-relative path"); ok = false; }
    else {
      if (NON_DOMAIN.some((re) => re.test(normalize(s.target)))) { bad(`target ${s.target} is not domain code (harness, test or dependency)`); ok = false; }
      if (!existsSync(join(root, s.target))) { bad(`target ${s.target} does not exist`); ok = false; }
    }
    const hasFn = typeof s.fn === "string" && s.fn !== "";
    const hasRun = typeof s.run === "function";
    if (hasFn === hasRun) { bad("exactly one of fn (string) or run (function) is required"); ok = false; }
    if (hasFn && !Array.isArray(s.input)) { bad("fn spec needs an input array"); ok = false; }
    if (hasFn && s.target && isDataTarget(s.target)) { bad("data targets need a run probe"); ok = false; }
    if (!("expected" in s) || s.expected === undefined) { bad("expected value is required"); ok = false; }
    if (typeof s.claim !== "string" || s.claim.trim().length < 20) { bad("claim must be a text of at least 20 characters"); ok = false; }
    if ("config" in s && typeof s.config !== "boolean") { bad("config must be a boolean when present"); ok = false; }
    if (ok) staged.push(rec);
  }
  for (const rec of staged) {
    rec.fingerprint = assertionFingerprint(rec);
    if (!byFp.has(rec.fingerprint)) byFp.set(rec.fingerprint, []);
    byFp.get(rec.fingerprint).push(rec.slot);
  }
  const shared = new Set();
  for (const [fp, slots] of byFp) if (slots.length > 1) { violations.push(`slots ${slots.join(",")} share assertion fingerprint ${fp.slice(0, 12)}`); slots.forEach((/** @type {any} */ x) => shared.add(x)); }
  const valid = new Map();
  for (const rec of staged) if (!shared.has(rec.slot)) valid.set(rec.slot, rec);
  return { valid, violations };
}

/** An entry is CONFIG_PINNED when its spec says so or its target is a data/config file: no domain code is under test. */
export const isConfigEntry = (/** @type {any} */ e) => e.config === true || isDataTarget(String(e.target));

/** Largest number of slots allowed to execute one and the same code path (see sharedPathGroups). */
export const MAX_SHARED_PATH_GROUP = 8;

/**
 * Merge per-file entries (as emitted by factory/matrix/runner.mjs) into the final picture.
 * entry = { slot, file, target, claim, config, fingerprint, behaviour, valid, result: {ok, calls, digest, path, feeds, error} | null }
 * Returns { specified, domainVerified, configPinned, sharedPathGroups, sharedPathSlots, violations }.
 *  - a slot with two specs is ambiguous: neither counts;
 *  - two slots sharing an assertion fingerprint, or a behaviour fingerprint, are not unique: neither counts;
 *  - DOMAIN_VERIFIED additionally needs an ok result, >= 1 observed call into the target, a result that feeds the
 *    assertion (not constant after a call) and a spec that is not config-only;
 *  - CONFIG_PINNED = specified + ok result + config-only (the assertion pins configuration, not code behaviour);
 *  - sharedPathGroups: specified slots whose observed executed-code path is identical to another slot's. They are
 *    reported, not hidden, and a group larger than MAX_SHARED_PATH_GROUP is a violation.
 */
export function combineEntries(/** @type {any} */ entries) {
  const violations = [];
  const out = new Set();
  const bySlot = new Map();
  for (const e of entries) {
    if (!bySlot.has(e.slot)) bySlot.set(e.slot, []);
    bySlot.get(e.slot).push(e);
  }
  for (const [slot, es] of bySlot) if (es.length > 1) { violations.push(`slot ${slot} has ${es.length} specs (${es.map((/** @type {any} */ x) => x.file).join(", ")})`); out.add(slot); }
  const live = entries.filter((/** @type {any} */ e) => e.valid && !out.has(e.slot));
  for (const key of ["fingerprint", "behaviour"]) {
    const g = new Map();
    for (const e of live) { if (!e[key]) continue; if (!g.has(e[key])) g.set(e[key], []); g.get(e[key]).push(e.slot); }
    for (const [fp, slots] of g) {
      if (slots.length < 2) continue;
      violations.push(`slots ${slots.join(",")} share ${key === "fingerprint" ? "assertion" : "behaviour"} fingerprint ${fp.slice(0, 12)}`);
      for (const x of slots) out.add(x);
    }
  }
  const specified = new Map();
  const domainVerified = new Set();
  const configPinned = new Set();
  for (const e of entries) {
    if (!e.valid || out.has(e.slot)) continue;
    specified.set(e.slot, e);
    const ran = !!(e.result && e.result.ok === true && e.result.calls >= 1);
    if (!ran) continue;
    if (isConfigEntry(e)) configPinned.add(e.slot);
    else if (e.result.feeds !== false) domainVerified.add(e.slot);
  }
  // shared executed-code paths (only observed paths count; "-" / "/0" means nothing was instrumented)
  const byPath = new Map();
  for (const e of specified.values()) {
    const p = e.result?.path;
    if (typeof p !== "string" || p === "-" || p.endsWith("/0")) continue;
    if (!byPath.has(p)) byPath.set(p, []);
    byPath.get(p).push(e.slot);
  }
  const sharedPathGroups = [...byPath.values()].filter((g) => g.length > 1).map((g) => g.sort((/** @type {any} */ a, /** @type {any} */ b) => a - b)).sort((a, b) => a[0] - b[0]);
  for (const g of sharedPathGroups) if (g.length > MAX_SHARED_PATH_GROUP) violations.push(`${g.length} slots (${g.join(",")}) execute one identical code path (limit ${MAX_SHARED_PATH_GROUP})`);
  return { specified, domainVerified, configPinned, sharedPathGroups, sharedPathSlots: new Set(sharedPathGroups.flat()), violations };
}
