// SECURITY/TRUST domain (slots 52-100): auth-invariant, sign-out plan, sign-in gate, gate identity verification.
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT } from "jose";

const CAI = "scripts/check-auth-invariant.mjs";
const SOP = "scripts/sign-out-plan.mjs";
const SIG = "src/lib/auth/sign-in-gate.ts";
const GID = "src/lib/auth/gate-identity.server.ts";

/** Run fn with the given env vars set (undefined = unset), restoring afterwards. */
async function withEnv(/** @type {any} */ vars, /** @type {any} */ fn) {
  const saved = /** @type {Record<string, string | undefined>} */ ({});
  for (const k of Object.keys(vars)) { saved[k] = process.env[k]; if (vars[k] === undefined) delete process.env[k]; else process.env[k] = vars[k]; }
  try { return await fn(); } finally { for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } }
}

const KEYS = generateKeyPairSync("ed25519");
const ISS = "https://gate.grok.me";
const AUD = "app:proj-77";
const now = () => Math.floor(Date.now() / 1000);
/** @param {{ aud?: string, iss?: string, sub?: string, exp?: number | "set" | "none", iat?: number, claims?: Record<string, unknown> }} [o] */
async function token({ aud = AUD, iss = ISS, sub = "user-1", exp = "set", iat = now(), claims = {} } = {}) {
  let j = new SignJWT({ ...claims }).setProtectedHeader({ alg: "EdDSA", kid: "k1" }).setSubject(sub).setIssuer(iss).setAudience(aud).setIssuedAt(iat);
  if (exp === "set") j = j.setExpirationTime(now() + 300);
  else if (typeof exp === "number") j = j.setExpirationTime(exp);
  return j.sign(KEYS.privateKey);
}
const getKey = async () => KEYS.publicKey;
const verify = (/** @type {any} */ m, /** @type {any} */ t, o = {}) => m.verifyGateIdentityToken(t, { issuer: ISS, audience: AUD, getKey, ...o });

/** Records which sign-out steps ran, in order. */
/** @param {{ requestSignOut?: () => unknown }} [over] */
function steps(over = {}) {
  /** @type {string[]} */ const calls = [];
  const behaviour = over.requestSignOut ?? (() => {});
  return { calls, s: { livePreview: true, hasBearer: true, clearToken: () => calls.push("clear"), redirect: () => calls.push("redirect"), timeoutMs: 20, ...over, requestSignOut: () => { calls.push("request"); return behaviour(); } } };
}
async function signOutOutcome(/** @type {any} */ m, /** @type {any} */ over, fnName = "runSignOut") {
  const { calls, s } = steps(over);
  let error = null;
  try { await m[fnName](s); } catch (e) { error = /** @type {any} */ (e).message; }
  return { calls, error };
}
const hang = () => new Promise(() => {});

/** @type {import("../types.d.ts").Spec[]} */
export const SPECS = [
  // ---- check-auth-invariant (52-62)
  { slot: 52, target: CAI, expected: { exactFalseIsOff: false, trueIsOn: true, booleanFalseIsNotTheOffString: true, paddedIsOn: true },
    run: (m) => ({ exactFalseIsOff: m.authEnabledFromEnvValue("false"), trueIsOn: m.authEnabledFromEnvValue("true"), booleanFalseIsNotTheOffString: m.authEnabledFromEnvValue(false), paddedIsOn: m.authEnabledFromEnvValue(" false") }),
    claim: "only the exact string 'false' turns sign-in off: 'true', a boolean false and a space-padded ' false' all leave it on" },
  { slot: 53, target: CAI, expected: { unset: true, empty: true, zero: true, upper: true, no: true },
    run: (m) => ({ unset: m.authEnabledFromEnvValue(undefined), empty: m.authEnabledFromEnvValue(""), zero: m.authEnabledFromEnvValue("0"), upper: m.authEnabledFromEnvValue("FALSE"), no: m.authEnabledFromEnvValue("no") }),
    claim: "every value other than exactly 'false' (unset, empty, 0, FALSE, no) leaves sign-in ON - the fail-safe direction" },
  { slot: 54, target: CAI, fn: "compareAuthInvariant", input: [{ devAuthEnabled: true, buildAuthEnabled: true }], expected: { status: "ok", message: "[auth-invariant] dev and build agree: sign-in on" },
    claim: "agreeing flags report ok with the 'sign-in on' message" },
  { slot: 55, target: CAI, expected: { status: "diverged", head: "[auth-invariant] dev server has sign-in on but the next build has it off." },
    run: (m) => { const r = m.compareAuthInvariant({ devAuthEnabled: true, buildAuthEnabled: false }); return { status: r.status, head: r.message.split(" Start the app")[0] }; },
    claim: "dev on / build off is a divergence that names both sides" },
  { slot: 56, target: CAI, expected: { status: "diverged", head: "[auth-invariant] dev server has sign-in off but the next build has it on.", remedy: true },
    run: (m) => { const r = m.compareAuthInvariant({ devAuthEnabled: false, buildAuthEnabled: true }); return { status: r.status, head: r.message.split(" Start the app")[0], remedy: r.message.includes("npm run dev") }; },
    claim: "dev off / build on is also a divergence (opposite direction) and the message tells the user to start via npm run dev" },
  { slot: 57, target: CAI, fn: "compareAuthInvariant", input: [{ devAuthEnabled: null, buildAuthEnabled: true }], expected: { status: "indeterminate", message: "[auth-invariant] could not read the dev server's resolved VITE_AUTH_ENABLED" },
    claim: "an unobservable dev server is 'indeterminate', never agreement" },
  { slot: 58, target: CAI, fn: "probeDevAuthEnabled", input: ["http://127.0.0.1:1", async () => { throw new Error("ECONNREFUSED"); }], expected: null,
    claim: "an unreachable dev server probes as null rather than throwing" },
  { slot: 59, target: CAI, expected: { notOk: null, requested: "http://127.0.0.1:8080/__app-env" },
    run: async (m) => { let url = ""; const notOk = await m.probeDevAuthEnabled("http://127.0.0.1:8080", async (/** @type {any} */ u) => { url = u; return { ok: false, text: async () => "{}" }; }); return { notOk, requested: url }; },
    claim: "a server without the endpoint (non-2xx) probes as null, and the probe asked exactly <dev>/__app-env" },
  { slot: 60, target: CAI, fn: "probeDevAuthEnabled", input: ["http://127.0.0.1:8080", async () => ({ ok: true, text: async () => '{"VITE_AUTH_ENABLED":"false"}' })], expected: false,
    claim: "a dev server reporting VITE_AUTH_ENABLED=false probes as sign-in off" },
  { slot: 61, target: CAI, expected: { diverged: ["M"], ok: [], indeterminate: [] },
    run: (m) => ({ diverged: m.authInvariantWarnings({ status: "diverged", message: "M" }), ok: m.authInvariantWarnings({ status: "ok", message: "M" }), indeterminate: m.authInvariantWarnings({ status: "indeterminate", message: "M" }) }),
    claim: "only a real divergence yields a smoke-verdict warning; ok and indeterminate yield none" },
  { slot: 62, target: CAI, expected: { fromFile: true, overridden: false },
    run: (m) => { const r = mkdtempSync(join(tmpdir(), "m62-")); mkdirSync(join(r, ".grok")); writeFileSync(join(r, ".grok/app-env.json"), '{"VITE_AUTH_ENABLED":"true"}'); return { fromFile: m.buildAuthEnabled(r, {}), overridden: m.buildAuthEnabled(r, { VITE_AUTH_ENABLED: "false" }) }; },
    claim: "the build-side flag is the app-env file value, and a process-env value overrides it" },

  // ---- sign-out plan (63-80)
  { slot: 63, target: SOP, fn: "signOutTimeoutMs", input: [true], expected: 1500, claim: "the live preview waits at most 1500 ms for sign-out" },
  { slot: 64, target: SOP, fn: "signOutTimeoutMs", input: [false], expected: 10000, claim: "a deployed app waits up to 10000 ms for sign-out" },
  { slot: 65, target: SOP, fn: "settleWithin", input: [() => Promise.resolve(), 200], expected: "ok", claim: "a resolving start settles 'ok'" },
  { slot: 66, target: SOP, fn: "settleWithin", input: [() => Promise.reject(new Error("net")), 200], expected: "failed", claim: "a rejecting start settles 'failed'" },
  { slot: 67, target: SOP, fn: "settleWithin", input: [() => { throw new Error("sync"); }, 200], expected: "failed", claim: "a synchronously throwing start also settles 'failed' (never escapes)" },
  { slot: 68, target: SOP, fn: "settleWithin", input: [hang, 20], expected: "timeout", claim: "a never-settling start settles 'timeout' after the bound" },
  { slot: 69, target: SOP, expected: { calls: ["request", "clear", "redirect"], error: null },
    run: (m) => signOutOutcome(m, {}), claim: "preview + bearer + confirmed sign-out: request, then clear, then redirect" },
  { slot: 70, target: SOP, expected: { calls: ["request", "clear", "redirect"], error: null },
    run: async (m) => { const o = await signOutOutcome(m, { requestSignOut: () => Promise.reject(new Error("401")) }); return { ...o }; },
    claim: "preview: a rejected server sign-out still clears the token and redirects without throwing" },
  { slot: 71, target: SOP, expected: { calls: ["clear", "redirect"], error: null },
    run: (m) => signOutOutcome(m, { hasBearer: false }), claim: "preview without a bearer never contacts the server but still clears and redirects" },
  { slot: 72, target: SOP, expected: { calls: ["request", "clear", "redirect"], error: null },
    run: async (m) => ({ ...(await signOutOutcome(m, { requestSignOut: hang })) }),
    claim: "preview: a server that never answers cannot block - the bound elapses, then clear and redirect run" },
  { slot: 73, target: SOP, expected: { calls: ["request", "clear", "redirect"], error: null },
    run: async (m) => ({ ...(await signOutOutcome(m, { livePreview: false })) }), claim: "deployed: a confirmed sign-out clears and redirects" },
  { slot: 74, target: SOP, expected: { calls: ["request"], error: "Sign-out failed — you are still signed in. Please try again." },
    run: (m) => signOutOutcome(m, { livePreview: false, requestSignOut: () => Promise.reject(new Error("500")) }),
    claim: "deployed: a failed sign-out throws and does NOT clear the token or redirect" },
  { slot: 75, target: SOP, expected: { calls: ["request"], error: "Sign-out timed out — you are still signed in. Please try again." },
    run: (m) => signOutOutcome(m, { livePreview: false, requestSignOut: hang }),
    claim: "deployed: a timed-out sign-out throws the timeout message and leaves the token in place" },
  { slot: 76, target: SOP, expected: { calls: ["clear"], error: null },
    run: (m) => signOutOutcome(m, { hasBearer: false }, "runPreSignInSignOut"), claim: "pre-sign-in in the preview without a bearer only clears the token" },
  { slot: 77, target: SOP, expected: { calls: ["request", "clear"], error: null },
    run: (m) => signOutOutcome(m, {}, "runPreSignInSignOut"), claim: "pre-sign-in in the preview with a bearer asks the server, then clears" },
  { slot: 78, target: SOP, expected: { calls: ["request", "clear"], error: null },
    run: async (m) => ({ ...(await signOutOutcome(m, { livePreview: false, hasBearer: false }, "runPreSignInSignOut")) }),
    claim: "pre-sign-in when deployed always asks the server even without a bearer" },
  { slot: 79, target: SOP, expected: { calls: ["request", "clear"], error: null },
    run: async (m) => ({ ...(await signOutOutcome(m, { requestSignOut: () => { throw new Error("boom"); } }, "runPreSignInSignOut")) }),
    claim: "pre-sign-in is best effort: a server error never throws and the token is still cleared" },
  { slot: 80, target: SOP, expected: { calls: ["request", "clear"], error: null },
    run: async (m) => ({ ...(await signOutOutcome(m, { requestSignOut: () => { return hang(); } }, "runPreSignInSignOut")) }),
    claim: "pre-sign-in never waits past the bound on a hung server and still clears" },

  // ---- sign-in gate (81-83)
  { slot: 81, target: SIG, fn: "resolveSignInGateState", input: [{ isPending: true, hasUser: true }], expected: "pending", claim: "an in-flight session check is 'pending' even if a user is already cached" },
  { slot: 82, target: SIG, fn: "resolveSignInGateState", input: [{ isPending: false, hasUser: true }], expected: "signed_in", claim: "a resolved check with a user is 'signed_in'" },
  { slot: 83, target: SIG, fn: "resolveSignInGateState", input: [{ isPending: false, hasUser: false }], expected: "signed_out", claim: "a resolved check with no user is 'signed_out'" },

  // ---- gate identity (84-100)
  { slot: 84, target: GID, expected: true, run: (m) => withEnv({ VITE_AUTH_ENABLED: undefined }, () => m.gateIdentityEnabled()), claim: "gate identity is on when VITE_AUTH_ENABLED is unset" },
  { slot: 85, target: GID, expected: false, run: (m) => withEnv({ VITE_AUTH_ENABLED: "false" }, () => m.gateIdentityEnabled()), claim: "gate identity is off when VITE_AUTH_ENABLED=false" },
  { slot: 86, target: GID, expected: "app:proj-9", run: (m) => withEnv({ GROK_PROJECT_ID: "proj-9" }, () => m.gateTokenAudience()), claim: "with a project id the audience is pinned to app:<id>" },
  { slot: 87, target: GID, expected: "preview", run: (m) => withEnv({ GROK_PROJECT_ID: undefined }, () => m.gateTokenAudience()), claim: "without a project id the audience is 'preview'" },
  { slot: 88, target: GID, expected: { issuer: "https://g.example", jwksUrl: "https://g.example/__gate/identity-key" },
    run: (m) => withEnv({ GROK_GATE_ORIGIN: "https://g.example///", GROK_PROJECT_ID: undefined }, () => m.resolveGateEndpoints(new Headers())),
    claim: "an explicit GROK_GATE_ORIGIN wins, with trailing slashes trimmed, and derives the JWKS URL from it" },
  { slot: 89, target: GID, expected: { issuer: "http://127.0.0.1:6014", jwksUrl: "http://127.0.0.1:6014/__gate/identity-key" },
    run: (m) => withEnv({ GROK_GATE_ORIGIN: undefined, GROK_PROJECT_ID: undefined }, () => m.resolveGateEndpoints(new Headers())),
    claim: "with no gate env at all the endpoints default to the loopback preview gate" },
  { slot: 90, target: GID, expected: { issuer: "https://gate.grok.me", jwksUrl: "https://gate.grok.me/__gate/identity-key" },
    run: (m) => withEnv({ GROK_GATE_ORIGIN: undefined, GROK_PROJECT_ID: "p" }, () => m.resolveGateEndpoints(new Headers({ host: "my-app.grok.me:443" }))),
    claim: "a deployed *.grok.me host (port stripped) maps to the grok.me gate" },
  { slot: 91, target: GID, expected: null,
    run: (m) => withEnv({ GROK_GATE_ORIGIN: undefined, GROK_PROJECT_ID: "p" }, () => m.resolveGateEndpoints(new Headers({ host: "grok.me.evil.example" }))),
    claim: "a look-alike host that merely contains grok.me gets no gate (fail closed)" },
  { slot: 92, target: GID, expected: "https://gate.app-builder-testing.com",
    run: (m) => withEnv({ GROK_GATE_ORIGIN: undefined, GROK_PROJECT_ID: "p" }, () => m.resolveGateEndpoints(new Headers({ "x-forwarded-host": "a.app-builder-testing.com, other.example", host: "internal" }))?.issuer),
    claim: "the first x-forwarded-host entry wins over Host and an app-builder-testing host maps to its own gate" },
  { slot: 93, target: GID, fn: "sessionBoundToGateIdentity", input: [[{ providerId: "grok-gate", accountId: "u1" }], "u1", "grok-gate"], expected: true,
    claim: "a session whose gate-provider account equals the identity sub is bound" },
  { slot: 94, target: GID, expected: { otherSub: false, otherProvider: false, noAccounts: false },
    run: (m) => ({ otherSub: m.sessionBoundToGateIdentity([{ providerId: "grok-gate", accountId: "u1" }], "u2", "grok-gate"), otherProvider: m.sessionBoundToGateIdentity([{ providerId: "github", accountId: "u1" }], "u1", "grok-gate"), noAccounts: m.sessionBoundToGateIdentity([], "u1", "grok-gate") }),
    claim: "a different sub, a same-sub account on another provider, or no accounts are all NOT bound (session must rotate)" },
  { slot: 95, target: GID, fn: "gateIdentityUserInfo", input: [{ sub: "s1", email: null, name: null, teamId: null }], expected: { id: "s1", email: "s1@viewer.grok.invalid", emailVerified: false, name: "Grok user" },
    claim: "a sub-only identity gets a synthetic, unverified email and the 'Grok user' name" },
  { slot: 96, target: GID, fn: "gateIdentityUserInfo", input: [{ sub: "s2", email: "Ann@Example.COM", name: "Ann", teamId: "t" }], expected: { id: "s2", email: "ann@example.com", emailVerified: true, name: "Ann" },
    claim: "real claims are kept, the email is lower-cased and marked verified" },
  { slot: 97, target: GID, expected: { sub: "user-1", email: "a@b.c", name: "A", teamId: "t1" },
    run: async (m) => verify(m, await token({ claims: { email: "a@b.c", name: "A", team_id: "t1" } })), claim: "a correctly signed, in-window, right-issuer/audience token yields the full identity" },
  { slot: 98, target: GID, expected: { wrongAudience: null, sameTokenRightAudience: "user-1" },
    run: async (m) => { const t = await token(); return { wrongAudience: await verify(m, t, { audience: "app:other" }), sameTokenRightAudience: (await verify(m, t))?.sub }; },
    claim: "the very same token is rejected for a different audience and accepted for the right one - audience is what flips it" },
  { slot: 99, target: GID, expected: { noExp: null, withExp: "user-1" },
    run: async (m) => ({ noExp: await verify(m, await token({ exp: "none" })), withExp: (await verify(m, await token()))?.sub }), claim: "a token with no exp claim is rejected; the same token shape with exp is accepted" },
  { slot: 100, target: GID, expected: { expired: null, tooOld: null, fresh: "user-1" },
    run: async (m) => ({ expired: await verify(m, await token({ iat: now() - 7200, exp: now() - 3600 })), tooOld: await verify(m, await token({ iat: now() - 1200, exp: now() + 600 })), fresh: (await verify(m, await token()))?.sub }),
    claim: "an expired token and a token older than the 10-minute max age are rejected while a fresh one passes" },
];
