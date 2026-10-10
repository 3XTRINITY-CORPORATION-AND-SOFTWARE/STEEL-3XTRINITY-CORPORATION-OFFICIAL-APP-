// REGRESSION GUARDS for security-relevant branches of src/lib/auth/gate-identity.server.ts that no matrix slot asserts.
// A guard is NOT a slot: it never counts towards SPECIFIED_SLOTS / DOMAIN_VERIFIED. It exists so that a defect in one of
// these branches turns the matrix run red. Each guard was written against a concrete mutant (see docs/factory/MATRIX.md).
import { generateKeyPairSync } from "node:crypto";
import { SignJWT } from "jose";

const GID = "src/lib/auth/gate-identity.server.ts";
const KEYS = generateKeyPairSync("ed25519");
const ISS = "https://gate.grok.me";
const AUD = "app:proj-77";
const now = () => Math.floor(Date.now() / 1000);
async function token({ alg = "EdDSA", iss = ISS, sub = "user-1" } = {}) {
  return new SignJWT({}).setProtectedHeader({ alg, kid: "k1" }).setSubject(sub).setIssuer(iss).setAudience(AUD).setIssuedAt(now()).setExpirationTime(now() + 300).sign(KEYS.privateKey);
}
const getKey = async () => KEYS.publicKey;
const verify = async (/** @type {any} */ m, /** @type {any} */ t) => (await m.verifyGateIdentityToken(t, { issuer: ISS, audience: AUD, getKey }))?.sub ?? null;
const jwk = (/** @type {any} */ pair, /** @type {any} */ kid) => ({ ...pair.publicKey.export({ format: "jwk" }), kid });
const keyError = async (/** @type {any} */ m, /** @type {any} */ url, /** @type {any} */ keys) => { try { await m.gateKeyResolver(url, async () => ({ keys }))({ alg: "EdDSA", kid: "k1" }); return "resolved"; } catch (e) { return /** @type {any} */ (e).message; } };

/** @type {import("../types.d.ts").Spec[]} */
export const GUARDS = [
  { slot: 1001, target: GID, expected: { x25519KeyWithTheRightKid: "no gate identity key matches the token kid", ed25519Control: "public" },
    run: async (m) => ({
      x25519KeyWithTheRightKid: await keyError(m, "https://jwks.test/guard-1001-x25519", [jwk(generateKeyPairSync("x25519"), "k1")]),
      ed25519Control: (await m.gateKeyResolver("https://jwks.test/guard-1001-ed", async () => ({ keys: [jwk(KEYS, "k1")] }))({ alg: "EdDSA", kid: "k1" })).type,
    }),
    claim: "the JWKS key lookup only accepts an OKP key on curve Ed25519: an X25519 key under the right kid is refused with the no-matching-key error" },
  { slot: 1002, target: GID, expected: { fullySpecifiedAlgHeader: null, eddsaControl: "user-1" },
    run: async (m) => ({ fullySpecifiedAlgHeader: await verify(m, await token({ alg: "Ed25519" })), eddsaControl: await verify(m, await token()) }),
    claim: "verification pins the JWS algorithm to EdDSA: a token whose header says Ed25519, signed with the very same key, is rejected while the EdDSA token verifies" },
  { slot: 1003, target: GID, expected: { foreignIssuer: null, rightIssuer: "user-1" },
    run: async (m) => ({ foreignIssuer: await verify(m, await token({ iss: "https://evil.example" })), rightIssuer: await verify(m, await token()) }),
    claim: "the issuer is enforced: a correctly signed, fresh token from a different issuer is rejected" },
  { slot: 1004, target: GID, expected: { blankSub: null, paddedSub: "user-1" },
    run: async (m) => ({ blankSub: await verify(m, await token({ sub: "   " })), paddedSub: await verify(m, await token({ sub: " user-1 " })) }),
    claim: "a whitespace-only subject is rejected (no empty identity) and a padded subject is trimmed" },
];
