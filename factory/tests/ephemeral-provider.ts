import { generateKeyPairSync, randomBytes, sign as edSign, verify as edVerify } from "node:crypto";
import type { SigningProvider } from "../signing.ts";

/**
 * TEST-ONLY signing provider. The ed25519 key pair is generated inside the calling process, lives only in
 * closure variables (a KeyObject does not serialise: JSON.stringify gives {}), and is never written anywhere.
 * Every call yields a NEW random key, so no key can be committed or shared between runs.
 * Do not import from production code.
 */
export function ephemeralEd25519(name = "test-ephemeral-ed25519"): SigningProvider & { readonly key_id: string; cannotSign(): SigningProvider } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const key_id = `ephemeral-${randomBytes(4).toString("hex")}`;
  const pub = publicKey;
  const priv = privateKey;
  const provider: SigningProvider = {
    name,
    async sign(payload) {
      return { key_id, alg: "ed25519", value: edSign(null, Buffer.from(payload), priv).toString("base64") };
    },
    async verify(payload, sig) {
      if (sig.key_id !== key_id || sig.alg !== "ed25519") return false;
      try {
        return edVerify(null, Buffer.from(payload), pub, Buffer.from(sig.value, "base64"));
      } catch {
        return false;
      }
    },
  };
  return { ...provider, key_id, cannotSign: () => ({ name, sign: async () => null, verify: provider.verify }) };
}
