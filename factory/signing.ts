import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { verifyDecisionReceipt } from "../cerberus/receipts/decision-receipt.ts";
import { digestOf } from "./protocol/types.ts";
import { rastikEvidenceDigest, type RastikRun } from "./rastik-types.ts";
import type { ActionReceipt, EvidenceBundle } from "./protocol/types.ts";

/**
 * Evidence authentication: provider ABSTRACTION only.
 *
 * This repo contains NO signing key, generates NO key, and ships NO real provider. The default
 * provider is `noSigningProvider`, so every artifact is UNSIGNED. A real provider (KMS/HSM/Sigstore/...)
 * and its key custody are a HUMAN GATE (see docs/factory/TRUST-HARDENING.md). Test-only providers
 * with EPHEMERAL in-memory keys live under factory/tests/ and are not importable from production code.
 *
 * Statuses:
 *   UNSIGNED             no signature was presented
 *   SIGNED               a signature was presented and the provider verified it over the exact subject
 *   VERIFICATION_FAILED  a signature was presented but could not be verified (wrong key/purpose/subject,
 *                        malformed, provider threw, provider cannot verify)
 */
export type SignatureStatus = "UNSIGNED" | "SIGNED" | "VERIFICATION_FAILED";
export type SignaturePurpose = "evidence-bundle" | "rastik-report" | "action-receipt" | "decision-receipt";
const PURPOSES: readonly SignaturePurpose[] = ["evidence-bundle", "rastik-report", "action-receipt", "decision-receipt"];

export interface Signature {
  provider: string;
  key_id: string;
  alg: string;
  purpose: SignaturePurpose;
  /** The digest that was signed (recomputed by the verifier; never trusted from here). */
  subject_digest: string;
  /** Opaque, provider-defined (e.g. base64). */
  value: string;
}

/** Producer side. Production: NO implementation in this repo (key custody is a human gate); tests use an ephemeral in-process key. */
export interface ReceiptSigner {
  readonly name: string;
  /** Sign `payload` (see `signingPayload`). Returns null when this signer cannot sign (=> artifact stays UNSIGNED). */
  sign(payload: string): Promise<{ key_id: string; alg: string; value: string } | null>;
}

/** Verifier side. Production: `ed25519Verifier` over a provisioned PUBLIC key (`resolveSigningConfig`). */
export interface ReceiptVerifier {
  readonly name: string;
  /** true only if `value` is a valid signature by `key_id` over exactly `payload`. Must not throw for bad input. */
  verify(payload: string, sig: { key_id: string; alg: string; value: string }): Promise<boolean>;
}

export interface SigningProvider extends ReceiptSigner, ReceiptVerifier {}

/** Default provider: no signing, no verifying. Everything is UNSIGNED; any presented signature is VERIFICATION_FAILED. */
export const noSigningProvider: SigningProvider = {
  name: "none",
  sign: async () => null,
  verify: async () => false,
};

const SHA256_HEX = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9:._-]{1,128}$/;

/** Domain-separated payload: a signature for one purpose/subject cannot be replayed for another. */
export function signingPayload(purpose: SignaturePurpose, subjectDigest: string): string {
  return `3xtrinity-factory-sig/v1\n${purpose}\n${subjectDigest}`;
}

function wellFormed(s: unknown): s is Signature {
  if (typeof s !== "object" || s === null || Array.isArray(s)) return false;
  const o = s as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(",");
  return (
    keys === "alg,key_id,provider,purpose,subject_digest,value" &&
    typeof o.provider === "string" && TOKEN.test(o.provider) &&
    typeof o.key_id === "string" && TOKEN.test(o.key_id) &&
    typeof o.alg === "string" && TOKEN.test(o.alg) &&
    (PURPOSES as readonly unknown[]).includes(o.purpose) &&
    typeof o.subject_digest === "string" && SHA256_HEX.test(o.subject_digest) &&
    typeof o.value === "string" && o.value.length >= 1 && o.value.length <= 4096
  );
}

export async function signSubject(provider: ReceiptSigner, purpose: SignaturePurpose, subjectDigest: string): Promise<Signature | null> {
  try {
    const r = await provider.sign(signingPayload(purpose, subjectDigest));
    if (r === null) return null;
    const sig: Signature = { provider: provider.name, key_id: r.key_id, alg: r.alg, purpose, subject_digest: subjectDigest, value: r.value };
    return wellFormed(sig) ? sig : null;
  } catch {
    return null;
  }
}

/**
 * Status of `sig` for the subject the VERIFIER computed itself. A signature over a different subject or
 * purpose, from another provider, or with a malformed shape is VERIFICATION_FAILED, never SIGNED.
 */
export async function signatureStatus(provider: ReceiptVerifier, purpose: SignaturePurpose, expectedSubjectDigest: string, sig: unknown): Promise<SignatureStatus> {
  if (sig === null || sig === undefined) return "UNSIGNED";
  if (!wellFormed(sig)) return "VERIFICATION_FAILED";
  if (sig.purpose !== purpose || sig.subject_digest !== expectedSubjectDigest || sig.provider !== provider.name) return "VERIFICATION_FAILED";
  try {
    const ok = await provider.verify(signingPayload(purpose, expectedSubjectDigest), { key_id: sig.key_id, alg: sig.alg, value: sig.value });
    return ok === true ? "SIGNED" : "VERIFICATION_FAILED";
  } catch {
    return "VERIFICATION_FAILED";
  }
}

export const bundleSubject = (b: EvidenceBundle): string => b.bundle_digest;

/** RÄSTIK subject: the digest RECOMPUTED from the report body, bound to the receipt it attacked. */
export function rastikSubject(run: RastikRun): string {
  const { evidence_digest: _claimed, ...body } = run;
  return digestOf({ rastik_report: rastikEvidenceDigest(body), target_receipt_digest: run.target_receipt_digest });
}

export interface SigningPolicy {
  provider: SigningProvider;
  /** When true, UNSIGNED or VERIFICATION_FAILED artifacts are DENIED by CERBERUS. Default false. */
  required: boolean;
}

export interface ArtifactSignatures {
  bundle?: Signature | null;
  rastik?: Signature | null;
  /** Detached signature over the KRATT action receipt (purpose "action-receipt"). */
  receipt?: Signature | null;
}

export interface SignatureReport {
  bundle: SignatureStatus;
  rastik: SignatureStatus | "NOT_APPLICABLE";
  /** The KRATT action receipt's signature, verified over the digest of the validated receipt. */
  receipt: SignatureStatus;
}

// ---------------------------------------------------------------------------------------------------------------------
// Receipt authentication (ActionReceipt + CERBERUS decision receipts): INTERFACE + verifier only.
//
// What exists: the Signer/Verifier split above, a node:crypto Ed25519 VERIFIER over a provisioned public key, a config
// resolver that fails closed with SIGNING_KEY_UNAVAILABLE, detached signatures with domain separation, and the policy
// helper. What does NOT exist (human gate): any production signing key or signer. This module never generates, reads
// or holds signing-key material; a config file that contains private-key material is refused.
// ---------------------------------------------------------------------------------------------------------------------
export const SIGNING_KEY_UNAVAILABLE = "SIGNING_KEY_UNAVAILABLE";

/**
 * Honest maturity flag. "partial": the interface, the Ed25519 verifier, the fail-closed config and the policy exist and
 * are tested with an EPHEMERAL in-process test key only. No production key or signer exists (human gate), so no
 * production receipt is authenticated today. Flip to "full" only when a provisioned signer + key custody exist.
 */
export const EVIDENCE_AUTHENTICATED = "partial" as const;

export class SigningKeyUnavailableError extends Error {
  readonly code = SIGNING_KEY_UNAVAILABLE;
  constructor(reason: string) {
    super(`${SIGNING_KEY_UNAVAILABLE}: ${reason}`);
    this.name = "SigningKeyUnavailableError";
  }
}

/**
 * Receipt-signing policy (TÖEPÄRA + CERBERUS + loop).
 * `require` default: required EXACTLY when a verification key is configured (`key_configured`). With no key configured,
 * nothing is required and receipts are reported UNSIGNED (behaviour unchanged). `require: true` without a key can never
 * verify anything (fail closed); `require: false` with a key is an explicit, documented opt-out.
 */
export interface ReceiptSigningPolicy {
  verifier: ReceiptVerifier;
  key_configured: boolean;
  require?: boolean;
  /** Producer-side signer used by the loop's KRATT stage. Never set by `resolveSigningConfig` (no production signer here). */
  signer?: ReceiptSigner;
}

export function receiptSigningRequired(p: ReceiptSigningPolicy | undefined): boolean {
  if (p === undefined) return false;
  return p.require ?? p.key_configured;
}

export function requireReceiptSigner(p: ReceiptSigningPolicy | undefined): ReceiptSigner {
  if (p?.signer === undefined) throw new SigningKeyUnavailableError("no signer provisioned (key custody is a human gate)");
  return p.signer;
}

/** Subject of an action-receipt signature: the digest of the receipt AS VALIDATED (canonical JSON, timestamp included). */
export const actionReceiptSubject = (r: ActionReceipt): string => digestOf(r);

export async function signActionReceipt(signer: ReceiptSigner | undefined, r: ActionReceipt): Promise<Signature> {
  if (signer === undefined) throw new SigningKeyUnavailableError("no signer");
  const sig = await signSubject(signer, "action-receipt", actionReceiptSubject(r));
  if (sig === null) throw new SigningKeyUnavailableError(`signer ${signer.name} cannot sign`);
  return sig;
}

/** Subject of a decision-receipt signature: its receipt_digest, but only after `verifyDecisionReceipt` re-derived it. */
export function decisionReceiptSubject(d: unknown): string | null {
  if (!verifyDecisionReceipt(d).ok) return null;
  return (d as { receipt_digest: string }).receipt_digest;
}

export async function signDecisionReceipt(signer: ReceiptSigner | undefined, d: unknown): Promise<Signature> {
  const subject = decisionReceiptSubject(d);
  if (subject === null) throw new Error("decision-receipt-invalid: refusing to sign a receipt that does not verify");
  if (signer === undefined) throw new SigningKeyUnavailableError("no signer");
  const sig = await signSubject(signer, "decision-receipt", subject);
  if (sig === null) throw new SigningKeyUnavailableError(`signer ${signer.name} cannot sign`);
  return sig;
}

export async function decisionReceiptSignatureStatus(verifier: ReceiptVerifier, d: unknown, sig: unknown): Promise<SignatureStatus> {
  if (sig === null || sig === undefined) return "UNSIGNED";
  const subject = decisionReceiptSubject(d);
  if (subject === null) return "VERIFICATION_FAILED";
  return signatureStatus(verifier, "decision-receipt", subject, sig);
}

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** Ed25519 verifier (node:crypto) over a provisioned PUBLIC key. Throws SigningKeyUnavailableError for anything else. It never signs. */
export function ed25519Verifier(publicKeyPem: string, keyId: string, name = "ed25519"): SigningProvider {
  if (!TOKEN.test(keyId)) throw new SigningKeyUnavailableError("invalid key id");
  if (!TOKEN.test(name)) throw new SigningKeyUnavailableError("invalid provider name");
  if (/PRIVATE/.test(publicKeyPem)) throw new SigningKeyUnavailableError("private-key material refused (only a public key may be configured)");
  let key: KeyObject;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    throw new SigningKeyUnavailableError("public key unreadable");
  }
  if (key.asymmetricKeyType !== "ed25519") throw new SigningKeyUnavailableError(`not an Ed25519 key: ${key.asymmetricKeyType ?? "unknown"}`);
  return {
    name,
    sign: async () => null,
    async verify(payload, sig) {
      try {
        if (sig.alg !== "ed25519" || sig.key_id !== keyId) return false;
        if (typeof sig.value !== "string" || sig.value.length > 200 || !B64.test(sig.value)) return false;
        const raw = Buffer.from(sig.value, "base64");
        if (raw.length !== 64) return false;
        return cryptoVerify(null, Buffer.from(payload, "utf8"), key, raw) === true;
      } catch {
        return false;
      }
    },
  };
}

export interface SigningConfig {
  status: "CONFIGURED" | typeof SIGNING_KEY_UNAVAILABLE;
  reason: string;
  policy: ReceiptSigningPolicy;
}

/**
 * Resolve receipt signing from configuration (environment by default):
 *   FACTORY_SIGNING_PUBLIC_KEY_FILE  path to a provisioned Ed25519 PUBLIC key (SPKI PEM), regular file, not a symlink, <= 16 KiB
 *   FACTORY_SIGNING_KEY_ID           key id the signatures must name
 *   FACTORY_SIGNING_PROVIDER         provider name the signatures must name (default "ed25519")
 * Anything missing or wrong => SIGNING_KEY_UNAVAILABLE with a verifier that verifies nothing. No key is ever generated.
 * The resolved policy never carries a signer: a production signer (KMS/HSM/...) is a human gate.
 */
export function resolveSigningConfig(env: Record<string, string | undefined> = process.env): SigningConfig {
  const unavailable = (reason: string): SigningConfig => ({ status: SIGNING_KEY_UNAVAILABLE, reason, policy: { verifier: noSigningProvider, key_configured: false } });
  const file = env.FACTORY_SIGNING_PUBLIC_KEY_FILE;
  const keyId = env.FACTORY_SIGNING_KEY_ID;
  const name = env.FACTORY_SIGNING_PROVIDER ?? "ed25519";
  if (file === undefined || file === "") return unavailable("no verification key provisioned (FACTORY_SIGNING_PUBLIC_KEY_FILE unset)");
  if (keyId === undefined || !TOKEN.test(keyId)) return unavailable("FACTORY_SIGNING_KEY_ID missing or invalid");
  let pem: string;
  try {
    const st = lstatSync(file);
    if (!st.isFile()) return unavailable("key path is not a regular file (symlinks refused)");
    if (st.size > 16 * 1024) return unavailable("key file too large");
    pem = readFileSync(file, "utf8");
  } catch {
    return unavailable("key file unreadable");
  }
  try {
    return { status: "CONFIGURED", reason: "verification key provisioned", policy: { verifier: ed25519Verifier(pem, keyId, name), key_configured: true } };
  } catch (e) {
    return unavailable(e instanceof Error ? e.message : "key rejected");
  }
}
