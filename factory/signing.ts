import { digestOf } from "./protocol/types.ts";
import { rastikEvidenceDigest, type RastikRun } from "./rastik-types.ts";
import type { EvidenceBundle } from "./protocol/types.ts";

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
export type SignaturePurpose = "evidence-bundle" | "rastik-report";

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

export interface SigningProvider {
  readonly name: string;
  /** Sign `payload` (see `signingPayload`). Returns null when this provider cannot sign (=> artifact stays UNSIGNED). */
  sign(payload: string): Promise<{ key_id: string; alg: string; value: string } | null>;
  /** true only if `value` is a valid signature by `key_id` over exactly `payload`. Must not throw for bad input. */
  verify(payload: string, sig: { key_id: string; alg: string; value: string }): Promise<boolean>;
}

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
    (o.purpose === "evidence-bundle" || o.purpose === "rastik-report") &&
    typeof o.subject_digest === "string" && SHA256_HEX.test(o.subject_digest) &&
    typeof o.value === "string" && o.value.length >= 1 && o.value.length <= 4096
  );
}

export async function signSubject(provider: SigningProvider, purpose: SignaturePurpose, subjectDigest: string): Promise<Signature | null> {
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
export async function signatureStatus(provider: SigningProvider, purpose: SignaturePurpose, expectedSubjectDigest: string, sig: unknown): Promise<SignatureStatus> {
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
}

export interface SignatureReport {
  bundle: SignatureStatus;
  rastik: SignatureStatus | "NOT_APPLICABLE";
}
