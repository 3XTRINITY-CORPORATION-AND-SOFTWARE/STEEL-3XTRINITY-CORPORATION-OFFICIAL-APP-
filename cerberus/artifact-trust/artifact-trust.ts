import { createHash } from "node:crypto";

export interface ArtifactEvidence {
  name: string;
  content: string;
  /** Declared lowercase hex SHA-256 of `content`. */
  sha256: string;
}

export function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

/** Returns a reason string when the artifact is NOT trusted, otherwise null. */
export function artifactTrustFailure(artifact: unknown): string | null {
  if (typeof artifact !== "object" || artifact === null) return "artifact-missing";
  const a = artifact as Partial<ArtifactEvidence>;
  if (typeof a.name !== "string" || a.name === "") return "artifact-name-invalid";
  if (typeof a.content !== "string") return "artifact-content-invalid";
  if (typeof a.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(a.sha256)) return "artifact-digest-malformed";
  return sha256Hex(a.content) === a.sha256 ? null : "artifact-digest-mismatch";
}
