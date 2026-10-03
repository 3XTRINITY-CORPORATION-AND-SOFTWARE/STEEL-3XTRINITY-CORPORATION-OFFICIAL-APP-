import { digestOf } from "../protocol/types.ts";
import { byAscii, DEFAULT_LIMITS, READ_ONLY, type Analysis, type Finding, type Handler } from "./types.ts";
import { sha256 } from "./repo-view.ts";

const SHA256 = /^[0-9a-f]{64}$/;
const MANIFEST_MAX_FILES = 256;

/** CITADEL-104 Evidence Hasher: deterministic per-file SHA-256 receipt over git blobs, with a single manifest digest. */
export const evidenceHash: Handler = {
  contract: {
    contract_version: 1,
    capability: "evidence:hash-blobs",
    agent_id: "CITADEL-104",
    role: "Evidence Hasher",
    summary: "Hash every tracked file under the scope (path-sorted, from git blobs at base_sha) and fold the (path, sha256, bytes) list into one manifest digest. Same commit => same digest, on any machine.",
    permissions: READ_ONLY,
    scope: { min: 1, max: 64, kind: "path", meaning: "files or directories to hash (expanded to at most 256 tracked files)" },
    limits: DEFAULT_LIMITS,
    summary_keys: ["files", "bytes", "manifest_digest", "entries"],
  },
  analyze(view, scope): Analysis {
    const findings: Finding[] = [];
    const paths = new Set<string>();
    for (const p of scope) {
      const ex = view.expand(p);
      if (ex.length === 0) findings.push({ severity: "error", code: "path-not-found", path: p, detail: "no tracked entry at base_sha" });
      for (const e of ex) paths.add(e.path);
    }
    if (paths.size > MANIFEST_MAX_FILES) return { summary: { files: paths.size, bytes: 0, manifest_digest: null, entries: [] }, findings, failure: `expansion-exceeds-${MANIFEST_MAX_FILES}-files` };
    const entries: { path: string; sha256: string; bytes: number }[] = [];
    let bytes = 0;
    for (const path of [...paths].sort(byAscii)) {
      const r = view.read(path);
      if (!r.ok) {
        findings.push({ severity: "error", code: "unhashable", path, detail: r.reason });
        continue;
      }
      bytes += r.buf.length;
      entries.push({ path, sha256: sha256(r.buf), bytes: r.buf.length });
    }
    return { summary: { files: entries.length, bytes, manifest_digest: findings.length === 0 ? digestOf(entries) : null, entries }, findings };
  },
};

/** SERPENT-066 Artifact Integrity Tester: re-hash files against a committed manifest and report every drift. */
export const manifestVerify: Handler = {
  contract: {
    contract_version: 1,
    capability: "artifact:verify-manifest",
    agent_id: "SERPENT-066",
    role: "Artifact Integrity Tester",
    summary: 'Verify a committed manifest {"manifest_version":1,"files":[{"path","sha256"}]} against the blobs of the same commit: missing files, digest drift, malformed rows and duplicates are all errors.',
    permissions: READ_ONLY,
    scope: { min: 1, max: 1, kind: "file", meaning: "one manifest JSON file" },
    limits: DEFAULT_LIMITS,
    summary_keys: ["manifest", "declared", "verified", "mismatched", "missing"],
  },
  analyze(view, scope): Analysis {
    const mp = scope[0] ?? "";
    const sum = { manifest: mp, declared: 0, verified: 0, mismatched: 0, missing: 0 };
    const findings: Finding[] = [];
    const j = view.readJson(mp);
    if (!j.ok) return { summary: sum, findings, failure: `manifest-unreadable:${j.reason}` };
    const m = j.value as { manifest_version?: unknown; files?: unknown };
    if (typeof m !== "object" || m === null || m.manifest_version !== 1 || !Array.isArray(m.files)) return { summary: sum, findings, failure: "manifest-malformed" };
    if (m.files.length === 0 || m.files.length > MANIFEST_MAX_FILES) return { summary: sum, findings, failure: "manifest-file-count-out-of-range" };
    sum.declared = m.files.length;
    const seen = new Set<string>();
    for (const row of m.files as unknown[]) {
      const r = row as { path?: unknown; sha256?: unknown };
      if (typeof r !== "object" || r === null || typeof r.path !== "string" || typeof r.sha256 !== "string" || !SHA256.test(r.sha256)) {
        findings.push({ severity: "error", code: "malformed-row", path: mp, detail: "row needs string path and 64-hex sha256" });
        continue;
      }
      if (seen.has(r.path)) {
        findings.push({ severity: "error", code: "duplicate-path", path: r.path, detail: "listed more than once" });
        continue;
      }
      seen.add(r.path);
      const f = view.read(r.path);
      if (!f.ok) {
        sum.missing++;
        findings.push({ severity: "error", code: "file-unreadable", path: r.path, detail: f.reason });
      } else if (sha256(f.buf) !== r.sha256) {
        sum.mismatched++;
        findings.push({ severity: "error", code: "digest-mismatch", path: r.path, detail: `expected=${r.sha256.slice(0, 16)}… actual=${sha256(f.buf).slice(0, 16)}…` });
      } else sum.verified++;
    }
    return { summary: sum, findings };
  },
};
