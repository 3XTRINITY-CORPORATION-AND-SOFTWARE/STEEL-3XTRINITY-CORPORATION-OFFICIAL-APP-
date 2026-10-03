import { byAscii, DEFAULT_LIMITS, READ_ONLY, type Analysis, type Finding, type Handler } from "./types.ts";
import { sha256 } from "./repo-view.ts";

/** High-confidence token shapes only (low false-positive rate). Linear-time regexes. */
export const RULES: readonly { id: string; re: RegExp }[] = [
  { id: "aws-access-key-id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/ },
  { id: "github-fine-grained-pat", re: /\bgithub_pat_[A-Za-z0-9_]{50,255}\b/ },
  { id: "private-key-block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  { id: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "stripe-live-key", re: /\b[sr]k_live_[0-9A-Za-z]{24,}\b/ },
  { id: "npm-token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
];

/** SERPENT-069 Secret Exposure Reviewer: committed-secret scan. Never echoes a secret; reports a short SHA-256 fingerprint instead. */
export const secretsScan: Handler = {
  contract: {
    contract_version: 1,
    capability: "secrets:scan-files",
    agent_id: "SERPENT-069",
    role: "Secret Exposure Reviewer",
    summary: "Scan committed files for high-confidence credential shapes (cloud/VCS/chat/payment tokens, private-key blocks). Findings carry rule, path, line and a SHA-256 fingerprint, never the secret.",
    permissions: READ_ONLY,
    scope: { min: 1, max: 64, kind: "path", meaning: "files or directories to scan (expanded to tracked files)" },
    limits: DEFAULT_LIMITS,
    summary_keys: ["files_scanned", "binary_skipped", "unreadable", "rules"],
  },
  analyze(view, scope): Analysis {
    const findings: Finding[] = [];
    const files = new Map<string, true>();
    for (const p of scope) {
      const ex = view.expand(p);
      if (ex.length === 0) findings.push({ severity: "error", code: "path-not-found", path: p, detail: "no tracked entry at base_sha" });
      for (const e of ex) files.set(e.path, true);
    }
    let scanned = 0;
    let binary = 0;
    let unreadable = 0;
    for (const path of [...files.keys()].sort(byAscii)) {
      const r = view.read(path);
      if (!r.ok) {
        unreadable++;
        findings.push({ severity: "warn", code: "unreadable", path, detail: r.reason });
        continue;
      }
      if (r.buf.includes(0)) {
        binary++;
        continue;
      }
      scanned++;
      const lines = r.buf.toString("utf8").split("\n");
      lines.forEach((line, i) => {
        if (line.length > 20_000) return;
        for (const rule of RULES) {
          const m = rule.re.exec(line);
          if (m) findings.push({ severity: "error", code: `secret:${rule.id}`, path, line: i + 1, detail: `fingerprint=${sha256(m[0]).slice(0, 16)}` });
        }
      });
    }
    return { summary: { files_scanned: scanned, binary_skipped: binary, unreadable, rules: RULES.map((r) => r.id) }, findings };
  },
};
