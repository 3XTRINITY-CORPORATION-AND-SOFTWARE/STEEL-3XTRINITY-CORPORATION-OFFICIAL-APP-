import { createHash } from "node:crypto";
import { byAscii, DEFAULT_LIMITS, READ_ONLY, type Analysis, type Finding, type Handler } from "./types.ts";
import type { RepoView } from "./repo-view.ts";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const DIGEST_BYTES: Record<string, number> = { sha512: 64, sha384: 48, sha256: 32, sha1: 20 };

interface Lock {
  version: number;
  packages: [string, Obj][];
  root: Obj;
}
function loadLock(view: RepoView, path: string): { ok: true; lock: Lock } | { ok: false; failure: string } {
  const j = view.readJson(path);
  if (!j.ok) return { ok: false, failure: `lockfile-unreadable:${j.reason}` };
  if (!isObj(j.value)) return { ok: false, failure: "lockfile-not-object" };
  const v = j.value.lockfileVersion;
  if (v !== 2 && v !== 3) return { ok: false, failure: `unsupported-lockfileVersion:${String(v)}` };
  if (!isObj(j.value.packages)) return { ok: false, failure: "lockfile-has-no-packages-map" };
  const pk = j.value.packages;
  const root = isObj(pk[""]) ? pk[""] : {};
  const packages = Object.entries(pk).filter(([k, val]) => k !== "" && isObj(val)).map(([k, val]) => [k, val as Obj] as [string, Obj]).sort(([a], [b]) => byAscii(a, b));
  return { ok: true, lock: { version: v, packages, root } };
}
const pkgName = (key: string): string => key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);

/** SERPENT-078 Package-Lock Auditor: structural integrity of package-lock.json. */
export const lockfileAudit: Handler = {
  contract: {
    contract_version: 1,
    capability: "lockfile:audit-integrity",
    agent_id: "SERPENT-078",
    role: "Package-Lock Auditor",
    summary: "Audit package-lock.json integrity metadata: every resolved package carries a well-formed, correctly sized SRI digest (weak/absent flagged), and every root dependency is locked.",
    permissions: READ_ONLY,
    scope: { min: 1, max: 1, kind: "file", meaning: "one package-lock.json (lockfileVersion 2 or 3)" },
    limits: DEFAULT_LIMITS,
    summary_keys: ["lockfile_version", "packages", "with_integrity", "algorithms", "lock_digest"],
  },
  analyze(view, scope): Analysis {
    const path = scope[0] ?? "";
    const base = { lockfile_version: 0, packages: 0, with_integrity: 0, algorithms: {} as Record<string, number>, lock_digest: null as string | null };
    const r = view.read(path);
    if (r.ok) base.lock_digest = createHash("sha256").update(r.buf).digest("hex");
    const l = loadLock(view, path);
    if (!l.ok) return { summary: base, findings: [], failure: l.failure };
    base.lockfile_version = l.lock.version;
    const findings: Finding[] = [];
    const names = new Set<string>();
    for (const [key, p] of l.lock.packages) {
      if (!key.includes("node_modules/") || p.link === true) continue; // workspace members / links have no registry artifact
      base.packages++;
      names.add(key);
      if (typeof p.resolved !== "string" && p.inBundle !== true) {
        findings.push({ severity: "warn", code: "no-resolved", path: key, detail: "package has no resolved URL" });
        continue;
      }
      if (p.inBundle === true) continue;
      const integ = p.integrity;
      if (typeof integ !== "string") {
        findings.push({ severity: "error", code: "missing-integrity", path: key, detail: `${pkgName(key)} has a resolved URL but no integrity` });
        continue;
      }
      const m = /^(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/]+={0,2})$/.exec(integ);
      if (!m) {
        findings.push({ severity: "error", code: "malformed-integrity", path: key, detail: `${pkgName(key)}: not a valid SRI string` });
        continue;
      }
      const [, algo = "", b64 = ""] = m;
      const raw = Buffer.from(b64, "base64");
      if (raw.length !== DIGEST_BYTES[algo] || raw.toString("base64") !== b64) {
        findings.push({ severity: "error", code: "integrity-length-mismatch", path: key, detail: `${pkgName(key)}: ${algo} digest has ${raw.length} bytes, expected ${DIGEST_BYTES[algo]}` });
        continue;
      }
      base.with_integrity++;
      base.algorithms[algo] = (base.algorithms[algo] ?? 0) + 1;
      if (algo === "sha1") findings.push({ severity: "warn", code: "weak-integrity", path: key, detail: `${pkgName(key)} only has sha1` });
    }
    for (const sec of ["dependencies", "devDependencies", "optionalDependencies"]) {
      const block = l.lock.root[sec];
      if (!isObj(block)) continue;
      for (const name of Object.keys(block).sort(byAscii)) {
        if (!names.has(`node_modules/${name}`) && !l.lock.packages.some(([k]) => k === name || k === `node_modules/${name}`))
          findings.push({ severity: sec === "optionalDependencies" ? "warn" : "error", code: "root-dependency-not-locked", path: "package-lock.json", detail: `${sec}.${name}` });
      }
    }
    base.algorithms = Object.fromEntries(Object.entries(base.algorithms).sort(([a], [b]) => byAscii(a, b)));
    return { summary: base, findings };
  },
};

/** SERPENT-068 Supply-Chain Reviewer: install-time execution and source exposure in package-lock.json. */
export const supplyChainReview: Handler = {
  contract: {
    contract_version: 1,
    capability: "supply-chain:review-lockfile",
    agent_id: "SERPENT-068",
    role: "Supply-Chain Reviewer",
    summary: "Review package-lock.json for install-script packages, non-https or non-registry sources (git/tarball/file), deprecated packages and registry-host spread.",
    permissions: READ_ONLY,
    scope: { min: 1, max: 1, kind: "file", meaning: "one package-lock.json (lockfileVersion 2 or 3)" },
    limits: DEFAULT_LIMITS,
    summary_keys: ["packages", "install_script_count", "install_script_packages", "non_registry_sources", "deprecated", "hosts"],
  },
  analyze(view, scope): Analysis {
    const path = scope[0] ?? "";
    const base = { packages: 0, install_script_count: 0, install_script_packages: [] as string[], non_registry_sources: 0, deprecated: 0, hosts: {} as Record<string, number> };
    const l = loadLock(view, path);
    if (!l.ok) return { summary: base, findings: [], failure: l.failure };
    const findings: Finding[] = [];
    for (const [key, p] of l.lock.packages) {
      if (!key.includes("node_modules/") || p.link === true) continue;
      base.packages++;
      const name = pkgName(key);
      if (p.hasInstallScript === true) {
        base.install_script_count++;
        base.install_script_packages.push(name);
        findings.push({ severity: "info", code: "install-script", path: key, detail: `${name} runs install-time scripts` });
      }
      if (typeof p.deprecated === "string") {
        base.deprecated++;
        findings.push({ severity: "warn", code: "deprecated", path: key, detail: `${name}: ${p.deprecated.slice(0, 120)}` });
      }
      if (typeof p.resolved === "string" && p.inBundle !== true) {
        let u: URL | null = null;
        try {
          u = new URL(p.resolved.replace(/^git\+/, ""));
        } catch {
          /* handled below */
        }
        if (!u) {
          base.non_registry_sources++;
          findings.push({ severity: "error", code: "unparseable-source", path: key, detail: `${name}: resolved is not a URL` });
        } else {
          base.hosts[u.host] = (base.hosts[u.host] ?? 0) + 1;
          if (p.resolved.startsWith("git+") || u.protocol === "git:" || u.protocol === "ssh:") {
            base.non_registry_sources++;
            findings.push({ severity: "error", code: "git-source", path: key, detail: `${name} resolves from ${u.host}` });
          } else if (u.protocol !== "https:") {
            base.non_registry_sources++;
            findings.push({ severity: "error", code: "insecure-transport", path: key, detail: `${name} resolves over ${u.protocol}` });
          } else if (u.host !== "registry.npmjs.org") {
            base.non_registry_sources++;
            findings.push({ severity: "warn", code: "non-default-registry", path: key, detail: `${name} resolves from ${u.host}` });
          }
        }
      }
    }
    base.install_script_packages.sort(byAscii);
    base.install_script_packages = base.install_script_packages.slice(0, 50);
    base.hosts = Object.fromEntries(Object.entries(base.hosts).sort(([a], [b]) => byAscii(a, b)));
    return { summary: base, findings };
  },
};
