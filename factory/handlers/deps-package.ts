import { byAscii, DEFAULT_LIMITS, READ_ONLY, type Analysis, type Finding, type Handler } from "./types.ts";

const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

export type RangeKind = "exact" | "caret" | "tilde" | "range" | "wildcard" | "git" | "url" | "file" | "alias" | "tag";
/** Classify a dependency specifier. Pure. */
export function classifyRange(spec: string): RangeKind {
  const s = spec.trim();
  if (s === "" || s === "*" || s === "x" || /^latest$/i.test(s)) return "wildcard";
  if (/^(git(\+[a-z]+)?|github|gitlab|bitbucket):/i.test(s) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(s)) return "git";
  if (/^https?:\/\//i.test(s)) return "url";
  if (/^(file|link|workspace):/i.test(s)) return "file";
  if (/^npm:/i.test(s)) return "alias";
  if (/^\d+\.\d+\.\d+([-+][\w.+-]+)?$/.test(s)) return "exact";
  if (s.startsWith("^")) return "caret";
  if (s.startsWith("~")) return "tilde";
  if (/^[<>=\d]/.test(s) || s.includes("||") || s.includes(" - ") || /^\d+(\.\d+|\.x)?$/.test(s)) return "range";
  return "tag";
}

/** FORGE-003 Dependency Mapper: dependency inventory + specifier hygiene of package.json files. */
export const depsPackage: Handler = {
  contract: {
    contract_version: 1,
    capability: "deps:map-package",
    agent_id: "FORGE-003",
    role: "Dependency Mapper",
    summary: "Map dependency sections of package.json files, classify every specifier (exact/caret/tilde/range/wildcard/git/url/file) and flag unpinned, URL, duplicated and malformed entries.",
    permissions: READ_ONLY,
    scope: { min: 1, max: 8, kind: "file", meaning: "package.json files" },
    limits: DEFAULT_LIMITS,
    summary_keys: ["manifests", "totals", "by_kind"],
  },
  analyze(view, scope): Analysis {
    const findings: Finding[] = [];
    const totals: Record<string, number> = Object.fromEntries(SECTIONS.map((s) => [s, 0]));
    const kinds: Record<string, number> = {};
    let manifests = 0;
    let failure: string | undefined;
    for (const p of scope) {
      const j = view.readJson(p);
      if (!j.ok) {
        failure ??= `manifest-unreadable:${p}:${j.reason}`;
        findings.push({ severity: "error", code: "manifest-unreadable", path: p, detail: j.reason });
        continue;
      }
      if (!isObj(j.value)) {
        findings.push({ severity: "error", code: "manifest-not-object", path: p, detail: "top level is not a JSON object" });
        continue;
      }
      manifests++;
      const names = new Map<string, string>();
      for (const sec of SECTIONS) {
        const block = j.value[sec];
        if (block === undefined) continue;
        if (!isObj(block)) {
          findings.push({ severity: "error", code: "section-not-object", path: p, detail: sec });
          continue;
        }
        for (const [name, spec] of Object.entries(block).sort(([a], [b]) => byAscii(a, b))) {
          totals[sec] = (totals[sec] ?? 0) + 1;
          if (typeof spec !== "string") {
            findings.push({ severity: "error", code: "specifier-not-string", path: p, detail: `${sec}.${name}` });
            continue;
          }
          const kind = classifyRange(spec);
          kinds[kind] = (kinds[kind] ?? 0) + 1;
          if (kind === "wildcard") findings.push({ severity: "error", code: "unpinned-wildcard", path: p, detail: `${sec}.${name}=${JSON.stringify(spec)}` });
          else if (kind === "git" || kind === "url") findings.push({ severity: "error", code: "non-registry-source", path: p, detail: `${sec}.${name} (${kind})` });
          else if (kind === "tag") findings.push({ severity: "warn", code: "dist-tag", path: p, detail: `${sec}.${name}=${JSON.stringify(spec)}` });
          else if (kind === "file") findings.push({ severity: "warn", code: "local-source", path: p, detail: `${sec}.${name}` });
          const prev = names.get(name);
          if (prev && !(prev === "peerDependencies" || sec === "peerDependencies")) findings.push({ severity: "warn", code: "duplicate-dependency", path: p, detail: `${name} in ${prev} and ${sec}` });
          if (!prev) names.set(name, sec);
        }
      }
    }
    return { summary: { manifests, totals, by_kind: Object.fromEntries(Object.entries(kinds).sort(([a], [b]) => byAscii(a, b))) }, findings, ...(failure ? { failure } : {}) };
  },
};
