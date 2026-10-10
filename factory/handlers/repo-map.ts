import { byAscii, DEFAULT_LIMITS, READ_ONLY, type Analysis, type Handler } from "./types.ts";

const MAX_ENTRIES = 100_000;

/** FORGE-002 Repository Mapper: structural inventory (counts, bytes, extension histogram) of paths in a commit. Reads tree metadata only, never file contents. */
export const repoMap: Handler = {
  contract: {
    contract_version: 1,
    capability: "repo:map-tree",
    agent_id: "FORGE-002",
    role: "Repository Mapper",
    summary: "Inventory files under the scoped paths of a commit: file/byte totals, per-extension and per-top-directory histograms, symlinks and submodules, from tree metadata only.",
    permissions: READ_ONLY,
    scope: { min: 1, max: 64, kind: "path", meaning: "directories or files to inventory" },
    limits: DEFAULT_LIMITS,
    summary_keys: ["files", "bytes", "by_extension", "by_top_dir", "symlinks", "submodules", "largest"],
  },
  analyze(view, scope): Analysis {
    const findings: Analysis["findings"] = [];
    const seen = new Set<string>();
    let bytes = 0;
    let symlinks = 0;
    let submodules = 0;
    const ext: Record<string, number> = {};
    const top: Record<string, number> = {};
    const sized: { path: string; bytes: number }[] = [];
    for (const p of scope) {
      const entries = view.expand(p);
      if (entries.length === 0) {
        findings.push({ severity: "error", code: "path-not-found", path: p, detail: "no tracked entry at base_sha" });
        continue;
      }
      for (const e of entries) {
        if (seen.has(e.path)) continue;
        seen.add(e.path);
        if (seen.size > MAX_ENTRIES) return { summary: { files: seen.size }, findings, failure: "too-many-entries" };
        if (e.type === "commit") {
          submodules++;
          findings.push({ severity: "warn", code: "submodule", path: e.path, detail: "gitlink entry; contents not inventoried" });
        } else if (e.mode === "120000") {
          symlinks++;
          findings.push({ severity: "warn", code: "symlink", path: e.path, detail: "symbolic link" });
        }
        bytes += e.bytes;
        const name = e.path.slice(e.path.lastIndexOf("/") + 1);
        const dot = name.lastIndexOf(".");
        const x = dot > 0 ? name.slice(dot).toLowerCase() : "(none)";
        ext[x] = (ext[x] ?? 0) + 1;
        const t = e.path.includes("/") ? e.path.slice(0, e.path.indexOf("/")) : "(root)";
        top[t] = (top[t] ?? 0) + 1;
        sized.push({ path: e.path, bytes: e.bytes });
      }
    }
    const sortObj = (o: Record<string, number>) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => byAscii(a, b)));
    sized.sort((a, b) => b.bytes - a.bytes || byAscii(a.path, b.path));
    return { summary: { files: seen.size, bytes, by_extension: sortObj(ext), by_top_dir: sortObj(top), symlinks, submodules, largest: sized.slice(0, 5) }, findings };
  },
};
