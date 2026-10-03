import { DEFAULT_LIMITS, READ_ONLY, byAscii, type Analysis, type Finding, type Handler } from "./types.ts";
import type { RepoView } from "./repo-view.ts";

/** GitHub-style heading slug, with -1/-2 suffixes for duplicates. */
export function headingSlugs(md: string): Set<string> {
  const out = new Set<string>();
  const used = new Map<string, number>();
  let fence = false;
  for (const line of md.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) fence = !fence;
    if (fence) continue;
    const m = /^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
    if (!m) continue;
    const base = (m[1] ?? "").replace(/<[^>]*>/g, "").replace(/\[([^\]]*)\]\([^)]*\)/g, "$1").replace(/[`*_~]/g, "").toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, "").trim().replace(/\s/g, "-");
    const n = used.get(base) ?? 0;
    used.set(base, n + 1);
    out.add(n === 0 ? base : `${base}-${n}`);
  }
  return out;
}

interface Link {
  target: string;
  line: number;
}
/** Inline `[t](x)`, `![t](x)` and reference definitions `[id]: x`; fenced blocks and inline code spans are skipped. */
export function extractLinks(md: string): Link[] {
  const links: Link[] = [];
  let fence = false;
  md.split("\n").forEach((raw, i) => {
    if (/^\s*(```|~~~)/.test(raw)) return void (fence = !fence);
    if (fence) return;
    const line = raw.replace(/`[^`]*`/g, "");
    for (const m of line.matchAll(/!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)) links.push({ target: m[1] ?? "", line: i + 1 });
    const ref = /^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$/.exec(line);
    if (ref) links.push({ target: ref[1] ?? "", line: i + 1 });
  });
  return links;
}

function resolvePath(fromFile: string, target: string): string | null {
  const stack = target.startsWith("/") ? [] : fromFile.split("/").slice(0, -1);
  for (const seg of target.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (stack.length === 0) return null;
      stack.pop();
    } else stack.push(seg);
  }
  return stack.join("/");
}

/** FORGE-049 Documentation-from-Code Agent: documentation link/anchor integrity inside a commit. */
export const docsLinks: Handler = {
  contract: {
    contract_version: 1,
    capability: "docs:check-links",
    agent_id: "FORGE-049",
    role: "Documentation-from-Code Agent",
    summary: "Check relative links and #anchors in Markdown files against the tree and headings of the same commit. External URLs are counted, never fetched.",
    permissions: READ_ONLY,
    scope: { min: 1, max: 64, kind: "file", meaning: "Markdown files" },
    limits: DEFAULT_LIMITS,
    summary_keys: ["files", "links", "external_skipped", "broken"],
  },
  analyze(view: RepoView, scope): Analysis {
    const findings: Finding[] = [];
    let links = 0;
    let external = 0;
    let broken = 0;
    let failure: string | undefined;
    const slugCache = new Map<string, Set<string> | null>();
    const slugsOf = (path: string): Set<string> | null => {
      if (!slugCache.has(path)) {
        const r = view.read(path);
        slugCache.set(path, r.ok ? headingSlugs(r.buf.toString("utf8")) : null);
      }
      return slugCache.get(path) ?? null;
    };
    const bad = (code: string, path: string, line: number, detail: string) => {
      broken++;
      findings.push({ severity: "error", code, path, line, detail });
    };
    for (const file of [...scope].sort(byAscii)) {
      const r = view.read(file);
      if (!r.ok) {
        failure ??= `markdown-unreadable:${file}:${r.reason}`;
        findings.push({ severity: "error", code: "markdown-unreadable", path: file, detail: r.reason });
        continue;
      }
      for (const { target, line } of extractLinks(r.buf.toString("utf8"))) {
        links++;
        if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith("//")) {
          external++;
          continue;
        }
        const hash = target.indexOf("#");
        const rawPath = hash >= 0 ? target.slice(0, hash) : target;
        const frag = hash >= 0 ? target.slice(hash + 1) : "";
        let pathPart = rawPath.split("?")[0] ?? "";
        try {
          pathPart = decodeURIComponent(pathPart);
        } catch {
          bad("bad-link-encoding", file, line, target);
          continue;
        }
        const dest = pathPart === "" ? file : resolvePath(file, pathPart);
        if (dest === null) {
          bad("link-escapes-root", file, line, target);
          continue;
        }
        if (!view.hasFile(dest) && !view.hasDir(dest)) {
          bad("broken-link", file, line, `${target} -> ${dest} not found`);
          continue;
        }
        if (frag !== "" && view.hasFile(dest) && /\.(md|markdown)$/i.test(dest)) {
          let want = frag;
          try {
            want = decodeURIComponent(frag).toLowerCase();
          } catch {
            want = frag.toLowerCase();
          }
          if (/^L\d+(-L\d+)?$/i.test(frag)) continue;
          const s = slugsOf(dest);
          if (s === null || !s.has(want)) bad("broken-anchor", file, line, `${target}: no heading "${want}" in ${dest}`);
        }
      }
    }
    return { summary: { files: scope.length, links, external_skipped: external, broken }, findings, ...(failure ? { failure } : {}) };
  },
};
