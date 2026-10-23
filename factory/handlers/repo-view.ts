import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

/**
 * Read-only view of one commit. The ONLY module in factory/handlers allowed to spawn a process:
 * fixed `git` argv (ls-tree / cat-file / rev-parse), shell:false, minimal environment, no
 * network, no writes. Everything is read from git objects at `sha`, never from the working tree,
 * so results are reproducible and a symlink or dirty tree cannot change them.
 */
const SHA1 = /^[0-9a-f]{40}$/;
const MAX_OUT = 64 * 1024 * 1024;

function git(root: string, args: string[]): Buffer | null {
  const r = spawnSync("git", args, {
    cwd: root,
    shell: false,
    maxBuffer: MAX_OUT,
    timeout: 30_000,
    env: { PATH: process.env.PATH ?? "", LC_ALL: "C", GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0" },
  });
  return r.error || r.status !== 0 ? null : r.stdout;
}

export const sha256 = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

export interface TreeEntry {
  path: string;
  mode: string;
  type: string;
  bytes: number;
}
export type Stat = { kind: "file" | "symlink" | "dir" | "submodule" | "missing"; bytes: number };
export type ReadResult = { ok: true; buf: Buffer } | { ok: false; reason: string };

export class RepoView {
  readonly root: string;
  readonly sha: string;
  readonly maxFileBytes: number;
  #left: number;
  #all: TreeEntry[] | null = null;
  #byPath: Map<string, TreeEntry> | null = null;
  #dirs: Set<string> | null = null;

  constructor(root: string, sha: string, limits: { max_file_bytes: number; max_total_bytes: number }) {
    this.root = root;
    this.sha = sha;
    this.maxFileBytes = limits.max_file_bytes;
    this.#left = limits.max_total_bytes;
  }

  static commitExists(root: string, sha: string): boolean {
    return SHA1.test(sha) && git(root, ["cat-file", "-e", `${sha}^{commit}`]) !== null;
  }

  #parse(out: Buffer): TreeEntry[] {
    const entries: TreeEntry[] = [];
    for (const rec of out.toString("utf8").split("\0")) {
      if (rec === "") continue;
      const tab = rec.indexOf("\t");
      if (tab < 0) continue;
      const [mode = "", type = "", , size = "-"] = rec.slice(0, tab).split(/\s+/);
      entries.push({ path: rec.slice(tab + 1), mode, type, bytes: size === "-" ? 0 : Number(size) });
    }
    return entries;
  }

  /** Every entry of the commit (recursive, files only). Cached. */
  all(): readonly TreeEntry[] {
    if (this.#all === null) {
      const out = git(this.root, ["ls-tree", "-r", "-z", "-l", this.sha]);
      this.#all = out === null ? [] : this.#parse(out);
      this.#byPath = new Map(this.#all.map((e) => [e.path, e]));
      this.#dirs = new Set();
      for (const e of this.#all) {
        const parts = e.path.split("/");
        for (let i = 1; i < parts.length; i++) this.#dirs.add(parts.slice(0, i).join("/"));
      }
    }
    return this.#all;
  }

  hasFile(path: string): boolean {
    this.all();
    return this.#byPath!.has(path);
  }
  hasDir(path: string): boolean {
    this.all();
    return path === "" || this.#dirs!.has(path);
  }

  stat(path: string): Stat {
    this.all();
    const hit = this.#byPath!.get(path);
    if (hit) return { kind: hit.type === "commit" ? "submodule" : hit.mode === "120000" ? "symlink" : "file", bytes: hit.bytes };
    return this.hasDir(path) ? { kind: "dir", bytes: 0 } : { kind: "missing", bytes: 0 };
  }

  /** Regular files at or under `path` (a file yields itself), sorted by path. */
  expand(path: string): TreeEntry[] {
    const prefix = path + "/";
    return this.all()
      .filter((e) => e.path === path || e.path.startsWith(prefix))
      .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  }

  /** Read one regular file, charging the shared byte budget. */
  read(path: string): ReadResult {
    const st = this.stat(path);
    if (st.kind === "missing") return { ok: false, reason: "path-not-found" };
    if (st.kind === "dir") return { ok: false, reason: "not-regular-file" };
    if (st.kind === "symlink" || st.kind === "submodule") return { ok: false, reason: `not-regular-file:${st.kind}` };
    if (st.bytes > this.maxFileBytes) return { ok: false, reason: "file-too-large" };
    if (st.bytes > this.#left) return { ok: false, reason: "total-size-budget-exceeded" };
    const buf = git(this.root, ["cat-file", "blob", `${this.sha}:${path}`]);
    if (buf === null) return { ok: false, reason: "path-not-found" };
    this.#left -= buf.length;
    return { ok: true, buf };
  }

  /** Read + JSON.parse a file. */
  readJson(path: string): { ok: true; value: unknown } | { ok: false; reason: string } {
    const r = this.read(path);
    if (!r.ok) return r;
    try {
      return { ok: true, value: JSON.parse(r.buf.toString("utf8")) as unknown };
    } catch {
      return { ok: false, reason: "json-parse-error" };
    }
  }
}
