import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { relPathFailure } from "../kratt/paths.ts";

/**
 * Read-only git access for TÖEPÄRA's independent recomputation. Fixed argv, shell:false,
 * minimal environment, no network (partial-clone lazy fetch is disabled with GIT_NO_LAZY_FETCH=1), no writes. Every function returns null instead of throwing.
 */
const MAX = 16 * 1024 * 1024;
const SHA1 = /^[0-9a-f]{40}$/;

function git(root: string, args: string[]): Buffer | null {
  const r = spawnSync("git", args, {
    cwd: root,
    shell: false,
    maxBuffer: MAX,
    timeout: 30_000,
    env: { PATH: process.env.PATH ?? "", LC_ALL: "C", GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0", GIT_NO_LAZY_FETCH: "1" },
  });
  return r.error || r.status !== 0 ? null : r.stdout;
}

export const sha256Buf = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

export function headSha(root: string): string | null {
  const o = git(root, ["rev-parse", "--verify", "HEAD^{commit}"]);
  const s = o?.toString("utf8").trim() ?? "";
  return SHA1.test(s) ? s : null;
}

export function commitExists(root: string, sha: string): boolean {
  return SHA1.test(sha) && git(root, ["cat-file", "-e", `${sha}^{commit}`]) !== null;
}

/** SHA-256 + size of `path` as stored in commit `sha` (not the working tree). */
export function blobDigest(root: string, sha: string, path: string): { sha256: string; bytes: number } | null {
  if (!SHA1.test(sha) || relPathFailure(path) !== null) return null;
  const b = git(root, ["cat-file", "blob", `${sha}:${path}`]);
  return b === null ? null : { sha256: sha256Buf(b), bytes: b.length };
}

/** true when the checkout is shallow (history truncated: parents of the boundary commit are not available). */
export function isShallow(root: string): boolean {
  return git(root, ["rev-parse", "--is-shallow-repository"])?.toString("utf8").trim() === "true";
}

export type BlobState = "ok" | "absent-in-commit" | "object-unavailable" | "commit-unavailable";

/**
 * Why a blob cannot be read from commit `sha`: the commit is not in this checkout (shallow/partial/wrong clone),
 * the path is not in that commit's tree, or the tree lists it but the blob object is not present locally
 * (partial clone; no lazy fetch is attempted).
 */
export function blobState(root: string, sha: string, path: string): BlobState {
  if (!SHA1.test(sha) || relPathFailure(path) !== null) return "absent-in-commit";
  if (!commitExists(root, sha)) return "commit-unavailable";
  const listed = git(root, ["ls-tree", sha, "--", path]);
  if (listed === null) return "commit-unavailable";
  if (listed.length === 0) return "absent-in-commit";
  return git(root, ["cat-file", "blob", `${sha}:${path}`]) === null ? "object-unavailable" : "ok";
}

/** SHA-256 of `git diff <sha> -- <paths>`; null if git failed. Empty diff => SHA-256 of "". */
export function diffDigest(root: string, sha: string, paths: readonly string[]): { sha256: string; empty: boolean } | null {
  if (!SHA1.test(sha) || paths.some((p) => relPathFailure(p) !== null)) return null;
  const o = git(root, ["diff", "--no-ext-diff", "--no-textconv", "--binary", sha, "--", ...paths]);
  return o === null ? null : { sha256: sha256Buf(o), empty: o.length === 0 };
}

/** "owner/repo" from the origin URL, or null. */
export function repoSlug(root: string): string | null {
  const o = git(root, ["config", "--get", "remote.origin.url"])?.toString("utf8").trim() ?? "";
  const m = o.match(/github\.com[:/]([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/);
  return m ? `${m[1]}/${m[2]}` : null;
}

/**
 * TÖEPÄRA's own, independent view of the change introduced by `sha` against its first parent: both trees are listed
 * with `ls-tree -r` and compared entry by entry in JS (path -> mode/type/object). This deliberately does NOT use
 * `git diff`, which is what KRATT's diff-scope-check runs, so a defect in one implementation is not copied into the
 * check of the other. Returns the changed paths with a deleted flag, or null (no parent, unreadable, too large).
 */
export function changedPathsVsFirstParent(root: string, sha: string): { path: string; deleted: boolean }[] | null {
  if (!SHA1.test(sha)) return null;
  const parent = git(root, ["rev-parse", "--verify", "--quiet", `${sha}^1^{commit}`])?.toString("utf8").trim() ?? "";
  if (!SHA1.test(parent)) return null;
  const tree = (c: string): Map<string, string> | null => {
    const o = git(root, ["ls-tree", "-r", "-z", "--full-tree", c]);
    if (o === null) return null;
    const m = new Map<string, string>();
    for (const rec of o.toString("utf8").split("\0")) {
      if (rec === "") continue;
      const tab = rec.indexOf("\t");
      if (tab < 0) return null;
      m.set(rec.slice(tab + 1), rec.slice(0, tab)); // "<mode> <type> <object>"
    }
    return m;
  };
  const before = tree(parent);
  const after = tree(sha);
  if (before === null || after === null) return null;
  const out: { path: string; deleted: boolean }[] = [];
  for (const [p, v] of after) if (before.get(p) !== v) out.push({ path: p, deleted: false });
  for (const p of before.keys()) if (!after.has(p)) out.push({ path: p, deleted: true });
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** The only files the runtime verifier may read through `runtimeSourceAt` (host-fixed, never task-supplied). */
const RUNTIME_SOURCE = /^(\.nvmrc|package\.json|\.github\/workflows\/[^/]+|\.devcontainer\/[^/]+|docker\/[^/]+|Dockerfile[^/]*|[^/]+\.Dockerfile)$/;

/**
 * A read-only view of commit `sha` for scripts/runtime-verify.mjs (`verifyRuntime({ source })`): the same rules run on
 * git objects instead of the working tree. Only RUNTIME_SOURCE paths can be read; anything else "does not exist".
 * Returns null when the tree cannot be listed.
 */
export function runtimeSourceAt(root: string, sha: string): { isFile(rel: string): boolean; isDir(rel: string): boolean; list(rel: string): string[]; read(rel: string): string } | null {
  if (!SHA1.test(sha)) return null;
  const o = git(root, ["ls-tree", "-r", "-z", "--full-tree", sha]);
  if (o === null) return null;
  const files = new Set<string>();
  for (const rec of o.toString("utf8").split("\0")) {
    const tab = rec.indexOf("\t");
    if (tab < 0) continue;
    const [, type] = rec.slice(0, tab).split(" ");
    const p = rec.slice(tab + 1);
    if (type === "blob" && RUNTIME_SOURCE.test(p)) files.add(p);
  }
  const dirs = new Set<string>([""]);
  for (const f of files) {
    const parts = f.split("/");
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join("/"));
  }
  return {
    isFile: (rel) => files.has(rel),
    isDir: (rel) => dirs.has(rel),
    list: (rel) =>
      [...new Set([...files, ...dirs].filter((p) => p !== "" && p !== rel && (rel === "" ? !p.includes("/") : p.startsWith(`${rel}/`) && !p.slice(rel.length + 1).includes("/"))).map((p) => p.split("/").pop() as string))].sort(),
    read: (rel) => {
      if (!files.has(rel)) throw new Error("not a runtime source");
      const b = git(root, ["cat-file", "blob", `${sha}:${rel}`]);
      if (b === null) throw new Error("blob unreadable");
      return b.toString("utf8");
    },
  };
}
