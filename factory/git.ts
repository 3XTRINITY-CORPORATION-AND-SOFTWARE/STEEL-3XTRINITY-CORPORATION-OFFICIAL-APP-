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
