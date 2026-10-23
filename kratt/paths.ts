import { realpathSync, statSync } from "node:fs";
import { join, sep } from "node:path";

/**
 * Repo-relative path validation for KRATT. Deliberately an allow-list of characters
 * (not a deny-list of "..") so traversal, absolute paths, dotfiles (.git, .env),
 * backslashes, NUL, drive letters and empty segments are all rejected by construction.
 */
const SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;
export const MAX_PATH_LENGTH = 200;

/** Returns a reason when `p` is not an acceptable repo-relative path, else null. */
export function relPathFailure(p: unknown): string | null {
  if (typeof p !== "string") return "path-not-string";
  if (p.length === 0 || p.length > MAX_PATH_LENGTH) return "path-length-invalid";
  const segments = p.split("/");
  for (const s of segments) if (!SEGMENT.test(s)) return "path-segment-invalid";
  return null;
}

export type ResolvedFile = { ok: true; abs: string; bytes: number } | { ok: false; reason: string };

/**
 * Resolve `rel` under `realRoot` (already realpath'd). Symlinks are followed and the
 * final real path must still be inside the root, so a symlink cannot be used to escape.
 */
export function resolveRegularFile(realRoot: string, rel: string, maxBytes: number): ResolvedFile {
  const bad = relPathFailure(rel);
  if (bad) return { ok: false, reason: bad };
  let real: string;
  try {
    real = realpathSync(join(realRoot, rel));
  } catch {
    return { ok: false, reason: "path-not-found" };
  }
  if (real !== realRoot && !real.startsWith(realRoot + sep)) return { ok: false, reason: "path-escapes-root" };
  try {
    const st = statSync(real);
    if (!st.isFile()) return { ok: false, reason: "not-regular-file" };
    if (st.size > maxBytes) return { ok: false, reason: "file-too-large" };
    return { ok: true, abs: real, bytes: st.size };
  } catch {
    return { ok: false, reason: "path-not-found" };
  }
}
