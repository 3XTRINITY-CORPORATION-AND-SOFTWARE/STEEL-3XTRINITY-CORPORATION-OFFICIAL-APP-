import { randomBytes } from "node:crypto";
import { closeSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, unlinkSync, writeSync, existsSync } from "node:fs";
import { join } from "node:path";

/**
 * One-time-use registry of evidence digests. `consume` is the only way to pass: it returns
 * true exactly once per digest, for every caller sharing the same store, and false otherwise.
 * ANY failure (bad digest, unwritable store, unexpected filesystem state) returns false: fail closed.
 */
export interface ReplayStore {
  consume(digest: string): boolean;
}

const DIGEST = /^[0-9a-f]{64}$/;

/**
 * File-backed ReplayStore. One marker file per digest in `dir`.
 *
 * Atomicity / cross-process safety: the marker content is written and fsynced to a private temp
 * file, then published with link(2) to its final name. link fails with EEXIST if the name exists,
 * so exactly one of any number of concurrent processes wins, and a reader can never observe a
 * half-written marker. Durability: file and directory are fsynced before `consume` returns true,
 * so a consumed digest survives a process restart (and, on a journalling fs, a crash).
 *
 * Limits (honest): protects against replay between processes that share this directory on a
 * local POSIX filesystem. It does not protect against someone who can delete markers (needs
 * filesystem permissions / an external service), and `link` semantics on network filesystems vary.
 */
export class FileReplayGuard implements ReplayStore {
  readonly dir: string;
  /** Diagnostic only: the last reason consume returned false, or null. */
  lastDenyReason: string | null = null;
  constructor(dir: string) {
    this.dir = dir;
  }

  #prepare(): boolean {
    try {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      const st = lstatSync(this.dir);
      if (st.isSymbolicLink() || !st.isDirectory()) return this.#deny("store-not-a-plain-directory");
      return true;
    } catch {
      return this.#deny("store-unavailable");
    }
  }
  #deny(why: string): false {
    this.lastDenyReason = why;
    return false;
  }

  has(digest: string): boolean {
    return DIGEST.test(digest) && existsSync(join(this.dir, `${digest}.consumed`));
  }

  consume(digest: string): boolean {
    this.lastDenyReason = null;
    if (typeof digest !== "string" || !DIGEST.test(digest)) return this.#deny("invalid-digest");
    if (!this.#prepare()) return false;
    const final = join(this.dir, `${digest}.consumed`);
    const tmp = join(this.dir, `.tmp-${process.pid}-${randomBytes(8).toString("hex")}`);
    let fd: number | null = null;
    try {
      fd = openSync(tmp, "wx", 0o600);
      writeSync(fd, JSON.stringify({ digest, pid: process.pid }) + "\n");
      fsyncSync(fd);
      closeSync(fd);
      fd = null;
      try {
        linkSync(tmp, final);
      } catch (e) {
        return this.#deny((e as NodeJS.ErrnoException).code === "EEXIST" ? "replayed" : "publish-failed");
      }
      try {
        const d = openSync(this.dir, "r");
        try {
          fsyncSync(d);
        } finally {
          closeSync(d);
        }
      } catch {
        /* directory fsync is best effort; the marker is already published */
      }
      return true;
    } catch {
      return this.#deny("store-write-failed");
    } finally {
      if (fd !== null) {
        try {
          closeSync(fd);
        } catch {
          /* ignore */
        }
      }
      try {
        unlinkSync(tmp);
      } catch {
        /* temp already gone */
      }
    }
  }
}
