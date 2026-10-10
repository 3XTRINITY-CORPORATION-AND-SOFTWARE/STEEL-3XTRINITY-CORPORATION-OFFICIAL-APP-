import type { TaskEnvelope } from "../protocol/types.ts";
import type { RepoView } from "./repo-view.ts";

/**
 * Handler contract for the bounded, read-only analysis workers.
 *
 * A worker is AVAILABLE only if it appears in `HANDLERS` (handlers/index.ts): that single list
 * is what factory/capabilities.ts derives the capability map from, so "contract + handler" is
 * structural. The third leg (a test with distinct behaviour per handler) is enforced by
 * factory/tests/handlers.test.ts, which fails if a registered handler has no case table entry.
 *
 * Permissions are fixed literals on purpose: a handler can only read git objects of the task's
 * `base_sha`. It never touches the working tree, writes, spawns anything but a read-only git
 * argv (inside repo-view.ts, the single module allowed to), uses the network or reads the env.
 */
export interface Contract {
  contract_version: 1;
  capability: string;
  agent_id: string;
  /** Must equal the frozen role name in factory/roles.ts (asserted by a test). */
  role: string;
  summary: string;
  permissions: { read: "git-objects-at-base_sha"; write: false; network: false; env: false; spawn: "git-readonly-argv-in-repo-view-only" };
  scope: { min: number; max: number; kind: "file" | "path"; meaning: string };
  limits: { max_file_bytes: number; max_total_bytes: number; max_findings: number };
  /** Keys the analysis always puts into `result.summary` (asserted by a test). */
  summary_keys: readonly string[];
}

export type Severity = "error" | "warn" | "info";
export interface Finding {
  severity: Severity;
  code: string;
  path: string;
  line?: number;
  detail: string;
}

export interface Analysis {
  summary: Record<string, unknown>;
  findings: Finding[];
  /** Set when the analysis could not run to completion (unreadable input, parse failure...). */
  failure?: string;
}

export interface Handler {
  contract: Contract;
  analyze(view: RepoView, scope: readonly string[], env: TaskEnvelope): Analysis;
}

export const DEFAULT_LIMITS = { max_file_bytes: 2 * 1024 * 1024, max_total_bytes: 16 * 1024 * 1024, max_findings: 100 } as const;

export const READ_ONLY = {
  read: "git-objects-at-base_sha",
  write: false,
  network: false,
  env: false,
  spawn: "git-readonly-argv-in-repo-view-only",
} as const;

export const byAscii = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
