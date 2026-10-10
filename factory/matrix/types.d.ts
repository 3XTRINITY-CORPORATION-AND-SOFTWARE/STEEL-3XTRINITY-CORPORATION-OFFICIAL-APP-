// Types of the matrix spec harness (checked by tsconfig.cerberus.json through JSDoc in the .mjs files).
// The TARGET modules a spec exercises are loaded dynamically from any repo file, so a probe receives them as `any`:
// that is the one honest untyped boundary. Everything else (spec shape, ctx, results) is typed.

export interface ExecOptions {
  args?: string[];
  files?: Record<string, string>;
  stageAs?: string;
  env?: Record<string, string>;
  cwd?: string;
  input?: string;
  nodeArgs?: string[];
  linkAs?: string;
  /** repo-relative paths whose text (or null) is returned in `files` after the run */
  collect?: string[];
}
export interface ExecResult {
  status: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  files: Record<string, string | null>;
}
export interface Ctx {
  root: string;
  /** Run the REAL target script as a CLI; counts as a call into the target. */
  execTarget(opts?: ExecOptions): ExecResult;
}
/** The dynamically imported target module namespace (or `{ text }` for data targets). */
export type TargetModule = any;

interface SpecBase {
  slot: number;
  target: string;
  expected: unknown;
  /** at least 20 characters of written claim */
  claim: string;
  /** true when no domain code is under test (config / data pin): reported as CONFIG_PINNED */
  config?: boolean;
}
export interface FnSpec extends SpecBase {
  fn: string;
  input: unknown[];
  run?: undefined;
}
export interface RunSpec extends SpecBase {
  fn?: undefined;
  input?: undefined;
  run: (m: TargetModule, ctx: Ctx) => unknown;
}
export type Spec = FnSpec | RunSpec;
