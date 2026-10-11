// Types for scripts/runtime-verify.mjs (imported by kratt/actions.ts and factory/toepara.ts).
export declare const EXPECTED_MAJOR: number;
export interface RuntimeSource {
  isFile(rel: string): boolean;
  isDir(rel: string): boolean;
  list(rel: string): string[];
  read(rel: string): string;
}
export interface RuntimeSourceResult {
  source: string;
  found: string;
  ok: boolean;
  reason?: string;
}
export interface RuntimeReport {
  status: "RUNTIME_OK" | "RUNTIME_DRIFT";
  expected: number;
  sources: RuntimeSourceResult[];
  drift: RuntimeSourceResult[];
}
export declare function fsSource(root: string): RuntimeSource;
export declare function verifyRuntime(opts?: { root?: string; source?: RuntimeSource; localVersion?: string; expected?: number }): RuntimeReport;
export declare function render(r: RuntimeReport): string;
export declare function parseMajor(text: string): number | null;
export declare function satisfies(version: string, range: string): boolean;
export declare function rangePinsMajor(range: string, major?: number): { ok: boolean; missing: string[]; leaked: string[] };
export declare function stripJsonc(text: string): string;
