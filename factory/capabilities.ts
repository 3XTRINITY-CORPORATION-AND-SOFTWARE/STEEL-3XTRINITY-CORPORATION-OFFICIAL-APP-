import { HANDLER_CAPABILITIES } from "./handlers/index.ts";
import type { CapabilityMap } from "./registry.ts";

/**
 * The ONLY workers that have executable code behind them, and exactly which capabilities.
 * Two sources, both with executable code:
 *   - LOOP_CAPABILITIES: closed-loop stage workers, handled in factory/loop.ts (asserted by a test);
 *   - HANDLER_CAPABILITIES: bounded read-only analysis workers, derived from the handler list in
 *     factory/handlers/index.ts (each has a contract; tests in factory/tests/handlers*.test.ts
 *     refuse a handler without a case).
 * A worker not listed has no capability and is therefore never AVAILABLE.
 */
export const ATTACK_CLASSES = [
  "invalid-input",
  "boundary",
  "missing-evidence",
  "tampered-evidence",
  "unauthorized-action",
  "stale-base-sha",
  "malformed-receipt",
  "replay",
] as const;
export type AttackClass = (typeof ATTACK_CLASSES)[number];

/** attack class -> SERPENT worker whose role matches it. */
export const ATTACK_AGENT: Readonly<Record<AttackClass, string>> = {
  "invalid-input": "SERPENT-052", // Input Fuzzer
  boundary: "SERPENT-053", // Boundary Tester
  "missing-evidence": "SERPENT-064", // Evidence Tester
  "tampered-evidence": "SERPENT-065", // Digest Tester
  "unauthorized-action": "SERPENT-062", // Authorization Tester
  "stale-base-sha": "SERPENT-060", // Replay Tester (freshness)
  "malformed-receipt": "SERPENT-056", // Schema Breaker
  replay: "SERPENT-060", // Replay Tester
};

export const LOOP_CAPABILITIES: CapabilityMap = {
  "FORGE-026": ["kratt:hash-files", "kratt:validate-manifest", "kratt:run-test"], // KRATT Engineer
  "SERPENT-051": ["rastik:run-probes"], // RÄSTIK Commander
  "SERPENT-052": ["rastik:attack:invalid-input"],
  "SERPENT-053": ["rastik:attack:boundary"],
  "SERPENT-056": ["rastik:attack:malformed-receipt"],
  "SERPENT-060": ["rastik:attack:stale-base-sha", "rastik:attack:replay"],
  "SERPENT-062": ["rastik:attack:unauthorized-action"],
  "SERPENT-064": ["rastik:attack:missing-evidence"],
  "SERPENT-065": ["rastik:attack:tampered-evidence"],
  "CITADEL-101": ["toepara:verify"], // TÖEPÄRA Commander
  "CITADEL-111": ["cerberus:decide"], // CERBERUS Commander
};

function merge(...maps: CapabilityMap[]): CapabilityMap {
  const out: Record<string, string[]> = {};
  for (const m of maps)
    for (const [id, caps] of Object.entries(m)) {
      const cur = (out[id] ??= []);
      for (const c of caps) {
        if (cur.includes(c)) throw new Error(`duplicate capability ${id}:${c}`);
        cur.push(c);
      }
    }
  return out;
}

export const CAPABILITIES: CapabilityMap = merge(LOOP_CAPABILITIES, HANDLER_CAPABILITIES);

export const HANDLER_KEYS: readonly string[] = Object.entries(CAPABILITIES).flatMap(([id, caps]) => caps.map((c) => `${id}:${c}`));
