import { evaluate, malformedInputReceipt, type RecoveryReceipt } from "../core/decide.ts";
import { normalizeInput, type NormalizedInput } from "../core/normalize.ts";

/**
 * Seam for the real TÖEPÄRA and Trust Gate systems.
 *
 * NOTHING HERE IS A REAL INTEGRATION. No TÖEPÄRA or Trust Gate client exists in this
 * repo. This file only fixes the contract a real client must satisfy so that:
 *  - the verdict comes from the adapter, not from a string the caller typed;
 *  - an adapter that throws, returns a non-string, or is missing => the verdict is
 *    treated as absent => FAIL_CLOSED (never an exception, never PROCEED);
 *  - the adapters are mandatory parameters, so neither gate can be omitted.
 *
 * Adapters are synchronous here; a real network-backed client will need an async
 * variant (with timeout => deny), which is deliberately NOT built until its protocol exists.
 */
export interface VerdictAdapter {
  readonly name: string;
  /** Return the upstream verdict string for this evidence. Throwing is allowed and means "no verdict". */
  verdict(evidence: Readonly<NormalizedInput>): unknown;
}

export interface Adapters {
  toepara: VerdictAdapter;
  trustGate: VerdictAdapter;
}

function ask(adapter: VerdictAdapter | undefined, evidence: Readonly<NormalizedInput>): string | null {
  try {
    const v = adapter?.verdict(evidence);
    return typeof v === "string" ? v : null;
  } catch {
    return null;
  }
}

/**
 * Same pipeline as `decide`, but TÖEPÄRA / Trust Gate verdicts come from adapters.
 * Any `toepara` / `trustGate` fields present in the caller's input are ignored.
 */
export function decideWithAdapters(input: unknown, adapters: Adapters): RecoveryReceipt {
  try {
    const n = normalizeInput(input);
    if (!n.ok) return malformedInputReceipt(n.reason, "adapter");
    // Adapters get a snapshot with the caller's own verdict fields blanked.
    const evidence: Readonly<NormalizedInput> = Object.freeze({ ...n.value, toepara: null, trustGate: null });
    return evaluate(
      {
        ...n.value,
        toepara: ask(adapters?.toepara, evidence),
        trustGate: ask(adapters?.trustGate, evidence),
      },
      "adapter",
    );
  } catch {
    return malformedInputReceipt("internal-error", "adapter");
  }
}

/** STUB for tests / local wiring only: returns a fixed verdict. Proves nothing about any real system. */
export function stubAdapter(name: string, fixedVerdict: unknown): VerdictAdapter {
  return { name: `stub:${name}`, verdict: () => fixedVerdict };
}
