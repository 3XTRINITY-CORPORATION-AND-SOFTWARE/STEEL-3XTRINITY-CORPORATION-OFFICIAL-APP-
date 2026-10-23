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
 * Two entry points:
 *  - `decideWithAdapters`: synchronous adapters (unchanged).
 *  - `decideWithAdaptersAsync`: adapters may return a Promise (a network-backed client). Each adapter
 *    gets a deadline (default 2000 ms, 1..60000) and an AbortSignal. Timeout, rejection, a synchronous
 *    throw, a non-string answer, a missing adapter or an invalid timeout => verdict absent => FAIL_CLOSED.
 *    A late answer after the deadline is ignored (the decision is already final). Never PROCEED on any
 *    of these, never an exception. Sync adapters (e.g. `stubAdapter`) are valid async adapters.
 * Still NOT built: a real TÖEPÄRA / Trust Gate client or its wire protocol.
 */
export interface VerdictAdapter {
  readonly name: string;
  /** Return the upstream verdict string for this evidence. Throwing is allowed and means "no verdict". */
  verdict(evidence: Readonly<NormalizedInput>): unknown;
}

/** May answer synchronously or with a Promise. `signal` is aborted when the deadline passes: stop work, the answer is ignored. */
export interface AsyncVerdictAdapter {
  readonly name: string;
  verdict(evidence: Readonly<NormalizedInput>, signal: AbortSignal): unknown;
}

export interface AsyncAdapters {
  toepara: AsyncVerdictAdapter | VerdictAdapter;
  trustGate: AsyncVerdictAdapter | VerdictAdapter;
}

export const DEFAULT_ADAPTER_TIMEOUT_MS = 2000;
export const MAX_ADAPTER_TIMEOUT_MS = 60_000;

/** How an adapter call ended. Only "ok" carries a verdict string (which the pipeline still checks for EXACT equality). */
export type AdapterOutcome = "ok" | "timeout" | "threw" | "rejected" | "malformed" | "missing" | "invalid-timeout";

export interface AsyncDecision {
  receipt: RecoveryReceipt;
  outcomes: { toepara: AdapterOutcome; trustGate: AdapterOutcome };
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

async function askAsync(adapter: AsyncVerdictAdapter | VerdictAdapter | undefined, evidence: Readonly<NormalizedInput>, timeoutMs: number): Promise<{ verdict: string | null; outcome: AdapterOutcome }> {
  if (typeof adapter !== "object" || adapter === null || typeof adapter.verdict !== "function") return { verdict: null, outcome: "missing" };
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    let answer: unknown;
    try {
      answer = adapter.verdict(evidence, controller.signal);
    } catch {
      return { verdict: null, outcome: "threw" };
    }
    const deadline = new Promise<{ verdict: null; outcome: "timeout" }>((res) => {
      timer = setTimeout(() => {
        controller.abort();
        res({ verdict: null, outcome: "timeout" });
      }, timeoutMs);
    });
    // Promise.resolve adopts thenables safely (a throwing `then` getter => rejection); the first settlement wins.
    const settled = Promise.resolve(answer).then(
      (v): { verdict: string | null; outcome: AdapterOutcome } => (typeof v === "string" ? { verdict: v, outcome: "ok" } : { verdict: null, outcome: "malformed" }),
      (): { verdict: null; outcome: AdapterOutcome } => ({ verdict: null, outcome: "rejected" }),
    );
    return await Promise.race([settled, deadline]);
  } catch {
    return { verdict: null, outcome: "threw" };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

const validTimeout = (t: unknown): t is number => typeof t === "number" && Number.isInteger(t) && t >= 1 && t <= MAX_ADAPTER_TIMEOUT_MS;

/**
 * Async variant of `decideWithAdapters`: same pipeline, same receipt, verdicts from (possibly async) adapters with a deadline.
 * Resolves, never rejects. Any adapter failure => that verdict is absent => FAIL_CLOSED.
 */
export async function decideWithAdaptersAsync(input: unknown, adapters: AsyncAdapters, opts: { timeoutMs?: number } = {}): Promise<AsyncDecision> {
  try {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_ADAPTER_TIMEOUT_MS;
    const n = normalizeInput(input);
    if (!n.ok) return { receipt: malformedInputReceipt(n.reason, "adapter"), outcomes: { toepara: "missing", trustGate: "missing" } };
    const evidence: Readonly<NormalizedInput> = Object.freeze({ ...n.value, toepara: null, trustGate: null });
    if (!validTimeout(timeoutMs)) {
      return { receipt: evaluate({ ...n.value, toepara: null, trustGate: null }, "adapter"), outcomes: { toepara: "invalid-timeout", trustGate: "invalid-timeout" } };
    }
    const [t, g] = await Promise.all([askAsync(adapters?.toepara, evidence, timeoutMs), askAsync(adapters?.trustGate, evidence, timeoutMs)]);
    return { receipt: evaluate({ ...n.value, toepara: t.verdict, trustGate: g.verdict }, "adapter"), outcomes: { toepara: t.outcome, trustGate: g.outcome } };
  } catch {
    return { receipt: malformedInputReceipt("internal-error", "adapter"), outcomes: { toepara: "threw", trustGate: "threw" } };
  }
}

/** STUB for tests / local wiring only: returns a fixed verdict. Proves nothing about any real system. */
export function stubAdapter(name: string, fixedVerdict: unknown): VerdictAdapter {
  return { name: `stub:${name}`, verdict: () => fixedVerdict };
}
