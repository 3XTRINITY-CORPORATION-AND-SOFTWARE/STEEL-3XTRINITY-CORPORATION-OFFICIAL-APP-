import { sha256Hex } from "../cerberus/artifact-trust/artifact-trust.ts";
import { decideWithAdaptersAsync, stubAdapter, type AsyncVerdictAdapter } from "../cerberus/integrations/verdict-adapters.ts";
import type { RastikFinding } from "./protocol/types.ts";
import { resolveTrustGate, type TrustGateRequest } from "./trust-gate.ts";

// ---------------------------------------------------------------------------------------------
// ASYNC TRUST GATE: an unavailable / hostile Trust Gate must never yield PROCEED (F-P1-TG-002).
// Hypothesis for every case: "with this misbehaving gate the decision is PROCEED". The control (a
// prompt AUTHORIZED gate) MUST PROCEED, otherwise the battery is vacuous and nothing is reported.
// The decision target is injectable so a test can prove the battery catches a gate with no deadline.
// ---------------------------------------------------------------------------------------------

/** Decide with `trustGate` as the (only) Trust Gate, TÖEPÄRA a prompt ADMITTED stub. Resolves "PROCEED" or anything else (= denied). */
export type AsyncGateTarget = (trustGate: AsyncVerdictAdapter, timeoutMs: number) => Promise<string>;

export const ASYNC_GATE_TIMEOUT_MS = 30;
const LATE_MS = 120; // > ASYNC_GATE_TIMEOUT_MS: a verdict that arrives after the deadline
const WATCHDOG_MS = 1000; // the harness stops waiting here; a target still pending is a HUNG finding (no decision at all)

const asyncGateInput = (): Record<string, unknown> => {
  const content = "rastik-async-trust-gate";
  return { action: "detect", toepara: "ADMITTED", trustGate: "AUTHORIZED", artifact: { name: "rastik.json", content, sha256: sha256Hex(content) } };
};

/** Target 1: the Cerberus core async adapter seam. */
export const cerberusAsyncTarget: AsyncGateTarget = async (trustGate, timeoutMs) =>
  (await decideWithAdaptersAsync(asyncGateInput(), { toepara: stubAdapter("toepara", "ADMITTED"), trustGate }, { timeoutMs })).receipt.decision;

/** Target 2: the factory Trust Gate resolver (factory/trust-gate.ts) behind cerberusDecide; AUTHORIZED is its PROCEED. */
export const factoryResolveTarget: AsyncGateTarget = async (trustGate, timeoutMs) => {
  const req = Object.freeze({ task_id: "rastik", repository: "r", action: "hash-files", envelope: {}, host_repository: "r" }) as unknown as TrustGateRequest;
  const signal = new AbortController().signal; // resolveTrustGate passes no signal; the gate sees a never-aborted one
  const r = await resolveTrustGate({ name: trustGate.name, evaluate: () => Promise.resolve().then(() => trustGate.verdict(Object.freeze({}) as never, signal)) }, req, timeoutMs);
  return r.verdict === "AUTHORIZED" ? "PROCEED" : "FAIL_CLOSED";
};

const later = <T>(ms: number, v: T): Promise<T> => new Promise((res) => setTimeout(() => res(v), ms));
const gate = (name: string, verdict: (signal: AbortSignal) => unknown): AsyncVerdictAdapter => ({ name, verdict: (_e, signal) => verdict(signal) });

interface AsyncGateCase { id: string; hypothesis: string; gate: () => AsyncVerdictAdapter }

const ASYNC_GATE_CASES: AsyncGateCase[] = [
  { id: "hang-forever", hypothesis: "a Trust Gate that never answers yields PROCEED (or no decision)", gate: () => gate("hang", () => new Promise(() => {})) },
  { id: "hang-ignoring-abort", hypothesis: "a Trust Gate that ignores the abort signal and never answers yields PROCEED", gate: () => gate("hang-no-abort", () => new Promise(() => {})) },
  { id: "sync-throw", hypothesis: "a Trust Gate that throws synchronously yields PROCEED", gate: () => gate("throw", () => { throw new Error("gate down"); }) },
  { id: "async-reject", hypothesis: "a Trust Gate whose promise rejects yields PROCEED", gate: () => gate("reject", () => Promise.reject(new Error("503"))) },
  { id: "slow-authorized-after-deadline", hypothesis: "an AUTHORIZED that arrives after the deadline yields PROCEED", gate: () => gate("slow", () => later(LATE_MS, "AUTHORIZED")) },
  { id: "authorized-after-abort", hypothesis: "a gate that answers AUTHORIZED only once it is aborted yields PROCEED", gate: () => gate("on-abort", (s) => new Promise((res) => s.addEventListener("abort", () => res("AUTHORIZED")))) },
  { id: "malformed-object-verdict", hypothesis: "a structured { verdict: \"AUTHORIZED\" } response yields PROCEED", gate: () => gate("obj", async () => ({ verdict: "AUTHORIZED" })) },
  { id: "malformed-boxed-string", hypothesis: "a boxed String(\"AUTHORIZED\") response yields PROCEED", gate: () => gate("boxed", async () => new String("AUTHORIZED")) },
  { id: "malformed-array", hypothesis: "an [\"AUTHORIZED\"] response yields PROCEED", gate: () => gate("arr", async () => ["AUTHORIZED"]) },
  { id: "malformed-padded", hypothesis: "a whitespace-padded \" AUTHORIZED\" response yields PROCEED", gate: () => gate("pad", async () => " AUTHORIZED") },
  { id: "malformed-lowercase", hypothesis: "a lowercase \"authorized\" response yields PROCEED", gate: () => gate("lower", async () => "authorized") },
  { id: "malformed-wrong-vocabulary", hypothesis: "an \"ADMITTED\" / \"PROCEED\" response (another stage's word) yields PROCEED", gate: () => gate("vocab", async () => "PROCEED") },
  { id: "malformed-null", hypothesis: "a null response yields PROCEED", gate: () => gate("null", async () => null) },
  { id: "malformed-undefined", hypothesis: "an empty (undefined) response yields PROCEED", gate: () => gate("undef", async () => undefined) },
  { id: "echo-caller-claimed-verdict", hypothesis: "a rubber-stamp gate that echoes the caller-typed trustGate field (\"AUTHORIZED\") yields PROCEED", gate: () => ({ name: "echo", verdict: (e) => (e as { trustGate?: unknown }).trustGate }) },
  { id: "hostile-thenable-getter", hypothesis: "a response whose `then` getter throws yields PROCEED or throws", gate: () => gate("thenable", () => Object.defineProperty({}, "then", { get() { throw new Error("x"); } })) },
];

export function asyncGateCaseCount(): number {
  return ASYNC_GATE_CASES.length;
}

export interface AsyncGateAttackRecord {
  attack_id: string;
  case_id: string;
  hypothesis: string;
  outcome: "REPELLED" | "SUCCEEDED" | "HUNG";
  reproduced: boolean | null;
  decision: string;
  elapsed_ms: number;
}

async function runGateOnce(target: AsyncGateTarget, g: AsyncVerdictAdapter): Promise<{ decision: string; elapsed_ms: number }> {
  const t0 = Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const watchdog = new Promise<string>((res) => { timer = setTimeout(() => res("<no decision>"), WATCHDOG_MS); });
  try {
    const decision = await Promise.race([target(g, ASYNC_GATE_TIMEOUT_MS).then((d) => String(d), () => "<target threw>"), watchdog]);
    return { decision, elapsed_ms: Date.now() - t0 };
  } finally {
    clearTimeout(timer);
  }
}

export async function runAsyncTrustGateAttacks(
  target: AsyncGateTarget = cerberusAsyncTarget,
  o: { only?: string; targetName?: string } = {},
): Promise<{ control_proceeds: boolean; records: AsyncGateAttackRecord[]; findings: RastikFinding[] }> {
  const targetName = o.targetName ?? "cerberus/integrations/verdict-adapters.ts decideWithAdaptersAsync";
  const control = await runGateOnce(target, gate("control", async () => "AUTHORIZED"));
  const control_proceeds = control.decision === "PROCEED";
  const records: AsyncGateAttackRecord[] = [];
  const findings: RastikFinding[] = [];
  if (!control_proceeds) return { control_proceeds, records, findings };
  for (const c of ASYNC_GATE_CASES) {
    if (o.only !== undefined && c.id !== o.only) continue;
    const attack_id = `async-trust-gate/${c.id}`;
    const first = await runGateOnce(target, c.gate());
    const bad = (d: string): boolean => d === "PROCEED" || d === "<no decision>" || d === "<target threw>";
    if (!bad(first.decision)) {
      records.push({ attack_id, case_id: c.id, hypothesis: c.hypothesis, outcome: "REPELLED", reproduced: null, decision: first.decision, elapsed_ms: first.elapsed_ms });
      continue;
    }
    const again = bad((await runGateOnce(target, c.gate())).decision);
    records.push({ attack_id, case_id: c.id, hypothesis: c.hypothesis, outcome: first.decision === "<no decision>" ? "HUNG" : "SUCCEEDED", reproduced: again, decision: first.decision, elapsed_ms: first.elapsed_ms });
    findings.push({
      finding_id: `RASTIK-ASYNC-GATE-${c.id}`,
      target: targetName,
      hypothesis: c.hypothesis,
      reproduction: `Run runAsyncTrustGateAttacks(<target>, { only: ${JSON.stringify(c.id)} }) (factory/rastik-async-gate.ts ASYNC_GATE_CASES, deadline ${ASYNC_GATE_TIMEOUT_MS} ms): the decision was ${first.decision}${again ? " on two independent runs" : " once, but not on the re-run"}.`,
      severity: "critical",
      status: again ? "CONFIRMED" : "UNCONFIRMED",
      evidence: { attack_id, decision: first.decision, elapsed_ms: first.elapsed_ms, reproduced: again },
      regression_test: [
        `test(${JSON.stringify(`RASTIK async-trust-gate/${c.id}: must FAIL_CLOSED within the deadline`)}, async () => {`,
        `  // hypothesis: ${c.hypothesis}`,
        `  const r = await runAsyncTrustGateAttacks(cerberusAsyncTarget, { only: ${JSON.stringify(c.id)} });`,
        `  assert.equal(r.control_proceeds, true);`,
        `  assert.deepEqual(r.findings.map((f) => f.finding_id), []);`,
        `});`,
      ].join("\n"),
      proposed_smallest_fix: "Race every Trust Gate call against a deadline (clear the timer, abort the call); timeout, rejection, a synchronous throw or anything but the exact string AUTHORIZED => verdict absent => FAIL_CLOSED; ignore late answers.",
    });
  }
  return { control_proceeds, records, findings };
}
