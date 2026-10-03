import { DispatchError, type Dispatcher } from "../dispatcher.ts";
import { digestOf, validateEnvelope, type TaskEnvelope } from "../protocol/types.ts";
import { depsPackage } from "./deps-package.ts";
import { docsLinks } from "./docs-links.ts";
import { evidenceHash, manifestVerify } from "./evidence.ts";
import { lockfileAudit, supplyChainReview } from "./lockfile.ts";
import { repoMap } from "./repo-map.ts";
import { RepoView } from "./repo-view.ts";
import { schemaValidate } from "./schema-validate.ts";
import { secretsScan } from "./secrets.ts";
import { byAscii, type Contract, type Finding, type Handler } from "./types.ts";

/**
 * THE registry of handler-backed workers. factory/capabilities.ts derives the capability map
 * (and therefore AVAILABLE) from this list, so a worker cannot be AVAILABLE without a handler
 * and a contract. Adding a handler here without a case in factory/tests/handlers.test.ts
 * fails that test (a handler without a test is not allowed to exist).
 */
export const HANDLERS: readonly Handler[] = [
  repoMap,
  depsPackage,
  schemaValidate,
  docsLinks,
  lockfileAudit,
  supplyChainReview,
  secretsScan,
  manifestVerify,
  evidenceHash,
];

export const HANDLER_CAPABILITIES: Readonly<Record<string, readonly string[]>> = Object.fromEntries(
  Object.entries(
    HANDLERS.reduce<Record<string, string[]>>((acc, h) => {
      (acc[h.contract.agent_id] ??= []).push(h.contract.capability);
      return acc;
    }, {}),
  ).sort(([a], [b]) => byAscii(a, b)),
);

export const handlerFor = (agentId: string, capability: string): Handler | undefined =>
  HANDLERS.find((h) => h.contract.agent_id === agentId && h.contract.capability === capability);

export interface HandlerReceipt {
  receipt_kind: "handler/v1";
  protocol_version: 1;
  task_id: string;
  agent_id: string;
  capability: string;
  contract_digest: string;
  repository: string;
  base_sha: string;
  scope: string[];
  result: {
    /** true only when the analysis completed AND produced no error-severity finding. */
    ok: boolean;
    failure: string | null;
    summary: Record<string, unknown>;
    findings: Finding[];
    finding_counts: { error: number; warn: number; info: number };
    findings_truncated: boolean;
  };
  /** Handlers never verify their own output; only TÖEPÄRA may change this. */
  verification_state: "UNVERIFIED";
  timestamp: string;
  receipt_digest: string;
}

export type HandlerRefusal = { ok: false; reason: string };

const rank = { error: 0, warn: 1, info: 2 } as const;
const sortFindings = (f: Finding[]): Finding[] =>
  [...f].sort((a, b) => rank[a.severity] - rank[b.severity] || byAscii(a.path, b.path) || (a.line ?? 0) - (b.line ?? 0) || byAscii(a.code, b.code) || byAscii(a.detail, b.detail));

/** Pre-flight: does this envelope authorise exactly this handler's capability, inside its contract? */
export function checkEnvelope(h: Handler, e: TaskEnvelope): string | null {
  const c: Contract = h.contract;
  if (e.agent_id !== c.agent_id) return "agent-not-handler-owner";
  if (e.allowed_actions.length !== 1 || e.allowed_actions[0] !== c.capability) return "envelope-must-allow-exactly-the-handler-capability";
  if (e.forbidden_actions.includes(c.capability)) return "capability-forbidden";
  if (e.scope.length < c.scope.min || e.scope.length > c.scope.max) return `scope-size-out-of-contract:${c.scope.min}..${c.scope.max}`;
  if (new Set(e.scope).size !== e.scope.length) return "scope-has-duplicates";
  return null;
}

/**
 * Run one handler for one envelope and produce a sealed receipt. Pure with respect to the repo
 * (read-only); the only inputs are the envelope, the repo root and the clock. Never throws for
 * input problems: they come back as `{ok:false}` refusals or as `result.failure`.
 */
export function executeHandler(h: Handler, raw: unknown, root: string, clock: () => string): { ok: true; receipt: HandlerReceipt } | HandlerRefusal {
  const v = validateEnvelope(raw);
  if (!v.ok) return { ok: false, reason: `envelope-invalid:${v.reason}` };
  const e = v.value;
  const bad = checkEnvelope(h, e);
  if (bad) return { ok: false, reason: bad };
  if (!RepoView.commitExists(root, e.base_sha)) return { ok: false, reason: "base-sha-not-found" };
  const view = new RepoView(root, e.base_sha, h.contract.limits);
  let analysis;
  try {
    analysis = h.analyze(view, e.scope, e);
  } catch (err) {
    analysis = { summary: {}, findings: [] as Finding[], failure: `handler-threw:${err instanceof Error ? err.message.slice(0, 120) : "unknown"}` };
  }
  const all = sortFindings(analysis.findings);
  const counts = { error: 0, warn: 0, info: 0 };
  for (const f of all) counts[f.severity]++;
  let keep = Math.min(all.length, h.contract.limits.max_findings);
  let failure: string | null = analysis.failure ?? null;
  const build = (n: number): HandlerReceipt => {
    const body = {
      receipt_kind: "handler/v1" as const,
      protocol_version: 1 as const,
      task_id: e.task_id,
      agent_id: e.agent_id,
      capability: h.contract.capability,
      contract_digest: digestOf(h.contract),
      repository: e.repository,
      base_sha: e.base_sha,
      scope: [...e.scope],
      result: {
        ok: failure === null && counts.error === 0,
        failure,
        summary: failure === "output-budget-exceeded" ? {} : analysis.summary,
        findings: failure === "output-budget-exceeded" ? [] : all.slice(0, n),
        finding_counts: counts,
        findings_truncated: n < all.length,
      },
      verification_state: "UNVERIFIED" as const,
      timestamp: clock(),
    };
    return { ...body, receipt_digest: digestOf(body) };
  };
  let receipt = build(keep);
  const size = (r: HandlerReceipt) => Buffer.byteLength(JSON.stringify(r));
  while (size(receipt) > e.resource_budget.max_output_bytes && keep > 0) {
    keep = Math.floor(keep / 2);
    receipt = build(keep);
  }
  if (size(receipt) > e.resource_budget.max_output_bytes) {
    failure = "output-budget-exceeded";
    receipt = build(0);
  }
  return { ok: true, receipt };
}

export interface HandlerRunDeps {
  root: string;
  /** Host-configured repository ("owner/repo"); an envelope for another repository is refused. */
  repository: string;
  dispatcher: Dispatcher;
  clock: () => string;
}
export type HandlerRunOutcome =
  | { status: "DONE"; receipt: HandlerReceipt }
  | { status: "BLOCKED"; receipt: HandlerReceipt | null; reason: string }
  | { status: "REFUSED"; reason: string };

/**
 * Run a handler task through the dispatcher state machine (SLEEP->READY->ACTIVE->VERIFY->DONE->SLEEP).
 * Findings of severity "error" end the worker BLOCKED (the check did not pass) but the sealed
 * receipt is still returned so the evidence is not lost.
 */
export async function runHandlerTask(raw: unknown, deps: HandlerRunDeps): Promise<HandlerRunOutcome> {
  const v = validateEnvelope(raw);
  if (!v.ok) return { status: "REFUSED", reason: `envelope-invalid:${v.reason}` };
  const e = v.value;
  const cap = e.allowed_actions[0] ?? "";
  const h = handlerFor(e.agent_id, cap);
  if (!h) return { status: "REFUSED", reason: `no-handler:${e.agent_id}:${cap}` };
  const pre = checkEnvelope(h, e);
  if (pre) return { status: "REFUSED", reason: pre };
  if (e.repository !== deps.repository) return { status: "REFUSED", reason: "repository-mismatch" };
  try {
    deps.dispatcher.enqueue(e);
  } catch (err) {
    return { status: "REFUSED", reason: err instanceof DispatchError ? err.code : "enqueue-failed" };
  }
  type Out = { ok: boolean; evidence: string | null; note?: string; receipt?: HandlerReceipt };
  let out: Out | null;
  try {
    out = await deps.dispatcher.run<Out>(
      e.task_id,
      () => {
        const r = executeHandler(h, e, deps.root, deps.clock);
        if (!r.ok) return { ok: false, evidence: null, note: r.reason };
        const evidence = `handler-receipt:${e.task_id}:${r.receipt.receipt_digest}`;
        return r.receipt.result.ok
          ? { ok: true, evidence, receipt: r.receipt }
          : { ok: false, evidence, receipt: r.receipt, note: r.receipt.result.failure ?? `findings:${r.receipt.result.finding_counts.error}` };
      },
      { capability: cap },
    );
  } catch (err) {
    return { status: "REFUSED", reason: err instanceof DispatchError ? err.code : "dispatch-failed" };
  }
  if (out?.ok && out.receipt) return { status: "DONE", receipt: out.receipt };
  return { status: "BLOCKED", receipt: out?.receipt ?? null, reason: out?.note ?? "work-threw" };
}
