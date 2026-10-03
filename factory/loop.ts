import { verifyReceipt, type RecoveryReceipt } from "../cerberus/core/decide.ts";
import type { ReplayStore } from "./replay-store.ts";
import { bundleSubject, rastikSubject, signSubject, type ArtifactSignatures, type SignatureReport, type SigningPolicy } from "./signing.ts";
import type { KrattAction } from "../kratt/task.ts";
import { ATTACK_AGENT, ATTACK_CLASSES, CAPABILITIES, HANDLER_KEYS, type AttackClass } from "./capabilities.ts";
import { cerberusDecide, denyWithoutReceipt, type GateOutput } from "./cerberus-gate.ts";
import { decideIdempotent, type DecisionLedger } from "./replay-ledger.ts";
import { DispatchError, Dispatcher, type TransitionRecord } from "./dispatcher.ts";
import { headSha } from "./git.ts";
import { envelopeToKrattTask, runKrattStage } from "./kratt-stage.ts";
import {
  PROTOCOL_VERSION,
  digestOf,
  validateCerberusDecision,
  validateEnvelope,
  type ActionReceipt,
  type CerberusDecision,
  type RastikFinding,
  type TaskEnvelope,
  type ToeparaVerdict,
  type EvidenceBundle,
} from "./protocol/types.ts";
import { assembleRun, configureParentLookup, realAttackTarget, runAttackClass, runProbes, type AttackTarget } from "./rastik-attacks.ts";
import { rastikEvidenceDigest, type AttackRecord, type ProbeSummary, type RastikRun } from "./rastik-types.ts";
import { buildInitialRegistry, type Registry } from "./registry.ts";
import { bundleDigest, toeparaVerify } from "./toepara.ts";

/**
 * ARCHIDECT closed loop (first milestone):
 *
 *   TaskEnvelope (GOLIATH STAND-IN) -> dispatcher -> KRATT real action -> ActionReceipt (UNVERIFIED)
 *     -> RÄSTIK attacks that exact receipt -> TÖEPÄRA independent verification -> CERBERUS ADMIT/DENY/QUARANTINE
 *     -> structured final receipt
 *
 * Every stage is executed by a registry worker through `Dispatcher.run`, so the worker
 * transitions in the final receipt are the dispatcher's real log, not a narrative.
 */
export const GOLIATH_STAND_IN = {
  name: "GOLIATH-STAND-IN",
  real_goliath: false,
  note: "typed in-process caller; no GOLIATH control-plane spec exists in the repositories, so this is NOT the real GOLIATH",
} as const;

export interface LoopDeps {
  root: string;
  /** Host-configured repository this installation verifies for ("owner/repo"). */
  repository: string;
  dispatcher: Dispatcher;
  /** Replay store: in-memory `ReplayGuard` or the persistent `FileReplayGuard`. */
  guard: ReplayStore;
  /**
   * Optional persistent decision ledger (FACTORY_REPLAY_DIR). When set, the CERBERUS decision goes through `decideIdempotent`:
   * the request is evaluated once per ledger and the decision is stored. A request whose decision is already stored (or whose
   * ledger is unavailable) cannot be turned back into a full closed-loop receipt - the CERBERUS pipeline receipt is not stored -
   * so the loop answers with a DENY refusal that names the stored decision; it never re-admits and never fabricates a receipt.
   */
  ledger?: DecisionLedger;
  /** Evidence authentication. Absent => no signing (artifacts UNSIGNED, nothing required). */
  signing?: SigningPolicy;
  clock: () => string;
  /** The component RÄSTIK attacks. Default: the real TÖEPÄRA + Cerberus path. Injectable for mutation tests. */
  attackTarget?: AttackTarget;
  /** Run the existing rastik/ probes selected by the scope (default true). */
  runProbes?: boolean;
}

export interface StageRecord {
  stage: "KRATT" | "RASTIK" | "RASTIK_ATTACK" | "TOEPARA" | "CERBERUS";
  agent_id: string;
  task_id: string;
  capability: string;
  /** DONE if the worker reached DONE, BLOCKED if it ended BLOCKED -> SLEEP. */
  outcome: "DONE" | "BLOCKED" | "NOT_RUN";
  note: string | null;
  transitions: TransitionRecord[];
}

export interface ClosedLoopReceipt {
  receipt_kind: "closed-loop/v1";
  protocol_version: 1;
  caller: typeof GOLIATH_STAND_IN;
  task_id: string | null;
  envelope_digest: string | null;
  repository: string | null;
  base_sha: string | null;
  stages: StageRecord[];
  action_receipt: ActionReceipt | null;
  rastik: RastikRun | null;
  toepara: { verdict: ToeparaVerdict; bundle: EvidenceBundle | null } | null;
  cerberus: { decision: CerberusDecision; cerberus_receipt: RecoveryReceipt };
  final_decision: CerberusDecision["decision"];
  forge_followups: string[];
  /** Present only when a signing policy was configured. */
  signing?: SignatureReport;
  final_digest: string;
}

export function makeDispatcher(clock: () => string, registry: Registry = buildInitialRegistry(CAPABILITIES)): Dispatcher {
  return new Dispatcher(registry, { clock, handlers: HANDLER_KEYS });
}

function child(parent: TaskEnvelope, o: { suffix: string; agent_id: string; objective: string; allowed: string[]; required: string[] }): TaskEnvelope {
  const task_id = `${parent.task_id}-${o.suffix}`;
  if (task_id.length > 64) throw new Error("derived-task-id-too-long");
  return {
    ...structuredClone(parent),
    task_id,
    factory: o.agent_id.startsWith("SERPENT") ? "SERPENT" : o.agent_id.startsWith("CITADEL") ? "CITADEL" : "FORGE",
    agent_id: o.agent_id,
    objective: o.objective,
    allowed_actions: o.allowed,
    required_evidence: o.required,
  };
}

function stageOf(d: Dispatcher, stage: StageRecord["stage"], env: TaskEnvelope, capability: string, ran: boolean, note: string | null): StageRecord {
  const transitions = d.log.filter((t) => t.task_id === env.task_id);
  const last = [...transitions].reverse().find((t) => t.accepted && (t.to === "DONE" || t.to === "BLOCKED"));
  return { stage, agent_id: env.agent_id, task_id: env.task_id, capability, outcome: !ran ? "NOT_RUN" : last?.to === "DONE" ? "DONE" : "BLOCKED", note, transitions };
}

function seal(r: Omit<ClosedLoopReceipt, "final_digest">): ClosedLoopReceipt {
  return { ...r, final_digest: digestOf(r) };
}

function refusal(taskId: string | null, reason: string, stages: StageRecord[], env: TaskEnvelope | null): ClosedLoopReceipt {
  const den = denyWithoutReceipt(taskId ?? "invalid-task-id", reason);
  return seal({
    receipt_kind: "closed-loop/v1",
    protocol_version: PROTOCOL_VERSION,
    caller: GOLIATH_STAND_IN,
    task_id: taskId,
    envelope_digest: env ? digestOf(env) : null,
    repository: env?.repository ?? null,
    base_sha: env?.base_sha ?? null,
    stages,
    action_receipt: null,
    rastik: null,
    toepara: null,
    cerberus: { decision: den.decision, cerberus_receipt: den.cerberus_receipt },
    final_decision: "DENY",
    forge_followups: [],
  });
}

type KrattOut = { ok: boolean; evidence: string | null; note?: string; receipt?: ActionReceipt };
type RastikOut = { ok: boolean; evidence: string | null; note?: string; run?: RastikRun; attackStages?: StageRecord[] };

export async function runClosedLoop(raw: unknown, deps: LoopDeps): Promise<ClosedLoopReceipt> {
  const d = deps.dispatcher;
  const v = validateEnvelope(raw);
  if (!v.ok) return refusal(null, `envelope-invalid:${v.reason}`, [], null);
  const env = v.value;
  const stages: StageRecord[] = [];
  try {
    d.enqueue(env);
  } catch (e) {
    return refusal(env.task_id, e instanceof DispatchError ? e.code : "enqueue-failed", stages, env);
  }
  configureParentLookup(deps.root);
  const mapped = envelopeToKrattTask(env);
  const krattCap = `kratt:${mapped.ok ? mapped.action : (env.allowed_actions[0] ?? "none")}`;

  // ---- KRATT -----------------------------------------------------------------------------
  let kout: KrattOut | null;
  try {
    kout = await d.run<KrattOut>(
      env.task_id,
      async () => {
        if (env.repository !== deps.repository) return { ok: false, evidence: null, note: "repository-mismatch" };
        const head = headSha(deps.root);
        if (head === null || head !== env.base_sha) return { ok: false, evidence: null, note: "stale-base-sha" };
        const r = await runKrattStage(env, deps.root, deps.clock);
        if (!r.ok) return { ok: false, evidence: null, note: r.reason };
        return { ok: true, evidence: `action-receipt:${env.task_id}:${digestOf(r.receipt)}`, receipt: r.receipt };
      },
      { capability: krattCap },
    );
  } catch (e) {
    stages.push(stageOf(d, "KRATT", env, krattCap, false, e instanceof DispatchError ? e.code : "kratt-failed"));
    return refusal(env.task_id, e instanceof DispatchError ? e.code : "kratt-failed", stages, env);
  }
  stages.push(stageOf(d, "KRATT", env, krattCap, true, kout?.note ?? null));
  const receipt = kout?.receipt ?? null;
  if (!kout || !kout.ok || !receipt) return refusal(env.task_id, kout?.note ?? "kratt-produced-no-receipt", stages, env);

  // ---- RÄSTIK ------------------------------------------------------------------------------
  const rEnv = child(env, { suffix: "rastik", agent_id: "SERPENT-051", objective: `RÄSTIK attack on action receipt of ${env.task_id}`, allowed: ["rastik:run-probes"], required: ["rastik_findings"] });
  const target = deps.attackTarget ?? realAttackTarget({ root: deps.root, repository: deps.repository, rerun: new Map() });
  let rout: RastikOut | null = null;
  const attackStages: StageRecord[] = [];
  try {
    d.enqueue(rEnv);
    rout = await d.run<RastikOut>(
      rEnv.task_id,
      async () => {
        const probe: ProbeSummary & { findings: RastikFinding[] } =
          deps.runProbes === false
            ? { probes: 0, cases_executed: 0, confirmed_findings: 0, probe_errors: 0, evidence_digest: null, findings: [] }
            : await runProbes(deps.root, env.scope, env.base_sha);
        const attacks: AttackRecord[] = [];
        const findings: RastikFinding[] = [...probe.findings];
        for (const cls of ATTACK_CLASSES as readonly AttackClass[]) {
          const aEnv = child(env, { suffix: `atk-${cls}`, agent_id: ATTACK_AGENT[cls], objective: `RÄSTIK ${cls} attack on receipt of ${env.task_id}`, allowed: [`rastik:attack:${cls}`], required: ["rastik_findings"] });
          d.enqueue(aEnv);
          const res = await d.run<{ ok: boolean; evidence: string | null; note?: string; records: AttackRecord[]; findings: RastikFinding[] }>(
            aEnv.task_id,
            async () => {
              const r = await runAttackClass(cls, receipt, env, { target });
              return { ok: r.control_admitted && r.records.length >= 1, note: r.control_admitted ? undefined : "control-receipt-not-admitted", evidence: `rastik-attacks:${cls}:${digestOf(r.records)}`, ...r };
            },
            { capability: `rastik:attack:${cls}` },
          );
          attackStages.push(stageOf(d, "RASTIK_ATTACK", aEnv, `rastik:attack:${cls}`, true, null));
          if (res) {
            attacks.push(...res.records);
            findings.push(...res.findings);
          }
        }
        const run = assembleRun(receipt, attacks, findings, { probes: probe.probes, cases_executed: probe.cases_executed, confirmed_findings: probe.confirmed_findings, probe_errors: probe.probe_errors, evidence_digest: probe.evidence_digest });
        const covered = new Set(attacks.map((a) => a.class));
        const allClasses = ATTACK_CLASSES.every((c) => covered.has(c));
        return { ok: probe.probe_errors === 0 && allClasses, evidence: `rastik-run:${run.evidence_digest}`, run, note: probe.probe_errors ? "probe-errors" : allClasses ? undefined : "attack-class-not-executed" };
      },
      { capability: "rastik:run-probes" },
    );
  } catch (e) {
    rout = null;
    stages.push(stageOf(d, "RASTIK", rEnv, "rastik:run-probes", false, e instanceof DispatchError ? e.code : "rastik-failed"));
  }
  if (rout !== null || d.log.some((t) => t.task_id === rEnv.task_id)) stages.push(stageOf(d, "RASTIK", rEnv, "rastik:run-probes", true, rout?.note ?? null));
  stages.push(...attackStages);
  const rastik = rout?.ok ? (rout.run ?? null) : null;

  // ---- TÖEPÄRA ---------------------------------------------------------------------------
  const tEnv = child(env, { suffix: "toepara", agent_id: "CITADEL-101", objective: `TÖEPÄRA independent verification of ${env.task_id}`, allowed: ["toepara:verify"], required: ["source_digests"] });
  const tctx = { root: deps.root, repository: deps.repository, rerun: new Map() };
  d.enqueue(tEnv);
  const tout = await d.run<{ ok: boolean; evidence: string | null; result: Awaited<ReturnType<typeof toeparaVerify>> }>(
    tEnv.task_id,
    async () => {
      const result = await toeparaVerify(env, receipt, rastik, tctx);
      return { ok: true, evidence: `toepara-verdict:${result.verdict.verdict}:${result.verdict.evidence_digest}`, result };
    },
    { capability: "toepara:verify" },
  );
  stages.push(stageOf(d, "TOEPARA", tEnv, "toepara:verify", true, null));
  if (!tout) return refusal(env.task_id, "toepara-failed", stages, env);

  // ---- CERBERUS --------------------------------------------------------------------------
  const cEnv = child(env, { suffix: "cerberus", agent_id: "CITADEL-111", objective: `CERBERUS admission decision for ${env.task_id}`, allowed: ["cerberus:decide"], required: ["source_digests"] });
  d.enqueue(cEnv);
  const cout = await d.run<{ ok: boolean; evidence: string | null; gate: GateOutput | null; note?: string }>(
    cEnv.task_id,
    async () => {
      // Signing happens at each producer's identity (RÄSTIK signs its report, TÖEPÄRA its bundle); CERBERUS only verifies.
      const signatures: ArtifactSignatures | undefined = deps.signing
        ? {
            bundle: tout.result.bundle ? await signSubject(deps.signing.provider, "evidence-bundle", bundleSubject(tout.result.bundle)) : null,
            rastik: rastik ? await signSubject(deps.signing.provider, "rastik-report", rastikSubject(rastik)) : null,
          }
        : undefined;
      const input = { envelope: env, receipt, rastik, toepara: tout.result, signatures };
      const ctx = { ...tctx, guard: deps.guard, signing: deps.signing };
      if (deps.ledger) {
        const idem = await decideIdempotent(input, ctx, deps.ledger);
        // `gate` is set only when this call evaluated the request; the stored decision is authoritative (it may be stricter than the gate's).
        if (idem.gate === null) return { ok: true, evidence: `cerberus-decision:${idem.decision.decision}:${idem.decision.decision_digest}`, gate: null, note: `${idem.idempotent_replay ? "idempotent-replay-stored-decision" : "ledger-fail-closed"}:${idem.decision.decision}:${idem.decision.decision_digest}` };
        const gate: GateOutput = { ...idem.gate, decision: idem.decision };
        return { ok: true, evidence: `cerberus-decision:${gate.decision.decision}:${gate.decision.decision_digest}`, gate };
      }
      const gate = await cerberusDecide(input, ctx);
      return { ok: true, evidence: `cerberus-decision:${gate.decision.decision}:${gate.decision.decision_digest}`, gate };
    },
    { capability: "cerberus:decide" },
  );
  stages.push(stageOf(d, "CERBERUS", cEnv, "cerberus:decide", true, null));
  if (!cout) return refusal(env.task_id, "cerberus-failed", stages, env);
  if (cout.gate === null) return refusal(env.task_id, (cout.note ?? "ledger-no-gate-output").slice(0, 200), stages, env);

  // ---- confirmed findings go back to FORGE (queued, NOT executed) ------------------------
  const followups: string[] = [];
  (rastik?.findings ?? []).filter((f) => f.status === "CONFIRMED").forEach((f, i) => {
    const id = `${env.task_id}-fix-${i + 1}`;
    try {
      d.enqueue({
        ...structuredClone(env),
        task_id: id,
        factory: "FORGE",
        agent_id: "FORGE-043", // Regression Builder
        objective: `Add regression test and smallest fix for ${f.finding_id}`.slice(0, 500),
        scope: ["factory/tests/regression.test.ts"],
        allowed_actions: ["add-regression-test"],
        required_evidence: ["regression_test"],
      });
      followups.push(id);
    } catch {
      /* duplicate on re-run: already queued */
    }
  });

  return seal({
    receipt_kind: "closed-loop/v1",
    protocol_version: PROTOCOL_VERSION,
    caller: GOLIATH_STAND_IN,
    task_id: env.task_id,
    envelope_digest: digestOf(env),
    repository: env.repository,
    base_sha: env.base_sha,
    stages,
    action_receipt: receipt,
    rastik,
    toepara: tout.result,
    cerberus: { decision: cout.gate.decision, cerberus_receipt: cout.gate.cerberus_receipt },
    final_decision: cout.gate.decision.decision,
    forge_followups: followups,
    ...(deps.signing ? { signing: cout.gate.signature_status } : {}),
  });
}

/** Typed in-process caller standing in for GOLIATH. It only builds and submits envelopes. */
export class GoliathStandIn {
  readonly identity = GOLIATH_STAND_IN;
  #deps: LoopDeps;
  constructor(deps: LoopDeps) {
    this.#deps = deps;
  }
  issueEnvelope(p: { action: KrattAction; scope: string[]; branch: string; objective?: string; task_id?: string; base_sha?: string }): TaskEnvelope {
    const base = p.base_sha ?? headSha(this.#deps.root);
    if (base === null) throw new Error("cannot-resolve-HEAD");
    return {
      task_id: p.task_id ?? `cl-${p.action}-${base.slice(0, 7)}`,
      factory: "FORGE",
      agent_id: "FORGE-026",
      objective: p.objective ?? `KRATT ${p.action} on ${p.scope.length} repo file(s) at ${base.slice(0, 7)}`,
      repository: this.#deps.repository,
      branch: p.branch,
      base_sha: base,
      scope: p.scope,
      allowed_actions: [p.action],
      forbidden_actions: ["merge", "deploy", "network", "write-files", "push"],
      required_evidence: p.action === "run-test" ? ["source_digests", "test_evidence", "rastik_findings"] : ["source_digests", "rastik_findings"],
      resource_budget: { max_wall_ms: 60_000, max_output_bytes: 1_048_576, max_files: 64 },
      protocol_version: 1,
    };
  }
  submit(envelope: unknown): Promise<ClosedLoopReceipt> {
    return runClosedLoop(envelope, this.#deps);
  }
}

/**
 * Independent re-check of a stored final receipt's internal consistency. Pure and total: it never throws, whatever the
 * (possibly hand-edited) receipt looks like - a missing or malformed part is a violation, not a TypeError.
 *
 * Recomputed from the embedded objects (nothing is taken from a stored digest field without recomputing it):
 * the final digest, the CERBERUS decision digest + schema, the Cerberus pipeline receipt digest, the TÖEPÄRA bundle
 * digest, the RÄSTIK report digest, and the cross-links between them (decision <-> cerberus receipt, decision <->
 * TÖEPÄRA verdict, bundle <-> action receipt, bundle <-> RÄSTIK report, RÄSTIK report <-> action receipt).
 * Limit: nothing is signed here; a party who can rewrite the WHOLE receipt consistently can still forge it.
 */
export function selfCheckFinalReceipt(r: ClosedLoopReceipt): string[] {
  const v: string[] = [];
  const guard = (name: string, f: () => void): void => {
    try {
      f();
    } catch {
      v.push(`selfcheck-unreadable:${name}`);
    }
  };
  if (typeof r !== "object" || r === null) return ["receipt-not-an-object"];
  guard("final_digest", () => {
    const { final_digest, ...body } = r;
    if (digestOf(body) !== final_digest) v.push("final_digest-mismatch");
  });
  guard("caller", () => {
    if (r.caller?.real_goliath !== false) v.push("caller-claims-real-goliath");
  });

  // ---- CERBERUS decision + pipeline receipt (may be absent in a damaged receipt: violation, never a throw)
  let decision: CerberusDecision | null = null;
  guard("cerberus", () => {
    const c = r.cerberus as { decision?: unknown; cerberus_receipt?: unknown } | null | undefined;
    if (typeof c !== "object" || c === null) {
      v.push("cerberus-missing");
      return;
    }
    if (c.decision === undefined || c.decision === null) v.push("cerberus-decision-missing");
    else {
      const d = validateCerberusDecision(c.decision);
      if (!d.ok) v.push(`cerberus-decision-invalid:${d.reason}`);
      else {
        decision = d.value;
        const { decision_digest, ...body } = d.value;
        if (digestOf(body) !== decision_digest) v.push("cerberus-decision-digest-mismatch");
      }
    }
    if (c.cerberus_receipt === undefined || c.cerberus_receipt === null) v.push("cerberus-receipt-missing");
    else {
      if (!verifyReceipt(c.cerberus_receipt as RecoveryReceipt)) v.push("cerberus-receipt-digest-invalid");
      else if (decision !== null && decision.cerberus_receipt_digest !== (c.cerberus_receipt as RecoveryReceipt).receiptDigest) v.push("decision-cerberus-receipt-link-mismatch");
    }
  });
  guard("final_decision", () => {
    if (decision === null) v.push("final-decision-unverifiable");
    else if (r.final_decision !== (decision as CerberusDecision).decision) v.push("final-decision-differs-from-cerberus");
    if (decision !== null && (decision as CerberusDecision).task_id !== r.task_id && r.task_id !== null) v.push("decision-task-differs-from-receipt");
  });

  // ---- TÖEPÄRA verdict + bundle
  guard("toepara", () => {
    const t = r.toepara;
    if (t === null || t === undefined) return;
    const bundle = t.bundle;
    if (bundle !== null && bundle !== undefined) {
      const { bundle_digest, ...body } = bundle;
      if (bundleDigest(body) !== bundle_digest) v.push("bundle-digest-mismatch");
      if (t.verdict?.verdict === "VERIFIED" && t.verdict.evidence_digest !== bundle_digest) v.push("toepara-verdict-bundle-link-mismatch");
      if (r.action_receipt && bundle.action_receipt_digest !== digestOf(r.action_receipt)) v.push("bundle-action-receipt-link-mismatch");
      if (r.rastik && bundle.rastik_evidence_digest !== digestOf(null) && bundle.rastik_evidence_digest !== r.rastik.evidence_digest) v.push("bundle-rastik-link-mismatch");
    } else if (t.verdict?.verdict === "VERIFIED") v.push("toepara-verified-without-bundle");
    if (decision !== null && t.verdict && t.verdict.evidence_digest !== (decision as CerberusDecision).toepara_evidence_digest) v.push("decision-toepara-link-mismatch");
  });

  // ---- RÄSTIK report
  guard("rastik", () => {
    const k = r.rastik;
    if (k === null || k === undefined) return;
    const { evidence_digest, ...body } = k;
    if (rastikEvidenceDigest(body) !== evidence_digest) v.push("rastik-digest-mismatch");
    if (r.action_receipt && k.target_receipt_digest !== digestOf(r.action_receipt)) v.push("rastik-target-receipt-mismatch");
  });

  guard("admit", () => {
    if (r.final_decision === "ADMIT" && (r.toepara?.verdict.verdict !== "VERIFIED" || r.action_receipt?.verification_state !== "UNVERIFIED")) v.push("admit-without-independent-verification");
  });
  return v;
}
