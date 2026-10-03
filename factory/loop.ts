import { verifyReceipt, type RecoveryReceipt } from "../cerberus/core/decide.ts";
import type { ReplayStore } from "./replay-store.ts";
import { bundleSubject, rastikSubject, signSubject, type ArtifactSignatures, type SignatureReport, type SigningPolicy } from "./signing.ts";
import type { KrattAction } from "../kratt/task.ts";
import { ATTACK_AGENT, ATTACK_CLASSES, CAPABILITIES, HANDLER_KEYS, type AttackClass } from "./capabilities.ts";
import { cerberusDecide, denyWithoutReceipt } from "./cerberus-gate.ts";
import { DispatchError, Dispatcher, type TransitionRecord } from "./dispatcher.ts";
import { headSha } from "./git.ts";
import { envelopeToKrattTask, runKrattStage } from "./kratt-stage.ts";
import {
  PROTOCOL_VERSION,
  digestOf,
  validateEnvelope,
  type ActionReceipt,
  type CerberusDecision,
  type RastikFinding,
  type TaskEnvelope,
  type ToeparaVerdict,
  type EvidenceBundle,
} from "./protocol/types.ts";
import { assembleRun, configureParentLookup, realAttackTarget, runAttackClass, runProbes, type AttackTarget } from "./rastik-attacks.ts";
import type { AttackRecord, ProbeSummary, RastikRun } from "./rastik-types.ts";
import { buildInitialRegistry, type Registry } from "./registry.ts";
import { toeparaVerify } from "./toepara.ts";

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
  const cout = await d.run<{ ok: boolean; evidence: string | null; gate: Awaited<ReturnType<typeof cerberusDecide>> }>(
    cEnv.task_id,
    async () => {
      // Signing happens at each producer's identity (RÄSTIK signs its report, TÖEPÄRA its bundle); CERBERUS only verifies.
      const signatures: ArtifactSignatures | undefined = deps.signing
        ? {
            bundle: tout.result.bundle ? await signSubject(deps.signing.provider, "evidence-bundle", bundleSubject(tout.result.bundle)) : null,
            rastik: rastik ? await signSubject(deps.signing.provider, "rastik-report", rastikSubject(rastik)) : null,
          }
        : undefined;
      const gate = await cerberusDecide({ envelope: env, receipt, rastik, toepara: tout.result, signatures }, { ...tctx, guard: deps.guard, signing: deps.signing });
      return { ok: true, evidence: `cerberus-decision:${gate.decision.decision}:${gate.decision.decision_digest}`, gate };
    },
    { capability: "cerberus:decide" },
  );
  stages.push(stageOf(d, "CERBERUS", cEnv, "cerberus:decide", true, null));
  if (!cout) return refusal(env.task_id, "cerberus-failed", stages, env);

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

/** Independent re-check of a stored final receipt's internal consistency (digest + embedded objects). Pure. */
export function selfCheckFinalReceipt(r: ClosedLoopReceipt): string[] {
  const v: string[] = [];
  const { final_digest, ...body } = r;
  if (digestOf(body) !== final_digest) v.push("final_digest-mismatch");
  if (!verifyReceipt(r.cerberus.cerberus_receipt)) v.push("cerberus-receipt-digest-invalid");
  if (r.caller.real_goliath !== false) v.push("caller-claims-real-goliath");
  if (r.final_decision !== r.cerberus.decision.decision) v.push("final-decision-differs-from-cerberus");
  if (r.final_decision === "ADMIT" && (r.toepara?.verdict.verdict !== "VERIFIED" || r.action_receipt?.verification_state !== "UNVERIFIED")) v.push("admit-without-independent-verification");
  return v;
}
