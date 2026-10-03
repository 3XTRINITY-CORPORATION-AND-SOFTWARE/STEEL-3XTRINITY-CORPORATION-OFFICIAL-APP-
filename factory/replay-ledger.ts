import { randomBytes } from "node:crypto";
import { closeSync, existsSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { join, resolve } from "node:path";
import { verifyDecisionReceipt, digestJson, type DecisionReceipt } from "../cerberus/receipts/decision-receipt.ts";
import { cerberusDecide, type CerberusCtx, type GateInput } from "./cerberus-gate.ts";
import { FileReplayGuard } from "./replay-store.ts";
import { digestOf, validateCerberusDecision, type CerberusDecision } from "./protocol/types.ts";
import { decisionReceiptForGate, denyDecisionReceipt } from "./trust-gate-receipt.ts";

/**
 * Idempotent, restart-persistent admission decisions.
 *
 * The replay guard (`FileReplayGuard`) makes a TÖEPÄRA bundle digest consumable ONCE. That alone makes the second
 * presentation of the same receipt a DENY ("replayed-bundle"), i.e. a different answer than the first. This ledger
 * makes the answer itself idempotent: a request (envelope + action receipt + RÄSTIK report + presented bundle +
 * signatures) is evaluated exactly once per ledger; every later presentation of the SAME request - same process,
 * after a restart, or from another process sharing the directory - returns the stored decision and decision
 * receipt, byte for byte, WITHOUT evaluating again and WITHOUT a second consume/admit.
 *
 *  - First evaluation: the request key is claimed with link(2) (O_EXCL semantics: exactly one process wins).
 *    The winner runs `cerberusDecide`, builds the evidence-bound decision receipt, and publishes
 *    `{request_key, decision, receipt}` atomically (fsynced temp file + link(2)). Every outcome is stored, DENY
 *    included, because the gate burns the bundle on first evaluation: a retry of an identical request could not
 *    succeed anyway. To retry, issue a new task.
 *  - Losers poll for the winner's record (bounded) and return it. Never found in time => DENY
 *    `idempotency-incomplete` (fail closed, not stored). A winner that dies between claim and publish therefore
 *    leaves that request permanently DENYed until an operator removes `<key>.claim` (documented, deliberate).
 *  - A stored record is re-verified on every read (receipt digests, ADMIT invariants, request key, decision
 *    schema/digest, receipt<->decision consistency). Corrupt or tampered record => DENY `ledger-record-invalid`.
 *  - If the record cannot be published, the result is DENY `ledger-publish-failed`, never an unrecorded ADMIT.
 *
 * Limits (honest): same as FileReplayGuard - local POSIX filesystem, protects between processes sharing the
 * directory, not against someone who can delete or rewrite files in it. Records are hashed, not signed.
 */
const KEY = /^[0-9a-f]{64}$/;

export type LedgerRead = { kind: "none" } | { kind: "ok"; record: LedgerRecord } | { kind: "invalid"; why: string };
export interface LedgerRecord {
  request_key: string;
  decision: CerberusDecision;
  receipt: DecisionReceipt;
}

export class DecisionLedger {
  readonly dir: string;
  lastError: string | null = null;
  constructor(dir: string) {
    this.dir = dir;
  }
  #ready(): boolean {
    try {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      const st = lstatSync(this.dir);
      if (st.isSymbolicLink() || !st.isDirectory()) return this.#fail("ledger-not-a-plain-directory");
      return true;
    } catch {
      return this.#fail("ledger-unavailable");
    }
  }
  #fail(why: string): false {
    this.lastError = why;
    return false;
  }
  /** Atomically create `<name>` with `content`; "exists" if it was already there, "error" on any other problem. */
  #createExclusive(name: string, content: string): "created" | "exists" | "error" {
    if (!this.#ready()) return "error";
    const tmp = join(this.dir, `.tmp-${process.pid}-${randomBytes(8).toString("hex")}`);
    let fd: number | null = null;
    try {
      fd = openSync(tmp, "wx", 0o600);
      writeSync(fd, content);
      fsyncSync(fd);
      closeSync(fd);
      fd = null;
      try {
        linkSync(tmp, join(this.dir, name));
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "EEXIST") return "exists";
        this.#fail("ledger-link-failed");
        return "error";
      }
      try {
        const d = openSync(this.dir, "r");
        try {
          fsyncSync(d);
        } finally {
          closeSync(d);
        }
      } catch {
        /* best effort; the file is already published */
      }
      return "created";
    } catch {
      this.#fail("ledger-write-failed");
      return "error";
    } finally {
      if (fd !== null) {
        try {
          closeSync(fd);
        } catch {
          /* ignore */
        }
      }
      try {
        unlinkSync(tmp);
      } catch {
        /* gone */
      }
    }
  }
  claim(key: string): "won" | "exists" | "error" {
    if (!KEY.test(key)) return "error";
    const r = this.#createExclusive(`${key}.claim`, JSON.stringify({ key, pid: process.pid }) + "\n");
    return r === "created" ? "won" : r;
  }
  publish(record: LedgerRecord): boolean {
    if (!KEY.test(record.request_key)) return false;
    return this.#createExclusive(`${record.request_key}.decision.json`, JSON.stringify(record) + "\n") === "created";
  }
  hasClaim(key: string): boolean {
    return KEY.test(key) && existsSync(join(this.dir, `${key}.claim`));
  }
  read(key: string): LedgerRead {
    if (!KEY.test(key)) return { kind: "invalid", why: "bad-key" };
    const file = join(this.dir, `${key}.decision.json`);
    if (!existsSync(file)) return { kind: "none" };
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as Partial<LedgerRecord>;
      const why = recordProblem(key, parsed);
      return why === null ? { kind: "ok", record: parsed as LedgerRecord } : { kind: "invalid", why };
    } catch {
      return { kind: "invalid", why: "unreadable-or-not-json" };
    }
  }
}

/** Null when the stored record is internally consistent and belongs to `key`. */
export function recordProblem(key: string, r: Partial<LedgerRecord>): string | null {
  if (typeof r !== "object" || r === null) return "not-an-object";
  if (Object.keys(r).sort().join(",") !== "decision,receipt,request_key") return "unexpected-keys";
  if (r.request_key !== key) return "request-key-mismatch";
  const v = verifyDecisionReceipt(r.receipt);
  if (!v.ok) return `receipt:${v.problems[0] ?? "invalid"}`;
  const d = validateCerberusDecision(r.decision);
  if (!d.ok) return `decision:${d.reason}`;
  const { decision_digest, ...body } = d.value;
  if (digestOf(body) !== decision_digest) return "decision-digest";
  const receipt = r.receipt as DecisionReceipt;
  if (receipt.decision !== d.value.decision) return "receipt-decision-differs-from-decision";
  if (receipt.task_id !== d.value.task_id) return "receipt-task-differs-from-decision";
  return null;
}

/** Identity of a request. null when it cannot be derived (hostile/cyclic input) - the caller must then DENY. */
export function requestKey(input: GateInput): string | null {
  try {
    return digestJson({ v: 1, envelope: input.envelope ?? null, receipt: input.receipt ?? null, rastik: input.rastik ?? null, bundle: input.toepara?.bundle ?? null, signatures: input.signatures ?? null });
  } catch {
    return null;
  }
}

export interface IdempotentResult {
  decision: CerberusDecision;
  receipt: DecisionReceipt;
  /** true when this call returned a stored record instead of evaluating. Not part of the receipt. */
  idempotent_replay: boolean;
}

export interface IdempotentOptions {
  /** How long a loser waits for the winner's record (default 5000 ms). */
  waitMs?: number;
  pollMs?: number;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function failClosed(input: GateInput | null, taskId: string, reason: string): IdempotentResult {
  const receipt = denyDecisionReceipt(input, taskId, [reason]);
  const body = {
    protocol_version: 1 as const,
    task_id: receipt.task_id,
    decision: "DENY" as const,
    reasons: [reason],
    toepara_evidence_digest: digestOf({ no_gate_run: reason }),
    cerberus_receipt_digest: digestOf({ no_cerberus_receipt: reason }),
    unresolved_high_findings: [] as string[],
  };
  return { decision: { ...body, decision_digest: digestOf(body) }, receipt, idempotent_replay: false };
}

const taskIdOf = (input: GateInput): string => {
  try {
    const t = (input.envelope as { task_id?: unknown } | null)?.task_id;
    return typeof t === "string" && /^[a-z0-9][a-z0-9-]{0,63}$/.test(t) ? t : "invalid-task-id";
  } catch {
    return "invalid-task-id";
  }
};

export async function decideIdempotent(input: GateInput, ctx: CerberusCtx, ledger: DecisionLedger, opts: IdempotentOptions = {}): Promise<IdempotentResult> {
  const taskId = taskIdOf(input);
  const key = requestKey(input);
  if (key === null) return failClosed(null, taskId, "ledger-request-key-unavailable");
  const waitMs = Math.min(Math.max(opts.waitMs ?? 5000, 0), 60_000);
  const pollMs = Math.min(Math.max(opts.pollMs ?? 20, 1), 1000);
  const deadline = Date.now() + waitMs;
  for (;;) {
    const r = ledger.read(key);
    if (r.kind === "ok") return { decision: r.record.decision, receipt: r.record.receipt, idempotent_replay: true };
    if (r.kind === "invalid") return failClosed(input, taskId, `ledger-record-invalid:${r.why}`);
    const c = ledger.claim(key);
    if (c === "error") return failClosed(input, taskId, `ledger-unavailable:${ledger.lastError ?? "unknown"}`);
    if (c === "won") {
      try {
        const out = await cerberusDecide(input, ctx);
        const receipt = decisionReceiptForGate(input, out);
        // The receipt may only be STRICTER than the gate (never ADMIT where the gate said DENY).
        const decision: CerberusDecision =
          receipt.decision === out.decision.decision
            ? out.decision
            : (() => {
                const body = { ...out.decision, decision: receipt.decision, reasons: [...new Set([...out.decision.reasons, ...receipt.reasons])].slice(0, 64) } as Omit<CerberusDecision, "decision_digest"> & { decision_digest?: string };
                delete body.decision_digest;
                return { ...body, decision_digest: digestOf(body) } as CerberusDecision;
              })();
        if (!ledger.publish({ request_key: key, decision, receipt })) return failClosed(input, taskId, `ledger-publish-failed:${ledger.lastError ?? "unknown"}`);
        return { decision, receipt, idempotent_replay: false };
      } catch {
        // Record the failure as a final DENY so the request is idempotent and not left as a dangling claim (best effort).
        const fc = failClosed(input, taskId, "ledger-internal-error");
        ledger.publish({ request_key: key, decision: fc.decision, receipt: fc.receipt });
        return fc;
      }
    }
    // "exists": another evaluation of this very request is in flight (or crashed). Wait for its record.
    if (Date.now() >= deadline) return failClosed(input, taskId, "idempotency-incomplete");
    await sleep(pollMs);
  }
}

/** The persistent pair used when FACTORY_REPLAY_DIR is set (same variable as `npm run factory`): guard markers + decision ledger. */
export function replayStoresFromEnv(env: Record<string, string | undefined> = process.env): { guard: FileReplayGuard; ledger: DecisionLedger } | null {
  const d = env.FACTORY_REPLAY_DIR;
  if (typeof d !== "string" || d.length === 0) return null;
  const dir = resolve(d);
  return { guard: new FileReplayGuard(dir), ledger: new DecisionLedger(join(dir, "decisions")) };
}
