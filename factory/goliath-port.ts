import { headSha } from "./git.ts";
import { runKrattStage } from "./kratt-stage.ts";
import { validateActionReceipt, validateEnvelope, type ActionReceipt, type TaskEnvelope } from "./protocol/types.ts";

/**
 * GoliathPort: the smallest typed seam between a task source ("GOLIATH") and the factory.
 * No real GOLIATH control plane exists in any accessible repository (docs/factory/GOLIATH-CONVENTIONS.md),
 * so this is an INTERFACE plus an in-process stand-in. It does no networking and holds no credentials.
 */
export const PORT_ERROR_CODES = ["envelope-invalid", "repository-mismatch", "stale-base-sha", "action-refused", "receipt-invalid", "unavailable"] as const;
export type PortErrorCode = (typeof PORT_ERROR_CODES)[number];

export class GoliathPortError extends Error {
  readonly code: PortErrorCode;
  constructor(code: PortErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = "GoliathPortError";
    this.code = code;
  }
}

export interface PortIdentity {
  name: string;
  /** Literal true only for an implementation that talks to the real GOLIATH. Must carry an attestation. */
  real_goliath: boolean;
  transport: "in-process";
  attestation?: string;
}

export interface GoliathPort {
  readonly identity: PortIdentity;
  /** Resolves with an UNVERIFIED ActionReceipt or rejects with GoliathPortError. Never resolves with a fabricated receipt. */
  submit(envelope: TaskEnvelope): Promise<ActionReceipt>;
}

export interface StandInPortDeps {
  root: string;
  repository: string;
  clock: () => string;
  /** Injectable for tests (e.g. a KRATT stage that illegally self-verifies). Default: the real KRATT stage. */
  stage?: typeof runKrattStage;
}

export class StandInGoliathPort implements GoliathPort {
  readonly identity: PortIdentity = { name: "GOLIATH-STAND-IN-PORT", real_goliath: false, transport: "in-process" };
  #deps: StandInPortDeps;
  constructor(deps: StandInPortDeps) {
    this.#deps = deps;
  }
  async submit(envelope: TaskEnvelope): Promise<ActionReceipt> {
    const v = validateEnvelope(envelope);
    if (!v.ok) throw new GoliathPortError("envelope-invalid", v.reason);
    const e = v.value;
    if (e.repository !== this.#deps.repository) throw new GoliathPortError("repository-mismatch", e.repository);
    const head = headSha(this.#deps.root);
    if (head === null || head !== e.base_sha) throw new GoliathPortError("stale-base-sha", e.base_sha);
    let r: Awaited<ReturnType<typeof runKrattStage>>;
    try {
      r = await (this.#deps.stage ?? runKrattStage)(e, this.#deps.root, this.#deps.clock);
    } catch (err) {
      throw new GoliathPortError("unavailable", err instanceof Error ? err.message : "kratt-stage-threw");
    }
    if (!r.ok) throw new GoliathPortError("action-refused", r.reason);
    const out = validateActionReceipt(r.receipt);
    if (!out.ok) throw new GoliathPortError("receipt-invalid", out.reason);
    if (out.value.verification_state !== "UNVERIFIED") throw new GoliathPortError("receipt-invalid", "port-receipt-must-be-UNVERIFIED");
    return out.value;
  }
}

/** Naming guard (not authentication): only the stand-in or an attested port may exist; a stand-in may never claim to be real. */
export function assertAdapterHonest(port: GoliathPort): void {
  const id = port.identity;
  if (id.real_goliath === true && (typeof id.attestation !== "string" || id.attestation.length === 0)) throw new Error("port-claims-real-goliath-without-attestation");
  if (id.real_goliath === true && id.name.includes("STAND-IN")) throw new Error("stand-in-claims-real-goliath");
}
