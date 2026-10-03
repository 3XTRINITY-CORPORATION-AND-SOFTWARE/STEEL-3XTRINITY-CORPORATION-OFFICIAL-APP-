import type { Mutant } from "./engine.ts";

/**
 * Hand-written mutant catalog for the closed-loop gates and validators. Every entry weakens exactly
 * ONE guard with an exact textual edit. `find` must occur exactly once in `file` (asserted by
 * `validateCatalog`, so the catalog cannot silently rot when the source moves).
 * `equivalent` is only allowed with a concrete reason why no test CAN tell the mutant apart.
 */
const m = (id: string, file: string, what: string, find: string, replace: string, equivalent?: string): Mutant => ({
  id,
  file,
  description: `${what} [\`${find.replace(/\s+/g, " ")}\` -> \`${replace.replace(/\s+/g, " ")}\`]`,
  find,
  replace,
  ...(equivalent === undefined ? {} : { equivalent }),
});

const T = "factory/toepara.ts";
const G = "factory/cerberus-gate.ts";
const L = "factory/loop.ts";
const TY = "factory/protocol/types.ts";
const SP = "factory/protocol/spec.ts";
const RA = "factory/rastik-attacks.ts";
const D = "factory/dispatcher.ts";
const TG = "factory/trust-gate.ts";
const RS = "factory/replay-store.ts";
const SG = "factory/signing.ts";
const GT = "factory/git.ts";

const RAW: Mutant[] = [
  // ---- TÖEPÄRA: independent verification ------------------------------------------------------
  m("T01", T, "TÖEPÄRA: receipt/envelope task_id comparison disabled", `r.task_id === env.task_id, "receipt-task-id-mismatch"`, `true, "receipt-task-id-mismatch"`),
  m("T02", T, "TÖEPÄRA: receipt/envelope agent_id comparison disabled", `r.agent_id === env.agent_id, "receipt-agent-mismatch"`, `true, "receipt-agent-mismatch"`),
  m("T03", T, "TÖEPÄRA: host-configured repository comparison dropped (receipt vs envelope only)", `r.repository === env.repository && env.repository === ctx.repository`, `r.repository === env.repository`),
  m("T04", T, "TÖEPÄRA: receipt/envelope base_sha comparison disabled", `r.base_sha === env.base_sha, "receipt-base-sha-mismatch"`, `true, "receipt-base-sha-mismatch"`),
  m("T05", T, "TÖEPÄRA: receipt/envelope scope comparison disabled", `canonicalize(r.scope) === canonicalize(env.scope)`, `true`),
  m("T06", T, "TÖEPÄRA: self-verified (producer-set verification_state) check disabled", `note("not-self-verified", r.verification_state === "UNVERIFIED",`, `note("not-self-verified", true,`),
  m("T07", T, "TÖEPÄRA: allowed_actions membership dropped from action authorization", `env.allowed_actions.includes(r.action) && !env.forbidden_actions.includes(r.action)`, `!env.forbidden_actions.includes(r.action)`),
  m("T08", T, "TÖEPÄRA: forbidden_actions exclusion dropped from action authorization", `env.allowed_actions.includes(r.action) && !env.forbidden_actions.includes(r.action)`, `env.allowed_actions.includes(r.action)`),
  m("T09", T, "TÖEPÄRA: current-HEAD freshness check reduced to 'HEAD exists'", `head !== null && head === r.base_sha`, `head !== null`),
  m("T10", T, "TÖEPÄRA: base-sha-exists check disabled", `note("base-sha-exists", exists,`, `note("base-sha-exists", true,`),
  m("T11", T, "TÖEPÄRA: evidence task-digest comparison disabled", `kev.taskDigest === taskDigest(mapped.task)`, `true`),
  m("T12", T, "TÖEPÄRA: evidence action binding dropped (task id only)", `kev.taskId === r.task_id && kev.action === r.action && mapped.action === r.action`, `kev.taskId === r.task_id`),
  m("T13", T, "TÖEPÄRA: receipt exit_code vs evidence comparison dropped", `r.result.exit_code === kev.exitCode && r.result.checks.pass === kev.checks.pass`, `r.result.checks.pass === kev.checks.pass`),
  m("T14", T, "TÖEPÄRA: receipt checks.fail vs evidence comparison dropped", `&& r.result.checks.fail === kev.checks.fail`, ``),
  m("T15", T, "TÖEPÄRA: artifacts-equal-scope size comparison dropped", `names.length === scopeSet.size && names.every`, `names.every`),
  m("T16", T, "TÖEPÄRA: recomputed-vs-reported source digest comparison disabled (bytes only)", `d.sha256 !== a.sha256 || d.bytes !== a.bytes`, `d.bytes !== a.bytes`),
  m("T17", T, "TÖEPÄRA: working-tree-vs-base_sha diff must be empty: check disabled", `note("working-tree-matches-base-sha", scopeDiff.empty,`, `note("working-tree-matches-base-sha", true,`),
  m("T18", T, "TÖEPÄRA: independent test re-execution agreement disabled", `note("test-reexecution-agrees", same,`, `note("test-reexecution-agrees", true,`),
  m("T19", T, "TÖEPÄRA: success claim reduced to result.ok (fail/pass counts ignored)", `r.result.ok && r.result.checks.fail === 0 && r.result.checks.pass >= 1`, `r.result.ok`),
  m("T20", T, "TÖEPÄRA: required test_evidence presence disabled", `testEvidence !== null, "required-evidence-missing:test_evidence"`, `true, "required-evidence-missing:test_evidence"`),
  m("T21", T, "TÖEPÄRA: unsupported required evidence silently accepted", `if (!SUPPORTED_EVIDENCE.has(need))`, `if (false)`),
  m("T22", T, "TÖEPÄRA: RÄSTIK report must target this receipt: check disabled", `rastik.target_receipt_digest === receiptDigest`, `true`),
  m("T23", T, "TÖEPÄRA: RÄSTIK report digest recomputation disabled", `recomputed === evidence_digest`, `true`),
  m("T24", T, "TÖEPÄRA: INSUFFICIENT_EVIDENCE no longer blocks VERIFIED", `if (reject.length > 0 || insufficient.length > 0 || kev === null)`, `if (reject.length > 0 || kev === null)`),

  // ---- CERBERUS gate ---------------------------------------------------------------------------
  m("G01", G, "CERBERUS: replay guard result ignored (bundle may be presented again)", `if (!ctx.guard.consume(freshBundle.bundle_digest)) return reject("replayed-bundle");`, `void ctx.guard.consume(freshBundle.bundle_digest);`),
  m("G02", G, "CERBERUS: byte-equality of presented bundle with recomputed bundle disabled", `if (canonicalize(freshBundle) !== a.content) return reject("bundle-differs-from-recomputed");`, ``),
  m("G03", G, "CERBERUS: presented bundle_digest vs recomputed bundle_digest comparison disabled", `if (b.value.bundle_digest !== freshBundle?.bundle_digest) return reject("bundle-digest-differs-from-recomputed");`, ``),
  m("G04", G, "CERBERUS: recomputed TÖEPÄRA verdict must be VERIFIED: check reduced to 'bundle exists'", `fresh.verdict.verdict !== "VERIFIED" || freshBundle === null`, `freshBundle === null`),
  m("G05", TG, "trust-gate policy: non-KRATT allowed action no longer denied", `if (!envelope.allowed_actions.every((a) => (KRATT_ACTIONS as readonly string[]).includes(a))) why.push("policy:non-kratt-action-allowed");`, ``),
  m("G06", TG, "trust-gate policy: repository mismatch no longer denied", `if (envelope.repository !== hostRepository) why.push("policy:repository-mismatch");`, ``),
  m("G07", TG, "trust-gate policy: merge/deploy no longer required to be forbidden", `if (!envelope.forbidden_actions.includes(must)) why.push(`, `if (false) why.push(`),
  m("G08", TG, "trust-gate policy: receipt action no longer required to be in allowed_actions", `if (typeof action !== "string" || !envelope.allowed_actions.includes(action)) why.push(`, `if (typeof action !== "string") why.push(`),
  m("G09", G, "CERBERUS policy: trust gate always AUTHORIZED", `return why.length === 0 ? "AUTHORIZED" : "DENIED";`, `return "AUTHORIZED";`),
  m("G10", G, "CERBERUS: QUARANTINE branch for unresolved confirmed high/critical findings disabled", `else if (unresolved.length > 0) {`, `else if (false) {`),
  m("G11", G, "CERBERUS: FAIL_CLOSED no longer maps to DENY", `if (rc.decision !== "PROCEED") decision = "DENY";`, `if (false) decision = "DENY";`),
  m("G12", "factory/rastik-types.ts", "RÄSTIK types: only 'critical' counts as unresolved-high", `f.status === "CONFIRMED" && (f.severity === "high" || f.severity === "critical")`, `f.status === "CONFIRMED" && f.severity === "critical"`),
  m("G13", "factory/rastik-types.ts", "RÄSTIK types: UNCONFIRMED findings count as unresolved-high", `f.status === "CONFIRMED" && (f.severity`, `(f.severity`),

  // ---- closed loop / final receipt -------------------------------------------------------------
  m("L01", L, "loop: final_digest recomputation disabled in selfCheckFinalReceipt", `if (digestOf(body) !== final_digest) v.push("final_digest-mismatch");`, ``),
  m("L02", L, "loop: cerberus receipt digest verification disabled in selfCheckFinalReceipt", `if (!verifyReceipt(r.cerberus.cerberus_receipt)) v.push("cerberus-receipt-digest-invalid");`, ``),
  m("L03", L, "loop: caller.real_goliath claim check disabled", `if (r.caller.real_goliath !== false) v.push("caller-claims-real-goliath");`, ``),
  m("L04", L, "loop: final_decision == CERBERUS decision check disabled", `if (r.final_decision !== r.cerberus.decision.decision) v.push("final-decision-differs-from-cerberus");`, ``),
  m("L05", L, "loop: ADMIT without UNVERIFIED producer receipt no longer flagged", `r.toepara?.verdict.verdict !== "VERIFIED" || r.action_receipt?.verification_state !== "UNVERIFIED"`, `r.toepara?.verdict.verdict !== "VERIFIED"`),
  m("L06", L, "loop: ADMIT without VERIFIED TÖEPÄRA verdict no longer flagged", `r.toepara?.verdict.verdict !== "VERIFIED" || r.action_receipt?.verification_state`, `r.action_receipt?.verification_state`),
  m("L07", L, "loop: stale base_sha preflight disabled", `if (head === null || head !== env.base_sha) return { ok: false, evidence: null, note: "stale-base-sha" };`, ``),
  m("L08", L, "loop: repository preflight disabled", `if (env.repository !== deps.repository) return { ok: false, evidence: null, note: "repository-mismatch" };`, ``),
  m("L09", L, "loop: 'every attack class executed' requirement disabled", `const allClasses = ATTACK_CLASSES.every((c) => covered.has(c));`, `const allClasses = true;`),
  m("L10", L, "loop: RÄSTIK stage failure no longer withholds the report from TÖEPÄRA", `const rastik = rout?.ok ? (rout.run ?? null) : null;`, `const rastik = rout?.run ?? null;`),
  m("L11", L, "loop: attack class control receipt not required for stage success", `ok: r.control_admitted && r.records.length >= 1`, `ok: true`),

  // ---- protocol validators ---------------------------------------------------------------------
  m("P01", TY, "protocol: envelope agent_id/factory prefix check disabled", `if (!e.agent_id.startsWith(\`\${e.factory}-\`)) return { ok: false, reason: "agent-not-in-factory" };`, ``),
  m("P02", TY, "protocol: allowed-and-forbidden action overlap check disabled", `if (e.allowed_actions.some((a) => e.forbidden_actions.includes(a))) return { ok: false, reason: "action-both-allowed-and-forbidden" };`, ``),
  m("P03", TY, "protocol: scope size vs resource_budget.max_files check disabled", `if (e.scope.length > e.resource_budget.max_files) return { ok: false, reason: "scope-exceeds-max-files" };`, ``),
  m("P04", TY, "protocol: TASK_ID length limit off by one (65 characters allowed)", `export const TASK_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;`, `export const TASK_ID = /^[a-z0-9][a-z0-9-]{0,64}$/;`),
  m("P05", TY, "protocol: REL_PATH allows a leading dot in every segment ('..' becomes a valid path)", `export const REL_PATH = /^[A-Za-z0-9_][A-Za-z0-9._-]*(\\/[A-Za-z0-9_][A-Za-z0-9._-]*)*$/;`, `export const REL_PATH = /^[A-Za-z0-9_.][A-Za-z0-9._-]*(\\/[A-Za-z0-9_.][A-Za-z0-9._-]*)*$/;`),
  m("P06", TY, "protocol: scope path length limit raised from 200 to 20000", `const relPath = str({ re: REL_PATH, min: 1, max: 200 });`, `const relPath = str({ re: REL_PATH, min: 1, max: 20000 });`),
  m("P07", TY, "protocol: scope may be empty", `scope: arr(relPath, 1, 64, true),\n    allowed_actions`, `scope: arr(relPath, 0, 64, true),\n    allowed_actions`),
  m("P08", TY, "protocol: scope entry limit raised from 64 to 65 (envelope)", `scope: arr(relPath, 1, 64, true),\n    allowed_actions`, `scope: arr(relPath, 1, 65, true),\n    allowed_actions`),
  m("P09", TY, "protocol: exit_code upper bound raised from 255 to 256", `exit_code: int(-1, 255)`, `exit_code: int(-1, 256)`),
  m("P10", TY, "protocol: ISO timestamp pattern accepts any suffix", `const ISO_UTC = /^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,3})?Z$/;`, `const ISO_UTC = /^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,3})?Z?/;`),
  m("P11", SP, "spec: closed object key set check disabled (unknown keys accepted)", `if (keys.length !== want.length || !keys.every((k) => typeof k === "string" && want.includes(k)))\n        return \`\${path}:unexpected-or-missing-keys\`;`, ``),
  m("P12", SP, "spec: accessor (getter) properties accepted", `if (d === undefined || !("value" in d)) return \`\${path}.\${k}:accessor\`;`, `if (d === undefined) return \`\${path}.\${k}:accessor\`;`),
  m("P13", SP, "spec: any prototype accepted as a plain object", `return p === Object.prototype || p === null;`, `return true;`),
  m("P14", SP, "spec: string pattern check disabled", `if (spec.re && !spec.re.test(v)) return \`\${path}:pattern\`;`, ``),
  m("P15", SP, "spec: integers need not be integers (NaN/float accepted)", `if (typeof v !== "number" || !Number.isSafeInteger(v)) return \`\${path}:not-integer\`;`, `if (typeof v !== "number") return \`\${path}:not-integer\`;`),
  m("P16", SP, "spec: string max length not enforced", `if (spec.max !== undefined && v.length > spec.max) return \`\${path}:too-long\`;`, ``),
  m("P17", SP, "spec: unique-array constraint disabled", `if (seen.has(d.value)) return \`\${path}[\${i}]:duplicate\`;`, ``),

  // ---- dispatcher ------------------------------------------------------------------------------
  m("D01", D, "dispatcher: illegal worker transitions accepted", `if (!LEGAL_TRANSITIONS[from].includes(to)) return reject(`, `if (false) return reject(`),
  m("D02", D, "dispatcher: task owner mismatch accepted on wake", `if (q.agent_id !== w.id) return reject("task-owner-mismatch");`, ``),
  m("D03", D, "dispatcher: duplicate task ids accepted on enqueue", `if (this.queue.some((q) => q.task_id === e.task_id)) throw new DispatchError("duplicate-task");`, ``),
  m("D04", D, "dispatcher: owner factory mismatch accepted on enqueue", `if (w.factory !== e.factory) throw new DispatchError("owner-factory-mismatch");`, ``),

  // ---- Trust Gate (async), replay store, signing, shallow-checkout handling ---------------------
  m("TG01", TG, "trust gate: a malformed verdict 'ADMITTED'/'PROCEED' is accepted as AUTHORIZED", `if (r.value === "AUTHORIZED") return`, `if (r.value === "AUTHORIZED" || r.value === "ADMITTED" || r.value === "PROCEED") return`),
  m("TG02", TG, "trust gate: a throwing gate is AUTHORIZED instead of DENIED", `return deny("trust-gate:threw");`, `return { verdict: "AUTHORIZED", reasons: [] };`),
  m("TG03", TG, "trust gate: an invalid timeout is no longer rejected", `if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TRUST_TIMEOUT_MS) return deny("trust-gate:invalid-timeout");`, ``),
  m("TG04", TG, "trust gate: a timed-out gate is no longer reported as timeout", `if (r.timedOut) return deny("trust-gate:timeout");`, ``),
  m("CG01", G, "CERBERUS: the local policy no longer applies when an external Trust Gate says AUTHORIZED", `res.verdict === "AUTHORIZED" && local.length === 0 ? "AUTHORIZED" : "DENIED"`, `res.verdict === "AUTHORIZED" ? "AUTHORIZED" : "DENIED"`),
  m("CG02", G, "CERBERUS: required evidence authentication is never enforced", `const signingDenied = sp.required && (`, `const signingDenied = false && (`),
  m("CG03", G, "CERBERUS: a signing block no longer rejects the bundle", `if (signingBlock !== null) return reject(signingBlock);`, ``),
  m("RS01", RS, "replay store: a digest that already exists is reported as consumed-for-the-first-time", `return this.#deny((e as NodeJS.ErrnoException).code === "EEXIST" ? "replayed" : "publish-failed");`, `return true;`),
  m("RS02", RS, "replay store: malformed digests are accepted", `if (typeof digest !== "string" || !DIGEST.test(digest)) return this.#deny("invalid-digest");`, ``),
  m("RS03", RS, "replay store: a symlinked store directory is accepted", `if (st.isSymbolicLink() || !st.isDirectory()) return this.#deny("store-not-a-plain-directory");`, ``),
  m("SG01", SG, "signing: subject digest no longer bound (a signature over any subject verifies)", `sig.purpose !== purpose || sig.subject_digest !== expectedSubjectDigest || sig.provider !== provider.name`, `sig.purpose !== purpose || sig.provider !== provider.name`),
  m("SG02", SG, "signing: provider verification result ignored", `return ok === true ? "SIGNED" : "VERIFICATION_FAILED";`, `return "SIGNED";`),
  m("SG03", SG, "signing: purpose no longer part of the signed payload (cross-purpose replay)", "\\n${purpose}\\n${subjectDigest}`", "\\n${subjectDigest}`"),
  m("SG04", SG, "signing: purpose mismatch no longer fails verification", `sig.purpose !== purpose || sig.subject_digest`, `sig.subject_digest`),
  m("T25", T, "TÖEPÄRA: hash-files check count no longer recomputed from git", `kev.checks.pass === scopeSet.size && kev.checks.fail === 0 && r.result.checks.pass === scopeSet.size`, `true`),
  m("T26", T, "TÖEPÄRA: shallow checkout no longer treated as unavailable base evidence", `const baseUnavailable = !exists && isShallow(ctx.root);`, `const baseUnavailable = false;`),
  m("GT01", GT, "git: partial-clone lazy fetch no longer disabled", `GIT_NO_LAZY_FETCH: "1" }`, `GIT_NO_LAZY_FETCH: "0" }`),

  // ---- RÄSTIK v2 runtime drift check ------------------------------------------------------------
  m("RD01", RA, "runtime drift: engines major no longer compared with .nvmrc", `else if (pin !== null && eng !== pin) why.push("engines-major-differs-from-nvmrc");`, ``),
  m("RD02", RA, "runtime drift: CI node major no longer compared with .nvmrc", `else if (pin !== null && m !== pin) why.push(\`ci-major-differs-from-nvmrc:\${v.slice(0, 20)}\`);`, ``),
  m("RD03", RA, "runtime drift: CI that pins no Node version is accepted", `if (d.ci_node_versions.length === 0) why.push("ci-pins-no-node");`, ``),
  m("RD04", RA, "runtime drift: the RUNNING interpreter is no longer compared with .nvmrc", `else if (pin !== null && act !== pin) why.push("actual-major-differs-from-nvmrc");`, ``),
  m("RD05", RA, "runtime drift: version syntax accepts floating aliases (only a leading number is required)", `const NODE_VERSION = /^v?(\\d{1,3})(\\.\\d{1,3}){0,2}$/;`, `const NODE_VERSION = /^v?(\\d{1,3})/;`),
  m("RD06", RA, "runtime drift: engines may be any range starting with the major", `const ENGINES = /^(\\d{1,3})\\.x$/;`, `const ENGINES = /^\\^?>?=?(\\d{1,3})/;`),
  m("RD07", RA, "runtime drift: only the first CI node-version entry of the workflows is read", `if (ci.length < 100) ci.push(m[1] ?? "")`, `if (ci.length < 1) ci.push(m[1] ?? "")`),
  m("RD08", RA, "runtime drift: devcontainer major no longer compared with .nvmrc", `else if (pin !== null && dc !== pin) why.push("devcontainer-major-differs-from-nvmrc");`, ``),
  m("RD09", RA, "runtime drift attacks: a throwing checker is treated as clean", `return ["check-threw"]; // fail-closed`, `return [];`),

  // ---- RÄSTIK battery itself (a battery that cannot fail is worthless) -------------------------
  m("R01", RA, "RÄSTIK: control receipt requirement removed (a rejecting verifier would look 'all repelled')", `if (!control_admitted) return { records, findings, control_admitted };`, ``),
  m("R02", RA, "RÄSTIK: a throwing verifier is treated as admitting (bypass) instead of fail-closed", `last = false; // a throwing verifier is fail-closed; not a bypass`, `last = true;`),
  m("R03", RA, "RÄSTIK: independent re-run skipped (every bypass is 'reproduced')", `const again = await attempt(built.seq, env);`, `const again = true;`),
  m("R04", RA, "RÄSTIK: UNCONFIRMED findings reported as CONFIRMED", `severity: SEVERITY[cls],\n      status: again ? "CONFIRMED" : "UNCONFIRMED",`, `severity: SEVERITY[cls],\n      status: "CONFIRMED",`),
  m("R06", RA, "RÄSTIK real target: an ADMIT is no longer required (QUARANTINE also counts as admitted)", `return g.decision.decision === "ADMIT";`, `return g.decision.decision !== "DENY";`),
  m("R07", RA, "RÄSTIK real target: TÖEPÄRA verdict must be VERIFIED check removed (CERBERUS recomputes it)", `if (t.verdict.verdict !== "VERIFIED") return false;`, ``),
  m("R08", RA, "RÄSTIK: final-receipt control (genuine receipt must pass self-check) removed", `if (!control_clean) return { control_clean, records, findings };`, ``),
  m("R09", RA, "RÄSTIK: final-receipt attacks that throw are treated as accepted", `return { accepted: false, detail: \`threw:\${e instanceof Error ? e.name : "unknown"}\` }; // fail-closed`, `return { accepted: true, detail: "threw" };`),
];

/**
 * Survivors that no test CAN distinguish from the original, each with the concrete reason. They are
 * kept in the catalog (and in the score denominator) so that the justification is reviewable; if the
 * surrounding code changes and one of them becomes observable, a test should kill it instead.
 */
const EQUIVALENT: Record<string, string> = {
  T08: "validateEnvelope (mutant P02, which IS killed) rejects every envelope in which an allowed action is also forbidden, so for any envelope that reaches TÖEPÄRA env.allowed_actions.includes(a) already implies !env.forbidden_actions.includes(a).",
  G04: "toeparaVerify returns a non-null bundle only together with verdict VERIFIED and every rejected()/catch path returns bundle: null, so `verdict !== VERIFIED` and `bundle === null` are the same condition on every reachable value.",
  D04: "owner-factory-mismatch needs worker.factory !== envelope.factory; validateEnvelope (mutant P01, killed) forces agent_id to start with `${factory}-` and the registry derives each worker's factory from the same id prefix, so the two are always equal for an owned task.",
  R06: "realAttackTarget calls cerberusDecide with rastik: null; QUARANTINE requires a confirmed high/critical finding in the RÄSTIK report, so only ADMIT or DENY can be returned there and `=== ADMIT` equals `!== DENY`.",
  R07: "cerberusDecide recomputes TÖEPÄRA itself and returns DENY unless VERIFIED, so the early `return false` in the attack target is only an optimisation that skips a second recomputation; the returned boolean is identical.",
};
for (const id of Object.keys(EQUIVALENT)) if (!RAW.some((x) => x.id === id)) throw new Error(`EQUIVALENT names unknown mutant ${id}`);

export const MUTANTS: Mutant[] = RAW.map((x) => (EQUIVALENT[x.id] === undefined ? x : { ...x, equivalent: EQUIVALENT[x.id] }));
