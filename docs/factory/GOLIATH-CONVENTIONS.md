# GOLIATH control-plane conventions: research result

Date: 2026-10-03 (EEST). Method: read-only. `gh repo list` for every owner the `gh` identity `antonioportfelli-boop` can see
(`3XTRINITY-CORPORATION-AND-SOFTWARE`, `3XTRINITY-CORPORATION`, `AETHERNA-9`, `3XTRINITY-CORPORATIONS`, `tkynnap-creator`, `antonioportfelli-boop`),
depth-1 clones of every candidate, `rg -i goliath`, `gh search code goliath --owner 3XTRINITY-CORPORATION-AND-SOFTWARE`,
`gh api repos/<r>/branches`. GitLab is `EXTERNAL_CONNECTOR_BLOCKED` (recorded once; nothing from GitLab was read or inferred).

## Result: the real GOLIATH control plane was NOT FOUND in any accessible repository

| Candidate (repo @ commit read) | What it actually contains | GOLIATH control plane? |
|---|---|---|
| `tkynnap-creator/GOLIATH-OS` @ `fca77a8f` (named "source of truth" in `3XTRINITY-CORPORATION-AND-SOFTWARE/main` `Agent5:18-19`) | 2 files: `README.md` (one line, `# GOLIATH-OS`) and `.env.example` (config key names only). Default and only branch `main`, 2 commits | NO code |
| `3XTRINITY-CORPORATIONS/GOLIATH-OS2` @ `9753de97` (named "comparison target", `Agent5:20`) | 1 file: `README.md` (`# GOLIATH-OS`). 1 commit | NO code |
| `3XTRINITY-CORPORATION-AND-SOFTWARE/goliathOS-2` @ `70835687` (private) | `AGENTS.project.md:1` calls it "ETHER.NET9 - SANDBOX FOR SCHOOLS": a TanStack Start school/forum/mail/lab app (`src/lib/school/*`, `src/lib/ether/*`, migrations `0001..0009`). `rg -i goliath` finds no match in its content | NO (an unrelated app; only its name says "goliath") |
| `3XTRINITY-CORPORATION-AND-SOFTWARE/ETHER.-NET9` @ `0677975f` | same product line as above | NO |
| `3XTRINITY-CORPORATION-AND-SOFTWARE/STEEL-AURA-ULTIMA` @ `aeb48dd7` | `docs/GOLIATH-BRIDGE.md` (27 lines: patterns to lift from goliathOS-2: ping RTT, kinematics, kernel framing); `apps/os-host/src/main.ts:2,16` "Goliath-style" ping demo | NO (sync/ping bridge only) |
| `3XTRINITY-CORPORATION-AND-SOFTWARE/main` @ `7742c5dc`, `AETHERNA-9/{net,STEEL-...}` mirrors | `Agent5` / `copiolot` are prompt/script text that mention GOLIATH as a goal ("general control-plane, workspace, API and orchestration platform", `Agent5:7`) | NO code; requirements prose only |
| `APEX-OFFER-DESK`, `RIPPLE-...`, `AURA-...visualizer`, `AETHERNA-9/community`, `tkynnap-creator/community`, `antonioportfelli-boop/jev-and-ai-sdk` @ `d7a675cc` | no `goliath` match in code | NO |
| `3XTRINITY-CORPORATION-AND-SOFTWARE/3XTRINITY`, `.../GOLIATH-OS`, `.../GOLIATH-OS2`, `antonioportfelli-boop/GOLIATH-OS` | `gh api repos/<r>` -> HTTP 404 | do not exist / not visible |
| `Agent5:23` GitLab `goliath-os1/steel-3xtrinity-corporation-official-music-software` | not read | EXTERNAL_CONNECTOR_BLOCKED |

Consequence: there is no `/api/tasks/run`, no GOLIATH routing table, workflow engine, audit schema or error model to conform to.
Nothing in this repo may claim `REAL_GOLIATH_CONNECTED`. Stand-in and adapter are explicitly `real_goliath: false`.

## Conventions, with evidence and status

| Convention | Status | Evidence |
|---|---|---|
| GOLIATH control-plane routing (task submit/run endpoints) | NOT_FOUND | searches above; `GOLIATH-OS` has only `README.md` + `.env.example` @ `fca77a8f` |
| Request validation of GOLIATH commands | PARTIAL (config names only) | `tkynnap-creator/GOLIATH-OS/.env.example:26-29` `ENABLE_COMMAND_VALIDATION=true`, `MAX_COMMAND_LENGTH=2000`, `RATE_LIMIT_REQUESTS_PER_MINUTE=30`, `API_TIMEOUT_SECONDS=30` @ `fca77a8f`. Names exist; no implementation to read |
| Audit trail | NOT_FOUND for GOLIATH. (Unrelated app: `goliathOS-2/src/lib/school/api.ts:113-116` `log(userId, kind, detail)` inserts into table `activity`) | the school-app function is NOT GOLIATH evidence and was not adopted |
| Workflow execution | NOT_FOUND | no workflow code in any GOLIATH-named repo |
| Error model | NOT_FOUND for GOLIATH. (school app: plain `throw new Error("<Estonian text>")`, `api.ts:101,110,315`; tool errors `errors.ts:1-12` kinds `login/not_connected/scope_denied/access_denied/error`) | unrelated app; not adopted |
| Authentication / trust boundary | NOT_FOUND for GOLIATH. (school app: `authMiddleware` on every server fn, `src/lib/auth/middleware.ts`; `UnauthorizedError` `verify.server.ts:37`; "scope every row by `context.userId`", `AGENTS.project.md:8`) | unrelated app |
| GOLIATH role as stated by owner | VERIFIED as prose only | `Agent5:7` "GOLIATH OS - general control-plane, workspace, API and orchestration platform"; `Agent5:61` "first GOLIATH implementation priority is an offline Rust artifact validator with tests and CI" |

## What this repo does instead (design, not discovery)

`factory/goliath-port.ts` defines the smallest typed, in-process interface a real GOLIATH could later implement:

```ts
interface GoliathPort {
  readonly identity: { name: string; real_goliath: boolean; transport: "in-process" };
  submit(envelope: TaskEnvelope): Promise<ActionReceipt>;   // rejects with GoliathPortError, never resolves with a fake receipt
}
```

* `StandInGoliathPort` implements it with the existing KRATT stage (`runKrattStage`). `real_goliath` is the literal `false`.
* The port takes a protocol-v1 `TaskEnvelope` (validated by `validateEnvelope`) and returns an `ActionReceipt` that is always `UNVERIFIED`; admission stays with TÖEPÄRA + CERBERUS.
* `GoliathPortError.code` is a closed set (`envelope-invalid`, `repository-mismatch`, `stale-base-sha`, `action-refused`, `receipt-invalid`, `unavailable`).
* There is no network code, no endpoint URL, no credentials. Connecting a real GOLIATH is a human gate: it needs the GOLIATH spec (transport, authentication, trust boundary) first.
* `assertAdapterHonest(port)` fails if a port that is not the stand-in claims `real_goliath: true` without a non-empty `attestation`; this is a naming guard, not authentication.
