// Mutation table for scripts/matrix250/mutation-check.mjs: each row breaks ONE guard in real code. A row is KILLED when any slot spec
// of its group or any regression guard fails. Sets: builder (the 10 defects of the original PR), audit-targeted (23), audit-subtle (14),
// audit-slot-weakness (2). `from` must occur exactly once in `file` (checked by scripts/matrix250/specs.test.mjs).
export const MUTANTS = [
 {
  "set": "builder",
  "file": "cerberus/core/decide.ts",
  "group": "cerberus",
  "from": "stage(snapshot.toepara === \"ADMITTED\", \"toepara-not-admitted\")",
  "to": "stage(true, \"toepara-not-admitted\")",
  "desc": "TOEPARA self-verified check neutralised"
 },
 {
  "set": "builder",
  "file": "kratt/evidence.ts",
  "group": "kratt",
  "from": "b.checks.pass >= 1 &&",
  "to": "b.checks.pass >= 0 &&",
  "desc": "kratt evidence threshold pass>=1 -> >=0"
 },
 {
  "set": "builder",
  "file": "scripts/preview.mjs",
  "group": "build-runtime",
  "from": "pid > 1 ? pid : null",
  "to": "pid > 0 ? pid : null",
  "desc": "preview pid>1 -> >0"
 },
 {
  "set": "builder",
  "file": "src/lib/auth/gate-identity.server.ts",
  "group": "security-trust",
  "from": "maxTokenAge: \"10 minutes\",",
  "to": "",
  "desc": "gate-identity maxTokenAge removed"
 },
 {
  "set": "builder",
  "file": "scripts/sign-out-plan.mjs",
  "group": "security-trust",
  "from": "if (outcome !== \"ok\") {",
  "to": "if (outcome === \"never\") {",
  "desc": "sign-out outcome check neutralised"
 },
 {
  "set": "builder",
  "file": "scripts/grok-pwa-shared.mjs",
  "group": "pwa-asset",
  "from": ".replaceAll(\"&\", \"&amp;\")",
  "to": "",
  "desc": "escapeHtml & escape removed"
 },
 {
  "set": "builder",
  "file": "cerberus/policy/policy.ts",
  "group": "cerberus",
  "from": "[\"detect\", \"recover\", \"recommend\"] as const",
  "to": "[\"detect\", \"recover\", \"recommend\", \"merge\"] as const",
  "desc": "policy allow-list gains merge"
 },
 {
  "set": "builder",
  "file": "kratt/paths.ts",
  "group": "kratt",
  "from": "/^[A-Za-z0-9_][A-Za-z0-9._-]*$/",
  "to": "/^[A-Za-z0-9_.][A-Za-z0-9._-]*$/",
  "desc": "kratt path segment may start with a dot"
 },
 {
  "set": "builder",
  "file": "factory/dispatcher.ts",
  "group": "rastik-factory",
  "from": "  SLEEP: [\"READY\"],",
  "to": "  SLEEP: [\"READY\", \"ACTIVE\"],",
  "desc": "dispatcher allows SLEEP->ACTIVE"
 },
 {
  "set": "builder",
  "file": "rastik/run.ts",
  "group": "rastik-factory",
  "from": "if (!again) {",
  "to": "if (false) {",
  "desc": "rastik re-run guard removed"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/migration-plan.mjs",
  "group": "build-runtime",
  "from": "a.name.localeCompare(b.name)",
  "to": "b.name.localeCompare(a.name)",
  "desc": "pendingMigrations sorts descending instead of ascending"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/migration-plan.mjs",
  "group": "build-runtime",
  "from": "path.endsWith(\".sql\")",
  "to": "path.includes(\".sql\")",
  "desc": "isMigrationFile accepts any path merely containing .sql (e.g. .sql.bak)"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/with-app-env.mjs",
  "group": "build-runtime",
  "from": "{ ...appEnv, ...processEnv }",
  "to": "{ ...processEnv, ...appEnv }",
  "desc": "mergeAppEnv precedence swapped: file beats process env"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/with-app-env.mjs",
  "group": "build-runtime",
  "from": "return 128 + (typeof",
  "to": "return 64 + (typeof",
  "desc": "exitStatusFromChild signal base 128 -> 64"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/write-atomic.mjs",
  "group": "build-runtime",
  "from": "if (rest.length > 0)",
  "to": "if (rest.length > 1)",
  "desc": "parseWriteAtomicArgs tolerates exactly one extra positional arg"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/write-atomic.mjs",
  "group": "build-runtime",
  "from": "  mkdirSync(dirname(target), { recursive: true });\n",
  "to": "",
  "desc": "handOver no longer creates the target directory"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/preview.mjs",
  "group": "build-runtime",
  "from": "cols[3] !== TCP_LISTEN",
  "to": "false",
  "desc": "parseListenerInodes ignores socket state (accepts ESTABLISHED)"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/check-auth-invariant.mjs",
  "group": "security-trust",
  "from": "return value !== \"false\";",
  "to": "return String(value).toLowerCase() !== \"false\";",
  "desc": "authEnabledFromEnvValue case-insensitive ('FALSE' turns auth off)"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/sign-out-plan.mjs",
  "group": "security-trust",
  "from": "PREVIEW_SIGN_OUT_TIMEOUT_MS = 1500",
  "to": "PREVIEW_SIGN_OUT_TIMEOUT_MS = 15000",
  "desc": "preview sign-out timeout 1500 -> 15000"
 },
 {
  "set": "audit-targeted",
  "file": "src/lib/auth/sign-in-gate.ts",
  "group": "security-trust",
  "from": "if (input.isPending) return \"pending\";",
  "to": "if (input.isPending && !input.hasUser) return \"pending\";",
  "desc": "gate state: cached user overrides pending"
 },
 {
  "set": "audit-targeted",
  "file": "src/lib/auth/gate-identity.server.ts",
  "group": "security-trust",
  "from": "host === \"grok.me\" || host.endsWith(\".grok.me\")",
  "to": "host.includes(\"grok.me\")",
  "desc": "look-alike host containing grok.me gets the grok.me gate"
 },
 {
  "set": "audit-targeted",
  "file": "kratt/task.ts",
  "group": "kratt",
  "from": "if (new Set(out).size !== out.length) fail(\"files-duplicate\");",
  "to": "",
  "desc": "validateTask no longer rejects duplicate files"
 },
 {
  "set": "audit-targeted",
  "file": "kratt/paths.ts",
  "group": "kratt",
  "from": "MAX_PATH_LENGTH = 200",
  "to": "MAX_PATH_LENGTH = 300",
  "desc": "MAX_PATH_LENGTH 200 -> 300"
 },
 {
  "set": "audit-targeted",
  "file": "kratt/evidence.ts",
  "group": "kratt",
  "from": "if (canonicalize(v) !== content) return bad(\"evidence-not-canonical\");",
  "to": "",
  "desc": "parseEvidence no longer requires canonical form"
 },
 {
  "set": "audit-targeted",
  "file": "cerberus/artifact-trust/artifact-trust.ts",
  "group": "cerberus",
  "from": "update(content, \"utf8\")",
  "to": "update(content, \"latin1\")",
  "desc": "sha256Hex hashes latin1 instead of UTF-8"
 },
 {
  "set": "audit-targeted",
  "file": "cerberus/artifact-trust/artifact-trust.ts",
  "group": "cerberus",
  "from": "/^[0-9a-f]{64}$/",
  "to": "/^[0-9a-fA-F]{64}$/",
  "desc": "artifact digest regex accepts upper-case hex (compare still exact)"
 },
 {
  "set": "audit-targeted",
  "file": "cerberus/integrations/verdict-adapters.ts",
  "group": "cerberus",
  "from": "typeof v === \"string\" ? v : null",
  "to": "v == null ? null : String(v)",
  "desc": "adapter verdict coerced via String() (boxed String accepted)"
 },
 {
  "set": "audit-targeted",
  "file": "factory/kratt-stage.ts",
  "group": "rastik-factory",
  "from": "Math.min(e.resource_budget.max_wall_ms, 60_000)",
  "to": "Math.min(e.resource_budget.max_wall_ms, 120_000)",
  "desc": "run-test wall clamp 60s -> 120s"
 },
 {
  "set": "audit-targeted",
  "file": "factory/dispatcher.ts",
  "group": "rastik-factory",
  "from": "if (!ctx.task_id) return reject(\"no-task-no-wake\");",
  "to": "",
  "desc": "dispatcher no longer enforces no-task-no-wake"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/grok-pwa-shared.mjs",
  "group": "pwa-asset",
  "from": "&& platform === \"ios\"",
  "to": "",
  "desc": "isInstallQuery fires for any platform"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/brand-check.mjs",
  "group": "pwa-asset",
  "from": "OG_PENDING_MAX_AGE_MS = 10 * 60 * 1000",
  "to": "OG_PENDING_MAX_AGE_MS = 60 * 60 * 1000",
  "desc": "og-pending marker max age 10 min -> 60 min"
 },
 {
  "set": "audit-targeted",
  "file": "rastik/changed.ts",
  "group": "rastik-factory",
  "from": " || base.includes(\"..\")",
  "to": "",
  "desc": "changedFiles no longer rejects ranges (a..b)"
 },
 {
  "set": "audit-targeted",
  "file": "scripts/grok-pwa-shared.mjs",
  "group": "pwa-asset",
  "from": "host.endsWith(\".vercel.app\") ||",
  "to": "",
  "desc": "publicAppHost no longer rejects *.vercel.app"
 },
 {
  "set": "audit-subtle",
  "file": "src/lib/auth/gate-identity.server.ts",
  "group": "security-trust",
  "from": "k.crv === \"Ed25519\" && ",
  "to": "",
  "desc": "JWKS key lookup no longer checks crv=Ed25519"
 },
 {
  "set": "audit-subtle",
  "file": "src/lib/auth/gate-identity.server.ts",
  "group": "security-trust",
  "from": "algorithms: [\"EdDSA\"],",
  "to": "",
  "desc": "jwtVerify no longer pins algorithms to EdDSA"
 },
 {
  "set": "audit-subtle",
  "file": "src/lib/auth/gate-identity.server.ts",
  "group": "security-trust",
  "from": "      issuer: options.issuer,\n",
  "to": "",
  "desc": "jwtVerify no longer enforces the issuer"
 },
 {
  "set": "audit-subtle",
  "file": "src/lib/auth/gate-identity.server.ts",
  "group": "security-trust",
  "from": "if (!sub) return null;",
  "to": "",
  "desc": "verify no longer rejects empty/whitespace sub"
 },
 {
  "set": "audit-subtle",
  "file": "kratt/actions.ts",
  "group": "kratt",
  "from": "if (r.bytes > budget.left) return \"total-size-budget-exceeded\";",
  "to": "",
  "desc": "hashFile total byte budget check removed"
 },
 {
  "set": "audit-subtle",
  "file": "kratt/actions.ts",
  "group": "kratt",
  "from": "if (artifacts.some((a) => a.name === h.name)) {",
  "to": "if (false) {",
  "desc": "manifest self/duplicate-listing guard disabled"
 },
 {
  "set": "audit-subtle",
  "file": "scripts/brand-check.mjs",
  "group": "pwa-asset",
  "from": "MAX_CARD_BYTES = 600 * 1024",
  "to": "MAX_CARD_BYTES = 6000 * 1024",
  "desc": "card size limit 600KB -> 6000KB"
 },
 {
  "set": "audit-subtle",
  "file": "scripts/grok-pwa-shared.mjs",
  "group": "pwa-asset",
  "from": "(install === \"1\" || install === \"true\")",
  "to": "(install === \"1\")",
  "desc": "isInstallQuery drops install=true"
 },
 {
  "set": "audit-subtle",
  "file": "scripts/preview.mjs",
  "group": "build-runtime",
  "from": "for (const pid of killed) kill(pid, \"SIGKILL\");",
  "to": "for (const pid of killed) kill(pid, \"SIGTERM\");",
  "desc": "terminate escalation sends SIGTERM instead of SIGKILL"
 },
 {
  "set": "audit-subtle",
  "file": "scripts/preview.mjs",
  "group": "build-runtime",
  "from": "return Number.isInteger(pgid) && pgid > 0 ? pgid : null;",
  "to": "return Number.isInteger(pgid) && pgid >= 0 ? pgid : null;",
  "desc": "parsePgid accepts pgid 0"
 },
 {
  "set": "audit-subtle",
  "file": "scripts/write-atomic.mjs",
  "group": "build-runtime",
  "from": "return rel !== \"\" && !rel.startsWith(\"..\")",
  "to": "return !rel.startsWith(\"..\")",
  "desc": "isInside treats the dir itself as inside"
 },
 {
  "set": "audit-subtle",
  "file": "scripts/with-app-env.mjs",
  "group": "build-runtime",
  "from": "process.exit(127);",
  "to": "process.exit(1);",
  "desc": "spawn error exit code 127 -> 1"
 },
 {
  "set": "audit-subtle",
  "file": "scripts/grok-pwa-shared.mjs",
  "group": "pwa-asset",
  "from": "|| !host.includes(\".\")",
  "to": "",
  "desc": "publicAppHost no longer requires a dot (localhost accepted)"
 },
 {
  "set": "audit-subtle",
  "file": "kratt/actions.ts",
  "group": "kratt",
  "from": "(x.name < y.name ? -1 : x.name > y.name ? 1 : 0)",
  "to": "(x.name < y.name ? 1 : x.name > y.name ? -1 : 0)",
  "desc": "artifacts sorted descending"
 },
 {
  "set": "audit-slot-weakness",
  "file": "scripts/write-atomic.mjs",
  "group": "build-runtime",
  "from": "    rename(staged, target);\n",
  "to": "",
  "desc": "handOver never renames (staged file not moved; CLI still prints wrote)"
 },
 {
  "set": "audit-slot-weakness",
  "file": "scripts/check-auth-invariant.mjs",
  "group": "security-trust",
  "from": "return value !== \"false\";",
  "to": "return false;",
  "desc": "authEnabledFromEnvValue always returns false"
 }
];
