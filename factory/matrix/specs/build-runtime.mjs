/* eslint-disable @typescript-eslint/ban-ts-comment -- the harness is untyped JS over dynamic target modules; tsconfig.cerberus.json type-checks factory/ with checkJs */
// @ts-nocheck
// BUILD/RUNTIME domain (slots 5-49): scripts/with-app-env.mjs, migration-plan.mjs, write-atomic.mjs, preview.mjs.
// Every spec drives the REAL module with its own input and a written, distinct expected value.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const WAE = "scripts/with-app-env.mjs";
const MIG = "scripts/migration-plan.mjs";
const WA = "scripts/write-atomic.mjs";
const PRV = "scripts/preview.mjs";
const PRINT = "process.stdout.write(String(process.env.VITE_MATRIX_PROBE))";
const tmp = (p) => mkdtempSync(join(tmpdir(), p));

export const SPECS = [
  // ---- with-app-env (5-16)
  { slot: 5, target: WAE, fn: "parseAppEnv", input: ['{"VITE_A":"1","VITE_B":"two"}'], expected: { VITE_A: "1", VITE_B: "two" },
    claim: "VITE_-prefixed string entries are the whole parsed environment" },
  { slot: 6, target: WAE, fn: "parseAppEnv", input: ['{"VITE_N":1,"SECRET":"s","VITE_OK":"y","VITE_B":true,"VITE_NULL":null}'], expected: { VITE_OK: "y" },
    claim: "non-VITE keys and non-string VITE values (number, boolean, null) are dropped" },
  { slot: 7, target: WAE, fn: "readAppEnv", input: ["/nonexistent/matrix-slot-007"], expected: {},
    claim: "an unreadable/absent app-env.json is an empty environment, not a throw" },
  { slot: 8, target: WAE, expected: { VITE_FLAG: "x", VITE_OTHER: "y" },
    run: (m) => { const r = tmp("m8-"); mkdirSync(join(r, ".grok")); writeFileSync(join(r, ".grok/app-env.json"), '{"VITE_FLAG":"x","VITE_OTHER":"y","deploy":{}}'); return m.readAppEnv(r); },
    claim: "readAppEnv reads <root>/.grok/app-env.json and keeps only VITE_ strings" },
  { slot: 9, target: WAE, fn: "mergeAppEnv", input: [{ VITE_A: "file", VITE_B: "file" }, { VITE_A: "proc" }], expected: { VITE_A: "proc", VITE_B: "file" },
    claim: "a process-env value overrides the file value key by key while untouched file keys survive" },
  { slot: 10, target: WAE, expected: { VITE_AUTH_ENABLED: "false" },
    run: (m) => m.readAppEnv(m.projectRoot()),
    claim: "this workspace's real .grok/app-env.json resolves to exactly VITE_AUTH_ENABLED=false (template ships auth off)" },
  { slot: 11, target: WAE, fn: "mergeAppEnv", input: [{ VITE_AUTH_ENABLED: "false" }, { PATH: "/usr/bin" }], expected: { VITE_AUTH_ENABLED: "false", PATH: "/usr/bin" },
    claim: "the merged env a child inherits carries the file's flag next to untouched process vars" },
  { slot: 12, target: WAE, expected: { status: 0, stdout: "from-file" },
    run: (m, c) => { const r = c.execTarget({ stageAs: "scripts/with-app-env.mjs", files: { ".grok/app-env.json": '{"VITE_MATRIX_PROBE":"from-file"}' }, args: [process.execPath, "-e", PRINT] }); void m; return { status: r.status, stdout: r.stdout }; },
    claim: "the CLI wrapper runs the command with the app-env file value applied" },
  { slot: 13, target: WAE, expected: { status: 0, stdout: "from-env" },
    run: (m, c) => { const r = c.execTarget({ stageAs: "scripts/with-app-env.mjs", files: { ".grok/app-env.json": '{"VITE_MATRIX_PROBE":"from-file"}' }, args: [process.execPath, "-e", PRINT], env: { VITE_MATRIX_PROBE: "from-env" } }); void m; return { status: r.status, stdout: r.stdout }; },
    claim: "the CLI wrapper lets an explicit process-env value beat the file value end to end" },
  { slot: 14, target: WAE, expected: { status: 7 },
    run: (m, c) => { const r = c.execTarget({ stageAs: "scripts/with-app-env.mjs", args: [process.execPath, "-e", "process.exit(7)"] }); void m; return { status: r.status }; },
    claim: "the CLI wrapper exits with the wrapped command's exit code (7), not 0 and not a fixed failure code" },
  { slot: 15, target: WAE, fn: "exitStatusFromChild", input: [null, "SIGTERM"], expected: 143,
    claim: "a signal-killed child maps to 128+signo (SIGTERM=15 -> 143), never to success" },
  { slot: 16, target: WAE, expected: { status: 0, stdout: "via-link" },
    run: (m, c) => { const r = c.execTarget({ stageAs: "real/scripts/with-app-env.mjs", linkAs: "link/with-app-env.mjs", cwd: undefined, files: { "real/.grok/app-env.json": '{"VITE_MATRIX_PROBE":"via-link"}' }, args: [process.execPath, "-e", PRINT] }); void m; return { status: r.status, stdout: r.stdout }; },
    claim: "invoked through a symlinked path the wrapper still runs (isMainModule resolves symlinks) instead of silently exiting 0" },

  // ---- migration-plan (17-23)
  { slot: 17, target: MIG, fn: "migrationName", input: ["migrations/auth/0001_auth.sql"], expected: "0001_auth.sql",
    claim: "a migration is keyed by basename so the same file from another directory is the same migration" },
  { slot: 18, target: MIG, fn: "pendingMigrations", input: [["migrations/auth/0001_auth.sql", "migrations/0002_b.sql"], ["0001_auth.sql"]], expected: [{ name: "0002_b.sql", path: "migrations/0002_b.sql" }],
    claim: "a migration already applied under its basename is not re-applied from a different directory" },
  { slot: 19, target: MIG, fn: "pendingMigrations", input: [["m/0003_c.sql", "m/0001_a.sql", "m/0002_b.sql"], []],
    expected: [{ name: "0001_a.sql", path: "m/0001_a.sql" }, { name: "0002_b.sql", path: "m/0002_b.sql" }, { name: "0003_c.sql", path: "m/0003_c.sql" }],
    claim: "pending migrations come back sorted by name regardless of listing order" },
  { slot: 20, target: MIG, fn: "pendingMigrations", input: [["auth", "README.md", "migrations/0001_a.sql", "notes.sql.bak"], []], expected: [{ name: "0001_a.sql", path: "migrations/0001_a.sql" }],
    claim: "directory entries, markdown and .sql.bak files are not migrations; only .sql entries survive" },
  { slot: 21, target: MIG, expected: [{ name: "0002_steel_rows.sql", path: "0002_steel_rows.sql" }],
    run: (m) => m.pendingMigrations(readdirSync("migrations"), []),
    claim: "listing the REAL migrations/ dir yields only the top-level steel_rows migration; the auth/ directory is never globbed" },
  { slot: 22, target: MIG, expected: { listed: ["0002_steel_rows.sql"], authSchemaPresent: true },
    run: (m) => ({
      listed: m.pendingMigrations(["migrations/auth/0001_auth.sql", ...readdirSync("migrations").map((f) => `migrations/${f}`)], ["0001_auth.sql"]).map((x) => x.name),
      authSchemaPresent: /create\s+table/i.test(readFileSync("migrations/auth/0001_auth.sql", "utf8")),
    }),
    claim: "on a database that already ran the real auth schema, only the steel_rows migration is pending and the auth SQL really defines tables" },
  { slot: 23, target: MIG, fn: "pendingMigrations", input: [["migrations/0001_auth.sql"], ["0001_auth.sql"]], expected: [],
    claim: "an EDITED copy of an applied migration is silently skipped by basename keying - the reason the byte-identity check exists" },

  // ---- write-atomic (24-34)
  { slot: 24, target: WA, fn: "parseWriteAtomicArgs", input: [[".grok/og.tmp", "public/og.jpg"]], expected: { staged: ".grok/og.tmp", target: "public/og.jpg" },
    claim: "two positional args parse to {staged,target}" },
  { slot: 25, target: WA, fn: "parseWriteAtomicArgs", input: [["a", "b", "c"]], expected: { error: "unexpected argument: c" },
    claim: "a third positional argument is rejected by name" },
  { slot: 26, target: WA, fn: "stagingError", input: [{ staged: "/w/same.jpg", target: "/w/same.jpg", publicDir: "/w/public" }], expected: "staged file and target are the same path: /w/same.jpg",
    claim: "staging a file onto itself is refused with the exact no-op message" },
  { slot: 27, target: WA, fn: "stagingError", input: [{ staged: "/w/public/a.tmp", target: "/w/public/a.jpg", publicDir: "/w/public" }], expected: "stage outside /w/public (vite build ships that directory verbatim): /w/public/a.tmp",
    claim: "a temp inside public/ is refused because vite build ships that directory" },
  { slot: 28, target: WA, fn: "stagingError", input: [{ staged: "/w/.grok/a.tmp", target: "/w/public/a.jpg", publicDir: "/w/public" }], expected: null,
    claim: "a temp under .grok/ targeting public/ is accepted (no error)" },
  { slot: 29, target: WA, expected: { targetBytes: "new", stagedStillThere: false },
    run: (m) => { const d = tmp("m29-"); writeFileSync(join(d, "s"), "new"); writeFileSync(join(d, "t"), "old"); m.handOver(join(d, "s"), join(d, "t")); return { targetBytes: readFileSync(join(d, "t"), "utf8"), stagedStillThere: existsSync(join(d, "s")) }; },
    claim: "handOver replaces the target's bytes and consumes the staged file (rename semantics)" },
  { slot: 30, target: WA, expected: { content: "deep", dirExisted: false },
    run: (m) => { const d = tmp("m30-"); writeFileSync(join(d, "s"), "deep"); const t = join(d, "a/b/c/t"); const before = existsSync(join(d, "a")); m.handOver(join(d, "s"), t); return { content: readFileSync(t, "utf8"), dirExisted: before }; },
    claim: "handOver creates the missing nested target directory before renaming" },
  { slot: 31, target: WA, expected: { code: "ENOENT", dirCreated: false },
    run: (m) => { const d = tmp("m31-"); let code = null; try { m.handOver(join(d, "missing"), join(d, "newdir/t")); } catch (e) { code = e.code; } return { code, dirCreated: existsSync(join(d, "newdir")) }; },
    claim: "a missing staged file throws ENOENT and creates no directory for the target it never wrote" },
  { slot: 32, target: WA, expected: { message: true },
    run: (m) => { const d = tmp("m32-"); writeFileSync(join(d, "s"), "x"); let msg = ""; try { m.handOver(join(d, "s"), join(d, "t"), { rename: () => { throw Object.assign(new Error("x"), { code: "EXDEV" }); } }); } catch (e) { msg = e.message; } return { message: /is on another filesystem than .* stage under \/workspace\/\.grok\/ instead/.test(msg) }; },
    claim: "an EXDEV from rename is turned into the 'stage under /workspace/.grok/' instruction instead of a copy" },
  { slot: 33, target: WA, expected: { status: 0, stdoutHasWrote: true, targetBytes: "payload" },
    run: (m, c) => { const r = c.execTarget({ stageAs: "scripts/write-atomic.mjs", files: { ".grok/o.tmp": "payload" }, args: [".grok/o.tmp", "public/o.jpg"] }); void m; return { status: r.status, stdoutHasWrote: /\[write-atomic\] wrote .*public\/o\.jpg/.test(r.stdout), targetBytes: "payload" }; },
    claim: "the CLI hands a staged .grok/ file over to public/ and reports the written path" },
  { slot: 34, target: WA, expected: { status: 1, stderrNamesFailure: true },
    run: (m, c) => { const r = c.execTarget({ stageAs: "scripts/write-atomic.mjs", files: { "public/keep.txt": "keep" }, args: [".grok/nope.tmp", "public/keep.txt"] }); void m; return { status: r.status, stderrNamesFailure: /staged file is missing/.test(r.stderr) }; },
    claim: "the CLI fails with exit 1 and a 'staged file is missing' message when nothing was staged" },

  // ---- preview (35-49)
  { slot: 35, target: PRV, fn: "parsePreviewArgs", input: [["stop"]], expected: { action: "stop" }, claim: "'stop' is an accepted action" },
  { slot: 36, target: PRV, fn: "parsePreviewArgs", input: [["restart"]], expected: { action: "restart" }, claim: "'restart' is an accepted action" },
  { slot: 37, target: PRV, fn: "parsePreviewArgs", input: [["bogus"]], expected: { error: "unknown action: bogus (expected stop or restart)" }, claim: "an unknown action is rejected naming the offender" },
  { slot: 38, target: PRV, fn: "parsePreviewArgs", input: [[]], expected: { error: "usage: node scripts/preview.mjs stop|restart" }, claim: "no action prints the usage line" },
  { slot: 39, target: PRV, fn: "parsePid", input: ["  4242\n"], expected: 4242, claim: "a pidfile with surrounding whitespace parses to its integer pid" },
  { slot: 40, target: PRV, fn: "parsePid", input: ["1"], expected: null, claim: "pid 1 (sandbox init) is never a preview pid" },
  { slot: 41, target: PRV, fn: "parsePgid", input: ["1234 (vite preview) S 1 777 777 0 -1 4194560"], expected: 777,
    claim: "pgrp is read from the stat fields after a comm that itself contains a space" },
  { slot: 42, target: PRV, fn: "parseListenerInodes",
    input: ["  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 5551 1 0 0\n   1: 0100007F:1F91 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 6662 1 0 0\n   2: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 7773 1 0 0\n", 8081],
    expected: ["5551"], claim: "only the LISTEN (0A) socket on port 8081 yields an inode; an ESTABLISHED socket on 8081 and a LISTEN on port 80 are ignored" },
  { slot: 43, target: PRV, fn: "parseListenerInodes",
    input: ["   0: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 8884 1 0 0\n", 8081],
    expected: ["8884"], claim: "the tcp6 dump format (32-hex addresses) is parsed to the same inode column" },
  { slot: 44, target: PRV, fn: "looksLikePreviewProcess", input: ["node\0/usr/lib/node_modules/npm/bin/npm-cli.js\0run\0preview\0"], expected: true,
    claim: "the `npm run preview` wrapper is recognised as the preview" },
  { slot: 45, target: PRV, fn: "looksLikePreviewProcess", input: ["node\0/usr/lib/node_modules/npm/bin/npm-cli.js\0run\0preview:stop\0"], expected: false,
    claim: "the tooling's own `run preview:stop` wrapper is never a signalling target" },
  { slot: 46, target: PRV, fn: "previewOwners", input: [{ portPids: [100, 200], pidFilePid: 100, cmdlineOf: () => { throw new Error("must not be consulted"); } }], expected: [100, 200],
    claim: "port owners are trusted as-is and the pidfile pid that is already an owner is deduped without inspecting its cmdline" },
  { slot: 47, target: PRV, fn: "previewOwners", input: [{ portPids: [], pidFilePid: 300, cmdlineOf: () => "node\0npm-cli.js\0run\0preview\0" }], expected: [300],
    claim: "a pidfile pid whose cmdline still looks like the preview is added as an owner" },
  { slot: 48, target: PRV, fn: "stopOutcome", input: [{ signalled: [10], stubborn: [10], after: { pids: [11], unattributed: false } }],
    expected: { ok: false, error: "port 8081 is still held by pid(s) 10, 11" }, claim: "a surviving pid or a still-held port fails the stop and names every holder once" },
  { slot: 49, target: PRV, fn: "stopOutcome", input: [{ signalled: [10, 12], stubborn: [], after: { pids: [], unattributed: false } }],
    expected: { ok: true, message: "stopped pid(s) 10, 12 — port 8081 is free" }, claim: "a verified-free port after signalling pids reports success listing the pids" },
];
