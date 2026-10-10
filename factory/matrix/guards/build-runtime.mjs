// REGRESSION GUARDS for scripts/preview.mjs and scripts/with-app-env.mjs branches that no matrix slot asserts (not slots).
/** @type {import("../types.d.ts").Spec[]} */
export const GUARDS = [
  { slot: 1009, target: "scripts/preview.mjs", expected: { calls: [[7, "SIGTERM"], [8, "SIGTERM"], [7, "SIGKILL"]], signalled: [7, 8], killed: [7], stubborn: [] },
    run: async (m) => {
      const alive = new Set([7, 8]);
      /** @type {any} */ const calls = [];
      const kill = (/** @type {any} */ pid, /** @type {any} */ sig) => { calls.push([pid, sig]); if (sig === "SIGKILL" || pid === 8) alive.delete(pid); };
      const r = await m.terminatePids([7, 8], { kill, isAlive: (/** @type {any} */ p) => alive.has(p), sleep: async () => {}, graceMs: 10, pollMs: 5 });
      return { calls, signalled: r.signalled, killed: r.killed, stubborn: r.stubborn };
    },
    claim: "a pid that ignores SIGTERM is escalated to SIGKILL (and only that one); a pid that exits on SIGTERM is never SIGKILLed" },
  { slot: 1010, target: "scripts/preview.mjs", expected: { zeroPgid: null, realPgid: 42, spacesInComm: 42, noParen: null },
    run: (m) => ({ zeroPgid: m.parsePgid("123 (node) S 1 0 0 0 -1"), realPgid: m.parsePgid("123 (node) S 1 42 42 0 -1"), spacesInComm: m.parsePgid("123 (my proc (x)) S 1 42 42 0 -1"), noParen: m.parsePgid("garbage") }),
    claim: "a process-group id of 0 is not a group (null: killing -0 would signal our own group), real ids parse even when the command name contains spaces/parentheses" },
  { slot: 1011, target: "scripts/write-atomic.mjs", expected: { insidePublic: true, publicDirItself: null, outsidePublic: null },
    run: (m) => { const dir = "/w/public"; const refused = (/** @type {any} */ staged) => m.stagingError({ staged, target: "/w/x/out.jpg", publicDir: dir }) !== null; return { insidePublic: refused("/w/public/a.tmp"), publicDirItself: m.stagingError({ staged: dir, target: "/w/x/out.jpg", publicDir: dir }), outsidePublic: m.stagingError({ staged: "/w/.grok/a.tmp", target: "/w/public/out.jpg", publicDir: dir }) }; },
    claim: "CHARACTERISATION of a known gap: only paths strictly inside public/ are refused as staging sources; public/ itself is not (recorded as a finding in docs/factory/MATRIX.md, to be tightened in write-atomic.mjs, not asserted as desirable)" },
  { slot: 1012, target: "scripts/with-app-env.mjs", expected: { status: 127, namesFailure: true },
    run: (m, c) => { void m; const r = c.execTarget({ args: ["__matrix_no_such_command__"] }); return { status: r.status, namesFailure: /failed to run __matrix_no_such_command__/.test(r.stderr) }; },
    claim: "when the wrapped command cannot be spawned the wrapper exits 127 (command-not-found convention) and names the command" },
];
