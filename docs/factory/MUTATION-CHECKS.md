# Mutation checks (closed loop guards)

Method: `/tmp/mutate.py` (not committed; the table below is its output). Each row breaks ONE guard in the source, runs `node --experimental-strip-types --test factory/tests/*.test.ts` (Node 22), records the failing tests, and restores the file (asserted byte-identical after each run).

Result: **13/13 mutants KILLED, 0 survived** (final run, after adding the body-altered-bundle test).  
History: the first run had **M5 SURVIVE** (bundle-equality check had no dedicated test); the test `a bundle that keeps the genuine bundle_digest but has an altered body is DENIED` was added and now kills it.

Note: several TÖEPÄRA mutants (M1-M3) are killed *partly through RÄSTIK*: once the verifier is weakened, the attack battery CONFIRMS a finding (e.g. stale-base-sha) and CERBERUS QUARANTINEs the genuine loop, so the e2e loop tests fail. That is the intended closed-loop behaviour.

| # | mutation | killed | failing tests | first failing test |
|---|---|---|---|---|
| M1 | stale-base check disabled in TÖEPÄRA | yes | 7 | CLOSED LOOP (hash-files, real files at the real HEAD): envelope -> KRATT -> RÄSTIK -> TÖEP |
| M2 | self-verified check disabled in TÖEPÄRA | yes | 7 | CLOSED LOOP (hash-files, real files at the real HEAD): envelope -> KRATT -> RÄSTIK -> TÖEP |
| M3 | source-digest comparison disabled in TÖEPÄRA | yes | 7 | CLOSED LOOP (hash-files, real files at the real HEAD): envelope -> KRATT -> RÄSTIK -> TÖEP |
| M4 | replay guard disabled in CERBERUS adapter | yes | 7 | CERBERUS: a stale/replayed receipt (same bundle, same guard) is DENIED the second time |
| M5 | bundle-equality recomputation disabled in CERBERUS adapter | yes | 1 | CERBERUS: a bundle that keeps the genuine bundle_digest but has an altered body is DENIED  |
| M6 | QUARANTINE branch disabled in CERBERUS | yes | 2 | CERBERUS: unresolved CONFIRMED high/critical RÄSTIK finding => QUARANTINE; medium or UNCON |
| M7 | KRATT stage self-verifies (verification_state VERIFIED) | yes | 18 | CERBERUS: verified evidence + local policy => ADMIT with a verifiable, adapter-sourced rec |
| M8 | stale-base preflight disabled in loop | yes | 1 | NEGATIVE: stale base_sha => KRATT BLOCKED -> SLEEP, no receipt, final DENY |
| M9 | local policy trust gate always AUTHORIZED | yes | 1 | CERBERUS: policy violation (envelope does not forbid merge/deploy) => DENY even with VERIF |
| M10 | working-tree diff check disabled in TÖEPÄRA | yes | 2 | TÖEPÄRA (temp repo): a working tree that moved after KRATT ran is REJECTED even though the |
| M11 | action authorization disabled in TÖEPÄRA | yes | 1 | TÖEPÄRA: unauthorized action, agent spoof, repository spoof, receipt/envelope mismatch are |
| M12 | RÄSTIK control receipt check disabled | yes | 1 | RÄSTIK: if the control receipt is not admitted, no attack results are reported (no false ' |
| M13 | dispatcher accepts illegal transitions | yes | 1 | EVERY illegal (from,to) pair is rejected, logged as rejected, and leaves the worker unchan |
