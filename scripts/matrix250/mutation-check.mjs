#!/usr/bin/env node
// Mutation check for the matrix: breaks ONE guard in real code at a time (table: factory/matrix/mutants.mjs), runs the slot specs of
// the mutant's group plus every regression guard, and requires at least one of them to go red. The source file is restored after
// each mutant (verified byte-identical). Not part of `npm test` (about 3-4 minutes): run it with
//   node scripts/matrix250/mutation-check.mjs [--set builder|audit-targeted|audit-subtle|audit-slot-weakness] [--only 1,2,3]
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { MUTANTS } from "../../factory/matrix/mutants.mjs";

const ROOT = process.cwd();

/** Names of the slots/guards that fail with the current sources: group spec file + every guard file. */
export function failingEntries(group, root = ROOT) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const guardDir = join(root, "factory/matrix/guards");
  const files = [`factory/matrix/specs/${group}.mjs`, ...readdirSync(guardDir).filter((f) => f.endsWith(".mjs")).map((f) => `factory/matrix/guards/${f}`)];
  const failed = [];
  for (const f of files) {
    const r = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(root, "factory/matrix/runner.mjs"), f], { cwd: root, encoding: "utf8", env, timeout: 300_000, maxBuffer: 64 * 1024 * 1024 });
    const line = String(r.stdout ?? "").split("\n").find((l) => l.startsWith("MATRIX_SPEC_RESULTS:"));
    if (!line) { failed.push(`runner-error(${f})`); continue; }
    for (const e of JSON.parse(line.slice("MATRIX_SPEC_RESULTS:".length)).entries) if (!e.result.ok) failed.push(e.slot);
  }
  return failed;
}

/** Apply one mutant, run the check, ALWAYS restore. Returns { status: "KILLED"|"SURVIVED"|"SKIPPED", by }. */
export function runMutant(m, root = ROOT) {
  const p = join(root, m.file);
  const original = readFileSync(p, "utf8");
  if (original.split(m.from).length - 1 !== 1) return { status: "SKIPPED", by: [`pattern occurs ${original.split(m.from).length - 1} times`] };
  const restore = () => writeFileSync(p, original);
  process.once("exit", restore);
  /** @type {string[]} */
  let by = [];
  try {
    writeFileSync(p, original.replace(m.from, () => m.to));
    by = failingEntries(m.group, root);
  } finally {
    restore();
    process.removeListener("exit", restore);
  }
  if (readFileSync(p, "utf8") !== original) throw new Error(`restore of ${m.file} failed`);
  return { status: by.length > 0 ? "KILLED" : "SURVIVED", by };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const setArg = process.argv.indexOf("--set");
  const onlyArg = process.argv.indexOf("--only");
  const set = setArg > -1 ? process.argv[setArg + 1] : null;
  const only = onlyArg > -1 ? process.argv[onlyArg + 1].split(",").map(Number) : null;
  let killed = 0, total = 0, skipped = 0;
  const bySet = {};
  for (const [i, m] of MUTANTS.entries()) {
    if (set && m.set !== set) continue;
    if (only && !only.includes(i + 1)) continue;
    const r = runMutant(m);
    if (r.status === "SKIPPED") skipped++;
    else { total++; if (r.status === "KILLED") killed++; (bySet[m.set] ??= { killed: 0, total: 0 }); bySet[m.set].total++; if (r.status === "KILLED") bySet[m.set].killed++; }
    console.log(`#${i + 1} [${m.set}] ${m.file}: ${m.desc} => ${r.status}${r.by.length ? ` (${r.by.join(",")})` : ""}`);
  }
  console.log(`mutants killed ${killed}/${total}${skipped ? `, skipped ${skipped}` : ""}; ${Object.entries(bySet).map(([k, v]) => `${k} ${v.killed}/${v.total}`).join("; ")}`);
  process.exit(killed === total && skipped === 0 ? 0 : 1);
}
