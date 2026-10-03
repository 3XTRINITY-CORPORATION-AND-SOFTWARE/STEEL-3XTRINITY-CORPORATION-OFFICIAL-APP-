import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { buildJsonSchema } from "./protocol/types.ts";
import { buildInitialRegistry, countRegistry, validateRegistryShape, validateInitialRegistry, type Registry } from "./registry.ts";

/**
 * npm run factory -- init      write the initial (all SLEEP, 0 tasks) registry + empty queue/receipts/matrix + protocol schema
 * npm run factory -- validate  validate the committed registry (shape + counts); exit 1 on any violation
 * npm run factory -- status    print honest counts
 */
const root = resolve(import.meta.dirname);
const file = (n: string) => resolve(root, n);
const write = (n: string, v: unknown) => writeFileSync(file(n), JSON.stringify(v, null, 2) + "\n");

const cmd = process.argv[2];
if (cmd === "init") {
  write("factory-registry.json", buildInitialRegistry());
  write("factory-queue.json", { queue_version: 1, tasks: [], transitions: [] });
  write("factory-receipts.json", { receipts_version: 1, closed_loops: [] });
  write("factory-matrix.json", { matrix_version: 1, note: "no factory evidence connected to scripts/matrix250 yet", slots: [] });
  writeFileSync(file("protocol/protocol.schema.json"), JSON.stringify(buildJsonSchema(), null, 2) + "\n");
  console.log("factory: initial files written");
} else if (cmd === "validate" || cmd === "status") {
  const reg = JSON.parse(readFileSync(file("factory-registry.json"), "utf8")) as Registry;
  const shape = validateRegistryShape(reg);
  if (cmd === "status") {
    console.log(JSON.stringify({ shape_violations: shape.length, ...countRegistry(reg) }, null, 2));
    process.exit(shape.length ? 1 : 0);
  }
  const init = validateInitialRegistry(reg);
  if (shape.length) {
    console.error(`registry shape violations:\n${shape.join("\n")}`);
    process.exit(1);
  }
  console.log(`registry shape ok; initial-state invariants ${init.length === 0 ? "hold" : `do not hold (${init.length}; expected after real tasks ran)`}`);
} else {
  console.error("usage: factory <init|validate|status>");
  process.exit(2);
}
