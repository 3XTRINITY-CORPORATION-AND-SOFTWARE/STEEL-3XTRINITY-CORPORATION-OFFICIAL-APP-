import type { TaskEnvelope } from "../protocol/types.ts";

export const SHA = "a".repeat(40);

export function envelope(over: Partial<TaskEnvelope> = {}): TaskEnvelope {
  return {
    task_id: "t-001",
    factory: "FORGE",
    agent_id: "FORGE-026",
    objective: "hash two repo files",
    repository: "3XTRINITY-CORPORATION-AND-SOFTWARE/STEEL-3XTRINITY-CORPORATION-OFFICIAL-APP-",
    branch: "factory/test",
    base_sha: SHA,
    scope: ["cerberus/core/decide.ts"],
    allowed_actions: ["hash-files"],
    forbidden_actions: ["merge", "deploy", "network"],
    required_evidence: ["source_digests"],
    resource_budget: { max_wall_ms: 5000, max_output_bytes: 65536, max_files: 8 },
    protocol_version: 1,
    ...over,
  };
}

export const fixedClock = () => {
  let n = 0;
  return () => new Date(Date.UTC(2026, 9, 3, 0, 0, n++)).toISOString();
};
