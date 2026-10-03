/**
 * The frozen 150-role definition list (FORGE 001-050, SERPENT 051-100, CITADEL 101-150).
 * Architecture is frozen: this file is the only place roles are named. A role is a
 * DEFINITION, not a running agent; it counts as zero completed tasks.
 */
export const FACTORIES = ["FORGE", "SERPENT", "CITADEL"] as const;
export type FactoryName = (typeof FACTORIES)[number];

export const FORGE_ROLES: readonly string[] = [
  "Architect", "Repository Mapper", "Dependency Mapper", "Runtime Engineer", "Node Engineer",
  "TypeScript Engineer", "JavaScript Engineer", "Python Engineer", "Rust Engineer", "API Engineer",
  "Backend Engineer", "Frontend Engineer", "Data Model Engineer", "Schema Engineer", "Contract Engineer",
  "Integration Engineer", "Adapter Engineer", "CLI Engineer", "Build Engineer", "Package Engineer",
  "GOLIATH Engineer", "STEEL Engineer", "AURA Engineer", "CERBERUS Engineer", "TrinityOS Engineer",
  "KRATT Engineer", "TÖEPÄRA Engineer", "Finance/PANDORA Engineer", "Authentication Engineer", "Persistence Engineer",
  "Workflow Engineer", "Event Engineer", "Queue Engineer", "State-Machine Engineer", "Recovery Engineer",
  "Migration Engineer", "Compatibility Engineer", "Performance Engineer", "Offline Engineer", "Artifact Engineer",
  "Test Builder", "Fixture Builder", "Regression Builder", "Integration-Test Builder", "Contract-Test Builder",
  "CI Builder", "Devcontainer Engineer", "Release Engineer", "Documentation-from-Code Agent", "FORGE FOREMAN",
];

export const SERPENT_ROLES: readonly string[] = [
  "RÄSTIK Commander", "Input Fuzzer", "Boundary Tester", "Null/Empty Tester", "NaN/Infinity Tester",
  "Schema Breaker", "State Transition Tester", "Concurrency Tester", "Race Tester", "Replay Tester",
  "Authentication Tester", "Authorization Tester", "Trust-Gate Tester", "Evidence Tester", "Digest Tester",
  "Artifact Integrity Tester", "Dependency Auditor", "Supply-Chain Reviewer", "Secret Exposure Reviewer", "Configuration Auditor",
  "Runtime Compatibility Tester", "Node Compatibility Tester", "Python Compatibility Tester", "Rust Compatibility Tester", "Browser Compatibility Tester",
  "API Contract Tester", "Import/Export Tester", "Package-Lock Auditor", "Build Reproducibility Tester", "Offline Tester",
  "GOLIATH Adversary", "STEEL Adversary", "AURA Adversary", "CERBERUS Adversary", "KRATT Adversary",
  "TÖEPÄRA Adversary", "TrinityOS Adversary", "Finance/PANDORA Adversary", "Recovery Adversary", "Integration Adversary",
  "Static Analysis Agent", "CodeQL Agent", "Lint/TSC Agent", "Regression Investigator", "Failure Minimizer",
  "Reproduction Agent", "Evidence Challenger", "False-Pass Detector", "Matrix Auditor", "SERPENT FOREMAN",
];

export const CITADEL_ROLES: readonly string[] = [
  "TÖEPÄRA Commander", "Evidence Collector", "Evidence Normalizer", "Evidence Hasher", "Provenance Agent",
  "Receipt Generator", "Determinism Checker", "Reproducibility Checker", "Cross-Repo Evidence Agent", "Evidence Ledger Agent",
  "CERBERUS Commander", "Policy Evaluator", "Admission Controller", "Trust-Gate Controller", "Recovery Planner",
  "Recovery Receipt Agent", "Rollback Planner", "Failure Isolation Agent", "Quarantine Agent", "Safe-State Agent",
  "CI Gatekeeper", "Merge Gatekeeper", "Release Gatekeeper", "Branch Governance Agent", "Versioning Agent",
  "Protocol Compatibility Agent", "Dependency Policy Agent", "Runtime Policy Agent", "Security Policy Agent", "Artifact Gatekeeper",
  "GOLIATH Control Agent", "STEEL Operations Agent", "AURA Release Agent", "KRATT Governance Agent", "RÄSTIK Governance Agent",
  "TÖEPÄRA Governance Agent", "CERBERUS Governance Agent", "TrinityOS Governance Agent", "Finance/PANDORA Governance Agent", "Cross-System Governance Agent",
  "Matrix Controller", "Coverage Accountant", "Technical-Debt Accountant", "Blocker Router", "Priority Optimizer",
  "Compute/Token Accountant", "CI-Minute Accountant", "Human-Gate Router", "Final Evidence Auditor", "CITADEL FOREMAN",
];

export const ROLES: Record<FactoryName, readonly string[]> = {
  FORGE: FORGE_ROLES,
  SERPENT: SERPENT_ROLES,
  CITADEL: CITADEL_ROLES,
};

export const FACTORY_FIRST: Record<FactoryName, number> = { FORGE: 1, SERPENT: 51, CITADEL: 101 };

export function agentId(factory: FactoryName, number: number): string {
  return `${factory}-${String(number).padStart(3, "0")}`;
}
