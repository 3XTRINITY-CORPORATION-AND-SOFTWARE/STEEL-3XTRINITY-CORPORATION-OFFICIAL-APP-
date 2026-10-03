import { DEFAULT_LIMITS, READ_ONLY, type Analysis, type Finding, type Handler } from "./types.ts";
import { schemaProblems, validate } from "./json-schema.ts";

/** FORGE-014 Schema Engineer: validate JSON files against a JSON Schema (draft-07 subset) committed in the same commit. */
export const schemaValidate: Handler = {
  contract: {
    contract_version: 1,
    capability: "schema:validate-json",
    agent_id: "FORGE-014",
    role: "Schema Engineer",
    summary: "Validate JSON instance files against a JSON Schema (draft-07 subset, unsupported keywords fail closed) read from the same commit.",
    permissions: READ_ONLY,
    scope: { min: 2, max: 64, kind: "file", meaning: "scope[0] = schema file, scope[1..] = JSON instance files" },
    limits: DEFAULT_LIMITS,
    summary_keys: ["schema", "instances", "valid", "invalid"],
  },
  analyze(view, scope): Analysis {
    const [schemaPath = "", ...instances] = scope;
    const findings: Finding[] = [];
    const base = { schema: schemaPath, instances: instances.length, valid: 0, invalid: 0 };
    const sch = view.readJson(schemaPath);
    if (!sch.ok) return { summary: base, findings, failure: `schema-unreadable:${sch.reason}` };
    const problems = schemaProblems(sch.value);
    if (problems.length > 0) {
      for (const p of problems) findings.push({ severity: "error", code: "schema-unusable", path: schemaPath, detail: p });
      return { summary: base, findings, failure: "schema-unusable" };
    }
    for (const p of instances) {
      const inst = view.readJson(p);
      if (!inst.ok) {
        base.invalid++;
        findings.push({ severity: "error", code: "instance-unreadable", path: p, detail: inst.reason });
        continue;
      }
      const errs = validate(sch.value, inst.value);
      if (errs.length === 0) base.valid++;
      else {
        base.invalid++;
        for (const e of errs) findings.push({ severity: "error", code: "schema-violation", path: p, detail: e });
      }
    }
    return { summary: base, findings };
  },
};
