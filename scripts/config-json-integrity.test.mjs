// Regression: a stacked squash-merge once left a duplicate "include" key without a
// conflict marker in tsconfig.cerberus.json (and package.json, matrix tests), which broke `npm run typecheck` on main.
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import ts from "typescript";

const root = new URL("../", import.meta.url);

const factoryJson = (existsSync(new URL("factory/", root)) ? readdirSync(new URL("factory/", root)) : [])
  .filter((n) => n.endsWith(".json"))
  .map((n) => `factory/${n}`);

for (const f of [...readdirSync(root).filter((n) => /^(tsconfig.*|package)\.json$/.test(n)), ...factoryJson]) {
  test(`${f} parses without syntax errors and has no duplicate keys`, () => {
    const text = readFileSync(new URL(f, root), "utf8");
    const { error } = ts.parseConfigFileTextToJson(f, text);
    assert.equal(error, undefined, error && ts.flattenDiagnosticMessageText(error.messageText, "\n"));
    const sf = ts.parseJsonText(f, text);
    assert.equal(sf.parseDiagnostics.length, 0);
    const walk = (node) => {
      if (node.kind === ts.SyntaxKind.ObjectLiteralExpression) {
        const names = node.properties.map((p) => p.name && p.name.text);
        assert.equal(new Set(names).size, names.length, `duplicate key in ${f}: ${names.join(",")}`);
      }
      ts.forEachChild(node, walk);
    };
    walk(sf);
  });
}
