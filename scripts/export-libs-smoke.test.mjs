// Smoke test for the document-generation libraries pinned via package.json "overrides"
// (uuid for exceljs, image-size for pptxgenjs). Real generation, real round-trip.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import ExcelJS from "exceljs";
import PptxGenJS from "pptxgenjs";

const isZip = (b) => Buffer.from(b).subarray(0, 4).toString("hex") === "504b0304";

test("exceljs writes and re-reads a workbook (data-bar CF exercises its uuid v4 path)", async () => {
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet("s");
  ws.addRows([[1, 2], [3, 4], [5, 6]]);
  ws.addConditionalFormatting({
    ref: "A1:A3",
    rules: [{ type: "dataBar", priority: 1, cfvo: [{ type: "min" }, { type: "max" }], gradient: false, minLength: 0, maxLength: 100, border: false, negativeBarColorSameAsPositive: true, axisPosition: "auto", direction: "leftToRight", showValue: true }],
  });
  const buf = await wb.xlsx.writeBuffer();
  assert.ok(isZip(buf));
  const back = new ExcelJS.Workbook();
  await back.xlsx.load(buf);
  assert.equal(back.getWorksheet("s").getCell("B3").value, 6);
});

test("pptxgenjs writes a pptx with an embedded PNG", async () => {
  const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
  const p = new PptxGenJS();
  const s = p.addSlide();
  s.addText("hi", { x: 1, y: 1, w: 3, h: 1 });
  s.addImage({ data: `image/png;base64,${png}`, x: 2, y: 2, w: 1, h: 1 });
  const out = await p.write({ outputType: "nodebuffer" });
  assert.ok(isZip(out));
  assert.ok(out.length > 1000);
});

test("overridden transitive versions are the patched ones", () => {
  const ver = (name) =>
    JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version.split(".").map(Number);
  const atLeast = (v, min) => v[0] !== min[0] ? v[0] > min[0] : v[1] !== min[1] ? v[1] > min[1] : v[2] >= min[2];
  assert.ok(atLeast(ver("uuid"), [11, 1, 1]), "uuid must be >= 11.1.1");
  assert.ok(atLeast(ver("image-size"), [2, 0, 3]), "image-size must be >= 2.0.3");
});
