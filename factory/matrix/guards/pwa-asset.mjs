// REGRESSION GUARDS for scripts/brand-check.mjs and scripts/grok-pwa-shared.mjs branches that no matrix slot asserts (not slots).
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const tree = (files = {}) => { const r = mkdtempSync(join(tmpdir(), "g-pwa-")); for (const [rel, c] of Object.entries(files)) { mkdirSync(dirname(join(r, rel)), { recursive: true }); writeFileSync(join(r, rel), c); } return r; };

/** @type {import("../types.d.ts").Spec[]} */
export const GUARDS = [
  { slot: 1007, target: "scripts/brand-check.mjs", expected: { atLimit: false, oneByteOver: true, threeMiB: true },
    run: (m) => { const over = (/** @type {any} */ bytes) => m.computeBrandWarnings({ hasCanvas: false, workspaceRoot: tree({ "public/og.jpg": "x".repeat(bytes) }), now: Date.now() }).some((/** @type {any} */ w) => w.includes("is over 600 KB")); return { atLimit: over(600 * 1024), oneByteOver: over(600 * 1024 + 1), threeMiB: over(3 * 1024 * 1024) }; },
    claim: "the og card size limit is exactly 600 KiB: a file at the limit is fine, one byte over (and 3 MiB) draws the over-600-KB warning" },
  { slot: 1008, target: "scripts/grok-pwa-shared.mjs", expected: { install1: true, installTrue: true, installFalse: false, installYes: false, androidInstallTrue: false, noPlatform: false },
    run: (m) => ({ install1: m.isInstallQuery("/?install=1&platform=ios"), installTrue: m.isInstallQuery("/?install=true&platform=ios"), installFalse: m.isInstallQuery("/?install=false&platform=ios"), installYes: m.isInstallQuery("/?install=yes&platform=ios"), androidInstallTrue: m.isInstallQuery("/?install=true&platform=android"), noPlatform: m.isInstallQuery("/?install=true") }),
    claim: "the install tutorial is requested by install=1 or install=true on iOS only; false/yes values, other platforms and a missing platform are not install requests" },
];
