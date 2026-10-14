import type { SteelTab } from "./types.ts";

/** URL slug (/workspace/$module) -> STEEL tab. Only these own keys are workspace modules. */
export const WORKSPACE_TABS: Readonly<Record<string, SteelTab>> = Object.freeze({
  studio: "studio",
  aura: "aura",
  command: "console",
  kernel: "kernel",
  audit: "audit",
  desk: "desk",
  pipeline: "pipeline",
  hosts: "hosts",
});

/**
 * The tab for a workspace slug, or null. Own-key lookup only: `slug in tabs` would also accept inherited
 * Object.prototype names ("constructor", "toString", "__proto__", ...) and hand a function to setTab.
 */
export function workspaceTab(slug: string): SteelTab | null {
  return Object.hasOwn(WORKSPACE_TABS, slug) ? (WORKSPACE_TABS[slug] as SteelTab) : null;
}
