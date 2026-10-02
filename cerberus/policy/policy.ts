// Cerberus policy: Cerberus may only detect, recover or recommend.
// It never merges, deploys or authorizes; those require TÖEPÄRA + Trust Gate upstream.
export const ALLOWED_ACTIONS = ["detect", "recover", "recommend"] as const;
export type CerberusAction = (typeof ALLOWED_ACTIONS)[number];

export function isAllowedAction(action: unknown): action is CerberusAction {
  return typeof action === "string" && (ALLOWED_ACTIONS as readonly string[]).includes(action);
}
