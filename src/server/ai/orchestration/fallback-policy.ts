export interface FallbackPolicy { allowFallback: boolean; onStatuses: readonly number[] }
export const DEFAULT_FALLBACK_POLICY: FallbackPolicy = Object.freeze({ allowFallback: false, onStatuses: [] });
