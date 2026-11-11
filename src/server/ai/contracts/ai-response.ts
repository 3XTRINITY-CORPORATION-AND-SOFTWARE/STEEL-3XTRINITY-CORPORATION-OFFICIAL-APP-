import type { AiProviderId } from "./ai-provider.ts";
export interface ProviderResult { provider: AiProviderId; model: string; text: string; latencyMs: number; correlationId: string; receivedAt: string }
