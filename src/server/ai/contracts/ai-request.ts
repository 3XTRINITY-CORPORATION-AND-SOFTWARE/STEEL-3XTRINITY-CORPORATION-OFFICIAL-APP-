import type { AiProviderId } from "./ai-provider.ts";
export interface ProviderRequest { provider: AiProviderId | "AUTO"; prompt: string; model?: string; maxOutputTokens?: number; correlationId: string; signal?: AbortSignal; purpose?: "analysis" | "review" }
