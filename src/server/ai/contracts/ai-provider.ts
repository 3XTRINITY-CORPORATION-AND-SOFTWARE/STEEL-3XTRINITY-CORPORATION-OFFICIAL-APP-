export type AiProviderId = "OPENAI" | "XAI";
export type AiStatus = "NOT_CONFIGURED" | "CONNECTED_UNVERIFIED" | "VERIFIED" | "DEGRADED" | "DISABLED" | "ERROR";
export interface AiRequest { prompt: string; model?: string; maxOutputTokens?: number; correlationId: string; signal?: AbortSignal }
export interface AiResponse { provider: AiProviderId; model: string; text: string; latencyMs: number; provenance: { provider: AiProviderId; model: string; correlationId: string; receivedAt: string } }
export interface AiCapabilities { streaming: boolean; structuredOutput: boolean }
export interface AiProvider { readonly id: AiProviderId; generate(request: AiRequest): Promise<AiResponse>; stream(request: AiRequest): AsyncIterable<string>; healthCheck(): Promise<AiStatus>; getCapabilities(): AiCapabilities; normalizeError(error: unknown): Error }
