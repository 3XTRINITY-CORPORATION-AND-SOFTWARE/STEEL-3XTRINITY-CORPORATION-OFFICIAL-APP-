import type { AiProvider } from "../contracts/ai-provider.ts";
import type { AiRequest, AiResponse, AiStatus } from "../contracts/ai-provider.ts";

export interface ProviderConfig { apiKey?: string; model: string; baseUrl: string; timeoutMs?: number; fetcher?: typeof fetch }

type JsonRecord = Record<string, unknown>;
const record = (value: unknown): JsonRecord => typeof value === "object" && value !== null ? value as JsonRecord : {};
const safeMessage = (status: number) => `AI provider request failed (${status})`;

export function createOpenAiProvider(config: ProviderConfig): AiProvider {
  return createProvider("OPENAI", config, "https://api.openai.com/v1/responses");
}
export function createXaiProvider(config: ProviderConfig): AiProvider {
  return createProvider("XAI", config, "https://api.x.ai/v1/chat/completions");
}

function createProvider(id: "OPENAI" | "XAI", config: ProviderConfig, endpoint: string): AiProvider {
  const fetcher = config.fetcher ?? fetch;
  const timeoutMs = config.timeoutMs ?? 20_000;
  const model = config.model;
  const key = config.apiKey?.trim();
  const authStatus = (): AiStatus => key ? "CONNECTED_UNVERIFIED" : "NOT_CONFIGURED";
  function normalizeError(error: unknown): Error {
    if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) return new Error("AI provider request timed out");
    return new Error("AI provider request failed");
  }
  async function send(request: AiRequest, stream: boolean): Promise<Response> {
    if (!key) throw new Error("AI provider is not configured");
    if (!request.prompt.trim() || request.prompt.length > 20_000) throw new Error("Invalid AI prompt");
    if (!request.correlationId || request.correlationId.length > 128) throw new Error("Invalid correlation ID");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new DOMException("Timeout", "TimeoutError")), timeoutMs);
    const abort = () => controller.abort(request.signal?.reason);
    request.signal?.addEventListener("abort", abort, { once: true });
    try {
      const body = id === "OPENAI"
        ? { model: request.model ?? model, input: request.prompt, max_output_tokens: request.maxOutputTokens ?? 1024, stream }
        : { model: request.model ?? model, messages: [{ role: "user", content: request.prompt }], max_tokens: request.maxOutputTokens ?? 1024, stream };
      const response = await fetcher(endpoint, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${key}` }, body: JSON.stringify(body), signal: controller.signal });
      if (!response.ok) throw new Error(safeMessage(response.status));
      return response;
    } catch (error) { throw normalizeError(error); }
    finally { clearTimeout(timer); request.signal?.removeEventListener("abort", abort); }
  }
  function extract(payload: unknown): string {
    const data = record(payload);
    if (id === "OPENAI") {
      if (typeof data.output_text === "string") return data.output_text;
      const output = Array.isArray(data.output) ? data.output : [];
      return output.flatMap(item => { const content = record(item).content; return Array.isArray(content) ? content.map(part => record(part).text).filter((text): text is string => typeof text === "string") : []; }).join("");
    }
    const choices = Array.isArray(data.choices) ? data.choices : [];
    return typeof record(record(choices[0]).message).content === "string" ? record(record(choices[0]).message).content as string : "";
  }
  return {
    id,
    async generate(request: AiRequest): Promise<AiResponse> {
      const started = Date.now();
      const response = await send(request, false);
      let text: string;
      try { text = extract(await response.json()); } catch { throw new Error("AI provider returned an invalid response"); }
      if (!text) throw new Error("AI provider returned an empty response");
      return { provider: id, model: request.model ?? model, text, latencyMs: Date.now() - started, provenance: { provider: id, model: request.model ?? model, correlationId: request.correlationId, receivedAt: new Date().toISOString() } };
    },
    async *stream(request: AiRequest): AsyncIterable<string> {
      const response = await send(request, true);
      if (!response.body) throw new Error("AI provider stream unavailable");
      const reader = response.body.getReader(); const decoder = new TextDecoder();
      try { while (true) { const { done, value } = await reader.read(); if (done) break; yield decoder.decode(value, { stream: true }); } }
      finally { await reader.cancel().catch(() => undefined); }
    },
    async healthCheck(): Promise<AiStatus> {
      if (!key) return "NOT_CONFIGURED";
      try { const response = await send({ prompt: "Reply with OK.", correlationId: `health-${Date.now()}`, maxOutputTokens: 8 }, false); await response.body?.cancel(); return "VERIFIED"; }
      catch (error) { const message = error instanceof Error ? error.message : ""; return message.includes("timed out") ? "DEGRADED" : "ERROR"; }
    },
    getCapabilities: () => ({ streaming: true, structuredOutput: id === "OPENAI" }),
    normalizeError,
  };
}

export const providerStatusWithoutRequest = (provider: AiProvider): AiStatus => provider.getCapabilities() ? "CONNECTED_UNVERIFIED" : "ERROR";
export const configuredStatus = (provider: AiProvider, configured: boolean): AiStatus => configured ? "CONNECTED_UNVERIFIED" : "NOT_CONFIGURED";
