import type { AiProviderId } from "../contracts/ai-provider.ts";
import type { ProviderRequest } from "../contracts/ai-request.ts";
export function routeProvider(request: ProviderRequest, available: readonly AiProviderId[]): AiProviderId | null {
  if (request.provider !== "AUTO") return available.includes(request.provider) ? request.provider : null;
  // Deterministic policy: review goes to a different provider than analysis only when explicitly available;
  // otherwise choose OpenAI, then xAI. No model capability is inferred.
  const preferred: AiProviderId = request.purpose === "review" ? "XAI" : "OPENAI";
  return available.includes(preferred) ? preferred : available.includes("OPENAI") ? "OPENAI" : available.includes("XAI") ? "XAI" : null;
}
