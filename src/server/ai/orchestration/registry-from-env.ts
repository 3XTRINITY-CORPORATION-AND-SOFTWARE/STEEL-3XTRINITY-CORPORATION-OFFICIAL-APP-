import { createOpenAiProvider } from "../providers/openai-provider.ts";
import { createXaiProvider } from "../providers/xai-provider.ts";
import { ProviderRegistry } from "./provider-registry.ts";
export function createProviderRegistry(env: NodeJS.ProcessEnv = process.env): ProviderRegistry {
  const registry = new ProviderRegistry();
  if (env.OPENAI_API_KEY) registry.register(createOpenAiProvider({ apiKey: env.OPENAI_API_KEY, model: env.OPENAI_MODEL || "gpt-4.1-mini", baseUrl: "https://api.openai.com/v1" }));
  if (env.XAI_API_KEY) registry.register(createXaiProvider({ apiKey: env.XAI_API_KEY, model: env.XAI_MODEL || "grok-4.1-fast", baseUrl: "https://api.x.ai/v1" }));
  return registry;
}
