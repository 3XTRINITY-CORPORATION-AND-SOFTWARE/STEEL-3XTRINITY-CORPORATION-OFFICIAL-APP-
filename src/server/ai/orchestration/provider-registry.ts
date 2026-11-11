import type { AiProvider, AiProviderId } from "../contracts/ai-provider.ts";
export class ProviderRegistry {
  private readonly providers = new Map<AiProviderId, AiProvider>();
  register(provider: AiProvider): void { this.providers.set(provider.id, provider); }
  get(id: AiProviderId): AiProvider | undefined { return this.providers.get(id); }
  available(): AiProviderId[] { return [...this.providers.keys()]; }
}
