export class InMemoryRateLimiter {
  private readonly hits = new Map<string, number[]>();
  constructor(private readonly limit = 20, private readonly windowMs = 60_000) {}
  allow(key: string, now = Date.now()): boolean {
    const recent = (this.hits.get(key) ?? []).filter(time => time > now - this.windowMs);
    if (recent.length >= this.limit) { this.hits.set(key, recent); return false; }
    recent.push(now); this.hits.set(key, recent); return true;
  }
}
