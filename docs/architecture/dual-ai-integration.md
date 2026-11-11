# Secure dual-provider integration

STEEL exposes independent server-only OpenAI Responses API and xAI chat-completions adapters under `src/server/ai`. Credentials are read only from `OPENAI_API_KEY` and `XAI_API_KEY`; never prefix them with `VITE_`. The adapters use fixed provider URLs, bounded prompts, correlation IDs, abortable deadlines, normalized non-secret errors, and explicit streaming. Configure optional `OPENAI_MODEL` / `XAI_MODEL` on the server.

`AUTO` routing is deterministic: analysis prefers OpenAI; review prefers xAI; if unavailable it selects the other registered provider. This is routing preference only, not a quality claim. Fallback after provider errors is disabled by default. Each response records provider/model/correlation/time provenance. Text-overlap comparison is heuristic only, not verification; all comparisons require human review. Model output is untrusted and cannot authorize external writes.

The adapter health check issues a small authenticated request. A present key alone is only CONNECTED_UNVERIFIED; actual successful authenticated response is required for VERIFIED. The configured registry is deliberately not exposed to browser code. This integration does not create an AI HTTP route or grant GitHub permissions; it must be invoked behind the application's authenticated server-function boundary before product use.

KRATT's current repository pipeline already keeps task validation, evidence, and Cerberus decision separate (`kratt/run.ts`). The AI module does not replace that engine or promote model output into a verdict. Preserve typed envelopes and existing approval/evidence boundaries when wiring a caller.

Security primitives include fail-closed auth and request-bound expiring approval checks, secret redaction, and an in-memory limiter. The limiter is process-local and not suitable as a distributed production quota; deploy a shared store before horizontal scaling. Fixed upstream endpoints prevent caller-controlled SSRF. Server-side credentials must live in the hosting platform's secret manager.
