import test from "node:test";
import assert from "node:assert/strict";
import { createOpenAiProvider } from "../providers/openai-provider.ts";
import { createXaiProvider } from "../providers/xai-provider.ts";
import { routeProvider } from "../orchestration/ai-router.ts";
import { approveExternalWrite, requireAiAuthorization } from "../security/request-authorization.ts";
import { redactSecrets } from "../security/secret-redaction.ts";
import type { AiRequest } from "../contracts/ai-provider.ts";
const request: AiRequest = { prompt: "test", correlationId: "corr-1" };
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

test("provider factories stay independent and keys are required", async () => {
  assert.equal(await createOpenAiProvider({ model: "m", baseUrl: "ignored" }).healthCheck(), "NOT_CONFIGURED");
  assert.equal(await createXaiProvider({ model: "m", baseUrl: "ignored" }).healthCheck(), "NOT_CONFIGURED");
});
test("OpenAI and xAI normalize their respective response payloads", async () => {
  const openai = createOpenAiProvider({ apiKey: "secret-key", model: "model-a", baseUrl: "ignored", fetcher: async () => response({ output_text: "hello" }) });
  const xai = createXaiProvider({ apiKey: "secret-key", model: "model-b", baseUrl: "ignored", fetcher: async () => response({ choices: [{ message: { content: "world" } }] }) });
  assert.equal((await openai.generate(request)).text, "hello"); assert.equal((await xai.generate(request)).text, "world");
});
test("health verifies authenticated network response and errors do not reveal secrets", async () => {
  const provider = createOpenAiProvider({ apiKey: "secret-key", model: "m", baseUrl: "ignored", fetcher: async () => response({}, 401) });
  assert.equal(await provider.healthCheck(), "ERROR");
  await assert.rejects(() => provider.generate(request), /request failed/);
});
test("timeouts are normalized", async () => {
  const provider = createXaiProvider({ apiKey: "secret-key", model: "m", baseUrl: "ignored", fetcher: async (_url, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))) , timeoutMs: 1 });
  await assert.rejects(() => provider.generate(request), /timed out/);
});
test("AUTO routing follows explicit purpose policy", () => {
  assert.equal(routeProvider({ provider: "AUTO", prompt: "x", correlationId: "c" }, ["OPENAI", "XAI"]), "OPENAI");
  assert.equal(routeProvider({ provider: "AUTO", purpose: "review", prompt: "x", correlationId: "c" }, ["OPENAI", "XAI"]), "XAI");
});
test("write authorization fails closed and binds approval to request", () => {
  assert.equal(approveExternalWrite({ authenticated: true, humanApproved: true, requestId: "a", approvalRequestId: "b", trustedEvidence: true, authorizationScope: "repo", expiresAt: Date.now() + 1000 }), false);
  assert.throws(() => requireAiAuthorization({ authenticated: false }));
});
test("secret redaction removes common token forms", () => assert.equal(redactSecrets("Bearer abc sk-1234567890123456 xai-1234567890123456"), "[REDACTED] [REDACTED] [REDACTED]"));
