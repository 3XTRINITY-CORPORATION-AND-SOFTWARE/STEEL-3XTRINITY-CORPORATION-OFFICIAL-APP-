import type { AiResponse } from "../contracts/ai-provider.ts";
export interface Comparison { contradictory: boolean; requiresHumanReview: true; similarity: number | null; evidence: "text-overlap-heuristic"; outputs: readonly AiResponse[] }
export function compareResponses(outputs: readonly AiResponse[]): Comparison {
  if (outputs.length < 2) return { contradictory: false, requiresHumanReview: true, similarity: null, evidence: "text-overlap-heuristic", outputs };
  const tokens = (s: string) => new Set(s.toLowerCase().match(/[\p{L}\p{N}]{4,}/gu) ?? []);
  const [a, b] = [tokens(outputs[0].text), tokens(outputs[1].text)];
  const union = new Set([...a, ...b]); const intersection = [...a].filter(word => b.has(word)).length;
  const similarity = union.size ? intersection / union.size : 1;
  // Lexical overlap is only a warning signal, never proof of agreement or truth.
  return { contradictory: similarity < 0.12, requiresHumanReview: true, similarity, evidence: "text-overlap-heuristic", outputs };
}
