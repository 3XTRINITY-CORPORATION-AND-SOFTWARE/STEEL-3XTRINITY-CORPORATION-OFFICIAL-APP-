export interface AuthContext { authenticated: boolean; subject?: string }
export function requireAiAuthorization(context: AuthContext): void { if (!context.authenticated || !context.subject) throw new Error("Unauthorized"); }
export function approveExternalWrite(input: { authenticated: boolean; humanApproved: boolean; requestId: string; approvalRequestId?: string; trustedEvidence: boolean; authorizationScope?: string; expiresAt?: number; now?: number }): boolean {
  const now = input.now ?? Date.now();
  return input.authenticated && input.humanApproved && input.requestId.length > 0 && input.approvalRequestId === input.requestId && input.trustedEvidence && Boolean(input.authorizationScope) && Boolean(input.expiresAt && input.expiresAt > now);
}
