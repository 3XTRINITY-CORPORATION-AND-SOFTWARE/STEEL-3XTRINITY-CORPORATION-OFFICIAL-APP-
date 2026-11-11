const SECRET_PATTERNS = [/\bsk-[A-Za-z0-9_-]{8,}\b/g, /\bxai-[A-Za-z0-9_-]{8,}\b/g, /Bearer\s+\S+/gi];
export function redactSecrets(value: string): string { return SECRET_PATTERNS.reduce((text, pattern) => text.replace(pattern, "[REDACTED]"), value); }
