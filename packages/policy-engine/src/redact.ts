/**
 * Secret redaction (SR-02). Applied to every log line, chat message, report,
 * evidence file and AI payload. Redaction is best-effort pattern matching;
 * it is a safety net, not a guarantee.
 */

interface Pattern {
  name: string;
  regex: RegExp;
  /** Index of the capture group holding the secret; 0 masks the whole match. */
  group?: number;
}

const PATTERNS: Pattern[] = [
  { name: "private-key", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { name: "aws-access-key", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "github-token", regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
  { name: "anthropic-key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: "openai-key", regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/g },
  { name: "stripe-key", regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { name: "slack-token", regex: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { name: "google-api-key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "npm-token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: "jwt", regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { name: "bearer", regex: /\b(Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{8,})/gi, group: 2 },
  { name: "auth-header", regex: /((?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token)\s*[:=]\s*"?)([^"\r\n,}]{4,})/gi, group: 2 },
  { name: "cookie-header", regex: /((?:^|\n|")(?:set-)?cookie\s*[:=]\s*"?)([^"\r\n]{4,})/gi, group: 2 },
  { name: "url-credentials", regex: /([a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:)([^@\s/]+)(@)/gi, group: 2 },
  {
    name: "assignment",
    regex:
      /((?:password|passwd|pwd|secret|client_secret|api_key|apikey|access_token|refresh_token|auth_token|private_key)["']?\s*[:=]\s*["']?)([^\s"',;&}]{4,})/gi,
    group: 2,
  },
];

const SENSITIVE_KEYS =
  /^(?:password|passwd|pwd|secret|token|access_?token|refresh_?token|id_?token|api_?key|apikey|authorization|cookie|set-cookie|x-api-key|client_?secret|private_?key|session|sessionid|credentials?)$/i;

export function mask(value: string): string {
  if (value.length <= 8) return "[REDACTED]";
  return `${value.slice(0, 4)}…[REDACTED]`;
}

export interface Redactor {
  (text: string): string;
}

export function createRedactor(extraPatterns: string[] = []): Redactor {
  const extra: Pattern[] = extraPatterns.map((p, i) => ({ name: `custom-${i}`, regex: new RegExp(p, "g") }));
  const all = [...PATTERNS, ...extra];
  return (text: string) => {
    let out = text;
    for (const p of all) {
      p.regex.lastIndex = 0;
      out = out.replace(p.regex, (...args: unknown[]) => {
        const match = args[0] as string;
        const groups = args.slice(1, -2) as (string | undefined)[];
        if (!p.group) return mask(match);
        const secret = groups[p.group - 1];
        if (!secret || secret.includes("[REDACTED]")) return match;
        const before = groups.slice(0, p.group - 1).join("");
        const after = groups.slice(p.group).join("");
        return `${before}${mask(secret)}${after}`;
      });
    }
    return out;
  };
}

export const redact: Redactor = createRedactor();

/** Deep-redact a JSON-like value: masks sensitive keys and secret-looking strings. */
export function redactDeep<T>(value: T, redactor: Redactor = redact): T {
  const walk = (v: unknown, key?: string): unknown => {
    if (typeof v === "string") {
      if (key && SENSITIVE_KEYS.test(key) && v.length > 0) return mask(v);
      return redactor(v);
    }
    if (Array.isArray(v)) return v.map((item) => walk(item));
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, child] of Object.entries(v as Record<string, unknown>)) out[k] = walk(child, k);
      return out;
    }
    return v;
  };
  return walk(value) as T;
}

/** Truncate long evidence while keeping it readable. */
export function truncate(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text) <= maxBytes) return text;
  const head = Buffer.from(text).subarray(0, maxBytes).toString("utf8");
  return `${head}\n…[truncated ${Buffer.byteLength(text) - maxBytes} bytes]`;
}
