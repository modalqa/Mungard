import { checkRedirect, checkTarget, redactDeep, truncate, type Redactor, type SecurityPolicy } from "@mungard/policy-engine";

export interface HttpRequestSpec {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface HttpExchange {
  request: { method: string; url: string; headers: Record<string, string>; body?: string };
  response?: { status: number; headers: Record<string, string>; body: string; redirectedFrom?: string[] };
  error?: string;
  durationMs: number;
}

export class ScopeViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopeViolationError";
  }
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
export function isSafeMethod(method: string): boolean {
  return SAFE_METHODS.has(method.toUpperCase());
}

/**
 * HTTP client used by every built-in runtime test. It enforces scope on the
 * initial URL and on every redirect hop, rate-limits requests, caps the total
 * number of requests, and records redacted exchanges as evidence.
 */
export class ScopedHttpClient {
  private lastRequestAt = 0;
  private count = 0;
  readonly exchanges: HttpExchange[] = [];

  constructor(
    private readonly policy: SecurityPolicy,
    private readonly redact: Redactor,
    private readonly opts: { timeoutMs?: number; signal?: AbortSignal; userAgent?: string } = {},
  ) {}

  get requestCount(): number {
    return this.count;
  }

  private async throttle(): Promise<void> {
    const minInterval = 1000 / this.policy.limits.maxRequestsPerSecond;
    const wait = this.lastRequestAt + minInterval - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    this.lastRequestAt = Date.now();
  }

  async send(spec: HttpRequestSpec): Promise<HttpExchange> {
    const scope = checkTarget(spec.url, this.policy);
    if (!scope.allowed) throw new ScopeViolationError(scope.reasons.join(" "));
    const started = Date.now();
    const headers: Record<string, string> = {
      "user-agent": this.opts.userAgent ?? "mungard-security-test/0.1 (+authorized testing)",
      ...Object.fromEntries(Object.entries(spec.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v])),
    };
    const redirectedFrom: string[] = [];
    let url = spec.url;
    let method = spec.method.toUpperCase();
    let body = spec.body;
    try {
      for (let hop = 0; hop <= 5; hop++) {
        if (this.count >= this.policy.limits.maxHttpRequests) {
          throw new ScopeViolationError(`Request budget exhausted (policy.limits.maxHttpRequests = ${this.policy.limits.maxHttpRequests}).`);
        }
        await this.throttle();
        this.count++;
        const res = await fetch(url, {
          method,
          headers,
          body: method === "GET" || method === "HEAD" ? undefined : body,
          redirect: "manual",
          signal: AbortSignal.any([
            AbortSignal.timeout(this.opts.timeoutMs ?? 15_000),
            ...(this.opts.signal ? [this.opts.signal] : []),
          ]),
        });
        const location = res.headers.get("location");
        if (res.status >= 300 && res.status < 400 && location) {
          const redirect = checkRedirect(url, location, this.policy);
          if (!redirect.allowed) {
            // Do not follow; record the out-of-scope redirect as the final response.
            return this.record(spec, headers, started, res, await res.text(), [...redirectedFrom, `blocked:${redirect.url ?? location}`]);
          }
          redirectedFrom.push(url);
          url = new URL(location, url).toString();
          if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === "POST")) {
            method = "GET";
            body = undefined;
          }
          await res.arrayBuffer().catch(() => undefined);
          continue;
        }
        return this.record(spec, headers, started, res, await res.text(), redirectedFrom);
      }
      throw new Error("Too many redirects.");
    } catch (err) {
      if (err instanceof ScopeViolationError) throw err;
      const exchange: HttpExchange = {
        request: this.sanitizeRequest(spec, headers),
        error: (err as Error).message,
        durationMs: Date.now() - started,
      };
      this.exchanges.push(exchange);
      return exchange;
    }
  }

  private sanitizeRequest(spec: HttpRequestSpec, headers: Record<string, string>): HttpExchange["request"] {
    return redactDeep(
      { method: spec.method.toUpperCase(), url: spec.url, headers, body: spec.body ? truncate(spec.body, 4000) : undefined },
      this.redact,
    );
  }

  private record(
    spec: HttpRequestSpec,
    headers: Record<string, string>,
    started: number,
    res: Response,
    text: string,
    redirectedFrom: string[],
  ): HttpExchange {
    const exchange: HttpExchange = {
      request: this.sanitizeRequest(spec, headers),
      response: redactDeep(
        {
          status: res.status,
          headers: Object.fromEntries(res.headers.entries()),
          body: truncate(text, this.policy.limits.maxEvidenceBytes),
          redirectedFrom: redirectedFrom.length ? redirectedFrom : undefined,
        },
        this.redact,
      ),
      durationMs: Date.now() - started,
    };
    this.exchanges.push(exchange);
    // Keep the unredacted body/headers available to the caller for comparisons only;
    // the stored exchange (used for evidence) stays redacted.
    return {
      ...exchange,
      response: exchange.response ? { ...exchange.response, body: text, headers: Object.fromEntries(res.headers.entries()) } : undefined,
    };
  }
}

/** Render an exchange as a compact, already-redacted HTTP transcript for evidence excerpts. */
export function formatExchange(ex: HttpExchange, redact: Redactor, maxBody = 600): string {
  const req = `${ex.request.method} ${ex.request.url}`;
  if (!ex.response) return `${req}\n-> error: ${ex.error ?? "unknown"}`;
  const body = redact(truncate(ex.response.body, maxBody));
  return `${req}\n-> HTTP ${ex.response.status}\n${body}`;
}
