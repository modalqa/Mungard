import { isAllowedHost } from "./hosts";

export interface GuardOptions {
  /** Require `Content-Type: application/json` (all POST handlers set this). */
  json?: boolean;
}

function forbidden(reason: string): Response {
  return Response.json({ error: "forbidden", reason }, { status: 403, headers: { "Cache-Control": "no-store" } });
}

/**
 * Shared request guard for every route handler.
 *
 * - Host must be this loopback server (blocks DNS rebinding: a malicious site
 *   that re-points its own domain at 127.0.0.1 still sends its own Host).
 * - Non-GET/HEAD requests must carry an Origin that equals this host
 *   (blocks cross-site request forgery from other browser tabs).
 * - POST bodies must be declared as JSON, which browsers cannot send
 *   cross-origin without a CORS preflight that we never answer.
 *
 * Returns a 403 Response to send back, or `null` when the request may proceed.
 */
export function guard(request: Request, opts: GuardOptions = {}): Response | null {
  const host = request.headers.get("host");
  if (!isAllowedHost(host)) return forbidden("Host header is not this local Mungard server.");

  const method = request.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    const origin = request.headers.get("origin");
    if (!origin || origin.toLowerCase() !== `http://${host.toLowerCase()}`) {
      return forbidden("Missing or cross-origin Origin header.");
    }
    const fetchSite = request.headers.get("sec-fetch-site");
    if (fetchSite && fetchSite !== "same-origin") return forbidden("Cross-site request.");
  }

  if (opts.json || method === "POST") {
    const contentType = (request.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
    if (contentType !== "application/json") return forbidden("Content-Type must be application/json.");
  }
  return null;
}

/** Parse a JSON body with a size cap; returns undefined on invalid JSON. */
export async function readJson(request: Request, maxBytes = 64 * 1024): Promise<unknown> {
  const text = await request.text();
  if (text.length > maxBytes) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}
