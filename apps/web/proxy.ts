import { NextResponse, type NextRequest } from "next/server";
import { isAllowedHost } from "./lib/server/hosts";

/**
 * Runs before every request (except static build assets):
 * 1. Rejects requests whose Host is not this loopback server, so a DNS
 *    rebinding page cannot load the UI or call the API under its own origin.
 * 2. Sets a strict, per-request nonce Content-Security-Policy on pages. The
 *    App Router injects inline bootstrap scripts; Next.js reads the nonce from
 *    the request CSP header and attaches it to them, so no 'unsafe-inline'
 *    is needed for scripts. API routes get their own CSP from next.config.ts.
 */
export function proxy(request: NextRequest): NextResponse {
  if (!isAllowedHost(request.headers.get("host"))) {
    return NextResponse.json({ error: "forbidden", reason: "Host header is not this local Mungard server." }, { status: 403 });
  }
  if (request.nextUrl.pathname.startsWith("/api/")) return NextResponse.next();

  const nonce = btoa(crypto.randomUUID());
  const isDev = process.env.NODE_ENV === "development";
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    // React renders some style attributes; inline styles cannot run code.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|logo.jpeg).*)"],
};
