import { guard } from "@/lib/server/guard";
import { sessionCookieHeader } from "@/lib/server/session-token";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Hands the per-process approval token to the browser as an HttpOnly,
 * SameSite=Strict cookie. The token itself is never placed in a response body.
 */
export async function GET(request: Request): Promise<Response> {
  const denied = guard(request);
  if (denied) return denied;
  // Browsers mark cross-site subresource requests; only same-origin (or a
  // direct navigation, "none") may obtain the cookie.
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    return Response.json({ error: "forbidden", reason: "Cross-site request." }, { status: 403 });
  }
  return Response.json({ ok: true }, { headers: { "Set-Cookie": sessionCookieHeader(), "Cache-Control": "no-store" } });
}
