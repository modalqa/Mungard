import { randomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE = "mungard_ui_session";

/*
 * Per-process approval token.
 *
 * Generated once when the server process starts and handed to the browser
 * only through a same-origin GET /api/session as an HttpOnly, SameSite=Strict
 * cookie. Approval decisions must present it. This stops other web pages
 * (they cannot read or send the cookie cross-site) and raises the bar for
 * agents or scripts that blindly POST to the approvals endpoint.
 *
 * It is NOT a sandbox against code running as the same OS user: such code
 * can request /api/session itself, read the browser profile, or edit the
 * workspace files directly. Isolation from untrusted local code needs OS
 * level separation (different user, container, VM).
 *
 * Stored on globalThis so every route bundle in this process shares it.
 */
const KEY = Symbol.for("mungard.web.sessionToken");
type Holder = { [KEY]?: string };

export function sessionToken(): string {
  const g = globalThis as Holder;
  g[KEY] ??= randomBytes(32).toString("base64url");
  return g[KEY];
}

export function readCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get("cookie");
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return undefined;
}

export function hasValidSessionCookie(request: Request): boolean {
  const presented = readCookie(request, SESSION_COOKIE);
  if (!presented) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(sessionToken());
  return a.length === b.length && timingSafeEqual(a, b);
}

export function sessionCookieHeader(): string {
  return `${SESSION_COOKIE}=${sessionToken()}; Path=/api; HttpOnly; SameSite=Strict`;
}
