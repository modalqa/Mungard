/**
 * Host allow-list shared by `proxy.ts` and the route handler guard.
 * Kept free of Node-only imports so it can run in any Next.js runtime.
 */

/** Port the UI listens on. Must match the `--port` passed to `next start/dev`. */
export function uiPort(): string {
  return process.env.MUNGARD_WEB_PORT ?? process.env.PORT ?? "3737";
}

export function allowedHosts(): string[] {
  const port = uiPort();
  return [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`];
}

/** True when the Host header names this loopback server (DNS-rebinding protection). */
export function isAllowedHost(host: string | null): host is string {
  if (!host) return false;
  return allowedHosts().includes(host.toLowerCase());
}
