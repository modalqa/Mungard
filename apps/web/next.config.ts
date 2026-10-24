import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

/**
 * Static security headers for every response.
 *
 * The page Content-Security-Policy is set per request in `proxy.ts`, because
 * the App Router emits inline bootstrap scripts that need a fresh nonce; a
 * static policy would have to allow `'unsafe-inline'` for scripts. API
 * responses are JSON / SSE / Markdown and never need to execute anything, so
 * they get the strictest possible policy here.
 */
const commonHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  // Mungard core spawns scanners (child_process) and reads the workspace (fs);
  // load it and its dependencies with Node at runtime instead of bundling.
  serverExternalPackages: [
    "@mungard/core",
    "@mungard/findings",
    "@mungard/policy-engine",
    "@mungard/adapters",
    "@mungard/reporting",
    "@anthropic-ai/sdk",
    "yaml",
  ],
  outputFileTracingRoot: repoRoot,
  turbopack: { root: repoRoot },
  async headers() {
    return [
      { source: "/:path*", headers: commonHeaders },
      {
        source: "/api/:path*",
        headers: [
          { key: "Content-Security-Policy", value: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" },
          { key: "Cache-Control", value: "no-store" },
        ],
      },
    ];
  },
};

export default nextConfig;
