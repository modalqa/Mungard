import type { RawFinding } from "@mungard/findings";
import { z } from "zod";
import { ScopeViolationError, ScopedHttpClient, formatExchange } from "./http.js";
import { type AdapterResult, type HealthStatus, type SecurityAdapter, emptyResult } from "./types.js";
import { writeEvidence } from "./util.js";

export const HttpProbeInput = z.object({
  target: z.string().url(),
});
export type HttpProbeInput = z.input<typeof HttpProbeInput>;

const PROBE_ORIGIN = "https://mungard-cors-probe.invalid";

/**
 * Passive, read-only checks on a running app: security headers, cookie flags,
 * information disclosure and CORS origin reflection. Sends only GET/OPTIONS.
 */
export const httpProbeAdapter: SecurityAdapter<HttpProbeInput> = {
  id: "http-probe",
  name: "HTTP security headers & CORS probe (built in)",
  operation: "http_probe",
  inputSchema: HttpProbeInput,

  async healthCheck(): Promise<HealthStatus> {
    return { engine: "http-probe", available: true, via: "builtin", detail: "Built-in passive HTTP checks." };
  },

  async run(rawInput, ctx): Promise<AdapterResult> {
    const started = Date.now();
    const input = HttpProbeInput.parse(rawInput);
    const client = new ScopedHttpClient(ctx.policy, ctx.redact, { signal: ctx.signal });
    let main;
    try {
      main = await client.send({ method: "GET", url: input.target });
    } catch (err) {
      if (err instanceof ScopeViolationError) return emptyResult("http-probe", "skipped", { error: err.message });
      throw err;
    }
    if (!main.response) {
      return emptyResult("http-probe", "failed", {
        error: `Target ${input.target} is not reachable: ${main.error}. Start the application and retry.`,
        gaps: ["HTTP header checks were not performed."],
        durationMs: Date.now() - started,
      });
    }
    const h = main.response.headers;
    const isHttps = new URL(input.target).protocol === "https:";
    const html = (h["content-type"] ?? "").includes("text/html");
    const findings: RawFinding[] = [];
    const loc = [{ kind: "url" as const, url: input.target, path: new URL(input.target).pathname }];
    const evidence = [{ kind: "http_exchange" as const, description: `GET ${input.target}`, excerpt: formatExchange(main, ctx.redact, 200) + ctx.redact(`\n\nResponse headers:\n${Object.entries(main.response.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}`) }];
    const add = (id: string, title: string, severity: RawFinding["severity"], description: string, remediation: string, cwe: string[] = []) =>
      findings.push({
        title,
        description,
        category: "headers",
        severity,
        confidence: "high",
        ruleId: `mungard.http.${id}`,
        locations: loc,
        evidence,
        reproductionSteps: [`curl -sI ${input.target}`],
        impact: "Missing hardening that makes other vulnerabilities (XSS, clickjacking, downgrade) easier to exploit.",
        remediation,
        cwe,
      });

    if (html && !h["content-security-policy"]) {
      add("missing-csp", "Content-Security-Policy header is missing", "medium", "HTML responses do not set a Content-Security-Policy.", "Define a restrictive CSP (in Next.js via headers() in next.config or middleware), starting with default-src 'self'.", ["CWE-693"]);
    }
    if (html && !h["x-frame-options"] && !(h["content-security-policy"] ?? "").includes("frame-ancestors")) {
      add("clickjacking", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "low", "The page can be embedded in a frame on any origin.", "Set `Content-Security-Policy: frame-ancestors 'none'` (or 'self') or `X-Frame-Options: DENY`.", ["CWE-1021"]);
    }
    if ((h["x-content-type-options"] ?? "").toLowerCase() !== "nosniff") {
      add("nosniff", "X-Content-Type-Options: nosniff is missing", "low", "Browsers may MIME-sniff responses into executable content types.", "Set `X-Content-Type-Options: nosniff` on all responses.", ["CWE-693"]);
    }
    if (isHttps && !h["strict-transport-security"]) {
      add("hsts", "Strict-Transport-Security header is missing", "medium", "HTTPS is used but HSTS is not set, allowing SSL-stripping downgrade attacks.", "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`.", ["CWE-319"]);
    }
    if (!h["referrer-policy"]) {
      add("referrer-policy", "Referrer-Policy header is missing", "info", "Full URLs (including tokens in query strings) may leak to third parties via the Referer header.", "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.");
    }
    for (const header of ["x-powered-by", "server"]) {
      const value = h[header];
      if (value && /\d/.test(value)) {
        add(`disclosure-${header}`, `Technology/version disclosed in ${header} header`, "info", `\`${header}: ${value}\` reveals implementation details useful for targeting known vulnerabilities.`, header === "x-powered-by" ? "Disable it (Next.js: `poweredByHeader: false`; Express: `app.disable('x-powered-by')`)." : "Remove version information from the Server header.", ["CWE-200"]);
      }
    }
    // Raw Set-Cookie (only names and attribute flags are reported; values never are).
    const setCookie = h["set-cookie"];
    if (setCookie) {
      for (const cookie of setCookie.split(/,(?=\s*[^;=\s]+=)/)) {
        const name = cookie.split("=")[0]?.trim() ?? "cookie";
        const attrs = cookie.toLowerCase();
        const missing = [
          !attrs.includes("httponly") ? "HttpOnly" : undefined,
          isHttps && !attrs.includes("secure") ? "Secure" : undefined,
          !attrs.includes("samesite") ? "SameSite" : undefined,
        ].filter(Boolean);
        if (missing.length) {
          findings.push({
            title: `Cookie "${name}" is missing ${missing.join(", ")}`,
            description: `The cookie is set without ${missing.join(", ")}. If it carries a session, it can be stolen via XSS or sent cross-site.`,
            category: "headers",
            severity: /sess|auth|token|sid/i.test(name) ? "medium" : "low",
            confidence: "high",
            ruleId: "mungard.http.cookie-flags",
            locations: loc,
            evidence,
            reproductionSteps: [`curl -sI ${input.target} | grep -i set-cookie`],
            remediation: "Set HttpOnly, Secure and SameSite=Lax (or Strict) on session cookies.",
            cwe: ["CWE-1004", "CWE-614"],
            fingerprintHint: name,
          });
        }
      }
    }

    const cors = await client.send({ method: "GET", url: input.target, headers: { origin: PROBE_ORIGIN } });
    const acao = cors.response?.headers["access-control-allow-origin"];
    const acac = cors.response?.headers["access-control-allow-credentials"];
    if (acao === PROBE_ORIGIN || (acao === "null" && acac === "true")) {
      findings.push({
        title: acac === "true" ? "CORS reflects arbitrary origins with credentials" : "CORS reflects arbitrary origins",
        description: `A request with \`Origin: ${PROBE_ORIGIN}\` was answered with \`Access-Control-Allow-Origin: ${acao}\`${acac === "true" ? " and `Access-Control-Allow-Credentials: true`" : ""}.`,
        category: "headers",
        severity: acac === "true" ? "high" : "medium",
        confidence: "high",
        ruleId: "mungard.http.cors-reflection",
        locations: loc,
        evidence: [{ kind: "http_exchange", description: "CORS probe", excerpt: `GET ${input.target}\nOrigin: ${PROBE_ORIGIN}\n-> Access-Control-Allow-Origin: ${acao}\n-> Access-Control-Allow-Credentials: ${acac ?? "(absent)"}` }],
        reproductionSteps: [`curl -sI -H 'Origin: ${PROBE_ORIGIN}' ${input.target}`],
        impact: acac === "true" ? "Any website a logged-in user visits can read authenticated responses from this app." : "Any website can read responses from this endpoint.",
        remediation: "Allowlist exact trusted origins; never reflect the Origin header together with credentials.",
        cwe: ["CWE-942"],
      });
    }
    const evidencePath = await writeEvidence(ctx, "http-probe.json", client.exchanges);
    return {
      engine: "http-probe",
      engineVersion: "builtin",
      status: "succeeded",
      findings,
      coverage: [`Passive header, cookie and CORS checks on ${input.target} (${client.requestCount} GET request(s)).`],
      gaps: ["Only the target URL was checked; other routes may set different headers."],
      rawOutputPath: evidencePath,
      durationMs: Date.now() - started,
    };
  },
};
