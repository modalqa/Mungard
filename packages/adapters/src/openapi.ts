import { readFile, stat } from "node:fs/promises";
import type { RawFinding } from "@mungard/findings";
import { isLoopbackHost, resolveWithinRoot } from "@mungard/policy-engine";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { type AdapterResult, type HealthStatus, type SecurityAdapter, emptyResult } from "./types.js";
import { writeEvidence } from "./util.js";

export const OpenApiInput = z.object({
  /** Spec path relative to the project root. */
  spec: z.string(),
});
export type OpenApiInput = z.input<typeof OpenApiInput>;

const HTTP_METHODS = ["get", "put", "post", "delete", "patch", "head", "options", "trace"] as const;

export type EndpointTestStatus = "not_tested" | "tested" | "untestable" | "needs_test_data";

export interface EndpointInfo {
  method: string;
  path: string;
  operationId?: string;
  summary?: string;
  /** Names of security schemes required; [] = explicitly public; undefined = none declared. */
  security: string[] | undefined;
  requiresAuth: boolean;
  parameters: { name: string; in: string; required: boolean }[];
  hasRequestBody: boolean;
  /** Path parameters that look like object ids: candidates for BOLA/IDOR testing. */
  bolaCandidate: boolean;
  testStatus: EndpointTestStatus;
  statusReason: string;
}

export interface ApiInventory {
  title: string;
  version: string;
  openapiVersion: string;
  servers: string[];
  securitySchemes: Record<string, { type: string; scheme?: string; in?: string; name?: string }>;
  endpoints: EndpointInfo[];
}

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => !!v && typeof v === "object" && !Array.isArray(v);

/** Resolve local `#/components/...` references (one level is enough for parameters). */
function deref(doc: Json, v: unknown): unknown {
  if (isObj(v) && typeof v.$ref === "string" && v.$ref.startsWith("#/")) {
    let cur: unknown = doc;
    for (const part of v.$ref.slice(2).split("/")) {
      cur = isObj(cur) ? cur[part.replace(/~1/g, "/").replace(/~0/g, "~")] : undefined;
    }
    return cur ?? v;
  }
  return v;
}

export async function loadSpec(file: string, maxBytes: number): Promise<Json> {
  const s = await stat(file);
  if (s.size > maxBytes) throw new Error(`Spec is ${s.size} bytes, above policy.limits.maxFileSizeBytes (${maxBytes}).`);
  const text = await readFile(file, "utf8");
  const doc = file.endsWith(".json") ? JSON.parse(text) : parseYaml(text, { maxAliasCount: 100 });
  if (!isObj(doc)) throw new Error("Spec is not an object.");
  if (typeof doc.openapi !== "string" && typeof doc.swagger !== "string") {
    throw new Error("Not an OpenAPI/Swagger document (missing `openapi` or `swagger` field).");
  }
  if (!isObj(doc.paths)) throw new Error("Spec has no `paths` object.");
  return doc;
}

export function buildInventory(doc: Json): ApiInventory {
  const info = isObj(doc.info) ? doc.info : {};
  const components = isObj(doc.components) ? doc.components : {};
  const rawSchemes = isObj(components.securitySchemes) ? components.securitySchemes : isObj(doc.securityDefinitions) ? doc.securityDefinitions : {};
  const securitySchemes: ApiInventory["securitySchemes"] = {};
  for (const [name, s] of Object.entries(rawSchemes)) {
    const scheme = deref(doc, s);
    if (isObj(scheme)) {
      securitySchemes[name] = {
        type: String(scheme.type ?? "unknown"),
        scheme: typeof scheme.scheme === "string" ? scheme.scheme : undefined,
        in: typeof scheme.in === "string" ? scheme.in : undefined,
        name: typeof scheme.name === "string" ? scheme.name : undefined,
      };
    }
  }
  const securityNames = (sec: unknown): string[] | undefined =>
    Array.isArray(sec) ? sec.flatMap((req) => (isObj(req) ? Object.keys(req) : [])) : undefined;
  const globalSecurity = securityNames(doc.security);
  const servers = Array.isArray(doc.servers)
    ? doc.servers.flatMap((s) => (isObj(s) && typeof s.url === "string" ? [s.url] : []))
    : typeof doc.host === "string"
      ? [`${Array.isArray(doc.schemes) ? doc.schemes[0] : "https"}://${doc.host}${typeof doc.basePath === "string" ? doc.basePath : ""}`]
      : [];

  const endpoints: EndpointInfo[] = [];
  for (const [p, rawItem] of Object.entries(doc.paths as Json)) {
    const item = deref(doc, rawItem);
    if (!isObj(item)) continue;
    const pathParams = Array.isArray(item.parameters) ? item.parameters : [];
    for (const method of HTTP_METHODS) {
      const op = item[method];
      if (!isObj(op)) continue;
      const params = [...pathParams, ...(Array.isArray(op.parameters) ? op.parameters : [])]
        .map((x) => deref(doc, x))
        .filter(isObj)
        .map((x) => ({ name: String(x.name ?? ""), in: String(x.in ?? ""), required: x.required === true }));
      const opSecurity = securityNames(op.security);
      const security = opSecurity ?? globalSecurity;
      const requiresAuth = !!security && security.length > 0;
      const bolaCandidate = params.some((x) => x.in === "path" && /(^id$|id$|Id$|_id$|uuid|slug|key)/i.test(x.name));
      endpoints.push({
        method: method.toUpperCase(),
        path: p,
        operationId: typeof op.operationId === "string" ? op.operationId : undefined,
        summary: typeof op.summary === "string" ? op.summary : undefined,
        security,
        requiresAuth,
        parameters: params,
        hasRequestBody: isObj(op.requestBody) || params.some((x) => x.in === "body"),
        bolaCandidate,
        testStatus: "not_tested",
        statusReason: "Static analysis only. Runtime tests have not run against this endpoint.",
      });
    }
  }
  return {
    title: String(info.title ?? "Untitled API"),
    version: String(info.version ?? ""),
    openapiVersion: String(doc.openapi ?? doc.swagger),
    servers,
    securitySchemes,
    endpoints,
  };
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function analyzeInventory(inv: ApiInventory, specPath: string): RawFinding[] {
  const findings: RawFinding[] = [];
  const loc = (method: string, p: string) => ({ kind: "endpoint" as const, method, path: p });
  const specLoc = { kind: "file" as const, path: specPath };
  const authedCount = inv.endpoints.filter((e) => e.requiresAuth).length;

  if (Object.keys(inv.securitySchemes).length === 0 && inv.endpoints.length > 0) {
    findings.push({
      title: "API specification declares no security schemes",
      description: `${specPath} defines ${inv.endpoints.length} operation(s) but no securitySchemes. Either the API is fully public or authentication is undocumented, which prevents automated authorization testing.`,
      category: "api",
      severity: "low",
      confidence: "medium",
      ruleId: "mungard.openapi.no-security-schemes",
      locations: [specLoc],
      remediation: "Document authentication in components.securitySchemes and reference it via `security`.",
      impact: "Undocumented authentication makes it easy to ship endpoints that forget to enforce it.",
    });
  }

  for (const e of inv.endpoints) {
    if (!e.requiresAuth && MUTATING.has(e.method) && authedCount > 0) {
      findings.push({
        title: `State-changing endpoint without authentication: ${e.method} ${e.path}`,
        description: `Other operations in the spec require authentication, but ${e.method} ${e.path} declares ${e.security ? "an explicitly empty security requirement" : "no security requirement"}. Verify whether this is intentional.`,
        category: "authn",
        severity: "medium",
        confidence: "low",
        ruleId: "mungard.openapi.unauthenticated-mutation",
        locations: [loc(e.method, e.path), specLoc],
        reproductionSteps: [`Send ${e.method} ${e.path} without credentials against a test environment and check whether it succeeds.`],
        impact: "If the implementation matches the spec, anyone can change data through this endpoint.",
        remediation: "Add a security requirement to the operation and enforce it server-side, or document why it is public.",
        cwe: ["CWE-306"],
      });
    }
    const queryKey = Object.entries(inv.securitySchemes).find(([name, s]) => s.type === "apiKey" && s.in === "query" && e.security?.includes(name));
    if (queryKey) {
      findings.push({
        title: `API key sent in the query string: ${e.method} ${e.path}`,
        description: `Security scheme "${queryKey[0]}" passes the API key as query parameter "${queryKey[1].name}". URLs are logged by proxies, browsers and servers.`,
        category: "api",
        severity: "medium",
        confidence: "high",
        ruleId: "mungard.openapi.apikey-in-query",
        locations: [loc(e.method, e.path), specLoc],
        remediation: "Send credentials in a header (e.g. Authorization or X-API-Key) instead of the URL.",
        impact: "Credentials leak into access logs, browser history and Referer headers.",
        cwe: ["CWE-598"],
        fingerprintHint: queryKey[0],
      });
    }
  }

  for (const server of inv.servers) {
    try {
      const u = new URL(server);
      if (u.protocol === "http:" && !isLoopbackHost(u.hostname)) {
        findings.push({
          title: `API server uses plain HTTP: ${server}`,
          description: `The spec lists ${server}, which is not encrypted in transit.`,
          category: "api",
          severity: "medium",
          confidence: "high",
          ruleId: "mungard.openapi.http-server",
          locations: [specLoc],
          remediation: "Serve the API over HTTPS only and redirect HTTP to HTTPS.",
          impact: "Credentials and data can be intercepted or modified on the network.",
          cwe: ["CWE-319"],
          fingerprintHint: server,
        });
      }
    } catch {
      // relative server URLs are fine
    }
  }

  for (const [name, s] of Object.entries(inv.securitySchemes)) {
    if (s.type === "http" && s.scheme?.toLowerCase() === "basic") {
      findings.push({
        title: `HTTP Basic authentication scheme "${name}"`,
        description: "Basic auth sends reusable credentials with every request and has no built-in expiry or revocation.",
        category: "api",
        severity: "low",
        confidence: "high",
        ruleId: "mungard.openapi.basic-auth",
        locations: [specLoc],
        remediation: "Prefer short-lived bearer tokens or session cookies; if Basic is required, enforce HTTPS and rate limiting.",
        cwe: ["CWE-522"],
        fingerprintHint: name,
      });
    }
  }
  return findings;
}

export const openApiAdapter: SecurityAdapter<OpenApiInput> = {
  id: "openapi",
  name: "OpenAPI analyzer (built in)",
  operation: "api_analysis",
  inputSchema: OpenApiInput,

  async healthCheck(): Promise<HealthStatus> {
    return { engine: "openapi", available: true, via: "builtin", detail: "Built-in OpenAPI 2/3 parser." };
  },

  async run(rawInput, ctx): Promise<AdapterResult> {
    const started = Date.now();
    const input = OpenApiInput.parse(rawInput);
    let file: string;
    try {
      file = resolveWithinRoot(ctx.projectRoot, input.spec);
    } catch (err) {
      return emptyResult("openapi", "failed", { error: (err as Error).message });
    }
    let doc: Json;
    try {
      doc = await loadSpec(file, ctx.policy.limits.maxFileSizeBytes);
    } catch (err) {
      return emptyResult("openapi", "failed", {
        error: `Could not parse ${input.spec}: ${(err as Error).message}`,
        gaps: ["API specification analysis did not run."],
        durationMs: Date.now() - started,
      });
    }
    const inventory = buildInventory(doc);
    const findings = analyzeInventory(inventory, input.spec);
    const inventoryPath = await writeEvidence(ctx, "api-inventory.json", inventory);
    for (const f of findings) f.evidence = [{ kind: "config_excerpt", description: "Parsed API inventory", path: inventoryPath }];
    const bola = inventory.endpoints.filter((e) => e.bolaCandidate).length;
    return {
      engine: "openapi",
      engineVersion: "builtin",
      status: "succeeded",
      findings,
      coverage: [
        `Parsed ${input.spec} (OpenAPI ${inventory.openapiVersion}): ${inventory.endpoints.length} operation(s), ${inventory.endpoints.filter((e) => e.requiresAuth).length} requiring authentication, ${bola} BOLA/IDOR candidate(s).`,
      ],
      gaps: [
        "The spec describes intended behavior; it is not proof of what the server enforces. Run authorization tests to verify.",
        ...(bola > 0 ? [`${bola} endpoint(s) take object ids; BOLA/IDOR testing needs two test accounts and owned resource ids (configure authorization.checks).`] : []),
      ],
      rawOutputPath: inventoryPath,
      durationMs: Date.now() - started,
      data: inventory,
    };
  },
};
