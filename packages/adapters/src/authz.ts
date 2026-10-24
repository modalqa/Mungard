import type { RawFinding } from "@mungard/findings";
import { z } from "zod";
import { ScopeViolationError, ScopedHttpClient, formatExchange, isSafeMethod, type HttpExchange } from "./http.js";
import type { ApiInventory } from "./openapi.js";
import { type AdapterResult, type HealthStatus, type SecurityAdapter, emptyResult } from "./types.js";
import { writeEvidence } from "./util.js";

/**
 * Test account. Credentials are referenced from environment variables with
 * `${env:NAME}` so they never live in the config file.
 */
export const TestAccount = z.object({
  name: z.string().regex(/^[a-zA-Z0-9_-]+$/),
  role: z.string().default("user"),
  tenant: z.string().optional(),
  headers: z.record(z.string(), z.string()).default({}),
});
export type TestAccount = z.infer<typeof TestAccount>;

export const RequestSpec = z.object({
  method: z.string().default("GET"),
  path: z.string().startsWith("/"),
  headers: z.record(z.string(), z.string()).default({}),
  json: z.unknown().optional(),
});

/** Ownership/role check: the resource must be readable by `allowed` and not by `denied`. */
export const AuthorizationCheck = z.object({
  id: z.string().regex(/^[a-zA-Z0-9_.-]+$/),
  description: z.string(),
  request: RequestSpec,
  /** Account that owns the resource; its response is the baseline. */
  owner: z.string(),
  allowed: z.array(z.string()).default([]),
  /** Accounts (or "anonymous") that must NOT get the resource. */
  denied: z.array(z.string()).min(1),
  /** Strings that only appear in the owner's data (ids, emails of test users...). */
  sensitiveMarkers: z.array(z.string()).default([]),
  severity: z.enum(["critical", "high", "medium", "low"]).default("high"),
});
export type AuthorizationCheck = z.infer<typeof AuthorizationCheck>;

export const ScenarioStep = z.object({
  as: z.string(),
  request: RequestSpec,
  /** Capture values from a JSON response with a dotted path, e.g. { orderId: "id" }. */
  capture: z.record(z.string(), z.string()).default({}),
  expect: z
    .object({
      statusIn: z.array(z.number().int()).optional(),
      statusNotIn: z.array(z.number().int()).optional(),
      bodyNotContains: z.array(z.string()).optional(),
    })
    .optional(),
});

/** Business-logic scenario: an ordered sequence of requests with expectations (FR-10). */
export const BusinessScenario = z.object({
  id: z.string().regex(/^[a-zA-Z0-9_.-]+$/),
  description: z.string(),
  /** Business rules this scenario assumes; shown in reports. */
  assumptions: z.array(z.string()).default([]),
  /** Unconfirmed scenarios are reported but not executed. */
  confirmed: z.boolean().default(true),
  steps: z.array(ScenarioStep).min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).default("high"),
});
export type BusinessScenario = z.infer<typeof BusinessScenario>;

export const AuthzInput = z.object({
  baseUrl: z.string().url(),
  accounts: z.array(TestAccount).default([]),
  checks: z.array(AuthorizationCheck).default([]),
  scenarios: z.array(BusinessScenario).default([]),
  /** When an API inventory is given, GET endpoints requiring auth are probed anonymously. */
  inventory: z.custom<ApiInventory>().optional(),
  /** Run checks/scenarios that use POST/PUT/PATCH/DELETE. Requires approval upstream. */
  includeWriteTests: z.boolean().default(false),
  /**
   * Restrict the run to these check/scenario ids (used by retest). The special
   * id "@spec-auth-probe" selects the anonymous probe of documented endpoints.
   */
  only: z.array(z.string()).optional(),
});
export type AuthzInput = z.input<typeof AuthzInput>;

export const ANONYMOUS = "anonymous";
export const SPEC_PROBE_ID = "@spec-auth-probe";

export function resolveEnvRefs(value: string, env: NodeJS.ProcessEnv = process.env): { value: string; missing: string[] } {
  const missing: string[] = [];
  const out = value.replace(/\$\{env:([A-Z0-9_]+)\}/gi, (_, name: string) => {
    const v = env[name];
    if (v === undefined || v === "") missing.push(name);
    return v ?? "";
  });
  return { value: out, missing };
}

function interpolate(s: string, vars: Record<string, string>): string {
  return s.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, k: string) => encodeURIComponent(vars[k] ?? ""));
}

function getPath(obj: unknown, dotted: string): unknown {
  return dotted.split(".").reduce<unknown>((cur, key) => (cur && typeof cur === "object" ? (cur as Record<string, unknown>)[key] : undefined), obj);
}

function normalizeBody(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

export function usesWriteMethods(input: { checks?: AuthorizationCheck[]; scenarios?: BusinessScenario[] }): boolean {
  return (
    (input.checks ?? []).some((c) => !isSafeMethod(c.request.method)) ||
    (input.scenarios ?? []).some((s) => s.steps.some((st) => !isSafeMethod(st.request.method)))
  );
}

type Verdict = "pass" | "violation" | "suspicious" | "inconclusive";

/**
 * Decide whether a denied account's response leaked the owner's resource.
 * HTTP status alone is not treated as sufficient evidence (FR-09): a 2xx is
 * only a confirmed violation when the owner's data (markers or identical
 * body) appears in it.
 */
export function judgeAccess(owner: HttpExchange, other: HttpExchange, markers: string[]): { verdict: Verdict; reason: string } {
  if (!other.response) return { verdict: "inconclusive", reason: `Request failed: ${other.error}` };
  const status = other.response.status;
  if ([401, 403, 404].includes(status)) return { verdict: "pass", reason: `Denied with HTTP ${status}.` };
  if (status >= 300 && status < 400) return { verdict: "pass", reason: `Redirected (HTTP ${status}), typically to a login page.` };
  if (status >= 500) return { verdict: "inconclusive", reason: `Server error HTTP ${status}; access control could not be evaluated.` };
  if (status >= 400) return { verdict: "pass", reason: `Rejected with HTTP ${status}.` };
  const body = other.response.body;
  const leaked = markers.filter((m) => m && body.includes(m));
  if (leaked.length > 0) {
    return { verdict: "violation", reason: `HTTP ${status} and the response contains ${leaked.length} owner-only marker(s).` };
  }
  if (owner.response && owner.response.status < 300 && normalizeBody(owner.response.body) === normalizeBody(body) && body.length > 2) {
    return { verdict: "violation", reason: `HTTP ${status} with a body identical to the owner's response.` };
  }
  return {
    verdict: "suspicious",
    reason: `HTTP ${status} returned, but the body differs from the owner's and contains no owner markers. Could be a generic page or filtered data; needs manual review.`,
  };
}

export const authzAdapter: SecurityAdapter<AuthzInput> = {
  id: "authz",
  name: "Authorization & business-logic tester (built in)",
  operation: "authz_read_tests",
  inputSchema: AuthzInput,

  async healthCheck(): Promise<HealthStatus> {
    return { engine: "authz", available: true, via: "builtin", detail: "Built-in multi-account HTTP tester." };
  },

  async run(rawInput, ctx): Promise<AdapterResult> {
    const started = Date.now();
    const input = AuthzInput.parse(rawInput);
    const client = new ScopedHttpClient(ctx.policy, ctx.redact, { signal: ctx.signal });
    const findings: RawFinding[] = [];
    const coverage: string[] = [];
    const gaps: string[] = [];
    const results: Record<string, unknown>[] = [];

    const accounts = new Map<string, Record<string, string>>();
    accounts.set(ANONYMOUS, {});
    for (const a of input.accounts) {
      const headers: Record<string, string> = {};
      const missing: string[] = [];
      for (const [k, v] of Object.entries(a.headers)) {
        const r = resolveEnvRefs(v);
        headers[k] = r.value;
        missing.push(...r.missing);
      }
      if (missing.length) gaps.push(`Account "${a.name}" is missing environment variable(s) ${missing.join(", ")}; tests using it were skipped.`);
      else accounts.set(a.name, headers);
    }
    const roleOf = (name: string) => (name === ANONYMOUS ? "unauthenticated" : input.accounts.find((a) => a.name === name)?.role ?? "?");
    const selected = <T extends { id: string }>(items: T[]) => (input.only ? items.filter((i) => input.only!.includes(i.id)) : items);

    const send = async (account: string, spec: z.infer<typeof RequestSpec>, vars: Record<string, string> = {}) => {
      const headers = { ...spec.headers, ...(accounts.get(account) ?? {}) };
      let body: string | undefined;
      if (spec.json !== undefined) {
        body = interpolate(JSON.stringify(spec.json), vars);
        headers["content-type"] = "application/json";
      }
      return client.send({ method: spec.method, url: new URL(interpolate(spec.path, vars), input.baseUrl).toString(), headers, body });
    };

    try {
      // 1. Ownership / role checks (BOLA/IDOR, vertical privilege escalation, tenant isolation).
      for (const check of selected(input.checks)) {
        if (!isSafeMethod(check.request.method) && !input.includeWriteTests) {
          gaps.push(`Check "${check.id}" uses ${check.request.method} and was skipped: write tests need --include-write-tests and approval.`);
          continue;
        }
        const needed = [check.owner, ...check.denied, ...check.allowed];
        const unavailable = needed.filter((n) => !accounts.has(n));
        if (unavailable.length) {
          gaps.push(`Check "${check.id}" skipped: account(s) ${unavailable.join(", ")} not configured or missing credentials.`);
          continue;
        }
        const owner = await send(check.owner, check.request);
        if (!owner.response || owner.response.status >= 400) {
          gaps.push(`Check "${check.id}" inconclusive: the owner (${check.owner}) could not access the resource (${owner.response ? `HTTP ${owner.response.status}` : owner.error}). Fix the test data first.`);
          results.push({ check: check.id, verdict: "inconclusive" });
          continue;
        }
        const markers = check.sensitiveMarkers.length ? check.sensitiveMarkers : [];
        for (const name of check.denied) {
          const other = await send(name, check.request);
          const { verdict, reason } = judgeAccess(owner, other, markers);
          results.push({ check: check.id, account: name, verdict, reason });
          if (verdict === "pass" || verdict === "inconclusive") {
            if (verdict === "inconclusive") gaps.push(`Check "${check.id}" as ${name}: ${reason}`);
            continue;
          }
          const ownerRole = roleOf(check.owner);
          const otherRole = roleOf(name);
          const evidencePath = await writeEvidence(ctx, `authz-${check.id}-${name}.json`, { check: check.id, owner, other: other, verdict, reason });
          findings.push({
            title: `${name === ANONYMOUS ? "Unauthenticated" : `"${otherRole}" account`} can access ${check.request.method} ${check.request.path} (${check.id})`,
            description: `${check.description}\n\nTested as "${name}" (role ${otherRole}); the resource belongs to "${check.owner}" (role ${ownerRole}). ${reason}`,
            category: name === ANONYMOUS ? "authn" : "authz",
            severity: verdict === "violation" ? check.severity : "medium",
            confidence: verdict === "violation" ? "high" : "low",
            ruleId: `mungard.authz.${check.id}`,
            locations: [{ kind: "endpoint", method: check.request.method.toUpperCase(), path: check.request.path }],
            evidence: [
              { kind: "http_exchange", description: `Baseline as owner "${check.owner}"`, excerpt: formatExchange(owner, ctx.redact, 300) },
              { kind: "http_exchange", description: `Same request as "${name}"`, excerpt: formatExchange(other, ctx.redact, 300), path: evidencePath },
            ],
            reproductionSteps: [
              `Log in as ${check.owner} and request ${check.request.method} ${check.request.path}: succeeds (baseline).`,
              `Repeat the identical request with ${name === ANONYMOUS ? "no credentials" : `${name}'s credentials`}.`,
              `Observe: ${reason}`,
            ],
            impact:
              name === ANONYMOUS
                ? "Anyone on the network can read this resource without logging in."
                : "Users can read data that belongs to other users/tenants (Broken Object Level Authorization).",
            remediation:
              "Enforce authorization server-side on every request: load the resource scoped to the authenticated user/tenant (e.g. WHERE id = ? AND owner_id = ?) and return 404/403 otherwise. Add a regression test for this check.",
            references: ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
            cwe: name === ANONYMOUS ? ["CWE-306"] : ["CWE-639"],
            verified: verdict === "violation",
            fingerprintHint: name,
          });
        }
        coverage.push(`Authorization check "${check.id}": ${check.request.method} ${check.request.path} as ${[check.owner, ...check.denied].join(", ")}.`);
      }

      // 2. Business-logic scenarios.
      for (const scenario of selected(input.scenarios)) {
        if (!scenario.confirmed) {
          gaps.push(`Scenario "${scenario.id}" is unconfirmed (its business rules need user confirmation) and was not executed.`);
          continue;
        }
        if (scenario.steps.some((s) => !isSafeMethod(s.request.method)) && !input.includeWriteTests) {
          gaps.push(`Scenario "${scenario.id}" changes data and was skipped: needs --include-write-tests and approval.`);
          continue;
        }
        const missingAcc = scenario.steps.map((s) => s.as).filter((a) => !accounts.has(a));
        if (missingAcc.length) {
          gaps.push(`Scenario "${scenario.id}" skipped: account(s) ${[...new Set(missingAcc)].join(", ")} unavailable.`);
          continue;
        }
        const vars: Record<string, string> = {};
        const transcript: HttpExchange[] = [];
        let failure: { step: number; reason: string } | undefined;
        for (const [i, step] of scenario.steps.entries()) {
          const ex = await send(step.as, step.request, vars);
          transcript.push(ex);
          if (!ex.response) {
            failure = undefined;
            gaps.push(`Scenario "${scenario.id}" step ${i + 1} failed to execute: ${ex.error}`);
            break;
          }
          if (Object.keys(step.capture).length) {
            try {
              const json = JSON.parse(ex.response.body) as unknown;
              for (const [k, p] of Object.entries(step.capture)) {
                const v = getPath(json, p);
                if (v !== undefined) vars[k] = String(v);
              }
            } catch {
              gaps.push(`Scenario "${scenario.id}" step ${i + 1}: could not capture values (response is not JSON).`);
            }
          }
          const e = step.expect;
          if (!e) continue;
          const st = ex.response.status;
          if (e.statusIn && !e.statusIn.includes(st)) failure = { step: i + 1, reason: `expected status in [${e.statusIn.join(", ")}], got ${st}` };
          else if (e.statusNotIn?.includes(st)) failure = { step: i + 1, reason: `status ${st} is not allowed here` };
          else if (e.bodyNotContains?.some((m) => ex.response!.body.includes(interpolate(m, vars)))) failure = { step: i + 1, reason: "response contains data it must not contain" };
          if (failure) break;
        }
        results.push({ scenario: scenario.id, verdict: failure ? "violation" : "pass", failure });
        coverage.push(`Business-logic scenario "${scenario.id}" (${scenario.steps.length} step(s)).`);
        if (!failure) continue;
        const evidencePath = await writeEvidence(ctx, `scenario-${scenario.id}.json`, { scenario: scenario.id, transcript, failure });
        findings.push({
          title: `Business rule violated: ${scenario.description}`,
          description: `Scenario "${scenario.id}" failed at step ${failure.step}: ${failure.reason}.\n\nAssumed business rules:\n${scenario.assumptions.map((a) => `- ${a}`).join("\n") || "- (none stated)"}`,
          category: "business_logic",
          severity: scenario.severity,
          confidence: "high",
          ruleId: `mungard.scenario.${scenario.id}`,
          locations: [{ kind: "endpoint", method: scenario.steps[failure.step - 1]!.request.method.toUpperCase(), path: scenario.steps[failure.step - 1]!.request.path }],
          evidence: transcript.map((ex, i) => ({ kind: "http_exchange" as const, description: `Step ${i + 1} as ${scenario.steps[i]!.as}`, excerpt: formatExchange(ex, ctx.redact, 300), path: evidencePath })),
          reproductionSteps: scenario.steps.map((s, i) => `${i + 1}. As ${s.as}: ${s.request.method} ${s.request.path}${s.expect ? ` (expect ${JSON.stringify(s.expect)})` : ""}`),
          impact: "The application allows an action its business rules forbid. Impact depends on the rule (fraud, data integrity, privilege escalation).",
          remediation: "Enforce the rule server-side (state machine / precondition checks inside the same transaction) and add this scenario as a regression test.",
          cwe: ["CWE-840"],
          verified: true,
        });
      }

      // 3. Authentication enforcement on documented endpoints.
      if (input.inventory && (!input.only || input.only.includes(SPEC_PROBE_ID))) {
        const targets = input.inventory.endpoints.filter((e) => e.requiresAuth && e.method === "GET" && !e.path.includes("{"));
        for (const e of targets.slice(0, 50)) {
          const ex = await send(ANONYMOUS, { method: "GET", path: e.path, headers: {} });
          if (!ex.response) continue;
          e.testStatus = "tested";
          e.statusReason = `Anonymous GET returned HTTP ${ex.response.status}.`;
          if (ex.response.status >= 200 && ex.response.status < 300) {
            findings.push({
              title: `Endpoint documented as authenticated responds without credentials: GET ${e.path}`,
              description: `The OpenAPI spec requires ${e.security?.join(", ")} for GET ${e.path}, but an anonymous request returned HTTP ${ex.response.status}. This may be public data or a missing auth check; review the response.`,
              category: "authn",
              severity: "medium",
              confidence: "medium",
              ruleId: "mungard.authn.spec-mismatch",
              locations: [{ kind: "endpoint", method: "GET", path: e.path }],
              evidence: [{ kind: "http_exchange", description: "Anonymous request", excerpt: formatExchange(ex, ctx.redact, 400) }],
              reproductionSteps: [`curl -s ${new URL(e.path, input.baseUrl).toString()}`],
              impact: "If the endpoint returns user data, it is exposed to anyone.",
              remediation: "Enforce authentication in the route handler/middleware for this endpoint, or update the spec if it is intentionally public.",
              cwe: ["CWE-306"],
            });
          }
        }
        for (const e of input.inventory.endpoints) {
          if (e.testStatus !== "not_tested") continue;
          if (e.path.includes("{")) {
            e.testStatus = "needs_test_data";
            e.statusReason = "Path parameters need real resource ids; add an authorization check with owned ids.";
          } else if (e.method !== "GET") {
            e.testStatus = "untestable";
            e.statusReason = "State-changing endpoints are not probed automatically.";
          }
        }
        coverage.push(`Authentication enforcement probe on ${Math.min(targets.length, 50)} documented GET endpoint(s) without path parameters.`);
        if (targets.length > 50) gaps.push(`${targets.length - 50} additional authenticated GET endpoints were not probed (cap 50).`);
      }
    } catch (err) {
      if (err instanceof ScopeViolationError) {
        return emptyResult("authz", "failed", { error: err.message, findings, coverage, gaps, durationMs: Date.now() - started });
      }
      throw err;
    }

    if (input.checks.length === 0 && input.scenarios.length === 0) {
      gaps.push("No authorization checks or scenarios are configured; BOLA/IDOR and business-logic testing did not run. Run `mungard plan` for suggestions.");
    }
    if (input.accounts.length < 2) gaps.push("Fewer than two test accounts are configured; cross-user (BOLA/IDOR) tests need at least two.");
    const rawOutputPath = await writeEvidence(ctx, "authz-results.json", { results, requests: client.exchanges.length });
    return {
      engine: "authz",
      engineVersion: "builtin",
      status: "succeeded",
      findings,
      coverage,
      gaps,
      rawOutputPath,
      durationMs: Date.now() - started,
      data: { results, inventory: input.inventory },
    };
  },
};
