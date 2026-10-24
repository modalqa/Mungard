import { FINDING_STATUSES, FindingCategory, SEVERITIES, sortFindings, type Finding } from "@mungard/findings";
import { OPERATIONS, operationRule, redactDeep, type AuditActor } from "@mungard/policy-engine";
import { z } from "zod";
import { detectProject } from "./detect.js";
import type { LlmProvider } from "./llm.js";
import { PRESETS, STEP_IDS, runAssessment, startAssessment, type RunOutcome, type StepId, type StepOptions } from "./orchestrator.js";
import { planAssessment } from "./plan.js";
import { proposeRemediation } from "./remediation.js";
import { renderReport, buildReportInput, writeReport } from "./report.js";
import { runRetest } from "./retest.js";
import { heuristicTriage, triageFindings } from "./triage.js";
import type { RunRecord, Workspace } from "./workspace.js";

export interface ToolContext {
  ws: Workspace;
  actor: Extract<AuditActor, "mcp" | "chat" | "web">;
  /** Present in the standalone chat; MCP clients bring their own model. */
  llm?: LlmProvider;
  signal?: AbortSignal;
}

export interface MungardTool<S extends z.ZodObject = z.ZodObject> {
  name: string;
  title: string;
  description: string;
  inputSchema: S;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean; openWorldHint: boolean };
  handler: (input: z.infer<S>, ctx: ToolContext) => Promise<unknown>;
}

function tool<S extends z.ZodObject>(t: MungardTool<S>): MungardTool<S> {
  return t;
}

const UNVERIFIED_NOTE =
  "Findings with status new/needs_review are unverified scanner or heuristic output, not confirmed vulnerabilities. Only `confirmed` findings have been verified with evidence.";

function findingSummary(f: Finding) {
  const l = f.locations[0];
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    status: f.status,
    category: f.category,
    location: l ? [l.method, l.path ?? l.url ?? l.packageName ?? l.serverName, l.startLine].filter(Boolean).join(" ") : undefined,
    engines: [...new Set(f.sources.map((s) => s.engine))],
    retest: f.retest.status,
    triage: f.triage ? { source: f.triage.source, assessment: f.triage.assessment, priority: f.triage.priority } : undefined,
  };
}

export function runSummary(run: RunRecord, findings?: Finding[]) {
  return {
    runId: run.id,
    kind: run.kind,
    status: run.status,
    codeVersion: run.codeVersion,
    targets: run.targets,
    engines: run.engines.map((e) => ({ engine: e.engine, version: e.engineVersion, status: e.status, findings: e.findingCount, error: e.error })),
    blockedByPolicy: run.blocked.map((b) => ({ step: b.step, decision: b.decision, reasons: b.reasons, approvalId: b.approvalId })),
    coverage: run.engines.flatMap((e) => e.coverage),
    coverageGaps: run.engines.flatMap((e) => e.gaps),
    findings: findings ? sortFindings(findings).slice(0, 50).map(findingSummary) : undefined,
    note:
      run.engines.some((e) => e.status === "failed" || e.status === "unavailable")
        ? "Some engines did not run or failed; their checks were NOT performed. Do not report those areas as clean."
        : UNVERIFIED_NOTE,
  };
}

const waitParam = z.boolean().default(true).describe("Wait for the run to finish (true) or return a runId immediately and poll get_scan_status (false).");

async function execute(ctx: ToolContext, kind: string, steps: StepId[], options: StepOptions, wait: boolean) {
  if (!wait) {
    const runId = startAssessment(ctx.ws, { kind, steps, options, actor: ctx.actor });
    return { runId, status: "running", message: "Run started. Poll get_scan_status with this runId." };
  }
  const outcome: RunOutcome = await runAssessment(ctx.ws, { kind, steps, options, actor: ctx.actor, signal: ctx.signal });
  return runSummary(outcome.run, outcome.findings);
}

export const TOOLS = [
  tool({
    name: "get_project_context",
    title: "Get project context",
    description:
      "Detect the project's languages, frameworks, routes, OpenAPI specs, MCP and agent config files, and return the Mungard configuration (test accounts are listed by name/role only, never credentials).",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    handler: async (_i, { ws }) => {
      const det = await detectProject(ws.root);
      return {
        detection: { ...det, routes: det.routes.slice(0, 100), routeCount: det.routes.length },
        config: {
          target: ws.config.target,
          accounts: ws.config.auth.accounts.map((a) => ({ name: a.name, role: a.role, tenant: a.tenant })),
          authorizationChecks: ws.config.authorization.checks.map((c) => ({ id: c.id, description: c.description, method: c.request.method, path: c.request.path })),
          scenarios: ws.config.authorization.scenarios.map((s) => ({ id: s.id, description: s.description, confirmed: s.confirmed })),
          engines: ws.config.engines,
        },
      };
    },
  }),
  tool({
    name: "get_security_policy",
    title: "Get security policy",
    description: "Return the active security policy: allowed targets and ports, per-operation rules (allow / require_approval / deny), limits, AI data-sharing settings, and pending approvals.",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    handler: async (_i, { ws }) => ({
      targets: ws.config.policy.targets,
      operations: Object.fromEntries(OPERATIONS.map((op) => [op, operationRule(ws.config.policy, op)])),
      limits: ws.config.policy.limits,
      ai: ws.config.policy.ai,
      pendingApprovals: (await ws.approvals.list("pending")).map((a) => ({ id: a.id, operation: a.operation, summary: a.summary, expiresAt: a.expiresAt })),
      note: "Approvals can only be granted by a human in an interactive terminal (`mungard approvals approve <id>`) or in the Mungard web UI.",
    }),
  }),
  tool({
    name: "plan_security_assessment",
    title: "Plan a security assessment",
    description:
      "Build an assessment plan: which checks will run, the policy decision for each, missing prerequisites (tools, running app, test accounts), and suggested authorization/business-logic scenarios that need the user's confirmation. Does not run anything.",
    inputSchema: z.object({ goal: z.enum(["scan", "audit"]).default("audit") }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    handler: async ({ goal }, { ws }) => planAssessment(ws, goal),
  }),
  tool({
    name: "run_security_scan",
    title: "Run a security scan",
    description: `Run several checks in one run. preset "scan" = static analysis + secrets + dependencies; "audit" = everything applicable (adds agent config, MCP config, OpenAPI, and runtime tests when a target is configured). Or pass explicit steps (${STEP_IDS.join(", ")}). Active/destructive operations are never included.`,
    inputSchema: z.object({
      preset: z.enum(["scan", "audit"]).optional(),
      steps: z.array(z.enum(STEP_IDS)).optional(),
      wait: waitParam,
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    handler: async ({ preset, steps, wait }, ctx) => execute(ctx, preset ?? "custom", steps ?? [...PRESETS[preset ?? "scan"]], {}, wait),
  }),
  tool({
    name: "run_static_scan",
    title: "Run static analysis (SAST)",
    description: "Run Semgrep static analysis on the project source code with Mungard's bundled JS/TS rules (plus any configured registry packs).",
    inputSchema: z.object({ wait: waitParam }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    handler: async ({ wait }, ctx) => execute(ctx, "sast", ["sast"], {}, wait),
  }),
  tool({
    name: "run_secret_scan",
    title: "Run secret scan",
    description: "Run Gitleaks on the working tree and git history. Secret values are never returned; findings say whether the file is committed and gitignored.",
    inputSchema: z.object({ wait: waitParam }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    handler: async ({ wait }, ctx) => execute(ctx, "secrets", ["secrets"], {}, wait),
  }),
  tool({
    name: "run_dependency_audit",
    title: "Run dependency audit",
    description: "Run npm audit against package-lock.json. Never upgrades dependencies.",
    inputSchema: z.object({ wait: waitParam }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    handler: async ({ wait }, ctx) => execute(ctx, "deps", ["deps"], {}, wait),
  }),
  tool({
    name: "run_web_scan",
    title: "Run web DAST (OWASP ZAP)",
    description:
      "Scan the running web app with OWASP ZAP. mode=passive (default) spiders and applies passive rules only. mode=active sends attack payloads and ALWAYS requires human approval; the first call returns an approvalId, and after a human approves it, call again with the identical arguments. Also runs passive header/CORS checks. Defaults to wait=false because scans take minutes.",
    inputSchema: z.object({
      target: z.string().url().optional().describe("Defaults to target.baseUrl from config. Must be within the policy scope."),
      mode: z.enum(["passive", "active"]).default("passive"),
      wait: z.boolean().default(false),
    }),
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    handler: async ({ target, mode, wait }, ctx) => execute(ctx, `web-${mode}`, ["headers", "web"], { target, webMode: mode }, wait),
  }),
  tool({
    name: "analyze_api_spec",
    title: "Analyze OpenAPI specification",
    description: "Parse the OpenAPI spec, return the endpoint inventory (methods, parameters, auth requirements, BOLA candidates, test status) and spec-level security findings.",
    inputSchema: z.object({ spec: z.string().optional().describe("Path relative to the project root; defaults to config or detection.") }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    handler: async ({ spec }, ctx) => {
      const chosen = spec ?? ctx.ws.config.target.openapi ?? (await detectProject(ctx.ws.root)).openapiSpecs[0];
      if (!chosen) return { error: "No OpenAPI spec found. Pass spec or set target.openapi in .mungard/config.yaml." };
      const outcome = await runAssessment(ctx.ws, { kind: "api", steps: ["api"], options: { openapi: chosen }, actor: ctx.actor });
      return { ...runSummary(outcome.run, outcome.findings), inventory: outcome.results.api?.data };
    },
  }),
  tool({
    name: "run_authorization_tests",
    title: "Run authorization & business-logic tests",
    description:
      "Run configured authorization checks (BOLA/IDOR, role and tenant isolation) and business-logic scenarios against the running app using the configured test accounts, plus anonymous probes of documented endpoints. Read-only by default; includeWriteTests=true runs state-changing requests and requires human approval.",
    inputSchema: z.object({
      includeWriteTests: z.boolean().default(false),
      only: z.array(z.string()).optional().describe("Run only these check/scenario ids."),
      wait: waitParam,
    }),
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    handler: async ({ includeWriteTests, only, wait }, ctx) => execute(ctx, "authz", ["authz"], { includeWriteTests, authzOnly: only }, wait),
  }),
  tool({
    name: "inspect_mcp_config",
    title: "Inspect MCP configuration",
    description:
      "Inspect MCP server configurations (.mcp.json, .cursor/mcp.json, .vscode/mcp.json...) for hardcoded/committed credentials, unpinned packages, shell wrappers, weak Docker isolation, broad filesystem access and insecure remote servers. live=true starts the servers to check tool descriptions for poisoning, shadowing and changes; it executes third-party code and requires human approval.",
    inputSchema: z.object({
      live: z.boolean().default(false),
      servers: z.array(z.string()).optional(),
      includeUserConfig: z.boolean().default(false).describe("Also read user-level configs such as ~/.claude.json (only this project's entry is used)."),
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    handler: async ({ live, servers, includeUserConfig }, ctx) => {
      const outcome = await runAssessment(ctx.ws, { kind: "mcp", steps: ["mcp"], options: { mcpLive: live, mcpServers: servers, includeUserMcpConfig: includeUserConfig }, actor: ctx.actor });
      return { ...runSummary(outcome.run, outcome.findings), servers: (outcome.results.mcp?.data as { servers?: unknown } | undefined)?.servers };
    },
  }),
  tool({
    name: "audit_agent_config",
    title: "Audit AI agent configuration",
    description: "Audit AI agent instruction and permission files (CLAUDE.md, AGENTS.md, .cursorrules, .claude/settings.json, commands, skills) for hidden Unicode, prompt-injection indicators, over-broad permissions, risky hooks and literal credentials.",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    handler: async (_i, ctx) => execute(ctx, "agent", ["agent"], {}, true),
  }),
  tool({
    name: "get_scan_status",
    title: "Get scan status",
    description: "Return status, per-engine results, policy blocks and findings of a run. Without runId, returns the most recent runs.",
    inputSchema: z.object({ runId: z.string().optional() }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    handler: async ({ runId }, { ws }) => {
      if (!runId) return { runs: (await ws.listRuns(10)).map((r) => ({ runId: r.id, kind: r.kind, status: r.status, startedAt: r.startedAt, findings: r.findingIds.length })) };
      const run = await ws.getRun(runId);
      if (!run) return { error: `Run ${runId} not found.` };
      const all = await ws.loadFindings();
      return runSummary(run, all.filter((f) => run.findingIds.includes(f.id)));
    },
  }),
  tool({
    name: "list_findings",
    title: "List findings",
    description: `List normalized findings, most severe first. ${UNVERIFIED_NOTE}`,
    inputSchema: z.object({
      status: z.array(z.enum(FINDING_STATUSES)).optional(),
      severity: z.array(z.enum(SEVERITIES)).optional(),
      category: z.array(FindingCategory).optional(),
      unresolvedOnly: z.boolean().default(false),
      limit: z.number().int().min(1).max(200).default(50),
    }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    handler: async ({ status, severity, category, unresolvedOnly, limit }, { ws }) => {
      let all = await ws.loadFindings();
      if (status) all = all.filter((f) => status.includes(f.status));
      if (severity) all = all.filter((f) => severity.includes(f.severity));
      if (category) all = all.filter((f) => category.includes(f.category));
      if (unresolvedOnly) all = all.filter((f) => ["new", "needs_review", "confirmed", "fixed"].includes(f.status));
      return { total: all.length, findings: sortFindings(all).slice(0, limit).map(findingSummary), note: UNVERIFIED_NOTE };
    },
  }),
  tool({
    name: "get_finding_evidence",
    title: "Get finding evidence",
    description: "Return one finding in full: description, sources (scanner vs verification), locations, redacted evidence excerpts and evidence files, reproduction steps, triage, history and retest status.",
    inputSchema: z.object({ findingId: z.string(), includeEvidenceFiles: z.boolean().default(false) }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    handler: async ({ findingId, includeEvidenceFiles }, { ws }) => {
      const f = await ws.getFinding(findingId);
      if (!f) return { error: `Finding ${findingId} not found.` };
      const files: Record<string, string> = {};
      if (includeEvidenceFiles) {
        for (const p of [...new Set(f.evidence.map((e) => e.path).filter((p): p is string => !!p))].slice(0, 3)) {
          try {
            files[p] = await ws.readEvidence(p, 16_000);
          } catch (err) {
            files[p] = `unavailable: ${(err as Error).message}`;
          }
        }
      }
      return { finding: redactDeep(f, ws.redact), evidenceFiles: includeEvidenceFiles ? files : undefined, note: UNVERIFIED_NOTE };
    },
  }),
  tool({
    name: "triage_findings",
    title: "Triage findings",
    description:
      "Triage findings: group, estimate true/false positive likelihood, list missing evidence and verification steps, suggest priorities. Results are advisory and never change a finding's status.",
    inputSchema: z.object({ findingIds: z.array(z.string()).optional().describe("Defaults to all unresolved findings (max 60).") }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    handler: async ({ findingIds }, ctx) => {
      const all = await ctx.ws.loadFindings();
      const selected = (findingIds ? all.filter((f) => findingIds.includes(f.id)) : all.filter((f) => ["new", "needs_review", "confirmed"].includes(f.status))).slice(0, 60);
      const r = await triageFindings(ctx.ws, selected, { llm: ctx.llm, actor: ctx.actor });
      return {
        usedAi: r.usedAi,
        aiError: r.aiError,
        triage: selected.map((f) => ({ id: f.id, title: f.title, severity: f.severity, ...(r.triaged.get(f.id) ?? heuristicTriage(f)) })),
        note: "Triage is advisory. Statuses can only be changed by a human (CLI or web UI) or by deterministic verification/retests.",
      };
    },
  }),
  tool({
    name: "propose_remediation",
    title: "Propose remediation",
    description: "Return remediation guidance for a finding: affected code/endpoints with context, a suggested regression test, and the retest command. Mungard does not edit code; apply changes with the user's approval.",
    inputSchema: z.object({ findingId: z.string() }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    handler: async ({ findingId }, { ws }) => proposeRemediation(ws, findingId),
  }),
  tool({
    name: "run_retest",
    title: "Retest findings",
    description:
      "Re-run the engines that produced the given findings and compare before/after. A finding is closed (status retested) only when its engine completed and the issue is no longer detected; otherwise it stays unresolved. Records the git commit tested.",
    inputSchema: z.object({ findingIds: z.array(z.string()).min(1) }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    handler: async ({ findingIds }, ctx) => runRetest(ctx.ws, findingIds, { actor: ctx.actor, signal: ctx.signal }),
  }),
  tool({
    name: "generate_security_report",
    title: "Generate security report",
    description: "Generate a report (md, json or sarif) covering scope, tools and versions, coverage gaps, findings by severity with evidence, unverified findings and retest results. Saved under .mungard/reports/.",
    inputSchema: z.object({ format: z.enum(["md", "json", "sarif"]).default("md"), inline: z.boolean().default(false).describe("Also return the report content (Markdown only).") }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    handler: async ({ format, inline }, ctx) => {
      const { file } = await writeReport(ctx.ws, format, undefined, ctx.actor);
      return { file, content: inline && format === "md" ? renderReport(await buildReportInput(ctx.ws), "md").slice(0, 60_000) : undefined };
    },
  }),
  tool({
    name: "list_approvals",
    title: "List approval requests",
    description: "List approval requests and their status so you can tell the user what is waiting for their decision. Agents cannot approve requests.",
    inputSchema: z.object({ status: z.enum(["pending", "approved", "denied", "consumed", "expired"]).optional() }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    handler: async ({ status }, { ws }) => ({
      approvals: (await ws.approvals.list(status)).map((a) => ({ id: a.id, operation: a.operation, summary: a.summary, target: a.target, status: a.status, requestedAt: a.requestedAt, expiresAt: a.expiresAt })),
      howToApprove: "A human runs `mungard approvals approve <id>` in an interactive terminal, or uses the Approvals panel in the Mungard web UI.",
    }),
  }),
];

export type ToolName = (typeof TOOLS)[number]["name"];

export function findTool(name: string): MungardTool | undefined {
  return (TOOLS as unknown as MungardTool[]).find((t) => t.name === name);
}

/** Validate input with the tool's schema and run it. Unknown tools and invalid input are errors, never shell commands. */
export async function callTool(name: string, rawInput: unknown, ctx: ToolContext): Promise<{ ok: true; result: unknown } | { ok: false; error: string }> {
  const t = findTool(name);
  if (!t) return { ok: false, error: `Unknown tool "${name}".` };
  const parsed = t.inputSchema.safeParse(rawInput ?? {});
  if (!parsed.success) return { ok: false, error: `Invalid input for ${name}: ${parsed.error.message}` };
  await ctx.ws.audit.write({ actor: ctx.actor, event: "agent_request", operation: name, details: { input: parsed.data as Record<string, unknown> } });
  try {
    return { ok: true, result: await t.handler(parsed.data, ctx) };
  } catch (err) {
    return { ok: false, error: ctx.ws.redact((err as Error).message) };
  }
}

/** JSON Schema for a tool input (for MCP-less consumers such as the chat agent). */
export function toolJsonSchema(t: MungardTool): Record<string, unknown> {
  const schema = z.toJSONSchema(t.inputSchema, { io: "input" }) as Record<string, unknown>;
  delete schema.$schema;
  return schema;
}
