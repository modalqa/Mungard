import { randomBytes } from "node:crypto";
import path from "node:path";
import {
  BUILTIN_ADAPTERS,
  buildInventory,
  gitCodeVersion,
  loadSpec,
  usesWriteMethods,
  type AdapterContext,
  type AdapterResult,
  type ApiInventory,
  type SecurityAdapter,
} from "@mungard/adapters";
import { normalizeFinding, type Finding } from "@mungard/findings";
import { resolveWithinRoot, type AuditActor, type Operation } from "@mungard/policy-engine";
import type { EngineRunSummary } from "@mungard/reporting";
import type { RunRecord, Workspace } from "./workspace.js";

export const STEP_IDS = ["sast", "secrets", "deps", "agent", "mcp", "api", "headers", "web", "authz"] as const;
export type StepId = (typeof STEP_IDS)[number];

export const STEP_DESCRIPTIONS: Record<StepId, string> = {
  sast: "Static analysis of source code (Semgrep)",
  secrets: "Secret detection in files and git history (Gitleaks)",
  deps: "Known-vulnerable dependencies (npm audit)",
  agent: "AI agent instruction & permission files (CLAUDE.md, .claude/settings.json, rules)",
  mcp: "MCP server configurations (.mcp.json and client configs)",
  api: "OpenAPI specification analysis",
  headers: "HTTP security headers, cookies and CORS on the running app",
  web: "Web DAST with OWASP ZAP (passive baseline unless active is approved)",
  authz: "Authentication, authorization (BOLA/IDOR) and business-logic tests with test accounts",
};

/** Preset step lists for the CLI verbs. */
export const PRESETS = {
  scan: ["sast", "secrets", "deps"],
  audit: ["sast", "secrets", "deps", "agent", "mcp", "api", "headers", "authz", "web"],
  mcp: ["mcp"],
  agent: ["agent", "mcp"],
} as const satisfies Record<string, readonly StepId[]>;

export interface StepOptions {
  /** Runtime target; defaults to config target.baseUrl. */
  target?: string;
  webMode?: "passive" | "active";
  openapi?: string;
  mcpLive?: boolean;
  mcpServers?: string[];
  includeUserMcpConfig?: boolean;
  includeWriteTests?: boolean;
  /** Restrict authz to these check/scenario ids (used by retests). */
  authzOnly?: string[];
}

export type RunEvent =
  | { type: "run_started"; runId: string; steps: StepId[] }
  | { type: "step_started"; runId: string; step: StepId; engine: string }
  | { type: "step_finished"; runId: string; step: StepId; summary: EngineRunSummary }
  | { type: "step_blocked"; runId: string; step: StepId; decision: string; reasons: string[]; approvalId?: string }
  | { type: "step_skipped"; runId: string; step: StepId; reason: string }
  | { type: "log"; runId: string; message: string }
  | { type: "run_finished"; runId: string; run: RunRecord };

export interface RunRequest {
  kind: string;
  steps: StepId[];
  options?: StepOptions;
  actor: AuditActor;
  onEvent?: (e: RunEvent) => void;
  signal?: AbortSignal;
}

interface PlannedStep {
  step: StepId;
  adapter: SecurityAdapter<unknown>;
  operation: Operation;
  input: Record<string, unknown>;
  target?: string;
  summary: string;
  /** Approval binding: the parameters a human approves. */
  params: Record<string, unknown>;
}

export function newRunId(): string {
  const ts = new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  return `run_${ts}_${randomBytes(3).toString("hex")}`;
}

async function loadInventory(ws: Workspace, spec: string | undefined): Promise<ApiInventory | undefined> {
  if (!spec) return undefined;
  try {
    return buildInventory(await loadSpec(resolveWithinRoot(ws.root, spec), ws.config.policy.limits.maxFileSizeBytes));
  } catch {
    return undefined;
  }
}

/** Translate a step into an adapter call, or explain why it cannot run. */
async function planStep(ws: Workspace, step: StepId, opts: StepOptions): Promise<PlannedStep | { skip: string }> {
  const cfg = ws.config;
  const target = opts.target ?? cfg.target.baseUrl;
  const spec = opts.openapi ?? cfg.target.openapi;
  const a = BUILTIN_ADAPTERS as unknown as Record<string, SecurityAdapter<unknown>>;
  switch (step) {
    case "sast":
      if (!cfg.engines.semgrep.enabled) return { skip: "Semgrep is disabled in config." };
      return {
        step,
        adapter: a.semgrep!,
        operation: "static_scan",
        input: { registryRules: cfg.engines.semgrep.registryRules, localRules: cfg.engines.semgrep.localRules, exclude: cfg.engines.semgrep.exclude },
        summary: "Run Semgrep static analysis on the project source.",
        params: { root: ws.root },
      };
    case "secrets":
      if (!cfg.engines.gitleaks.enabled) return { skip: "Gitleaks is disabled in config." };
      return { step, adapter: a.gitleaks!, operation: "secret_scan", input: { history: cfg.engines.gitleaks.history, excludePaths: cfg.engines.gitleaks.excludePaths }, summary: "Run Gitleaks secret detection.", params: { root: ws.root } };
    case "deps":
      if (!cfg.engines.npmAudit.enabled) return { skip: "npm audit is disabled in config." };
      return { step, adapter: a["npm-audit"]!, operation: "dependency_audit", input: { omitDev: cfg.engines.npmAudit.omitDev }, summary: "Run npm audit on package-lock.json.", params: { root: ws.root } };
    case "agent":
      return { step, adapter: a["agent-config"]!, operation: "agent_config_audit", input: {}, summary: "Audit AI agent instruction and permission files.", params: { root: ws.root } };
    case "mcp": {
      const live = !!opts.mcpLive;
      return {
        step,
        adapter: a["mcp-inspector"]!,
        operation: live ? "mcp_live_inspect" : "mcp_inspect",
        input: { live, includeUserConfig: !!opts.includeUserMcpConfig, servers: opts.mcpServers },
        summary: live
          ? `Start ${opts.mcpServers?.length ? `MCP server(s) ${opts.mcpServers.join(", ")}` : "every configured MCP server"} to inspect live tool definitions (executes the configured commands).`
          : "Statically inspect MCP server configuration files.",
        params: { root: ws.root, live, servers: opts.mcpServers ?? "all", includeUserConfig: !!opts.includeUserMcpConfig },
      };
    }
    case "api":
      if (!spec) return { skip: "No OpenAPI spec configured (target.openapi) or detected." };
      return { step, adapter: a.openapi!, operation: "api_analysis", input: { spec }, summary: `Analyze OpenAPI spec ${spec}.`, params: { spec } };
    case "headers":
      if (!target) return { skip: "No runtime target configured (target.baseUrl); runtime checks skipped." };
      return { step, adapter: a["http-probe"]!, operation: "http_probe", input: { target }, target, summary: `Passive header/CORS checks on ${target}.`, params: { target } };
    case "web": {
      if (!target) return { skip: "No runtime target configured (target.baseUrl); web DAST skipped." };
      if (!cfg.engines.zap.enabled) return { skip: "ZAP is disabled in config." };
      const mode = opts.webMode ?? "passive";
      return {
        step,
        adapter: a.zap!,
        operation: mode === "active" ? "web_active_scan" : "web_passive_scan",
        input: { target, mode },
        target,
        summary:
          mode === "active"
            ? `ACTIVE OWASP ZAP scan of ${target}: sends attack payloads (SQLi, XSS, path traversal...) for up to ${cfg.policy.limits.activeScanMaxMinutes} minutes. May create or modify data in the target.`
            : `Passive OWASP ZAP baseline scan of ${target} (spider + passive rules).`,
        params: { target, mode },
      };
    }
    case "authz": {
      if (!target) return { skip: "No runtime target configured (target.baseUrl); authorization tests skipped." };
      const inventory = await loadInventory(ws, spec);
      const checks = cfg.authorization.checks;
      const scenarios = cfg.authorization.scenarios;
      const write = !!opts.includeWriteTests && usesWriteMethods({ checks, scenarios });
      return {
        step,
        adapter: a.authz!,
        operation: write ? "authz_write_tests" : "authz_read_tests",
        input: {
          baseUrl: target,
          accounts: cfg.auth.accounts,
          checks,
          scenarios,
          inventory,
          includeWriteTests: write,
          only: opts.authzOnly,
        },
        target,
        summary: write
          ? `Authorization & business-logic tests against ${target} INCLUDING state-changing requests (POST/PUT/PATCH/DELETE) as configured test accounts.`
          : `Read-only authorization tests against ${target} as configured test accounts.`,
        params: { target, write, checks: checks.map((c) => c.id), scenarios: scenarios.map((s) => s.id), only: opts.authzOnly ?? "all" },
      };
    }
  }
}

function summarize(result: AdapterResult): EngineRunSummary {
  return {
    engine: result.engine,
    engineVersion: result.engineVersion,
    status: result.status,
    coverage: result.coverage,
    gaps: result.gaps,
    error: result.error,
    findingCount: result.findings.length,
    durationMs: result.durationMs,
  };
}

export interface RunOutcome {
  run: RunRecord;
  findings: Finding[];
  results: Partial<Record<StepId, AdapterResult>>;
}

/**
 * Run an assessment. Each step is authorized by the policy engine first;
 * a failing engine never discards results of other engines (NFR reliability).
 */
export async function runAssessment(ws: Workspace, req: RunRequest, runId = newRunId()): Promise<RunOutcome> {
  await ws.ensure();
  const opts = req.options ?? {};
  const emit = (e: RunEvent) => req.onEvent?.(e);
  const run: RunRecord = {
    id: runId,
    kind: req.kind,
    status: "running",
    actor: req.actor,
    startedAt: new Date().toISOString(),
    codeVersion: await gitCodeVersion(ws.root),
    targets: [],
    steps: req.steps,
    engines: [],
    findingIds: [],
    blocked: [],
  };
  await ws.saveRun(run);
  emit({ type: "run_started", runId, steps: req.steps });
  const allFindings: Finding[] = [];
  const results: RunOutcome["results"] = {};

  try {
    for (const step of req.steps) {
      if (req.signal?.aborted) {
        run.status = "cancelled";
        break;
      }
      const planned = await planStep(ws, step, opts);
      if ("skip" in planned) {
        run.engines.push({ engine: step, status: "skipped", coverage: [], gaps: [planned.skip], findingCount: 0, durationMs: 0 });
        emit({ type: "step_skipped", runId, step, reason: planned.skip });
        continue;
      }
      const decision = await ws.policyEngine.authorize({
        operation: planned.operation,
        actor: req.actor,
        summary: planned.summary,
        target: planned.target,
        params: planned.params,
      });
      if (decision.kind !== "allow") {
        const approvalId = decision.kind === "approval_required" ? decision.approval.id : undefined;
        run.blocked.push({ step, decision: decision.kind, reasons: decision.reasons, approvalId });
        run.engines.push({
          engine: planned.adapter.id,
          status: "skipped",
          coverage: [],
          gaps: [`${STEP_DESCRIPTIONS[step]} did NOT run: ${decision.reasons.join(" ")}`],
          findingCount: 0,
          durationMs: 0,
        });
        emit({ type: "step_blocked", runId, step, decision: decision.kind, reasons: decision.reasons, approvalId });
        continue;
      }
      if (planned.target) run.targets = [...new Set([...run.targets, planned.target])];
      emit({ type: "step_started", runId, step, engine: planned.adapter.id });
      await ws.audit.write({ actor: req.actor, event: "tool_started", operation: planned.operation, target: planned.target, runId, details: { engine: planned.adapter.id } });
      const ctx: AdapterContext = {
        projectRoot: ws.root,
        workspaceDir: ws.dir,
        runId,
        policy: ws.config.policy,
        redact: ws.redact,
        evidenceDir: path.join(ws.runDir(runId), "evidence"),
        signal: req.signal,
        log: (message) => emit({ type: "log", runId, message: ws.redact(message) }),
      };
      let result: AdapterResult;
      try {
        result = await planned.adapter.run(planned.adapter.inputSchema.parse(planned.input), ctx);
      } catch (err) {
        result = {
          engine: planned.adapter.id,
          status: "failed",
          findings: [],
          coverage: [],
          gaps: [`${STEP_DESCRIPTIONS[step]} did not complete.`],
          error: ws.redact((err as Error).message),
          durationMs: 0,
        };
      }
      results[step] = result;
      const normalized = result.findings.map((f) =>
        normalizeFinding(f, { engine: result.engine, engineVersion: result.engineVersion, runId }),
      );
      const stored = normalized.length ? await ws.mergeFindings(normalized) : [];
      allFindings.push(...stored);
      const summary = summarize(result);
      run.engines.push(summary);
      run.findingIds = [...new Set([...run.findingIds, ...stored.map((f) => f.id)])];
      await ws.saveRun(run); // persist partial progress
      await ws.audit.write({
        actor: req.actor,
        event: result.status === "failed" || result.status === "unavailable" ? "tool_failed" : "tool_finished",
        operation: planned.operation,
        target: planned.target,
        runId,
        details: { engine: result.engine, status: result.status, findings: result.findings.length, error: result.error },
      });
      emit({ type: "step_finished", runId, step, summary });
    }
    if (run.status === "running") run.status = "completed";
  } catch (err) {
    run.status = "failed";
    run.error = ws.redact((err as Error).message);
  }
  run.finishedAt = new Date().toISOString();
  await ws.saveRun(run);
  emit({ type: "run_finished", runId, run });
  return { run, findings: allFindings, results };
}

const background = new Map<string, Promise<RunOutcome>>();

/** Start a run without waiting (MCP/chat). Poll with workspace.getRun(runId). */
export function startAssessment(ws: Workspace, req: RunRequest): string {
  const runId = newRunId();
  const p = runAssessment(ws, req, runId).finally(() => {
    setTimeout(() => background.delete(runId), 60_000).unref?.();
  });
  p.catch(() => undefined);
  background.set(runId, p);
  return runId;
}

export function waitForRun(runId: string): Promise<RunOutcome> | undefined {
  return background.get(runId);
}
