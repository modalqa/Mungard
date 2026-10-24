import { BUILTIN_ADAPTERS, buildInventory, loadSpec, type HealthStatus } from "@mungard/adapters";
import { operationRule, resolveWithinRoot, checkTarget, type Operation, type OperationRule } from "@mungard/policy-engine";
import { detectProject, type ProjectDetection } from "./detect.js";
import { PRESETS, STEP_DESCRIPTIONS, type StepId } from "./orchestrator.js";
import type { Workspace } from "./workspace.js";

export interface PlannedItem {
  step: StepId;
  description: string;
  operation: Operation;
  policy: OperationRule | "out_of_scope";
  ready: boolean;
  prerequisites: string[];
}

export interface SuggestedScenario {
  id: string;
  kind: "authorization_check" | "business_logic";
  description: string;
  assumptions: string[];
  /** Always true: scenarios built from guesses need the user to confirm the business rule. */
  needsConfirmation: true;
  template: unknown;
}

export interface AssessmentPlan {
  project: Pick<ProjectDetection, "name" | "frameworks" | "languages" | "openapiSpecs" | "mcpConfigFiles" | "agentFiles">;
  target?: string;
  items: PlannedItem[];
  suggestedScenarios: SuggestedScenario[];
  limitations: string[];
  engineHealth: HealthStatus[];
}

const STEP_OPERATION: Record<StepId, Operation> = {
  sast: "static_scan",
  secrets: "secret_scan",
  deps: "dependency_audit",
  agent: "agent_config_audit",
  mcp: "mcp_inspect",
  api: "api_analysis",
  headers: "http_probe",
  web: "web_passive_scan",
  authz: "authz_read_tests",
};

export async function engineHealth(ws: Workspace): Promise<HealthStatus[]> {
  return Promise.all(Object.values(BUILTIN_ADAPTERS).map((a) => a.healthCheck({ projectRoot: ws.root, policy: ws.config.policy })));
}

/**
 * Build a security assessment plan (FR-02, FR-10): which checks will run,
 * what policy says about each, what is missing, and suggested authorization
 * and business-logic scenarios that the user must confirm before they run.
 */
export async function planAssessment(ws: Workspace, goal: "scan" | "audit" = "audit"): Promise<AssessmentPlan> {
  const det = await detectProject(ws.root);
  const target = ws.config.target.baseUrl;
  const spec = ws.config.target.openapi ?? det.openapiSpecs[0];
  const health = await engineHealth(ws);
  const healthOf = (engine: string) => health.find((h) => h.engine === engine);
  const items: PlannedItem[] = [];
  for (const step of PRESETS[goal]) {
    const operation = STEP_OPERATION[step];
    const prerequisites: string[] = [];
    const engine = { sast: "semgrep", secrets: "gitleaks", deps: "npm-audit", web: "zap" }[step as string];
    const h = engine ? healthOf(engine) : undefined;
    if (h && !h.available) prerequisites.push(`${h.engine} unavailable: ${h.remedy ?? h.detail}`);
    if (["headers", "web", "authz"].includes(step) && !target) prerequisites.push("Set target.baseUrl in .mungard/config.yaml and start the app.");
    if (step === "api" && !spec) prerequisites.push("No OpenAPI spec found; set target.openapi.");
    if (step === "deps" && !det.dependencyFiles.includes("package-lock.json")) prerequisites.push("package-lock.json is required for npm audit.");
    if (step === "authz" && ws.config.auth.accounts.length < 2) prerequisites.push("Configure at least two test accounts (auth.accounts) for cross-user tests.");
    if (step === "mcp" && det.mcpConfigFiles.length === 0) prerequisites.push("No MCP config files in the project (nothing to inspect).");
    let policy: PlannedItem["policy"] = operationRule(ws.config.policy, operation);
    if (target && ["headers", "web", "authz"].includes(step) && !checkTarget(target, ws.config.policy).allowed) policy = "out_of_scope";
    items.push({ step, description: STEP_DESCRIPTIONS[step], operation, policy, ready: prerequisites.length === 0 && policy !== "deny" && policy !== "out_of_scope", prerequisites });
  }
  items.push({
    step: "web",
    description: "OPTIONAL: active OWASP ZAP scan (attack payloads). Separate operation, never part of the default run.",
    operation: "web_active_scan",
    policy: operationRule(ws.config.policy, "web_active_scan"),
    ready: false,
    prerequisites: ["Explicit human approval", "A disposable test environment (active scans can create/modify data)"],
  });

  const suggestedScenarios: SuggestedScenario[] = [];
  if (spec) {
    try {
      const inv = buildInventory(await loadSpec(resolveWithinRoot(ws.root, spec), ws.config.policy.limits.maxFileSizeBytes));
      for (const e of inv.endpoints.filter((x) => x.bolaCandidate && x.method === "GET").slice(0, 10)) {
        const id = `${e.operationId ?? e.path.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "")}-ownership`;
        suggestedScenarios.push({
          id,
          kind: "authorization_check",
          description: `Only the owner (and admins) can read ${e.path}`,
          assumptions: [`Resources behind ${e.path} belong to a single user or tenant.`, "Other users of the same role must not read them."],
          needsConfirmation: true,
          template: {
            id,
            description: `Only the owner can read ${e.path}`,
            request: { method: "GET", path: e.path.replace(/\{[^}]+\}/g, "<OWNED_BY_ALICE_ID>") },
            owner: "alice",
            denied: ["bob", "anonymous"],
            sensitiveMarkers: ["<A VALUE ONLY ALICE'S RECORD CONTAINS>"],
          },
        });
      }
      for (const e of inv.endpoints.filter((x) => ["POST", "PUT", "PATCH", "DELETE"].includes(x.method) && x.requiresAuth).slice(0, 5)) {
        const id = `${e.operationId ?? e.method.toLowerCase() + e.path.replace(/[^a-zA-Z0-9]+/g, "-")}-role-guard`.replace(/-+$/g, "");
        suggestedScenarios.push({
          id,
          kind: "business_logic",
          description: `A regular member cannot ${e.method} ${e.path} on another user's resource`,
          assumptions: [`${e.method} ${e.path} is restricted to the resource owner or an admin role.`, "Which roles may perform this action must be confirmed by you."],
          needsConfirmation: true,
          template: {
            id,
            description: `Member cannot ${e.method} ${e.path} on someone else's resource`,
            confirmed: false,
            assumptions: ["<CONFIRM THE BUSINESS RULE>"],
            steps: [{ as: "bob", request: { method: e.method, path: e.path.replace(/\{[^}]+\}/g, "<OWNED_BY_ALICE_ID>") }, expect: { statusIn: [401, 403, 404] } }],
          },
        });
      }
    } catch {
      // spec problems are reported by the api step
    }
  } else if (det.routes.length) {
    const dynamic = det.routes.filter((r) => r.path.includes("{")).slice(0, 10);
    for (const r of dynamic) {
      const id = `${r.path.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "")}-ownership`;
      suggestedScenarios.push({
        id,
        kind: "authorization_check",
        description: `Only the owner can access ${r.method === "*" ? "GET" : r.method} ${r.path} (from ${r.file})`,
        assumptions: [`${r.path} serves per-user data.`],
        needsConfirmation: true,
        template: { id, description: `Only the owner can read ${r.path}`, request: { method: "GET", path: r.path.replace(/\{[^}]+\}/g, "<OWNED_BY_ALICE_ID>") }, owner: "alice", denied: ["bob", "anonymous"] },
      });
    }
  }

  return {
    project: { name: det.name, frameworks: det.frameworks, languages: det.languages, openapiSpecs: det.openapiSpecs, mcpConfigFiles: det.mcpConfigFiles, agentFiles: det.agentFiles },
    target,
    items,
    suggestedScenarios,
    limitations: [
      "Automated tools cannot prove the absence of vulnerabilities.",
      "Business-logic scenarios are only as good as the rules you confirm; suggested scenarios are guesses until confirmed.",
      "Authorization tests need realistic test data owned by different accounts.",
      ...det.notes,
    ],
    engineHealth: health,
  };
}
