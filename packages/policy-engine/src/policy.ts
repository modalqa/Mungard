import { z } from "zod";

/**
 * Every operation an agent, CLI or chat can request. Operations are a closed
 * set: there is no "run arbitrary command" operation (PRD 7.3).
 */
export const OPERATIONS = [
  "project_read",
  "static_scan",
  "secret_scan",
  "dependency_audit",
  "web_passive_scan",
  "web_active_scan",
  "api_analysis",
  "http_probe",
  "authz_read_tests",
  "authz_write_tests",
  "mcp_inspect",
  "mcp_live_inspect",
  "agent_config_audit",
  "ai_triage",
  "retest",
  "report",
  "finding_update",
  "code_modification",
  "dependency_upgrade",
] as const;
export const Operation = z.enum(OPERATIONS);
export type Operation = z.infer<typeof Operation>;

export const OperationRule = z.enum(["allow", "require_approval", "deny"]);
export type OperationRule = z.infer<typeof OperationRule>;

/** Safe defaults (SR-08): anything active, mutating or destructive needs a human. */
export const DEFAULT_OPERATION_RULES: Record<Operation, OperationRule> = {
  project_read: "allow",
  static_scan: "allow",
  secret_scan: "allow",
  dependency_audit: "allow",
  web_passive_scan: "allow",
  web_active_scan: "require_approval",
  api_analysis: "allow",
  http_probe: "allow",
  authz_read_tests: "allow",
  authz_write_tests: "require_approval",
  mcp_inspect: "allow",
  // Launches the MCP servers listed in config files: executes third-party code.
  mcp_live_inspect: "require_approval",
  agent_config_audit: "allow",
  ai_triage: "allow",
  retest: "allow",
  report: "allow",
  finding_update: "allow",
  code_modification: "require_approval",
  dependency_upgrade: "require_approval",
};

/** Operations whose rule can never be relaxed to "allow" by configuration. */
export const ALWAYS_GATED: readonly Operation[] = [
  "web_active_scan",
  "authz_write_tests",
  "mcp_live_inspect",
  "code_modification",
  "dependency_upgrade",
];

export const SecurityPolicy = z.object({
  targets: z
    .object({
      /** Hostnames (exact, or `*.example.test` wildcard) that may be tested. */
      allowedHosts: z.array(z.string()).default(["localhost", "127.0.0.1", "::1"]),
      /** Allowed ports. Empty means any port on an allowed host. */
      allowedPorts: z.array(z.number().int().min(1).max(65535)).default([]),
      /** Hosts that are known production. Denied unless allowProduction is true. */
      productionHosts: z.array(z.string()).default([]),
      allowProduction: z.boolean().default(false),
      /** Follow redirects only when the redirect target is also in scope. */
      followOutOfScopeRedirects: z.literal(false).default(false),
    })
    .prefault({}),
  operations: z.partialRecord(Operation, OperationRule).default({}),
  limits: z
    .object({
      toolTimeoutSeconds: z.number().int().min(10).max(7200).default(600),
      activeScanMaxMinutes: z.number().int().min(1).max(120).default(10),
      spiderMaxMinutes: z.number().int().min(1).max(60).default(2),
      maxRequestsPerSecond: z.number().min(0.1).max(100).default(5),
      maxHttpRequests: z.number().int().min(1).max(10000).default(500),
      maxFileSizeBytes: z.number().int().min(1024).default(1_000_000),
      maxEvidenceBytes: z.number().int().min(256).default(16_000),
      maxOutputBytes: z.number().int().min(1024).default(64 * 1024 * 1024),
    })
    .prefault({}),
  approvals: z
    .object({
      expiresMinutes: z.number().int().min(1).max(24 * 60).default(60),
    })
    .prefault({}),
  redaction: z
    .object({
      /** Extra regular expressions whose matches are masked everywhere. */
      extraPatterns: z.array(z.string()).default([]),
    })
    .prefault({}),
  ai: z
    .object({
      enabled: z.boolean().default(true),
      /** What source code may be sent to the model provider (SR-09). */
      sendSourceCode: z.enum(["none", "snippets"]).default("snippets"),
      maxSnippetLines: z.number().int().min(0).max(200).default(30),
    })
    .prefault({}),
});
export type SecurityPolicy = z.infer<typeof SecurityPolicy>;
export type SecurityPolicyInput = z.input<typeof SecurityPolicy>;

export function parsePolicy(input: unknown): SecurityPolicy {
  return SecurityPolicy.parse(input ?? {});
}

export function defaultPolicy(): SecurityPolicy {
  return parsePolicy({});
}

/** Effective rule for an operation, with the always-gated floor applied. */
export function operationRule(policy: SecurityPolicy, op: Operation): OperationRule {
  const configured = policy.operations[op] ?? DEFAULT_OPERATION_RULES[op];
  if (configured === "allow" && ALWAYS_GATED.includes(op)) return "require_approval";
  return configured;
}
