export * from "./types.js";
export * from "./exec.js";
export * from "./http.js";
export * from "./util.js";
export * from "./injection.js";
export * from "./semgrep.js";
export * from "./gitleaks.js";
export * from "./npm-audit.js";
export * from "./zap.js";
export * from "./openapi.js";
export * from "./http-probe.js";
export * from "./authz.js";
export * from "./mcp-inspector.js";
export * from "./agent-config.js";

import { agentConfigAdapter } from "./agent-config.js";
import { authzAdapter } from "./authz.js";
import { gitleaksAdapter } from "./gitleaks.js";
import { httpProbeAdapter } from "./http-probe.js";
import { mcpInspectorAdapter } from "./mcp-inspector.js";
import { npmAuditAdapter } from "./npm-audit.js";
import { openApiAdapter } from "./openapi.js";
import { semgrepAdapter } from "./semgrep.js";
import { zapAdapter } from "./zap.js";

/**
 * Registry of built-in adapters. New engines are added here (or registered at
 * runtime by the orchestrator) without changing core orchestration.
 */
export const BUILTIN_ADAPTERS = {
  semgrep: semgrepAdapter,
  gitleaks: gitleaksAdapter,
  "npm-audit": npmAuditAdapter,
  zap: zapAdapter,
  openapi: openApiAdapter,
  "http-probe": httpProbeAdapter,
  authz: authzAdapter,
  "mcp-inspector": mcpInspectorAdapter,
  "agent-config": agentConfigAdapter,
} as const;

export type BuiltinAdapterId = keyof typeof BUILTIN_ADAPTERS;
