/** Shapes returned by the API routes (redacted copies of @mungard/core records). */

export interface Meta {
  name: string;
  root: string;
  version: string;
  mode: "ai" | "offline";
  model?: string;
  aiEnabledInConfig: boolean;
  credentialsAvailable: boolean;
  sendSourceCode: string;
  pendingApprovals: number;
}

export interface FindingLocation {
  kind: string;
  path?: string;
  startLine?: number;
  endLine?: number;
  method?: string;
  url?: string;
  packageName?: string;
  packageVersion?: string;
  serverName?: string;
}

export interface FindingSummary {
  id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  engines: string[];
  location?: FindingLocation;
  retest: string;
  triage?: { assessment: string; priority: string; source: string };
  lastSeen: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  sources: { engine: string; engineVersion?: string; ruleId?: string; runId: string; originalSeverity?: string }[];
  locations: FindingLocation[];
  evidence: { id: string; kind: string; description: string; path?: string; excerpt?: string }[];
  reproductionSteps: string[];
  impact: string;
  remediation: string;
  references: string[];
  cwe: string[];
  triage?: {
    source: string;
    model?: string;
    assessment: string;
    priority: string;
    rationale: string;
    supportingEvidence: string[];
    missingEvidence: string[];
    verificationSteps: string[];
    suggestedStatus?: string;
    at: string;
  };
  retest: { status: string; runId?: string; codeVersion?: string; at?: string; notes?: string };
  history: { from: string; to: string; actor: string; reason: string; at: string }[];
  firstSeen: string;
  lastSeen: string;
}

export interface Approval {
  id: string;
  operation: string;
  summary: string;
  target?: string;
  params: Record<string, unknown>;
  requestedBy: string;
  requestedAt: string;
  expiresAt: string;
  status: string;
  decidedBy?: string;
  decidedAt?: string;
  decisionNote?: string;
}

export interface EngineRun {
  engine: string;
  engineVersion?: string;
  status: "succeeded" | "partial" | "failed" | "unavailable" | "skipped";
  coverage: string[];
  gaps: string[];
  error?: string;
  findingCount: number;
  durationMs: number;
}

export interface Run {
  id: string;
  kind: string;
  status: string;
  actor: string;
  startedAt: string;
  finishedAt?: string;
  codeVersion?: string;
  targets: string[];
  steps: string[];
  engines: EngineRun[];
  findingIds: string[];
  blocked: { step: string; decision: string; reasons: string[]; approvalId?: string }[];
  error?: string;
}

export type ChatEvent =
  | { type: "session"; id: string; mode: "ai" | "offline"; model?: string }
  | { type: "text"; delta: string }
  | { type: "tool_call"; id: string; name: string; input: unknown }
  | { type: "tool_result"; id: string; name: string; isError: boolean; content: string }
  | { type: "notice"; message: string }
  | { type: "done" }
  | { type: "error"; message: string };
