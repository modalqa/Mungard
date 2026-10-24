import { z } from "zod";

/**
 * Version of the normalized finding schema. Bump on any breaking change to
 * the shape below so stored workspaces and exported reports stay readable.
 */
export const FINDING_SCHEMA_VERSION = "1.0.0";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const Severity = z.enum(SEVERITIES);
export type Severity = z.infer<typeof Severity>;

/** How sure we are that the finding is real, independent of its severity. */
export const Confidence = z.enum(["high", "medium", "low"]);
export type Confidence = z.infer<typeof Confidence>;

/**
 * Finding lifecycle (PRD FR-11).
 *
 * - new            produced by an engine, nobody looked at it yet
 * - needs_review   requires a human or further verification
 * - confirmed      verified with sufficient evidence (never set by AI)
 * - false_positive dismissed by a human
 * - accepted_risk  acknowledged by a human, not going to be fixed now
 * - fixed          developer reports a fix; still UNRESOLVED until retested
 * - retested       a retest ran and verified the fix (closed)
 */
export const FINDING_STATUSES = [
  "new",
  "needs_review",
  "confirmed",
  "false_positive",
  "accepted_risk",
  "fixed",
  "retested",
] as const;
export const FindingStatus = z.enum(FINDING_STATUSES);
export type FindingStatus = z.infer<typeof FindingStatus>;

export const FindingCategory = z.enum([
  "sast",
  "secret",
  "dependency",
  "dast",
  "api",
  "authn",
  "authz",
  "business_logic",
  "headers",
  "mcp",
  "agent_config",
  "config",
]);
export type FindingCategory = z.infer<typeof FindingCategory>;

/** Where the finding lives: a file, an endpoint, a package, or an MCP server. */
export const FindingLocation = z.object({
  kind: z.enum(["file", "endpoint", "package", "mcp_server", "url", "config"]),
  path: z.string().optional(),
  startLine: z.number().int().positive().optional(),
  endLine: z.number().int().positive().optional(),
  method: z.string().optional(),
  url: z.string().optional(),
  packageName: z.string().optional(),
  packageVersion: z.string().optional(),
  serverName: z.string().optional(),
});
export type FindingLocation = z.infer<typeof FindingLocation>;

export const EvidenceRef = z.object({
  id: z.string(),
  kind: z.enum(["scanner_output", "code_snippet", "http_exchange", "config_excerpt", "note"]),
  description: z.string(),
  /** Path relative to the workspace directory, e.g. runs/<id>/evidence/<file>.json */
  path: z.string().optional(),
  /** Short, already-redacted inline excerpt. */
  excerpt: z.string().optional(),
});
export type EvidenceRef = z.infer<typeof EvidenceRef>;

export const DetectionSource = z.object({
  engine: z.string(),
  engineVersion: z.string().optional(),
  ruleId: z.string().optional(),
  runId: z.string(),
  /** Severity exactly as reported by the engine, kept as source data (FR-12). */
  originalSeverity: z.string().optional(),
});
export type DetectionSource = z.infer<typeof DetectionSource>;

export const Actor = z.enum(["human", "tool", "ai"]);
export type Actor = z.infer<typeof Actor>;

export const StatusChange = z.object({
  from: FindingStatus,
  to: FindingStatus,
  actor: Actor,
  reason: z.string(),
  at: z.string(),
});
export type StatusChange = z.infer<typeof StatusChange>;

/** Output of triage. Advisory only: it never changes the finding status. */
export const Triage = z.object({
  source: z.enum(["heuristic", "ai"]),
  model: z.string().optional(),
  assessment: z.enum(["likely_true_positive", "likely_false_positive", "uncertain"]),
  priority: z.enum(["p0", "p1", "p2", "p3"]),
  rationale: z.string(),
  supportingEvidence: z.array(z.string()).default([]),
  missingEvidence: z.array(z.string()).default([]),
  verificationSteps: z.array(z.string()).default([]),
  suggestedStatus: FindingStatus.optional(),
  at: z.string(),
});
export type Triage = z.infer<typeof Triage>;

export const RetestRecord = z.object({
  status: z.enum(["not_retested", "passed", "failed", "inconclusive"]),
  runId: z.string().optional(),
  /** Code version that was tested: git commit or a content hash. */
  codeVersion: z.string().optional(),
  at: z.string().optional(),
  notes: z.string().optional(),
});
export type RetestRecord = z.infer<typeof RetestRecord>;

export const Finding = z.object({
  schemaVersion: z.literal(FINDING_SCHEMA_VERSION),
  id: z.string(),
  /** Stable hash used for deduplication and before/after comparison. */
  fingerprint: z.string(),
  title: z.string(),
  description: z.string(),
  category: FindingCategory,
  severity: Severity,
  confidence: Confidence,
  status: FindingStatus,
  /** All engines/runs that reported this finding (merged duplicates keep every source). */
  sources: z.array(DetectionSource).min(1),
  locations: z.array(FindingLocation).default([]),
  evidence: z.array(EvidenceRef).default([]),
  reproductionSteps: z.array(z.string()).default([]),
  impact: z.string().default(""),
  remediation: z.string().default(""),
  references: z.array(z.string()).default([]),
  cwe: z.array(z.string()).default([]),
  triage: Triage.optional(),
  retest: RetestRecord.default({ status: "not_retested" }),
  history: z.array(StatusChange).default([]),
  firstSeen: z.string(),
  lastSeen: z.string(),
});
export type Finding = z.infer<typeof Finding>;

/** What an adapter produces before the store assigns ids, status and history. */
export const RawFinding = z.object({
  title: z.string(),
  description: z.string(),
  category: FindingCategory,
  severity: Severity,
  confidence: Confidence,
  ruleId: z.string().optional(),
  originalSeverity: z.string().optional(),
  locations: z.array(FindingLocation).default([]),
  evidence: z.array(EvidenceRef.omit({ id: true })).default([]),
  reproductionSteps: z.array(z.string()).default([]),
  impact: z.string().default(""),
  remediation: z.string().default(""),
  references: z.array(z.string()).default([]),
  cwe: z.array(z.string()).default([]),
  /**
   * Set only by deterministic verification engines when a user-defined
   * expectation was violated and evidence was captured. Never set by AI.
   */
  verified: z.boolean().default(false),
  /** Optional extra key material for the fingerprint (e.g. a secret's hash). */
  fingerprintHint: z.string().optional(),
});
export type RawFinding = z.input<typeof RawFinding>;
export type ParsedRawFinding = z.output<typeof RawFinding>;

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function severityAtLeast(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];
}

/** Statuses that still need action. `fixed` stays unresolved until a retest passes (FR-13). */
export const UNRESOLVED_STATUSES: readonly FindingStatus[] = ["new", "needs_review", "confirmed", "fixed"];

export function isUnresolved(finding: Pick<Finding, "status">): boolean {
  return UNRESOLVED_STATUSES.includes(finding.status);
}
