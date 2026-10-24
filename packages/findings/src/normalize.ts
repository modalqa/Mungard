import { createHash } from "node:crypto";
import {
  FINDING_SCHEMA_VERSION,
  RawFinding,
  SEVERITY_RANK,
  type Confidence,
  type Finding,
  type FindingLocation,
  type ParsedRawFinding,
} from "./schema.js";

const CONFIDENCE_RANK: Record<Confidence, number> = { high: 2, medium: 1, low: 0 };

function locationKey(loc: FindingLocation): string {
  switch (loc.kind) {
    case "file":
      // Line numbers shift as code is edited; include them only coarsely so a
      // fix elsewhere in the file does not create a "new" finding.
      return `file:${loc.path ?? ""}`;
    case "endpoint":
      return `endpoint:${(loc.method ?? "").toUpperCase()} ${loc.path ?? loc.url ?? ""}`;
    case "package":
      return `package:${loc.packageName ?? ""}`;
    case "mcp_server":
      return `mcp:${loc.serverName ?? ""}:${loc.path ?? ""}`;
    default:
      return `${loc.kind}:${loc.path ?? loc.url ?? ""}`;
  }
}

/**
 * Stable identity of a finding across runs. Built from the category, rule,
 * locations and an optional hint, so the same issue reported by two runs (or
 * by a retest) maps to the same fingerprint.
 */
export function fingerprint(raw: Pick<ParsedRawFinding, "category" | "ruleId" | "title" | "locations" | "fingerprintHint">): string {
  const parts = [
    raw.category,
    raw.ruleId ?? raw.title,
    ...raw.locations.map(locationKey).sort(),
    raw.fingerprintHint ?? "",
  ];
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 24);
}

export interface NormalizeContext {
  engine: string;
  engineVersion?: string;
  runId: string;
  now?: string;
}

export function normalizeFinding(input: RawFinding, ctx: NormalizeContext): Finding {
  const raw = RawFinding.parse(input);
  const now = ctx.now ?? new Date().toISOString();
  const fp = fingerprint(raw);
  const evidence = raw.evidence.map((e, i) => ({ ...e, id: `${fp.slice(0, 8)}-${ctx.runId.slice(-6)}-${i}` }));
  // Deterministic engines may mark a finding verified when a user-defined
  // expectation failed and evidence exists. Everything else starts as `new`.
  const verified = raw.verified && evidence.length > 0;
  return {
    schemaVersion: FINDING_SCHEMA_VERSION,
    id: `MG-${fp.slice(0, 10).toUpperCase()}`,
    fingerprint: fp,
    title: raw.title,
    description: raw.description,
    category: raw.category,
    severity: raw.severity,
    confidence: raw.confidence,
    status: verified ? "confirmed" : "new",
    sources: [
      {
        engine: ctx.engine,
        engineVersion: ctx.engineVersion,
        ruleId: raw.ruleId,
        runId: ctx.runId,
        originalSeverity: raw.originalSeverity,
      },
    ],
    locations: raw.locations,
    evidence,
    reproductionSteps: raw.reproductionSteps,
    impact: raw.impact,
    remediation: raw.remediation,
    references: raw.references,
    cwe: raw.cwe,
    retest: { status: "not_retested" },
    history: verified
      ? [{ from: "new", to: "confirmed", actor: "tool", reason: `Verified by ${ctx.engine} with captured evidence.`, at: now }]
      : [],
    firstSeen: now,
    lastSeen: now,
  };
}

function uniqueBy<T>(items: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const k = key(item);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Merge two findings with the same fingerprint without losing evidence or
 * detection sources (FR-04). The existing record keeps its id, status,
 * history and triage; severity/confidence take the stronger value.
 */
export function mergeFindings(existing: Finding, incoming: Finding): Finding {
  return {
    ...existing,
    severity: SEVERITY_RANK[incoming.severity] > SEVERITY_RANK[existing.severity] ? incoming.severity : existing.severity,
    confidence:
      CONFIDENCE_RANK[incoming.confidence] > CONFIDENCE_RANK[existing.confidence] ? incoming.confidence : existing.confidence,
    sources: uniqueBy([...existing.sources, ...incoming.sources], (s) => `${s.engine}|${s.ruleId ?? ""}|${s.runId}`),
    locations: uniqueBy([...existing.locations, ...incoming.locations], (l) => JSON.stringify(l)),
    evidence: uniqueBy([...existing.evidence, ...incoming.evidence], (e) => e.id),
    references: [...new Set([...existing.references, ...incoming.references])],
    cwe: [...new Set([...existing.cwe, ...incoming.cwe])],
    reproductionSteps: existing.reproductionSteps.length ? existing.reproductionSteps : incoming.reproductionSteps,
    // A tool-verified incoming finding can confirm an existing `new`/`needs_review` one.
    status:
      incoming.status === "confirmed" && (existing.status === "new" || existing.status === "needs_review")
        ? "confirmed"
        : existing.status,
    history:
      incoming.status === "confirmed" && (existing.status === "new" || existing.status === "needs_review")
        ? [...existing.history, ...incoming.history.map((h) => ({ ...h, from: existing.status }))]
        : existing.history,
    lastSeen: incoming.lastSeen,
  };
}

/** Deduplicate a list of findings by fingerprint. */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const byFp = new Map<string, Finding>();
  for (const f of findings) {
    const prev = byFp.get(f.fingerprint);
    byFp.set(f.fingerprint, prev ? mergeFindings(prev, f) : f);
  }
  return [...byFp.values()];
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence] ||
      a.id.localeCompare(b.id),
  );
}
