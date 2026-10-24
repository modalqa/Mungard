import { SPEC_PROBE_ID } from "@mungard/adapters";
import type { Finding, FindingLocation } from "@mungard/findings";
import type { AuditActor } from "@mungard/policy-engine";
import type { RetestComparison } from "@mungard/reporting";
import { runAssessment, type RunEvent, type StepId, type StepOptions } from "./orchestrator.js";
import type { Workspace } from "./workspace.js";

const ENGINE_STEP: Record<string, StepId> = {
  semgrep: "sast",
  gitleaks: "secrets",
  "npm-audit": "deps",
  zap: "web",
  openapi: "api",
  "http-probe": "headers",
  authz: "authz",
  "mcp-inspector": "mcp",
  "agent-config": "agent",
};

function primaryKey(l: FindingLocation | undefined): string {
  if (!l) return "";
  return l.kind === "endpoint" ? `${l.method ?? ""} ${l.path ?? l.url ?? ""}` : (l.path ?? l.packageName ?? l.serverName ?? l.url ?? "");
}

/**
 * A finding is still present when the retest reports the same fingerprint,
 * or the same rule at the same file/endpoint/package (a rewritten line that
 * still matches the rule must not count as fixed).
 */
export function stillPresent(original: Finding, after: Finding[]): boolean {
  const rules = new Set(original.sources.map((s) => s.ruleId).filter(Boolean));
  const key = primaryKey(original.locations[0]);
  return after.some(
    (f) =>
      f.fingerprint === original.fingerprint ||
      (f.sources.some((s) => s.ruleId && rules.has(s.ruleId)) && primaryKey(f.locations[0]) === key),
  );
}

export interface RetestResult {
  runId: string;
  codeVersion?: string;
  comparisons: RetestComparison[];
  blocked: { step: string; reasons: string[]; approvalId?: string }[];
}

/**
 * Re-run only the engines that produced the selected findings, then compare
 * before/after (FR-13). A finding becomes `retested` (closed) only when its
 * engine completed successfully AND the finding is gone.
 */
export async function runRetest(
  ws: Workspace,
  findingIds: string[],
  opts: { actor: AuditActor; onEvent?: (e: RunEvent) => void; signal?: AbortSignal; webMode?: "passive" | "active" },
): Promise<RetestResult> {
  const all = await ws.loadFindings();
  const selected = findingIds.map((id) => {
    const f = all.find((x) => x.id === id);
    if (!f) throw new Error(`Finding ${id} not found.`);
    return f;
  });
  const steps = [...new Set(selected.flatMap((f) => f.sources.map((s) => ENGINE_STEP[s.engine]).filter((s): s is StepId => !!s)))];
  const options: StepOptions = { webMode: opts.webMode };
  // Narrow authz reruns to the checks that produced these findings; the
  // anonymous spec probe is its own selectable check.
  const authzIds = selected.flatMap((f) =>
    f.sources
      .map((s) => (s.ruleId === "mungard.authn.spec-mismatch" ? SPEC_PROBE_ID : s.ruleId?.match(/^mungard\.(?:authz|scenario)\.(.+)$/)?.[1]))
      .filter((x): x is string => !!x),
  );
  if (authzIds.length) options.authzOnly = [...new Set(authzIds)];
  if (selected.some((f) => f.sources.some((s) => s.engine === "mcp-inspector") && f.sources.some((s) => /tool-(poisoning|shadowing|changed)/.test(s.ruleId ?? "")))) {
    options.mcpLive = true;
  }

  const outcome = await runAssessment(ws, { kind: "retest", steps, options, actor: opts.actor, onEvent: opts.onEvent, signal: opts.signal });
  const engineStatus = new Map(outcome.run.engines.map((e) => [e.engine, e.status]));
  const comparisons: RetestComparison[] = [];
  const now = new Date().toISOString();
  const runFindings = outcome.findings;

  const authzData = outcome.results.authz?.data as
    | { results?: { check?: string; scenario?: string; verdict?: string }[]; inventory?: { endpoints: { method: string; path: string; testStatus: string }[] } }
    | undefined;

  /** For runtime checks, "not detected" only counts when the producing check actually ran and passed. */
  const recheckedCleanly = (f: Finding): boolean => {
    if (!f.sources.some((s) => s.engine === "authz")) return true;
    return f.sources.every((s) => {
      if (s.engine !== "authz") return true;
      if (s.ruleId === "mungard.authn.spec-mismatch") {
        const loc = f.locations[0];
        return !!authzData?.inventory?.endpoints.some((e) => e.method === loc?.method && e.path === loc?.path && e.testStatus === "tested");
      }
      const id = s.ruleId?.match(/^mungard\.(?:authz|scenario)\.(.+)$/)?.[1];
      const verdicts = (authzData?.results ?? []).filter((r) => r.check === id || r.scenario === id).map((r) => r.verdict);
      return verdicts.length > 0 && verdicts.every((v) => v === "pass");
    });
  };

  for (const f of selected) {
    const engines = f.sources.map((s) => s.engine);
    const completed = engines.some((e) => engineStatus.get(e) === "succeeded");
    let after: RetestComparison["after"];
    if (!completed) after = "inconclusive";
    else if (stillPresent(f, runFindings)) after = "failed";
    else after = recheckedCleanly(f) ? "passed" : "inconclusive";
    comparisons.push({ findingId: f.id, title: f.title, before: f.status, after, runId: outcome.run.id, codeVersion: outcome.run.codeVersion, at: now });
  }

  await ws.updateFindings((findings) => {
    for (const c of comparisons) {
      const idx = findings.findIndex((x) => x.id === c.findingId);
      if (idx < 0) continue;
      const f = findings[idx]!;
      const retest = { status: c.after, runId: c.runId, codeVersion: c.codeVersion, at: c.at };
      let next: Finding = { ...f, retest };
      if (c.after === "passed" && f.status !== "false_positive" && f.status !== "accepted_risk") {
        next = { ...next, status: "retested", history: [...f.history, { from: f.status, to: "retested", actor: "tool", reason: `Retest ${c.runId} no longer detects the issue at ${c.codeVersion ?? "current code"}.`, at: now }] };
      } else if (c.after === "failed" && (f.status === "fixed" || f.status === "retested")) {
        // A reported fix that did not hold stays unresolved.
        next = { ...next, status: "needs_review", history: [...f.history, { from: f.status, to: "needs_review", actor: "tool", reason: `Retest ${c.runId} still detects the issue.`, at: now }] };
      }
      findings[idx] = next;
    }
    return { findings, result: undefined };
  });
  await ws.addRetests(comparisons);
  return {
    runId: outcome.run.id,
    codeVersion: outcome.run.codeVersion,
    comparisons,
    blocked: outcome.run.blocked.map((b) => ({ step: b.step, reasons: b.reasons, approvalId: b.approvalId })),
  };
}
