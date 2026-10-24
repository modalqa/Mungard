import { SEVERITIES, isUnresolved, sortFindings, type Finding } from "@mungard/findings";
import type { ReportInput } from "./model.js";

const STATUS_LABEL: Record<Finding["status"], string> = {
  new: "New (unverified)",
  needs_review: "Needs review",
  confirmed: "Confirmed",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  fixed: "Fix reported, awaiting retest",
  retested: "Fixed (verified by retest)",
};

/** Escape characters that would break a Markdown table cell. */
function cell(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function location(f: Finding): string {
  const l = f.locations[0];
  if (!l) return "-";
  switch (l.kind) {
    case "file":
      return `${l.path}${l.startLine ? `:${l.startLine}` : ""}`;
    case "endpoint":
      return `${l.method ?? ""} ${l.path ?? l.url ?? ""}`.trim();
    case "package":
      return `${l.packageName}${l.packageVersion ? ` (${l.packageVersion})` : ""}`;
    case "mcp_server":
      return `MCP ${l.serverName} (${l.path})`;
    default:
      return l.path ?? l.url ?? "-";
  }
}

function fence(text: string): string {
  const longest = Math.max(2, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const f = "`".repeat(longest + 1);
  return `${f}\n${text}\n${f}`;
}

export function renderMarkdown(input: ReportInput): string {
  const findings = sortFindings(input.findings);
  const open = findings.filter(isUnresolved);
  const out: string[] = [];
  out.push(`# Mungard Security Report: ${input.project.name}`);
  out.push("");
  out.push(`Generated ${input.generatedAt} by ${input.tool.name} ${input.tool.version}.`);
  out.push("");
  out.push(
    "> Automated security testing reduces risk but cannot prove the absence of vulnerabilities. " +
      "Findings marked *New* or *Needs review* are scanner or AI output that has **not** been verified.",
  );
  out.push("");

  out.push("## Summary");
  out.push("");
  out.push("| Severity | Open | Total |");
  out.push("|---|---:|---:|");
  for (const s of SEVERITIES) {
    out.push(`| ${s} | ${open.filter((f) => f.severity === s).length} | ${findings.filter((f) => f.severity === s).length} |`);
  }
  out.push("");
  const byStatus = Object.entries(STATUS_LABEL)
    .map(([k, label]) => [label, findings.filter((f) => f.status === k).length] as const)
    .filter(([, n]) => n > 0);
  if (byStatus.length) out.push(`Status: ${byStatus.map(([l, n]) => `${l}: ${n}`).join(" · ")}`);
  out.push("");

  out.push("## Scope and targets");
  out.push("");
  out.push(`- Project root: \`${input.project.root}\``);
  out.push(`- Detected frameworks: ${input.project.frameworks.join(", ") || "none detected"}`);
  out.push(`- Allowed hosts: ${input.scope.allowedHosts.join(", ")}`);
  out.push(`- Allowed ports: ${input.scope.allowedPorts.length ? input.scope.allowedPorts.join(", ") : "any on allowed hosts"}`);
  out.push(`- Production testing allowed: ${input.scope.allowProduction ? "yes" : "no"}`);
  const targets = [...new Set(input.runs.flatMap((r) => r.targets))];
  out.push(`- Runtime targets tested: ${targets.length ? targets.join(", ") : "none (static analysis only)"}`);
  out.push("");

  out.push("## Test runs, tools and coverage");
  out.push("");
  for (const run of input.runs) {
    out.push(`### Run \`${run.id}\` (${run.kind})`);
    out.push("");
    out.push(`Started ${run.startedAt}${run.finishedAt ? `, finished ${run.finishedAt}` : ""}. Code version: ${run.codeVersion ?? "unknown (not a git repository)"}.`);
    out.push("");
    out.push("| Engine | Version | Status | Findings | Duration |");
    out.push("|---|---|---|---:|---:|");
    for (const e of run.engines) {
      out.push(`| ${e.engine} | ${e.engineVersion ?? "-"} | ${e.status.toUpperCase()} | ${e.findingCount} | ${(e.durationMs / 1000).toFixed(1)}s |`);
    }
    out.push("");
    const coverage = run.engines.flatMap((e) => e.coverage);
    if (coverage.length) {
      out.push("**What was tested**");
      out.push("");
      for (const c of coverage) out.push(`- ${c}`);
      out.push("");
    }
    const failures = run.engines.filter((e) => e.error);
    if (failures.length) {
      out.push("**Engines that did not complete** (their checks did NOT run)");
      out.push("");
      for (const e of failures) out.push(`- ${e.engine}: ${e.error}`);
      out.push("");
    }
  }

  const gaps = [...new Set(input.runs.flatMap((r) => r.engines.flatMap((e) => e.gaps)))];
  out.push("## Coverage gaps and limitations");
  out.push("");
  if (gaps.length) for (const g of gaps) out.push(`- ${g}`);
  else out.push("- No gaps were reported by the engines that ran.");
  out.push("");

  out.push("## Findings");
  out.push("");
  if (findings.length === 0) {
    out.push("No findings were reported. This only means the checks that ran found nothing; see coverage gaps above.");
    out.push("");
  } else {
    out.push("| ID | Severity | Confidence | Status | Title | Location |");
    out.push("|---|---|---|---|---|---|");
    for (const f of findings) {
      out.push(`| ${f.id} | ${f.severity} | ${f.confidence} | ${STATUS_LABEL[f.status]} | ${cell(f.title)} | ${cell(location(f))} |`);
    }
    out.push("");
    for (const f of findings) {
      out.push(`### ${f.id}: ${f.title}`);
      out.push("");
      out.push(`- **Severity:** ${f.severity} (scanner reported: ${f.sources.map((s) => `${s.engine} ${s.originalSeverity ?? "-"}`).join(", ")})`);
      out.push(`- **Confidence:** ${f.confidence}`);
      out.push(`- **Status:** ${STATUS_LABEL[f.status]}`);
      out.push(`- **Category:** ${f.category}${f.cwe.length ? ` · ${f.cwe.join(", ")}` : ""}`);
      out.push(`- **Detected by:** ${f.sources.map((s) => `${s.engine}${s.ruleId ? ` (${s.ruleId})` : ""}`).join("; ")}`);
      out.push(`- **Locations:** ${f.locations.map((l) => cell(location({ ...f, locations: [l] }))).join("; ") || "-"}`);
      out.push(`- **Retest:** ${f.retest.status}${f.retest.codeVersion ? ` at ${f.retest.codeVersion}` : ""}`);
      out.push("");
      out.push(f.description);
      out.push("");
      if (f.impact) {
        out.push(`**Impact.** ${f.impact}`);
        out.push("");
      }
      if (f.evidence.length) {
        out.push("**Evidence**");
        out.push("");
        for (const e of f.evidence) {
          out.push(`- ${e.description}${e.path ? ` (\`${e.path}\`)` : ""}`);
          if (e.excerpt) {
            out.push("");
            out.push(fence(e.excerpt));
          }
        }
        out.push("");
      }
      if (f.reproductionSteps.length) {
        out.push("**Reproduction**");
        out.push("");
        f.reproductionSteps.forEach((s) => out.push(`- ${s}`));
        out.push("");
      }
      if (f.triage) {
        out.push(`**Triage (${f.triage.source}${f.triage.model ? `, ${f.triage.model}` : ""}, advisory only).** ${f.triage.assessment.replace(/_/g, " ")}, priority ${f.triage.priority}. ${f.triage.rationale}`);
        if (f.triage.missingEvidence.length) out.push(`Missing evidence: ${f.triage.missingEvidence.join("; ")}.`);
        if (f.triage.verificationSteps.length) out.push(`Verify by: ${f.triage.verificationSteps.join("; ")}.`);
        out.push("");
      }
      if (f.remediation) {
        out.push("**Remediation**");
        out.push("");
        out.push(f.remediation);
        out.push("");
      }
    }
  }

  const unverified = findings.filter((f) => f.status === "new" || f.status === "needs_review");
  out.push("## Unverified findings");
  out.push("");
  out.push(unverified.length ? `${unverified.length} finding(s) have not been verified: ${unverified.map((f) => f.id).join(", ")}.` : "None.");
  out.push("");

  out.push("## Retest results");
  out.push("");
  if (input.retests.length === 0) out.push("No retests have been run.");
  else {
    out.push("| Finding | Before | Result | Code version | Run |");
    out.push("|---|---|---|---|---|");
    for (const r of input.retests) out.push(`| ${r.findingId} ${cell(r.title)} | ${r.before} | ${r.after.toUpperCase()} | ${r.codeVersion ?? "-"} | ${r.runId} |`);
  }
  out.push("");
  return out.join("\n");
}
