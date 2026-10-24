import { SEVERITY_RANK, isUnresolved, sortFindings, type Finding, type Severity } from "@mungard/findings";
import type { RunEvent, RunRecord } from "@mungard/core";

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code: number) => (s: string) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s);
export const c = {
  bold: wrap(1),
  dim: wrap(2),
  red: wrap(31),
  green: wrap(32),
  yellow: wrap(33),
  blue: wrap(34),
  magenta: wrap(35),
  cyan: wrap(36),
};

export const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => c.bold(c.red(s)),
  high: c.red,
  medium: c.yellow,
  low: c.blue,
  info: c.dim,
};

export function log(msg = ""): void {
  process.stdout.write(`${msg}\n`);
}

/** Progress goes to stderr so stdout stays clean for --json / piping. */
export function progress(msg: string): void {
  process.stderr.write(`${msg}\n`);
}

export function printEvent(e: RunEvent): void {
  switch (e.type) {
    case "run_started":
      progress(c.dim(`▶ run ${e.runId}: ${e.steps.join(", ")}`));
      break;
    case "step_started":
      progress(`${c.cyan("●")} ${e.step} ${c.dim(`(${e.engine})`)}`);
      break;
    case "step_finished": {
      const s = e.summary;
      const status =
        s.status === "succeeded" ? c.green("ok") : s.status === "partial" ? c.yellow("partial") : s.status === "skipped" ? c.dim("skipped") : c.red(s.status.toUpperCase());
      progress(`  ${status} ${s.engine}${s.engineVersion ? ` ${s.engineVersion}` : ""}: ${s.findingCount} finding(s) in ${(s.durationMs / 1000).toFixed(1)}s${s.error ? `\n  ${c.red(s.error)}` : ""}`);
      break;
    }
    case "step_blocked":
      progress(`${c.yellow("⏸")} ${e.step} ${c.yellow(e.decision === "deny" ? "DENIED by policy" : "needs approval")}: ${e.reasons.join(" ")}`);
      break;
    case "step_skipped":
      progress(`${c.dim("○")} ${e.step} ${c.dim(`skipped: ${e.reason}`)}`);
      break;
    case "log":
      progress(c.dim(`  ${e.message}`));
      break;
    case "run_finished":
      break;
  }
}

function where(f: Finding): string {
  const l = f.locations[0];
  if (!l) return "";
  if (l.kind === "file") return `${l.path}${l.startLine ? `:${l.startLine}` : ""}`;
  if (l.kind === "endpoint") return `${l.method ?? ""} ${l.path ?? l.url ?? ""}`;
  if (l.kind === "package") return `${l.packageName}`;
  if (l.kind === "mcp_server") return `mcp:${l.serverName} (${l.path})`;
  return l.path ?? l.url ?? "";
}

export function printFindings(findings: Finding[], opts: { limit?: number } = {}): void {
  const sorted = sortFindings(findings);
  if (sorted.length === 0) {
    log(c.green("No findings."));
    return;
  }
  for (const f of sorted.slice(0, opts.limit ?? 100)) {
    const sev = SEV_COLOR[f.severity](f.severity.toUpperCase().padEnd(8));
    const status = f.status === "confirmed" ? c.red("confirmed") : f.status === "retested" ? c.green("fixed✓") : c.dim(f.status);
    log(`${sev} ${c.dim(f.id)} ${f.title}`);
    log(`         ${c.dim(where(f))} ${c.dim("·")} ${f.confidence} confidence ${c.dim("·")} ${status}`);
  }
  if (sorted.length > (opts.limit ?? 100)) log(c.dim(`… ${sorted.length - (opts.limit ?? 100)} more (use --json or a report)`));
}

export function printRunSummary(run: RunRecord, findings: Finding[]): void {
  log("");
  log(c.bold(`Run ${run.id} ${run.status === "completed" ? c.green("completed") : c.red(run.status)}`));
  if (run.codeVersion) log(c.dim(`code version: ${run.codeVersion}`));
  log("");
  printFindings(findings);
  const failed = run.engines.filter((e) => e.status === "failed" || e.status === "unavailable");
  const gaps = [...new Set(run.engines.flatMap((e) => e.gaps))];
  if (failed.length) {
    log("");
    log(c.red(c.bold("Engines that did NOT run (their checks were not performed):")));
    for (const e of failed) log(`  ${c.red("✗")} ${e.engine}: ${e.error ?? e.status}`);
  }
  if (run.blocked.length) {
    log("");
    log(c.yellow(c.bold("Blocked by policy:")));
    for (const b of run.blocked) log(`  ${c.yellow("⏸")} ${b.step}: ${b.reasons.join(" ")}`);
  }
  if (gaps.length) {
    log("");
    log(c.bold("Coverage gaps:"));
    for (const g of gaps.slice(0, 15)) log(`  - ${g}`);
  }
  const unresolved = findings.filter(isUnresolved);
  log("");
  log(
    `${c.bold(String(unresolved.length))} unresolved finding(s) from this run. ${c.dim("Unverified findings (new/needs_review) are scanner output, not confirmed vulnerabilities.")}`,
  );
}

export function exceedsThreshold(findings: Finding[], threshold: Severity | undefined): Finding[] {
  if (!threshold) return [];
  return findings.filter((f) => isUnresolved(f) && SEVERITY_RANK[f.severity] >= SEVERITY_RANK[threshold]);
}
