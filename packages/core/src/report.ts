import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { redactDeep } from "@mungard/policy-engine";
import { renderJson, renderMarkdown, renderSarif, type ReportInput } from "@mungard/reporting";
import { detectProject } from "./detect.js";
import { MUNGARD_VERSION } from "./version.js";
import type { Workspace } from "./workspace.js";

export type ReportFormat = "md" | "json" | "sarif";

export async function buildReportInput(ws: Workspace, opts: { runIds?: string[]; maxRuns?: number } = {}): Promise<ReportInput> {
  const runs = (await ws.listRuns(opts.maxRuns ?? 20)).filter((r) => !opts.runIds || opts.runIds.includes(r.id));
  const det = await detectProject(ws.root);
  const input: ReportInput = {
    tool: { name: "Mungard", version: MUNGARD_VERSION },
    project: { name: ws.config.project.name !== "project" ? ws.config.project.name : det.name, root: ws.root, frameworks: det.frameworks },
    generatedAt: new Date().toISOString(),
    scope: {
      allowedHosts: ws.config.policy.targets.allowedHosts,
      allowedPorts: ws.config.policy.targets.allowedPorts,
      allowProduction: ws.config.policy.targets.allowProduction,
    },
    runs: runs.map((r) => ({ id: r.id, kind: r.kind, startedAt: r.startedAt, finishedAt: r.finishedAt, codeVersion: r.codeVersion, targets: r.targets, engines: r.engines })),
    findings: await ws.loadFindings(),
    retests: await ws.loadRetests(),
  };
  // Defense in depth: everything that leaves the workspace is redacted again (SR-02).
  return redactDeep(input, ws.redact);
}

export function renderReport(input: ReportInput, format: ReportFormat): string {
  if (format === "json") return renderJson(input);
  if (format === "sarif") return renderSarif(input);
  return renderMarkdown(input);
}

export async function writeReport(ws: Workspace, format: ReportFormat, outFile?: string, actor: "cli" | "mcp" | "chat" | "web" = "cli"): Promise<{ file: string; content: string }> {
  const content = renderReport(await buildReportInput(ws), format);
  const ext = format === "md" ? "md" : format === "sarif" ? "sarif" : "json";
  const file = outFile ? path.resolve(ws.root, outFile) : path.join(ws.dir, "reports", `mungard-report-${new Date().toISOString().replace(/[:.]/g, "-")}.${ext}`);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, content, { mode: 0o600 });
  await ws.audit.write({ actor, event: "report_generated", details: { format, file: path.relative(ws.root, file) } });
  return { file, content };
}
