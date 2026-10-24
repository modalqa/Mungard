import type { Finding, Severity } from "@mungard/findings";
import type { ReportInput } from "./model.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** GitHub code scanning uses this numeric property to rank results. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "0.0" };

/**
 * SARIF 2.1.0 export (FR-14). Only file-located findings get physical
 * locations; endpoint/MCP findings carry logical locations so code-scanning
 * tools still show them.
 */
export function renderSarif(input: ReportInput, opts: { includeResolved?: boolean } = {}): string {
  const findings = input.findings.filter(
    (f) => opts.includeResolved || !["false_positive", "retested", "accepted_risk"].includes(f.status),
  );
  const rules = new Map<string, { id: string; name: string; short: string; help: string; severity: Severity; cwe: string[] }>();
  for (const f of findings) {
    const id = f.sources[0]?.ruleId ?? `mungard.${f.category}`;
    if (!rules.has(id)) rules.set(id, { id, name: id, short: f.title, help: f.remediation || f.description, severity: f.severity, cwe: f.cwe });
  }
  const result = (f: Finding) => {
    const fileLocs = f.locations.filter((l) => l.kind === "file" && l.path);
    return {
      ruleId: f.sources[0]?.ruleId ?? `mungard.${f.category}`,
      level: LEVEL[f.severity],
      message: { text: `${f.title}\n\n${f.description}`.slice(0, 4000) },
      partialFingerprints: { mungardFingerprint: f.fingerprint },
      locations: fileLocs.length
        ? fileLocs.map((l) => ({
            physicalLocation: {
              artifactLocation: { uri: l.path!.split("\\").join("/"), uriBaseId: "%SRCROOT%" },
              ...(l.startLine ? { region: { startLine: l.startLine, ...(l.endLine ? { endLine: l.endLine } : {}) } } : {}),
            },
          }))
        : [
            {
              logicalLocations: f.locations.map((l) => ({
                name: l.kind === "endpoint" ? `${l.method ?? ""} ${l.path ?? l.url ?? ""}`.trim() : l.serverName ?? l.packageName ?? l.path ?? l.url ?? "unknown",
                kind: l.kind === "endpoint" ? "function" : "resource",
              })),
            },
          ],
      properties: {
        mungardId: f.id,
        status: f.status,
        confidence: f.confidence,
        category: f.category,
        "security-severity": SECURITY_SEVERITY[f.severity],
        engines: f.sources.map((s) => s.engine),
      },
    };
  };
  // %SRCROOT% is resolved by the consumer (e.g. GitHub uses the checkout root).
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Mungard",
            version: input.tool.version,
            rules: [...rules.values()].map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.short.slice(0, 200) },
              help: { text: r.help.slice(0, 2000) },
              defaultConfiguration: { level: LEVEL[r.severity] },
              properties: { tags: ["security", ...r.cwe], "security-severity": SECURITY_SEVERITY[r.severity] },
            })),
          },
        },
        results: findings.map(result),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
