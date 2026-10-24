import { FINDING_SCHEMA_VERSION, sortFindings } from "@mungard/findings";
import type { ReportInput } from "./model.js";

export * from "./model.js";
export * from "./markdown.js";
export * from "./sarif.js";

export const REPORT_SCHEMA_VERSION = "1.0.0";

/** Machine-readable report. Findings keep their normalized schema version. */
export function renderJson(input: ReportInput): string {
  return JSON.stringify(
    {
      reportSchemaVersion: REPORT_SCHEMA_VERSION,
      findingSchemaVersion: FINDING_SCHEMA_VERSION,
      ...input,
      findings: sortFindings(input.findings),
    },
    null,
    2,
  );
}
