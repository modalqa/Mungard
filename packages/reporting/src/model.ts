import type { Finding } from "@mungard/findings";

export interface EngineRunSummary {
  engine: string;
  engineVersion?: string;
  status: "succeeded" | "partial" | "failed" | "unavailable" | "skipped";
  coverage: string[];
  gaps: string[];
  error?: string;
  findingCount: number;
  durationMs: number;
}

export interface RunSummary {
  id: string;
  kind: string;
  startedAt: string;
  finishedAt?: string;
  codeVersion?: string;
  targets: string[];
  engines: EngineRunSummary[];
}

export interface RetestComparison {
  findingId: string;
  title: string;
  before: string;
  after: "passed" | "failed" | "inconclusive";
  runId: string;
  codeVersion?: string;
  at: string;
}

export interface ReportInput {
  tool: { name: string; version: string };
  project: { name: string; root: string; frameworks: string[] };
  generatedAt: string;
  scope: { allowedHosts: string[]; allowedPorts: number[]; allowProduction: boolean };
  runs: RunSummary[];
  findings: Finding[];
  retests: RetestComparison[];
}
