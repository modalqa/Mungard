import type { RawFinding } from "@mungard/findings";
import type { Operation, Redactor, SecurityPolicy } from "@mungard/policy-engine";
import type { ZodType } from "zod";

export interface AdapterContext {
  /** Absolute path of the project under test. */
  projectRoot: string;
  /** Absolute path of the Mungard workspace directory (`<project>/.mungard`). */
  workspaceDir: string;
  runId: string;
  policy: SecurityPolicy;
  redact: Redactor;
  /** Absolute directory where this run's evidence files are written. */
  evidenceDir: string;
  signal?: AbortSignal;
  log: (message: string) => void;
}

export type AdapterRunStatus = "succeeded" | "partial" | "failed" | "unavailable" | "skipped";

export interface AdapterResult {
  engine: string;
  engineVersion?: string;
  status: AdapterRunStatus;
  findings: RawFinding[];
  /** What was actually checked, in plain language (reported verbatim). */
  coverage: string[];
  /** What was NOT checked and why (coverage gaps, FR-02 / FR-14). */
  gaps: string[];
  error?: string;
  /** Workspace-relative path of the raw engine output, if kept. */
  rawOutputPath?: string;
  durationMs: number;
  /** Adapter-specific structured output, e.g. an endpoint inventory. */
  data?: unknown;
}

export interface HealthStatus {
  engine: string;
  available: boolean;
  version?: string;
  /** How the engine would run: local binary, docker image, or built in. */
  via?: "local" | "docker" | "builtin";
  detail: string;
  /** How to fix it when unavailable. */
  remedy?: string;
}

export interface SecurityAdapter<I = unknown> {
  id: string;
  name: string;
  /** Policy operation this adapter performs. */
  operation: Operation;
  inputSchema: ZodType<I>;
  healthCheck(ctx: Pick<AdapterContext, "projectRoot" | "policy">): Promise<HealthStatus>;
  run(input: I, ctx: AdapterContext): Promise<AdapterResult>;
}

export function emptyResult(engine: string, status: AdapterRunStatus, extra: Partial<AdapterResult> = {}): AdapterResult {
  return { engine, status, findings: [], coverage: [], gaps: [], durationMs: 0, ...extra };
}
