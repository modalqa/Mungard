import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Confidence, RawFinding, Severity } from "@mungard/findings";
import { z } from "zod";
import { dockerAvailable, dockerBaseArgs, findExecutable, probeVersion, runCommand } from "./exec.js";
import { MUNGARD_SEMGREP_RULES } from "./semgrep-rules.js";
import { type AdapterResult, type HealthStatus, type SecurityAdapter, emptyResult } from "./types.js";
import { readLine, readSnippet, writeEvidence } from "./util.js";

export const SEMGREP_IMAGE = "semgrep/semgrep:latest";

export const SemgrepInput = z.object({
  /** Semgrep Registry packs to add to the bundled Mungard rules, e.g. "p/default". */
  registryRules: z.array(z.string().regex(/^(p|r)\/[a-zA-Z0-9._/-]+$/)).default([]),
  /** Additional local rule files, relative to the project root. */
  localRules: z.array(z.string()).default([]),
  exclude: z.array(z.string()).default([]),
});
export type SemgrepInput = z.input<typeof SemgrepInput>;

const DEFAULT_EXCLUDES = ["node_modules", ".next", "dist", "build", "coverage", ".mungard", ".git", "vendor", "*.min.js"];

const SemgrepResult = z.object({
  check_id: z.string(),
  path: z.string(),
  start: z.object({ line: z.number() }),
  end: z.object({ line: z.number() }),
  extra: z.object({
    message: z.string(),
    severity: z.string(),
    metadata: z.record(z.string(), z.unknown()).default({}),
  }),
});
const SemgrepOutput = z.object({
  version: z.string().optional(),
  results: z.array(z.unknown()).default([]),
  errors: z.array(z.unknown()).default([]),
});

function mapSeverity(s: string): Severity {
  switch (s.toUpperCase()) {
    case "ERROR":
    case "HIGH":
    case "CRITICAL":
      return "high";
    case "WARNING":
    case "MEDIUM":
      return "medium";
    case "INFO":
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

function mapConfidence(meta: Record<string, unknown>): Confidence {
  const c = String(meta.confidence ?? "").toUpperCase();
  if (c === "HIGH") return "high";
  if (c === "LOW") return "low";
  return "medium";
}

function asStringArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === "string") return [v];
  return [];
}

async function resolveRunner(): Promise<{ via: "local" | "docker"; bin: string } | undefined> {
  const local = await findExecutable("semgrep");
  if (local) return { via: "local", bin: local };
  if (await dockerAvailable()) {
    const docker = await findExecutable("docker");
    if (docker) return { via: "docker", bin: docker };
  }
  return undefined;
}

export const semgrepAdapter: SecurityAdapter<SemgrepInput> = {
  id: "semgrep",
  name: "Semgrep (static analysis)",
  operation: "static_scan",
  inputSchema: SemgrepInput,

  async healthCheck(): Promise<HealthStatus> {
    const runner = await resolveRunner();
    if (!runner) {
      return {
        engine: "semgrep",
        available: false,
        detail: "Semgrep is not installed and Docker is not available.",
        remedy: "Install Semgrep (`brew install semgrep` or `pipx install semgrep`) or start Docker to use the semgrep/semgrep image.",
      };
    }
    if (runner.via === "local") {
      const version = await probeVersion(runner.bin);
      return { engine: "semgrep", available: true, version, via: "local", detail: `Local binary ${runner.bin}` };
    }
    return { engine: "semgrep", available: true, via: "docker", detail: `Docker image ${SEMGREP_IMAGE} (pulled on first use)` };
  },

  async run(rawInput, ctx): Promise<AdapterResult> {
    const started = Date.now();
    const input = SemgrepInput.parse(rawInput);
    const runner = await resolveRunner();
    if (!runner) {
      return emptyResult("semgrep", "unavailable", {
        error: "Semgrep is not installed and Docker is not available. Static analysis did NOT run.",
        gaps: ["Static analysis (SAST) was not performed."],
      });
    }
    const tmp = await mkdtemp(path.join(os.tmpdir(), "mungard-semgrep-"));
    const rulesFile = path.join(tmp, "mungard-rules.yml");
    await writeFile(rulesFile, MUNGARD_SEMGREP_RULES, { mode: 0o600 });
    const excludes = [...DEFAULT_EXCLUDES, ...input.exclude];
    const common = [
      "scan",
      "--json",
      "--metrics=off",
      "--disable-version-check",
      "--timeout",
      "30",
      "--max-target-bytes",
      String(ctx.policy.limits.maxFileSizeBytes),
      ...excludes.flatMap((e) => ["--exclude", e]),
      ...input.registryRules.flatMap((r) => ["--config", r]),
    ];
    let args: string[];
    let cwd: string | undefined = ctx.projectRoot;
    if (runner.via === "local") {
      args = [...common, "--config", rulesFile, ...input.localRules.flatMap((r) => ["--config", r]), "."];
    } else {
      cwd = undefined;
      args = [
        ...dockerBaseArgs({ network: input.registryRules.length ? undefined : "none" }),
        "-v",
        `${ctx.projectRoot}:/src:ro`,
        "-v",
        `${tmp}:/mungard-rules:ro`,
        "-w",
        "/src",
        SEMGREP_IMAGE,
        "semgrep",
        ...common,
        "--config",
        "/mungard-rules/mungard-rules.yml",
        ...input.localRules.flatMap((r) => ["--config", r]),
        ".",
      ];
    }
    ctx.log(`semgrep: running via ${runner.via}${input.registryRules.length ? ` with registry rules ${input.registryRules.join(", ")}` : " with bundled rules only"}`);
    try {
      const res = await runCommand(runner.bin, args, {
        cwd,
        timeoutMs: ctx.policy.limits.toolTimeoutSeconds * 1000,
        maxOutputBytes: ctx.policy.limits.maxOutputBytes,
        signal: ctx.signal,
        env: { SEMGREP_SEND_METRICS: "off" },
      });
      if (res.timedOut) {
        return emptyResult("semgrep", "failed", {
          error: `Semgrep timed out after ${ctx.policy.limits.toolTimeoutSeconds}s.`,
          gaps: ["Static analysis did not complete."],
          durationMs: Date.now() - started,
        });
      }
      let parsed: z.infer<typeof SemgrepOutput>;
      try {
        parsed = SemgrepOutput.parse(JSON.parse(res.stdout));
      } catch {
        return emptyResult("semgrep", "failed", {
          error: `Semgrep exited with code ${res.exitCode} and produced no JSON output: ${ctx.redact(res.stderr.slice(-800))}`,
          gaps: ["Static analysis did not complete."],
          durationMs: Date.now() - started,
        });
      }
      const rawOutputPath = await writeEvidence(ctx, "semgrep-output.json", parsed);
      const findings: RawFinding[] = [];
      for (const item of parsed.results) {
        const r = SemgrepResult.safeParse(item);
        if (!r.success) continue;
        const res = r.data;
        const meta = res.extra.metadata;
        const relPath = res.path.replace(/^\.\//, "");
        const snippet = await readSnippet(path.join(ctx.projectRoot, relPath), res.start.line, ctx.redact, {
          maxFileSizeBytes: ctx.policy.limits.maxFileSizeBytes,
        });
        // Line content (not line number) keeps the fingerprint stable when code above moves.
        const lineText = await readLine(path.join(ctx.projectRoot, relPath), res.start.line, ctx.policy.limits.maxFileSizeBytes);
        const ruleShort = res.check_id.split(".").slice(-1)[0] ?? res.check_id;
        findings.push({
          title: `${ruleShort.charAt(0).toUpperCase()}${ruleShort.slice(1).replace(/[-_]/g, " ")} in ${relPath}`,
          description: res.extra.message,
          category: "sast",
          severity: mapSeverity(res.extra.severity),
          originalSeverity: res.extra.severity,
          confidence: mapConfidence(meta),
          ruleId: res.check_id,
          locations: [{ kind: "file", path: relPath, startLine: res.start.line, endLine: res.end.line }],
          evidence: [
            { kind: "scanner_output", description: `Semgrep rule ${res.check_id}`, path: rawOutputPath },
            ...(snippet ? [{ kind: "code_snippet" as const, description: `${relPath}:${res.start.line}`, excerpt: snippet }] : []),
          ],
          reproductionSteps: [`Run \`mungard scan --only sast\` or \`semgrep --config <rule> ${relPath}\` and inspect line ${res.start.line}.`],
          impact: "Depends on whether attacker-controlled data reaches this code path; verify the data flow.",
          remediation: res.extra.message,
          references: asStringArray(meta.references),
          cwe: asStringArray(meta.cwe).map((c) => c.split(":")[0] ?? c),
          fingerprintHint: lineText ?? `${res.start.line}`,
        });
      }
      const errors = parsed.errors.length;
      return {
        engine: "semgrep",
        engineVersion: parsed.version,
        status: errors > 0 ? "partial" : "succeeded",
        findings,
        coverage: [
          `Semgrep static analysis with bundled Mungard JS/TS rules${input.registryRules.length ? ` and ${input.registryRules.join(", ")}` : ""}.`,
        ],
        gaps: [
          ...(errors > 0 ? [`Semgrep reported ${errors} error(s) (unparseable files or rule errors); see ${rawOutputPath}.`] : []),
          ...(input.registryRules.length === 0 ? ["Only bundled rules were used; enable registry packs in config for broader coverage."] : []),
          "Static analysis cannot prove exploitability or find authorization/business-logic flaws on its own.",
        ],
        rawOutputPath,
        durationMs: Date.now() - started,
      };
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  },
};
