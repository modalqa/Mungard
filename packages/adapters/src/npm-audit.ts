import { access } from "node:fs/promises";
import path from "node:path";
import type { RawFinding, Severity } from "@mungard/findings";
import { z } from "zod";
import { findExecutable, probeVersion, runCommand } from "./exec.js";
import { type AdapterResult, type HealthStatus, type SecurityAdapter, emptyResult } from "./types.js";
import { writeEvidence } from "./util.js";

export const NpmAuditInput = z.object({
  /** Skip devDependencies (they usually do not ship to production). */
  omitDev: z.boolean().default(false),
});
export type NpmAuditInput = z.input<typeof NpmAuditInput>;

const Via = z.union([
  z.string(),
  z.object({
    source: z.union([z.number(), z.string()]).optional(),
    name: z.string(),
    title: z.string().default(""),
    url: z.string().default(""),
    severity: z.string().default("moderate"),
    cwe: z.array(z.string()).default([]),
    range: z.string().default(""),
  }),
]);
const Vulnerability = z.object({
  name: z.string(),
  severity: z.string(),
  isDirect: z.boolean().default(false),
  via: z.array(Via).default([]),
  range: z.string().default(""),
  fixAvailable: z.union([z.boolean(), z.object({ name: z.string(), version: z.string(), isSemVerMajor: z.boolean().default(false) })]).default(false),
});
const AuditReport = z.object({
  auditReportVersion: z.number().optional(),
  vulnerabilities: z.record(z.string(), z.unknown()).default({}),
});

function mapSeverity(s: string): Severity {
  switch (s) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

async function exists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

export const npmAuditAdapter: SecurityAdapter<NpmAuditInput> = {
  id: "npm-audit",
  name: "npm audit (dependency vulnerabilities)",
  operation: "dependency_audit",
  inputSchema: NpmAuditInput,

  async healthCheck(): Promise<HealthStatus> {
    const npm = await findExecutable("npm");
    if (!npm) return { engine: "npm-audit", available: false, detail: "npm is not on PATH.", remedy: "Install Node.js 22+ which ships npm." };
    return { engine: "npm-audit", available: true, via: "local", version: await probeVersion(npm), detail: npm };
  },

  async run(rawInput, ctx): Promise<AdapterResult> {
    const started = Date.now();
    const input = NpmAuditInput.parse(rawInput);
    if (!(await exists(path.join(ctx.projectRoot, "package.json")))) {
      return emptyResult("npm-audit", "skipped", { gaps: ["No package.json found; npm dependency audit not applicable."] });
    }
    const hasLock = await exists(path.join(ctx.projectRoot, "package-lock.json"));
    if (!hasLock) {
      const other = (await exists(path.join(ctx.projectRoot, "pnpm-lock.yaml")))
        ? "pnpm-lock.yaml (run `pnpm audit`)"
        : (await exists(path.join(ctx.projectRoot, "yarn.lock")))
          ? "yarn.lock (run `yarn npm audit`)"
          : undefined;
      return emptyResult("npm-audit", "skipped", {
        gaps: [
          other
            ? `Found ${other}; Mungard's npm audit adapter needs package-lock.json. Dependency audit did NOT run.`
            : "No package-lock.json found. Run `npm install --package-lock-only` to create one; dependency audit did NOT run.",
        ],
      });
    }
    const npm = await findExecutable("npm");
    if (!npm) return emptyResult("npm-audit", "unavailable", { error: "npm is not on PATH. Dependency audit did NOT run." });
    const version = await probeVersion(npm);
    ctx.log("npm audit: checking package-lock.json against the npm advisory database");
    const res = await runCommand(npm, ["audit", "--json", "--package-lock-only", ...(input.omitDev ? ["--omit=dev"] : [])], {
      cwd: ctx.projectRoot,
      timeoutMs: ctx.policy.limits.toolTimeoutSeconds * 1000,
      maxOutputBytes: ctx.policy.limits.maxOutputBytes,
      signal: ctx.signal,
      env: { npm_config_update_notifier: "false", npm_config_fund: "false" },
    });
    let report: z.infer<typeof AuditReport>;
    try {
      report = AuditReport.parse(JSON.parse(res.stdout));
    } catch {
      return emptyResult("npm-audit", "failed", {
        engineVersion: version,
        error: `npm audit failed (exit ${res.exitCode}${res.timedOut ? ", timed out" : ""}): ${ctx.redact(res.stderr.slice(-600))}`,
        gaps: ["Dependency audit did not complete (the npm registry may be unreachable)."],
        durationMs: Date.now() - started,
      });
    }
    if ("error" in (JSON.parse(res.stdout) as Record<string, unknown>)) {
      return emptyResult("npm-audit", "failed", {
        engineVersion: version,
        error: `npm audit returned an error: ${ctx.redact(res.stdout.slice(0, 600))}`,
        durationMs: Date.now() - started,
      });
    }
    const rawOutputPath = await writeEvidence(ctx, "npm-audit.json", report);
    const findings: RawFinding[] = [];
    for (const value of Object.values(report.vulnerabilities)) {
      const parsed = Vulnerability.safeParse(value);
      if (!parsed.success) continue;
      const v = parsed.data;
      const advisories = v.via.filter((x): x is Exclude<typeof x, string> => typeof x !== "string");
      // Packages that are only vulnerable through another package are reported by the root package.
      if (advisories.length === 0) continue;
      const fix =
        typeof v.fixAvailable === "object"
          ? `Upgrade ${v.fixAvailable.name} to ${v.fixAvailable.version}${v.fixAvailable.isSemVerMajor ? " (semver-major: review breaking changes)" : ""}.`
          : v.fixAvailable
            ? "A fix is available: run `npm audit fix` (review the lockfile diff)."
            : "No fixed version is available yet; consider replacing the package or mitigating the vulnerable code path.";
      findings.push({
        title: `Vulnerable dependency ${v.name} (${advisories.map((a) => a.title).filter(Boolean)[0] ?? "known advisory"})`,
        description: advisories.map((a) => `- ${a.title || a.name} (${a.severity}) affecting ${a.range || v.range}: ${a.url}`).join("\n"),
        category: "dependency",
        severity: mapSeverity(v.severity),
        originalSeverity: v.severity,
        confidence: "high",
        ruleId: `npm-audit.${v.name}`,
        locations: [{ kind: "package", packageName: v.name, packageVersion: v.range, path: "package-lock.json" }],
        evidence: [{ kind: "scanner_output", description: "npm audit JSON report", path: rawOutputPath }],
        reproductionSteps: ["Run `npm audit --package-lock-only` in the project root."],
        impact: `${v.isDirect ? "Direct" : "Transitive"} dependency with a published advisory. Exploitability depends on whether the vulnerable function is used.`,
        remediation: `${fix} Mungard never upgrades dependencies automatically.`,
        references: advisories.map((a) => a.url).filter(Boolean),
        cwe: [...new Set(advisories.flatMap((a) => a.cwe))],
      });
    }
    return {
      engine: "npm-audit",
      engineVersion: version,
      status: "succeeded",
      findings,
      coverage: [`npm audit of package-lock.json (${input.omitDev ? "production dependencies only" : "all dependencies"}, direct and transitive).`],
      gaps: ["Only packages with published advisories are reported; malicious or unmaintained packages are not detected."],
      rawOutputPath,
      durationMs: Date.now() - started,
    };
  },
};
