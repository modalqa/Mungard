import { mkdtemp, readFile, rm, writeFile, chmod } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Confidence, RawFinding, Severity } from "@mungard/findings";
import { checkTarget, isLoopbackHost } from "@mungard/policy-engine";
import { z } from "zod";
import { dockerAvailable, dockerBaseArgs, findExecutable, runCommand } from "./exec.js";
import { type AdapterResult, type HealthStatus, type SecurityAdapter, emptyResult } from "./types.js";
import { writeEvidence } from "./util.js";

export const ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable";

export const ZapInput = z.object({
  target: z.string().url(),
  /** passive = spider + passive rules (baseline). active = adds active attacks (needs approval). */
  mode: z.enum(["passive", "active"]).default("passive"),
  /** Optional OpenAPI spec (workspace-relative path or URL) for an API scan. */
  openapi: z.string().optional(),
});
export type ZapInput = z.input<typeof ZapInput>;

const ZapAlert = z.object({
  pluginid: z.string(),
  alertRef: z.string().optional(),
  alert: z.string().optional(),
  name: z.string(),
  riskcode: z.string(),
  confidence: z.string(),
  desc: z.string().default(""),
  solution: z.string().default(""),
  reference: z.string().default(""),
  cweid: z.string().default(""),
  instances: z
    .array(z.object({ uri: z.string(), method: z.string().default("GET"), param: z.string().default(""), evidence: z.string().default("") }))
    .default([]),
});
const ZapReport = z.object({
  "@version": z.string().optional(),
  site: z.array(z.object({ "@name": z.string(), alerts: z.array(z.unknown()).default([]) })).default([]),
});

const RISK: Record<string, Severity> = { "3": "high", "2": "medium", "1": "low", "0": "info" };
const CONF: Record<string, Confidence> = { "4": "high", "3": "high", "2": "medium", "1": "low", "0": "low" };

function stripHtml(s: string): string {
  return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

/** Containers cannot reach the host's loopback; rewrite to the Docker host alias. */
export function containerTargetUrl(target: string): { url: string; network?: string } {
  const u = new URL(target);
  if (!isLoopbackHost(u.hostname)) return { url: target };
  if (process.platform === "linux") return { url: target, network: "host" };
  u.hostname = "host.docker.internal";
  return { url: u.toString() };
}

export const zapAdapter: SecurityAdapter<ZapInput> = {
  id: "zap",
  name: "OWASP ZAP (web DAST)",
  operation: "web_passive_scan",
  inputSchema: ZapInput,

  async healthCheck(): Promise<HealthStatus> {
    if (!(await dockerAvailable())) {
      return {
        engine: "zap",
        available: false,
        detail: "Docker is not available; Mungard runs OWASP ZAP in a container.",
        remedy: `Install and start Docker, then run \`docker pull ${ZAP_IMAGE}\`.`,
      };
    }
    return { engine: "zap", available: true, via: "docker", detail: `Docker image ${ZAP_IMAGE}` };
  },

  async run(rawInput, ctx): Promise<AdapterResult> {
    const started = Date.now();
    const input = ZapInput.parse(rawInput);
    // Defense in depth: the orchestrator already authorized this target.
    const scope = checkTarget(input.target, ctx.policy);
    if (!scope.allowed) return emptyResult("zap", "skipped", { error: scope.reasons.join(" "), gaps: ["Target out of scope; ZAP did not run."] });
    if (!(await dockerAvailable())) {
      return emptyResult("zap", "unavailable", { error: "Docker is not available; the web scan did NOT run.", gaps: ["Web DAST was not performed."] });
    }
    const docker = (await findExecutable("docker"))!;
    // Reachability pre-check so we fail fast with a clear message (FR-07).
    try {
      await fetch(input.target, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(10_000) });
    } catch (err) {
      return emptyResult("zap", "failed", {
        error: `Target ${input.target} is not reachable: ${(err as Error).message}. Start the application and retry.`,
        gaps: ["Web DAST was not performed because the target was unreachable."],
        durationMs: Date.now() - started,
      });
    }
    const { url, network } = containerTargetUrl(input.target);
    const tmp = await mkdtemp(path.join(os.tmpdir(), "mungard-zap-"));
    await chmod(tmp, 0o777); // the ZAP image runs as its own unprivileged user
    const limits = ctx.policy.limits;
    let script: string;
    let args: string[];
    if (input.openapi) {
      script = "zap-api-scan.py";
      let specArg = input.openapi;
      if (!/^https?:\/\//.test(input.openapi)) {
        const spec = await readFile(path.resolve(ctx.projectRoot, input.openapi), "utf8");
        await writeFile(path.join(tmp, "openapi-spec"), spec);
        specArg = "/zap/wrk/openapi-spec";
      }
      args = ["-t", specArg, "-f", "openapi", "-O", url, "-J", "zap-report.json", "-I"];
      if (input.mode === "passive") args.push("-S"); // safe mode: skip the active scan
    } else if (input.mode === "active") {
      script = "zap-full-scan.py";
      args = ["-t", url, "-J", "zap-report.json", "-I", "-m", String(limits.spiderMaxMinutes), "-T", String(limits.activeScanMaxMinutes)];
    } else {
      script = "zap-baseline.py";
      args = ["-t", url, "-J", "zap-report.json", "-I", "-m", String(limits.spiderMaxMinutes)];
    }
    const base = dockerBaseArgs({ network, memory: "3g" }).filter((a, i, all) => !(a === "--user" || all[i - 1] === "--user"));
    // ZAP needs to write its home directory, so it keeps the image's own user and default capabilities minus the dropped set.
    const dockerArgs = [...base, "-v", `${tmp}:/zap/wrk:rw`, ZAP_IMAGE, script, ...args];
    ctx.log(`zap: ${script} (${input.mode}) against ${input.target}`);
    try {
      const timeoutMs = (limits.spiderMaxMinutes + (input.mode === "active" ? limits.activeScanMaxMinutes : 0) + 5) * 60_000;
      const res = await runCommand(docker, dockerArgs, { timeoutMs, maxOutputBytes: limits.maxOutputBytes, signal: ctx.signal });
      let report: z.infer<typeof ZapReport>;
      try {
        report = ZapReport.parse(JSON.parse(await readFile(path.join(tmp, "zap-report.json"), "utf8")));
      } catch {
        return emptyResult("zap", "failed", {
          error: `ZAP produced no report (exit ${res.exitCode}${res.timedOut ? ", timed out" : ""}): ${ctx.redact(res.stderr.slice(-600) || res.stdout.slice(-600))}`,
          gaps: ["Web DAST did not complete."],
          durationMs: Date.now() - started,
        });
      }
      const rawOutputPath = await writeEvidence(ctx, `zap-${input.mode}-report.json`, report);
      const findings: RawFinding[] = [];
      for (const site of report.site) {
        for (const a of site.alerts) {
          const parsed = ZapAlert.safeParse(a);
          if (!parsed.success) continue;
          const alert = parsed.data;
          const instances = alert.instances.slice(0, 10);
          findings.push({
            title: alert.name,
            description: stripHtml(alert.desc),
            category: "dast",
            severity: RISK[alert.riskcode] ?? "info",
            originalSeverity: `riskcode ${alert.riskcode}`,
            confidence: CONF[alert.confidence] ?? "medium",
            ruleId: `zap.${alert.pluginid}`,
            locations: instances.map((i) => ({ kind: "endpoint" as const, method: i.method, url: i.uri.replace("host.docker.internal", new URL(input.target).hostname), path: new URL(i.uri).pathname })),
            evidence: [
              { kind: "scanner_output", description: `ZAP ${input.mode} scan report`, path: rawOutputPath },
              ...instances.slice(0, 3).filter((i) => i.evidence).map((i) => ({ kind: "http_exchange" as const, description: `${i.method} ${i.uri}`, excerpt: ctx.redact(i.evidence.slice(0, 400)) })),
            ],
            reproductionSteps: [`Run \`mungard web scan ${input.target}${input.mode === "active" ? " --active" : ""}\` and look for ZAP rule ${alert.pluginid}.`],
            impact: "See the ZAP rule description; passive alerts usually indicate missing hardening rather than a proven exploit.",
            remediation: stripHtml(alert.solution),
            references: stripHtml(alert.reference).split(" ").filter((r) => r.startsWith("http")),
            cwe: alert.cweid && alert.cweid !== "-1" && alert.cweid !== "0" ? [`CWE-${alert.cweid}`] : [],
          });
        }
      }
      return {
        engine: "zap",
        engineVersion: report["@version"],
        status: res.timedOut ? "partial" : "succeeded",
        findings,
        coverage: [
          input.openapi
            ? `ZAP API scan of ${input.target} from the OpenAPI definition (${input.mode === "active" ? "active attacks enabled" : "safe mode, no active attacks"}).`
            : input.mode === "active"
              ? `ZAP full scan of ${input.target}: spider (${limits.spiderMaxMinutes} min) + passive rules + ACTIVE attacks (max ${limits.activeScanMaxMinutes} min).`
              : `ZAP baseline scan of ${input.target}: spider (${limits.spiderMaxMinutes} min) + passive rules only. No attack payloads were sent.`,
        ],
        gaps: [
          ...(res.timedOut ? ["ZAP hit the time limit; results are partial."] : []),
          ...(input.mode === "passive" ? ["Active scanning (injection, XSS payloads) was not run; it requires explicit approval."] : []),
          "ZAP scans unauthenticated unless an authenticated context is configured; pages behind login may be missed.",
        ],
        rawOutputPath,
        durationMs: Date.now() - started,
      };
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  },
};
