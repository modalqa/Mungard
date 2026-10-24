import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { RawFinding } from "@mungard/findings";
import { mask } from "@mungard/policy-engine";
import { z } from "zod";
import { dockerAvailable, dockerBaseArgs, findExecutable, probeVersion, runCommand } from "./exec.js";
import { type AdapterResult, type HealthStatus, type SecurityAdapter, emptyResult } from "./types.js";
import { gitFileState, readSnippet, writeEvidence } from "./util.js";

export const GITLEAKS_IMAGE = "zricethezav/gitleaks:latest";

export const GitleaksInput = z.object({
  /** Also scan git history (committed secrets stay exposed even after deletion). */
  history: z.boolean().default(true),
  /** Extra path regexes (Go RE2 syntax) to skip, e.g. "^tests/fixtures/". */
  excludePaths: z.array(z.string().regex(/^[^'\n]+$/)).default([]),
});
export type GitleaksInput = z.input<typeof GitleaksInput>;

const GitleaksFinding = z.object({
  RuleID: z.string(),
  Description: z.string().default(""),
  StartLine: z.number().default(0),
  EndLine: z.number().default(0),
  File: z.string(),
  Commit: z.string().default(""),
  Secret: z.string().default(""),
  Match: z.string().default(""),
  Entropy: z.number().optional(),
});

/** Gitleaks output contains author names/emails: never kept (no PII in evidence). */
function stripPii(items: unknown[]): unknown[] {
  return items.map((i) => {
    if (!i || typeof i !== "object") return i;
    const { Author: _a, Email: _e, Message: _m, ...rest } = i as Record<string, unknown>;
    return rest;
  });
}

/** Extends the default Gitleaks rules and skips generated/vendored paths (plus configured excludes). */
function gitleaksConfig(excludePaths: string[]): string {
  const paths = [
    "(^|/)node_modules/",
    "(^|/)\\.next/",
    "(^|/)\\.mungard/",
    "(^|/)(dist|build|coverage)/",
    "(^|/)\\.git/",
    ...excludePaths,
  ];
  // TOML literal strings (''' ... ''') take the regex verbatim; quotes are rejected by the input schema.
  return `[extend]
useDefault = true

[allowlist]
description = "Mungard: skip vendored, generated, workspace and excluded files"
paths = [
${paths.map((p) => `  '''${p}''',`).join("\n")}
]
`;
}

async function resolveRunner(): Promise<{ via: "local" | "docker"; bin: string } | undefined> {
  const local = await findExecutable("gitleaks");
  if (local) return { via: "local", bin: local };
  if (await dockerAvailable()) {
    const docker = await findExecutable("docker");
    if (docker) return { via: "docker", bin: docker };
  }
  return undefined;
}

async function isGitRepo(root: string): Promise<boolean> {
  try {
    await stat(path.join(root, ".git"));
    return true;
  } catch {
    return false;
  }
}

export const gitleaksAdapter: SecurityAdapter<GitleaksInput> = {
  id: "gitleaks",
  name: "Gitleaks (secret detection)",
  operation: "secret_scan",
  inputSchema: GitleaksInput,

  async healthCheck(): Promise<HealthStatus> {
    const runner = await resolveRunner();
    if (!runner) {
      return {
        engine: "gitleaks",
        available: false,
        detail: "Gitleaks is not installed and Docker is not available.",
        remedy: "Install Gitleaks (`brew install gitleaks`) or start Docker to use the zricethezav/gitleaks image.",
      };
    }
    if (runner.via === "local") {
      return { engine: "gitleaks", available: true, via: "local", version: await probeVersion(runner.bin, ["version"]), detail: runner.bin };
    }
    return { engine: "gitleaks", available: true, via: "docker", detail: `Docker image ${GITLEAKS_IMAGE}` };
  },

  async run(rawInput, ctx): Promise<AdapterResult> {
    const started = Date.now();
    const input = GitleaksInput.parse(rawInput);
    const runner = await resolveRunner();
    if (!runner) {
      return emptyResult("gitleaks", "unavailable", {
        error: "Gitleaks is not installed and Docker is not available. Secret scanning did NOT run.",
        gaps: ["Secret scanning was not performed."],
      });
    }
    const version = runner.via === "local" ? await probeVersion(runner.bin, ["version"]) : undefined;
    const tmp = await mkdtemp(path.join(os.tmpdir(), "mungard-gitleaks-"));
    await writeFile(path.join(tmp, "gitleaks.toml"), gitleaksConfig(input.excludePaths), { mode: 0o600 });
    const modes: Array<"dir" | "git"> = ["dir"];
    if (input.history && (await isGitRepo(ctx.projectRoot))) modes.push("git");
    const gaps: string[] = [];
    if (input.history && !modes.includes("git")) gaps.push("Git history was not scanned (not a git repository).");
    const all: z.infer<typeof GitleaksFinding>[] = [];
    let failed = 0;
    try {
      for (const mode of modes) {
        const reportName = `gitleaks-${mode}.json`;
        const flags = ["--report-format", "json", "--redact", "--no-banner", "--exit-code", "0", "--max-target-megabytes", "5"];
        const args =
          runner.via === "local"
            ? [mode, ctx.projectRoot, "--config", path.join(tmp, "gitleaks.toml"), "--report-path", path.join(tmp, reportName), ...flags]
            : [
                ...dockerBaseArgs({ network: "none" }),
                "-v",
                `${ctx.projectRoot}:/src:ro`,
                "-v",
                `${tmp}:/out`,
                GITLEAKS_IMAGE,
                mode,
                "/src",
                "--config",
                "/out/gitleaks.toml",
                "--report-path",
                `/out/${reportName}`,
                ...flags,
              ];
        ctx.log(`gitleaks: scanning ${mode === "git" ? "git history" : "working tree"} via ${runner.via}`);
        const res = await runCommand(runner.bin, args, {
          timeoutMs: ctx.policy.limits.toolTimeoutSeconds * 1000,
          maxOutputBytes: ctx.policy.limits.maxOutputBytes,
          signal: ctx.signal,
        });
        if (res.timedOut || res.exitCode !== 0) {
          failed++;
          gaps.push(`Gitleaks ${mode} scan failed (exit ${res.exitCode}${res.timedOut ? ", timed out" : ""}): ${ctx.redact(res.stderr.slice(-400))}`);
          continue;
        }
        try {
          const items = JSON.parse(await readFile(path.join(tmp, reportName), "utf8")) as unknown[];
          for (const item of stripPii(items)) {
            const parsed = GitleaksFinding.safeParse(item);
            if (parsed.success) all.push({ ...parsed.data, File: parsed.data.File.replace(/^\/src\//, "") });
          }
        } catch (err) {
          failed++;
          gaps.push(`Could not read Gitleaks ${mode} report: ${(err as Error).message}`);
        }
      }
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }

    if (failed === modes.length) {
      return emptyResult("gitleaks", "failed", { engineVersion: version, error: "All Gitleaks scans failed.", gaps, durationMs: Date.now() - started });
    }
    const rawOutputPath = await writeEvidence(ctx, "gitleaks-output.json", all.map((f) => ({ ...f, Secret: mask(f.Secret), Match: ctx.redact(f.Match) })));

    // One finding per (rule, file); history hits are merged into the same finding.
    const grouped = new Map<string, z.infer<typeof GitleaksFinding>[]>();
    for (const f of all) {
      const rel = path.isAbsolute(f.File) ? path.relative(ctx.projectRoot, f.File) : f.File;
      const key = `${f.RuleID}\u0000${rel}`;
      grouped.set(key, [...(grouped.get(key) ?? []), { ...f, File: rel }]);
    }
    const findings: RawFinding[] = [];
    for (const items of grouped.values()) {
      const first = items[0]!;
      const inWorkingTree = items.some((i) => !i.Commit);
      const commits = [...new Set(items.map((i) => i.Commit).filter(Boolean))];
      const git = await gitFileState(ctx.projectRoot, first.File);
      const committed = commits.length > 0 || git.inHistory || git.tracked;
      const isExample = /(^|\/)(\.env\.(example|sample|template)|.*\.example\.[a-z]+)$/i.test(first.File) || /test|fixture|mock/i.test(first.File);
      const snippet = inWorkingTree
        ? await readSnippet(path.join(ctx.projectRoot, first.File), first.StartLine, ctx.redact, { context: 1 })
        : undefined;
      const exposure = [
        `Committed to git: ${committed ? "YES" : "no"}${commits.length ? ` (${commits.length} commit(s), e.g. ${commits[0]!.slice(0, 10)})` : ""}.`,
        `Gitignored: ${git.isRepo ? (git.ignored ? "yes" : "NO") : "unknown (not a git repo)"}.`,
        `Present in working tree: ${inWorkingTree ? "yes" : "no (history only)"}.`,
      ].join(" ");
      findings.push({
        title: `Possible ${committed ? "committed " : ""}secret (${first.RuleID}) in ${first.File}`,
        description: `Gitleaks rule "${first.RuleID}" matched a value that looks like a credential${first.Description ? ` (${first.Description.replace(/\.$/, "")})` : ""}. The secret value is not shown. ${exposure}`,
        category: "secret",
        severity: committed ? "high" : isExample ? "low" : "medium",
        confidence: isExample ? "low" : "medium",
        ruleId: `gitleaks.${first.RuleID}`,
        locations: [{ kind: "file", path: first.File, startLine: first.StartLine || undefined, endLine: first.EndLine || undefined }],
        evidence: [
          { kind: "scanner_output", description: "Gitleaks report (secrets masked, author data removed)", path: rawOutputPath },
          ...(snippet ? [{ kind: "code_snippet" as const, description: `${first.File}:${first.StartLine}`, excerpt: snippet }] : []),
        ],
        reproductionSteps: [`Run \`gitleaks ${commits.length ? "git" : "dir"} . --redact\` and look for rule ${first.RuleID} in ${first.File}.`],
        impact: "Anyone with access to the code or repository history can use this credential until it is revoked.",
        remediation: [
          "1. Treat the credential as compromised if it is real: revoke/rotate it with the provider first.",
          "2. Remove it from code and load it from an environment variable or secret manager.",
          committed
            ? "3. It is in git history: deleting the line does not remove it. Rotate it, then consider rewriting history (git filter-repo) if the repository is shared."
            : "3. Add the file to .gitignore if it holds local configuration.",
        ].join("\n"),
        references: ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
        cwe: ["CWE-798"],
      });
    }
    return {
      engine: "gitleaks",
      engineVersion: version,
      status: failed > 0 ? "partial" : "succeeded",
      findings,
      coverage: [`Gitleaks secret detection on the working tree${modes.includes("git") ? " and full git history" : ""}.`],
      gaps: [...gaps, "Detected values are not validated against providers; a finding may be a test or revoked value."],
      rawOutputPath,
      durationMs: Date.now() - started,
    };
  },
};
