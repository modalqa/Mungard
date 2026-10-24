#!/usr/bin/env node
import path from "node:path";
import { createInterface } from "node:readline/promises";
import {
  MUNGARD_VERSION,
  PRESETS,
  STEP_IDS,
  Workspace,
  anthropicCredentialsAvailable,
  buildTriagePayload,
  claudeCodeHookSettings,
  createLlmProvider,
  detectProject,
  engineHealth,
  evaluateGuard,
  parseConfig,
  planAssessment,
  proposeRemediation,
  runAssessment,
  runRetest,
  toClaudeCodeHookOutput,
  triageFindings,
  writeReport,
  type ReportFormat,
  type StepId,
  type StepOptions,
} from "@mungard/core";
import { FINDING_STATUSES, SEVERITIES, isUnresolved, type FindingStatus, type Severity } from "@mungard/findings";
import { redactDeep } from "@mungard/policy-engine";
import { BUILTIN_ADAPTERS } from "@mungard/adapters";
import { Command, InvalidArgumentError, Option } from "commander";
import { c, exceedsThreshold, log, printEvent, printFindings, printRunSummary, progress } from "./output.js";

const program = new Command();

program
  .name("mungard")
  .description("Mungard: open-source, local-first AI security testing agent. Guard every agent action.")
  .version(MUNGARD_VERSION)
  .showHelpAfterError();

function severityOption(value: string): Severity {
  if (!(SEVERITIES as readonly string[]).includes(value)) throw new InvalidArgumentError(`Expected one of ${SEVERITIES.join(", ")}.`);
  return value as Severity;
}

function stepsOption(value: string): StepId[] {
  const steps = value.split(",").map((s) => s.trim()).filter(Boolean);
  const bad = steps.filter((s) => !(STEP_IDS as readonly string[]).includes(s));
  if (bad.length) throw new InvalidArgumentError(`Unknown step(s) ${bad.join(", ")}. Valid: ${STEP_IDS.join(", ")}.`);
  return steps as StepId[];
}

async function openWorkspace(root: string): Promise<Workspace> {
  const ws = await Workspace.open(root);
  if (!(await Workspace.exists(root))) {
    progress(c.dim(`No .mungard/config.yaml in ${ws.root}; using safe defaults (run \`mungard init\` to customize).`));
  }
  return ws;
}

interface RunCliOptions {
  json?: boolean;
  failOn?: Severity;
  format?: ReportFormat;
  output?: string;
  strict?: boolean;
}

/** Shared runner for scan/audit/mcp inspect and single-engine commands. */
async function runAndReport(root: string, kind: string, steps: StepId[], options: StepOptions, cli: RunCliOptions): Promise<void> {
  const ws = await openWorkspace(root);
  const outcome = await runAssessment(ws, { kind, steps, options, actor: "cli", onEvent: printEvent });
  if (cli.json) {
    log(JSON.stringify(redactDeep({ run: outcome.run, findings: outcome.findings }, ws.redact), null, 2));
  } else {
    printRunSummary(outcome.run, outcome.findings);
  }
  if (cli.output || cli.format) {
    const { file } = await writeReport(ws, cli.format ?? "md", cli.output);
    progress(`${c.green("✔")} Report written to ${path.relative(process.cwd(), file) || file}`);
  }
  const pendingApproval = outcome.run.blocked.filter((b) => b.approvalId);
  if (pendingApproval.length) {
    progress("");
    progress(c.yellow("Some steps need human approval:"));
    for (const b of pendingApproval) progress(`  mungard approvals approve ${b.approvalId}    ${c.dim(`# ${b.step}`)}`);
    progress(c.dim("Then re-run the same command."));
  }
  const over = exceedsThreshold(outcome.findings, cli.failOn);
  const engineFailures = outcome.run.engines.filter((e) => e.status === "failed" || e.status === "unavailable");
  if (over.length) {
    progress(c.red(`✗ ${over.length} unresolved finding(s) at or above "${cli.failOn}".`));
    process.exitCode = 1;
  }
  if (cli.strict && engineFailures.length) {
    progress(c.red(`✗ --strict: ${engineFailures.length} engine(s) failed or were unavailable.`));
    process.exitCode = process.exitCode || 3;
  }
}

function addRunOptions(cmd: Command): Command {
  return cmd
    .option("--fail-on <severity>", "exit with code 1 if unresolved findings at/above this severity exist (critical|high|medium|low|info)", severityOption)
    .addOption(new Option("--format <format>", "also write a report in this format").choices(["md", "json", "sarif"]))
    .option("-o, --output <file>", "report output path (default: .mungard/reports/)")
    .option("--json", "print machine-readable JSON to stdout")
    .option("--strict", "exit with code 3 if any engine failed or was unavailable");
}

// ---------------- init ----------------
program
  .command("init")
  .description("Detect the project and create .mungard/config.yaml (does not modify application source code)")
  .argument("[path]", "project root", ".")
  .option("--target <url>", "runtime target base URL (e.g. http://localhost:3000)")
  .option("--force", "overwrite an existing config")
  .action(async (root: string, opts: { target?: string; force?: boolean }) => {
    const abs = path.resolve(root);
    if ((await Workspace.exists(abs)) && !opts.force) {
      log(c.yellow(`.mungard/config.yaml already exists in ${abs}. Use --force to overwrite.`));
      process.exitCode = 1;
      return;
    }
    const det = await detectProject(abs);
    log(c.bold(`Detected project "${det.name}"`));
    log(`  languages:      ${det.languages.join(", ") || "-"}`);
    log(`  frameworks:     ${det.frameworks.join(", ") || "-"}`);
    log(`  package manager:${det.packageManager ? ` ${det.packageManager}` : " -"} ${c.dim(det.dependencyFiles.join(", "))}`);
    log(`  OpenAPI specs:  ${det.openapiSpecs.join(", ") || "-"}`);
    log(`  routes:         ${det.routes.length}`);
    log(`  MCP configs:    ${det.mcpConfigFiles.join(", ") || "-"}`);
    log(`  agent files:    ${det.agentFiles.join(", ") || "-"}`);
    log(`  git repository: ${det.isGitRepo ? "yes" : "no"}`);
    for (const n of det.notes) log(c.yellow(`  note: ${n}`));
    log("");
    log(c.bold("Recommended engines:"));
    for (const r of det.recommendedEngines) log(`  - ${r.engine}: ${c.dim(r.reason)}`);
    const target = opts.target ?? det.suggestedBaseUrl;
    const port = target ? new URL(target).port : "";
    const config = parseConfig({
      project: { name: det.name, frameworks: det.frameworks },
      target: { baseUrl: target, openapi: det.openapiSpecs[0] },
      policy: { targets: { allowedPorts: port ? [Number(port)] : [] } },
    });
    const header = `# Mungard project configuration. Review before running scans.
# Docs: docs/configuration.md. Results, evidence and approvals are stored next to this file and gitignored.
# Test account credentials must be referenced from environment variables: "\${env:MY_TOKEN}".
`;
    const file = await Workspace.writeConfig(abs, config, header);
    log("");
    log(`${c.green("✔")} Wrote ${path.relative(process.cwd(), file) || file}`);
    log("");
    log(c.bold("Next steps"));
    log(`  1. Review the policy and target:   ${c.cyan(`$EDITOR ${path.relative(process.cwd(), file) || file}`)}`);
    log(`  2. Check engines:                  ${c.cyan("mungard doctor")}`);
    log(`  3. Run a scan:                     ${c.cyan("mungard scan .")}`);
    log(`  4. Connect Claude Code (MCP):      ${c.cyan("claude mcp add --scope project mungard -- mungard mcp serve")}`);
    log(`  5. Guard agent actions (optional): ${c.cyan("mungard guard install")}`);
  });

// ---------------- doctor ----------------
program
  .command("doctor")
  .description("Check runtime, security engines, configuration, AI credentials and target reachability")
  .argument("[path]", "project root", ".")
  .action(async (root: string) => {
    const ws = await openWorkspace(root);
    const ok = (b: boolean) => (b ? c.green("✔") : c.red("✗"));
    const major = Number(process.versions.node.split(".")[0]);
    log(`${ok(major >= 22)} Node.js ${process.versions.node}${major >= 22 ? "" : c.red(" (22.12+ required)")}`);
    log(`${ok(await Workspace.exists(ws.root))} Config ${Workspace.configPath(ws.root)}`);
    for (const h of await engineHealth(ws)) {
      log(`${ok(h.available)} ${h.engine.padEnd(14)} ${h.available ? c.dim(`${h.via}${h.version ? ` ${h.version}` : ""}: ${h.detail}`) : c.yellow(`${h.detail} ${h.remedy ?? ""}`)}`);
    }
    const ai = anthropicCredentialsAvailable();
    log(`${ai ? c.green("✔") : c.yellow("–")} AI provider ${ws.config.ai.provider} (${ws.config.ai.model}): ${ai ? "credentials found" : "no credentials (chat runs in offline mode; CLI and MCP work without AI)"}`);
    const target = ws.config.target.baseUrl;
    if (target) {
      const inScope = ws.policyEngine.inScope(target);
      let reachable = false;
      try {
        await fetch(target, { redirect: "manual", signal: AbortSignal.timeout(5000) });
        reachable = true;
      } catch {
        reachable = false;
      }
      log(`${ok(inScope)} Target ${target} ${inScope ? "is within policy scope" : c.red("is OUT of policy scope")}`);
      log(`${reachable ? c.green("✔") : c.yellow("–")} Target ${reachable ? "is reachable" : "is not reachable (start the app for runtime tests)"}`);
    } else {
      log(`${c.yellow("–")} No runtime target configured (target.baseUrl); runtime tests will be skipped.`);
    }
    log(`${c.dim("i")} Accounts configured: ${ws.config.auth.accounts.map((a) => `${a.name} (${a.role})`).join(", ") || "none"}`);
  });

// ---------------- scan / audit ----------------
addRunOptions(
  program
    .command("scan")
    .description("Fast static checks: source code (SAST), secrets and dependencies")
    .argument("[path]", "project root", ".")
    .option("--only <steps>", `comma-separated steps (${STEP_IDS.join(", ")})`, stepsOption),
).action(async (root: string, opts: RunCliOptions & { only?: StepId[] }) => {
  await runAndReport(root, "scan", opts.only ?? [...PRESETS.scan], {}, opts);
});

addRunOptions(
  program
    .command("audit")
    .description("Full assessment: scan + AI agent config + MCP config + OpenAPI + runtime tests (headers, authz, passive DAST) when a target is configured")
    .argument("[path]", "project root", ".")
    .option("--target <url>", "runtime target (overrides target.baseUrl)")
    .option("--no-dast", "skip the OWASP ZAP web scan")
    .option("--no-runtime", "skip all runtime tests (headers, authz, DAST)")
    .option("--include-write-tests", "include state-changing authorization/business-logic tests (requires approval)")
    .option("--mcp-live", "start MCP servers to inspect live tool definitions (requires approval)")
    .option("--include-user-config", "also inspect user-level MCP configs (~/.claude.json etc.)"),
).action(async (root: string, opts: RunCliOptions & { target?: string; dast: boolean; runtime: boolean; includeWriteTests?: boolean; mcpLive?: boolean; includeUserConfig?: boolean }) => {
  let steps: StepId[] = [...PRESETS.audit];
  if (!opts.dast) steps = steps.filter((s) => s !== "web");
  if (!opts.runtime) steps = steps.filter((s) => !["headers", "web", "authz"].includes(s));
  await runAndReport(root, "audit", steps, { target: opts.target, includeWriteTests: opts.includeWriteTests, mcpLive: opts.mcpLive, includeUserMcpConfig: opts.includeUserConfig }, opts);
});

// ---------------- mcp ----------------
const mcp = program.command("mcp").description("MCP security: inspect MCP configurations or run Mungard's own MCP server");

addRunOptions(
  mcp
    .command("inspect")
    .description("Inspect MCP server configs for hardcoded credentials, unpinned packages, risky launch commands and insecure remotes")
    .argument("[path]", "project root", ".")
    .option("--live", "start the servers and inspect their tool definitions for poisoning/shadowing/changes (executes them; requires approval)")
    .option("--server <name...>", "limit live inspection to these servers")
    .option("--include-user-config", "also read user-level configs (~/.claude.json, Claude Desktop, Cursor...)"),
).action(async (root: string, opts: RunCliOptions & { live?: boolean; server?: string[]; includeUserConfig?: boolean }) => {
  await runAndReport(root, "mcp", ["mcp"], { mcpLive: opts.live, mcpServers: opts.server, includeUserMcpConfig: opts.includeUserConfig }, opts);
});

mcp
  .command("serve")
  .description("Run the Mungard MCP server over stdio (for Claude Code and other MCP clients)")
  .option("--root <path>", "project root", process.env.MUNGARD_PROJECT_ROOT ?? ".")
  .action(async (opts: { root: string }) => {
    const { startStdioServer } = await import("@mungard/mcp-server");
    await startStdioServer({ root: opts.root });
  });

mcp
  .command("config")
  .description("Print the configuration to connect Claude Code (or another MCP client) to Mungard")
  .action(() => {
    log(c.bold("Claude Code (recommended):"));
    log(`  claude mcp add --scope project mungard -- mungard mcp serve`);
    log("");
    log(c.bold(".mcp.json equivalent:"));
    log(JSON.stringify({ mcpServers: { mungard: { command: "mungard", args: ["mcp", "serve"] } } }, null, 2));
    log("");
    log(c.dim(`If you use npx, pin the version: "command": "npx", "args": ["-y", "mungard@${MUNGARD_VERSION}", "mcp", "serve"].`));
  });

// ---------------- runtime / single engines ----------------
addRunOptions(
  program
    .command("web-scan")
    .description("Scan a running web app with OWASP ZAP (passive by default) plus header/CORS checks")
    .argument("[url]", "target URL (defaults to target.baseUrl)")
    .option("--root <path>", "project root", ".")
    .option("--active", "ACTIVE scan with attack payloads (requires approval; use only on test environments)"),
).action(async (url: string | undefined, opts: RunCliOptions & { root: string; active?: boolean }) => {
  await runAndReport(opts.root, `web-${opts.active ? "active" : "passive"}`, ["headers", "web"], { target: url, webMode: opts.active ? "active" : "passive" }, opts);
});

addRunOptions(
  program
    .command("api")
    .description("Analyze an OpenAPI specification (endpoint inventory, auth requirements, spec-level issues)")
    .argument("[spec]", "spec path relative to the project root")
    .option("--root <path>", "project root", "."),
).action(async (spec: string | undefined, opts: RunCliOptions & { root: string }) => {
  await runAndReport(opts.root, "api", ["api"], { openapi: spec }, opts);
});

addRunOptions(
  program
    .command("authz")
    .description("Run authorization (BOLA/IDOR, roles, tenants) and business-logic tests with configured test accounts")
    .option("--root <path>", "project root", ".")
    .option("--include-write-tests", "include state-changing requests (requires approval)")
    .option("--only <ids...>", "only these check/scenario ids"),
).action(async (opts: RunCliOptions & { root: string; includeWriteTests?: boolean; only?: string[] }) => {
  await runAndReport(opts.root, "authz", ["authz"], { includeWriteTests: opts.includeWriteTests, authzOnly: opts.only }, opts);
});

program
  .command("plan")
  .description("Show the assessment plan: checks, policy decisions, prerequisites and suggested scenarios (runs nothing)")
  .argument("[path]", "project root", ".")
  .option("--json", "print JSON")
  .action(async (root: string, opts: { json?: boolean }) => {
    const ws = await openWorkspace(root);
    const plan = await planAssessment(ws, "audit");
    if (opts.json) return log(JSON.stringify(plan, null, 2));
    log(c.bold(`Assessment plan for ${plan.project.name}`) + c.dim(` (${plan.project.frameworks.join(", ") || "no framework detected"})`));
    log(`Target: ${plan.target ?? c.yellow("none configured")}`);
    log("");
    for (const i of plan.items) {
      const pol = i.policy === "allow" ? c.green("allow") : i.policy === "require_approval" ? c.yellow("approval") : c.red(i.policy);
      log(`${i.ready ? c.green("●") : c.dim("○")} ${i.step.padEnd(8)} ${pol.padEnd(18)} ${i.description}`);
      for (const p of i.prerequisites) log(`             ${c.yellow("needs:")} ${p}`);
    }
    if (plan.suggestedScenarios.length) {
      log("");
      log(c.bold("Suggested scenarios (need your confirmation before they run):"));
      for (const s of plan.suggestedScenarios) {
        log(`  - [${s.kind}] ${s.description}`);
        log(c.dim(`    assumes: ${s.assumptions.join(" ")}`));
      }
      log(c.dim("  Use `mungard plan --json` to get config templates for authorization.checks / authorization.scenarios."));
    }
    log("");
    log(c.bold("Limitations:"));
    for (const l of plan.limitations) log(`  - ${l}`);
  });

// ---------------- findings ----------------
const findings = program.command("findings").description("Inspect and manage findings");

findings
  .command("list")
  .description("List findings, most severe first")
  .option("--root <path>", "project root", ".")
  .option("--status <status...>", `filter by status (${FINDING_STATUSES.join(", ")})`)
  .option("--severity <severity...>", "filter by severity")
  .option("--unresolved", "only unresolved findings")
  .option("--json", "print JSON")
  .action(async (opts: { root: string; status?: string[]; severity?: string[]; unresolved?: boolean; json?: boolean }) => {
    const ws = await openWorkspace(opts.root);
    let all = await ws.loadFindings();
    if (opts.status) all = all.filter((f) => opts.status!.includes(f.status));
    if (opts.severity) all = all.filter((f) => opts.severity!.includes(f.severity));
    if (opts.unresolved) all = all.filter(isUnresolved);
    if (opts.json) return log(JSON.stringify(redactDeep(all, ws.redact), null, 2));
    printFindings(all, { limit: 500 });
  });

findings
  .command("show")
  .description("Show one finding with evidence")
  .argument("<id>", "finding id (MG-...)")
  .option("--root <path>", "project root", ".")
  .action(async (id: string, opts: { root: string }) => {
    const ws = await openWorkspace(opts.root);
    const f = await ws.getFinding(id);
    if (!f) {
      log(c.red(`Finding ${id} not found.`));
      process.exitCode = 1;
      return;
    }
    log(JSON.stringify(redactDeep(f, ws.redact), null, 2));
  });

findings
  .command("set-status")
  .description("Change a finding's status (human decision; recorded in history and the audit log)")
  .argument("<id>", "finding id")
  .argument("<status>", `new status (${FINDING_STATUSES.filter((s) => s !== "retested").join(", ")})`)
  .requiredOption("--reason <text>", "why (required)")
  .option("--root <path>", "project root", ".")
  .action(async (id: string, status: string, opts: { reason: string; root: string }) => {
    if (!(FINDING_STATUSES as readonly string[]).includes(status)) throw new InvalidArgumentError(`Unknown status ${status}.`);
    const ws = await openWorkspace(opts.root);
    const f = await ws.setFindingStatus(id, status as FindingStatus, "human", opts.reason, "cli");
    log(`${c.green("✔")} ${f.id} is now ${f.status}${status === "fixed" ? c.dim(". Run `mungard retest " + f.id + "` to verify the fix.") : ""}`);
  });

// ---------------- triage / remediation / retest ----------------
program
  .command("triage")
  .description("Triage findings (heuristics, plus AI when configured). Advisory only; never changes statuses")
  .argument("[ids...]", "finding ids (default: all unresolved)")
  .option("--root <path>", "project root", ".")
  .option("--no-ai", "heuristics only")
  .option("--dry-run", "print the exact redacted payload that would be sent to the AI model, then exit")
  .action(async (ids: string[], opts: { root: string; ai: boolean; dryRun?: boolean }) => {
    const ws = await openWorkspace(opts.root);
    const all = await ws.loadFindings();
    const selected = (ids.length ? all.filter((f) => ids.includes(f.id)) : all.filter((f) => ["new", "needs_review", "confirmed"].includes(f.status))).slice(0, 60);
    if (opts.dryRun) {
      log(JSON.stringify(await buildTriagePayload(ws, selected), null, 2));
      progress(c.dim(`This payload (${selected.length} finding(s)) would be sent to ${ws.config.ai.provider}/${ws.config.ai.model}. policy.ai.sendSourceCode=${ws.config.policy.ai.sendSourceCode}.`));
      return;
    }
    const llm = opts.ai ? createLlmProvider(ws.config.ai, ws.config.policy.ai.enabled) : undefined;
    if (opts.ai && !llm) progress(c.yellow("AI triage unavailable (no credentials or disabled by policy); using heuristics only."));
    const r = await triageFindings(ws, selected, { llm, actor: "cli" });
    if (r.aiError) progress(c.yellow(r.aiError));
    for (const f of selected) {
      const t = r.triaged.get(f.id);
      if (!t) continue;
      log(`${c.bold(t.priority.toUpperCase())} ${c.dim(f.id)} ${f.title}`);
      log(`   ${t.assessment.replace(/_/g, " ")} ${c.dim(`(${t.source}${t.model ? ` ${t.model}` : ""})`)}: ${t.rationale}`);
      if (t.missingEvidence.length) log(c.dim(`   missing: ${t.missingEvidence.join("; ")}`));
    }
    log("");
    log(c.dim("Triage is advisory. Change statuses yourself with `mungard findings set-status`."));
  });

program
  .command("remediate")
  .description("Show remediation guidance and a regression test for a finding (does not modify code)")
  .argument("<id>", "finding id")
  .option("--root <path>", "project root", ".")
  .action(async (id: string, opts: { root: string }) => {
    const ws = await openWorkspace(opts.root);
    const p = await proposeRemediation(ws, id);
    log(c.bold(`${p.findingId}: ${p.title}`));
    log(`Affected: ${p.affected.join("; ")}`);
    if (p.codeContext) log(`\n${p.codeContext}\n`);
    log(c.bold("Fix"));
    log(p.guidance);
    log("");
    log(c.bold(`Regression test: ${p.regressionTest.description}`));
    log(p.regressionTest.example);
    log("");
    log(c.dim(p.approvalNote));
    log(`Then: ${c.cyan(p.retestCommand)}`);
  });

program
  .command("retest")
  .description("Re-run the relevant engines for findings and compare before/after")
  .argument("<ids...>", "finding ids")
  .option("--root <path>", "project root", ".")
  .action(async (ids: string[], opts: { root: string }) => {
    const ws = await openWorkspace(opts.root);
    const r = await runRetest(ws, ids, { actor: "cli", onEvent: printEvent });
    log("");
    log(c.bold(`Retest ${r.runId}`) + c.dim(` at ${r.codeVersion ?? "unknown code version"}`));
    for (const cmp of r.comparisons) {
      const res = cmp.after === "passed" ? c.green("PASSED (fixed, verified)") : cmp.after === "failed" ? c.red("FAILED (still present)") : c.yellow("INCONCLUSIVE (engine did not complete)");
      log(`  ${cmp.findingId} ${res}  ${c.dim(cmp.title)}`);
    }
    for (const b of r.blocked) log(c.yellow(`  ⏸ ${b.step}: ${b.reasons.join(" ")}`));
    if (r.comparisons.some((x) => x.after !== "passed")) process.exitCode = 1;
  });

program
  .command("report")
  .description("Generate a report from the workspace (Markdown, JSON or SARIF)")
  .option("--root <path>", "project root", ".")
  .addOption(new Option("--format <format>", "report format").choices(["md", "json", "sarif"]).default("md"))
  .option("-o, --output <file>", "output path")
  .option("--stdout", "print the report to stdout instead of only writing a file")
  .action(async (opts: { root: string; format: ReportFormat; output?: string; stdout?: boolean }) => {
    const ws = await openWorkspace(opts.root);
    const { file, content } = await writeReport(ws, opts.format, opts.output);
    if (opts.stdout) log(content);
    progress(`${c.green("✔")} ${path.relative(process.cwd(), file) || file}`);
  });

// ---------------- approvals / policy / audit ----------------
const approvals = program.command("approvals").description("Human approval queue for risky operations");

approvals
  .command("list")
  .option("--root <path>", "project root", ".")
  .option("--all", "include decided and expired requests")
  .action(async (opts: { root: string; all?: boolean }) => {
    const ws = await openWorkspace(opts.root);
    const list = await ws.approvals.list(opts.all ? undefined : "pending");
    if (!list.length) return log(c.dim(opts.all ? "No approval requests." : "No pending approval requests."));
    for (const a of list) {
      log(`${c.bold(a.id)} ${c.yellow(a.status)} ${a.operation} ${c.dim(`requested by ${a.requestedBy} ${a.requestedAt}, expires ${a.expiresAt}`)}`);
      log(`  ${a.summary}`);
    }
  });

async function decide(id: string, decision: "approved" | "denied", opts: { root: string; note?: string }): Promise<void> {
  const ws = await openWorkspace(opts.root);
  const req = await ws.approvals.get(id);
  if (!req) {
    log(c.red(`Approval ${id} not found.`));
    process.exitCode = 1;
    return;
  }
  // Approvals are a human decision: require an interactive terminal so an agent
  // calling the CLI non-interactively cannot approve its own requests.
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    log(c.red("Approvals must be decided in an interactive terminal (or in the Mungard web UI)."));
    process.exitCode = 2;
    return;
  }
  log(c.bold(`${req.operation}`) + c.dim(` (${req.id}, requested by ${req.requestedBy})`));
  log(req.summary);
  if (req.target) log(`Target: ${req.target}`);
  log(c.dim(`Parameters: ${JSON.stringify(req.params)}`));
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const word = decision === "approved" ? "approve" : "deny";
  const answer = await rl.question(`Type "${word}" to ${word} this request: `);
  rl.close();
  if (answer.trim().toLowerCase() !== word) {
    log("Cancelled.");
    return;
  }
  const decided = await ws.approvals.decide(id, decision, `human:${process.env.USER ?? "cli"}`, opts.note);
  await ws.audit.write({ actor: "cli", event: "approval_decided", operation: decided.operation, target: decided.target, decision, details: { approvalId: id, note: opts.note } });
  log(`${decision === "approved" ? c.green("✔ Approved") : c.yellow("✔ Denied")} ${id}. ${decision === "approved" ? "It can be used once, until " + decided.expiresAt + "." : ""}`);
}

approvals
  .command("approve")
  .argument("<id>", "approval id")
  .option("--root <path>", "project root", ".")
  .option("--note <text>", "note recorded with the decision")
  .action((id: string, opts: { root: string; note?: string }) => decide(id, "approved", opts));

approvals
  .command("deny")
  .argument("<id>", "approval id")
  .option("--root <path>", "project root", ".")
  .option("--note <text>", "note recorded with the decision")
  .action((id: string, opts: { root: string; note?: string }) => decide(id, "denied", opts));

program
  .command("policy")
  .description("Show the effective security policy")
  .option("--root <path>", "project root", ".")
  .action(async (opts: { root: string }) => {
    const ws = await openWorkspace(opts.root);
    const { OPERATIONS, operationRule } = await import("@mungard/policy-engine");
    log(JSON.stringify({ ...ws.config.policy, effectiveOperations: Object.fromEntries(OPERATIONS.map((o) => [o, operationRule(ws.config.policy, o)])) }, null, 2));
  });

program
  .command("audit-log")
  .description("Show recent audit log entries (agent requests, policy decisions, tool runs)")
  .option("--root <path>", "project root", ".")
  .option("-n, --limit <n>", "entries", "50")
  .action(async (opts: { root: string; limit: string }) => {
    const ws = await openWorkspace(opts.root);
    for (const e of await ws.audit.read(Number(opts.limit))) {
      log(`${c.dim(e.ts)} ${e.actor.padEnd(6)} ${e.event.padEnd(22)} ${e.operation ?? ""} ${e.decision ? c.yellow(e.decision) : ""} ${e.target ?? ""}`);
    }
  });

// ---------------- guard ----------------
const guard = program.command("guard").description("Guard AI coding agent actions (Claude Code PreToolUse hook)");

guard
  .command("hook")
  .description("Claude Code PreToolUse hook: reads the tool call JSON on stdin and returns allow/ask/deny")
  .action(async () => {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
    let payload: { tool_name?: string; tool_input?: Record<string, unknown>; cwd?: string };
    try {
      payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      return; // never break the agent on malformed input; no decision
    }
    const result = evaluateGuard({ toolName: payload.tool_name ?? "", toolInput: payload.tool_input ?? {}, cwd: payload.cwd });
    const out = toClaudeCodeHookOutput(result);
    if (out) process.stdout.write(`${out}\n`);
    if (result.decision !== "none" && payload.cwd && (await Workspace.exists(payload.cwd))) {
      const ws = await Workspace.open(payload.cwd);
      await ws.audit.write({ actor: "guard", event: "guard_decision", operation: payload.tool_name, decision: result.decision, details: { rule: result.rule, reasons: result.reasons } });
    }
  });

guard
  .command("check")
  .description("Evaluate a tool call manually, e.g. mungard guard check Bash '{\"command\":\"cat .env\"}'")
  .argument("<tool>", "tool name (Bash, Read, Write, Edit, WebFetch...)")
  .argument("<input>", "tool input JSON")
  .action((tool: string, input: string) => {
    const r = evaluateGuard({ toolName: tool, toolInput: JSON.parse(input) as Record<string, unknown> });
    log(JSON.stringify(r, null, 2));
    if (r.decision === "deny") process.exitCode = 1;
  });

guard
  .command("install")
  .description("Print the Claude Code settings that enable Mungard Guard (hook + deny rules)")
  .action(() => {
    log(c.bold("Add this to .claude/settings.json (project) or ~/.claude/settings.json (all projects):"));
    log(JSON.stringify(claudeCodeHookSettings(), null, 2));
    log("");
    log(c.dim("Mungard Guard inspects tool calls before they run. It is a guardrail, not a sandbox: it cannot see what scripts do once started."));
  });

// ---------------- ui ----------------
program
  .command("ui")
  .description("Start the local web UI (chat, findings, approvals) on 127.0.0.1")
  .action(async () => {
    log("The web UI ships with the Mungard repository. From the repository root run:");
    log(c.cyan("  MUNGARD_PROJECT_ROOT=/path/to/your/app npm run dev:web"));
    log("Then open http://127.0.0.1:3737");
  });

program
  .command("engines")
  .description("List built-in security engines")
  .action(() => {
    for (const a of Object.values(BUILTIN_ADAPTERS)) log(`${a.id.padEnd(14)} ${a.operation.padEnd(20)} ${a.name}`);
  });

program.parseAsync(process.argv).catch(async (err: unknown) => {
  const msg = (err as Error).message ?? String(err);
  process.stderr.write(`${c.red("error:")} ${msg}\n`);
  process.exitCode = 2;
});
