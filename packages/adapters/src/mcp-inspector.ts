import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { RawFinding } from "@mungard/findings";
import { isLoopbackHost, mask } from "@mungard/policy-engine";
import { z } from "zod";
import { minimalEnv } from "./exec.js";
import { findTextIndicators } from "./injection.js";
import { type AdapterResult, type HealthStatus, type SecurityAdapter } from "./types.js";
import { gitFileState, writeEvidence } from "./util.js";

export const McpInspectInput = z.object({
  /** Also read user-level client configs in the home directory (Claude Code, Claude Desktop, Cursor...). */
  includeUserConfig: z.boolean().default(false),
  /** Start each server and inspect its live tool definitions. Executes third-party code: needs approval. */
  live: z.boolean().default(false),
  /** Restrict live inspection to these server names. */
  servers: z.array(z.string()).optional(),
});
export type McpInspectInput = z.input<typeof McpInspectInput>;

export interface McpServerConfig {
  name: string;
  /** Workspace- or home-relative display path of the config file. */
  source: string;
  sourceAbs: string;
  scope: "project" | "user";
  transport: "stdio" | "http" | "sse" | "unknown";
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  headers: Record<string, string>;
}

const PROJECT_CONFIGS = [".mcp.json", "mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json", ".windsurf/mcp.json", ".roo/mcp.json", ".amazonq/mcp.json"];

function userConfigs(): string[] {
  const home = os.homedir();
  return [
    path.join(home, ".claude.json"),
    path.join(home, ".cursor/mcp.json"),
    path.join(home, ".gemini/settings.json"),
    path.join(home, ".codeium/windsurf/mcp_config.json"),
    path.join(home, "Library/Application Support/Claude/claude_desktop_config.json"),
    path.join(home, ".config/Claude/claude_desktop_config.json"),
    path.join(home, "AppData/Roaming/Claude/claude_desktop_config.json"),
  ];
}

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => !!v && typeof v === "object" && !Array.isArray(v);
const strRecord = (v: unknown): Record<string, string> =>
  isObj(v) ? Object.fromEntries(Object.entries(v).filter(([, x]) => typeof x === "string" || typeof x === "number").map(([k, x]) => [k, String(x)])) : {};

function parseServers(block: unknown, source: string, sourceAbs: string, scope: McpServerConfig["scope"]): McpServerConfig[] {
  if (!isObj(block)) return [];
  return Object.entries(block).flatMap(([name, raw]) => {
    if (!isObj(raw)) return [];
    const url = [raw.url, raw.serverUrl, raw.httpUrl].find((u): u is string => typeof u === "string");
    const type = typeof raw.type === "string" ? raw.type : typeof raw.transport === "string" ? raw.transport : undefined;
    const transport: McpServerConfig["transport"] =
      type === "sse" ? "sse" : url || type === "http" || type === "streamable-http" ? "http" : typeof raw.command === "string" ? "stdio" : "unknown";
    return [
      {
        name,
        source,
        sourceAbs,
        scope,
        transport,
        command: typeof raw.command === "string" ? raw.command : undefined,
        args: Array.isArray(raw.args) ? raw.args.map(String) : [],
        env: strRecord(raw.env),
        url,
        headers: strRecord(raw.headers),
      },
    ];
  });
}

export interface DiscoveredConfigs {
  servers: McpServerConfig[];
  files: string[];
  claudeSettings: { file: string; enableAllProjectMcpServers?: boolean }[];
  errors: string[];
}

export async function discoverMcpConfigs(projectRoot: string, includeUserConfig: boolean): Promise<DiscoveredConfigs> {
  const result: DiscoveredConfigs = { servers: [], files: [], claudeSettings: [], errors: [] };
  const candidates = [
    ...PROJECT_CONFIGS.map((rel) => ({ abs: path.join(projectRoot, rel), display: rel, scope: "project" as const })),
    ...(includeUserConfig ? userConfigs().map((abs) => ({ abs, display: abs.replace(os.homedir(), "~"), scope: "user" as const })) : []),
  ];
  for (const c of candidates) {
    let doc: unknown;
    try {
      const s = await stat(c.abs);
      if (s.size > 5_000_000) {
        result.errors.push(`${c.display} is larger than 5 MB and was skipped.`);
        continue;
      }
      doc = JSON.parse(await readFile(c.abs, "utf8"));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") result.errors.push(`${c.display}: ${(err as Error).message}`);
      continue;
    }
    if (!isObj(doc)) continue;
    result.files.push(c.display);
    result.servers.push(...parseServers(doc.mcpServers, c.display, c.abs, c.scope));
    result.servers.push(...parseServers(doc.servers, c.display, c.abs, c.scope)); // VS Code format
    // ~/.claude.json keeps per-project servers; only read the entry for this project (no other personal data).
    if (isObj(doc.projects)) {
      const entry = doc.projects[path.resolve(projectRoot)];
      if (isObj(entry)) result.servers.push(...parseServers(entry.mcpServers, `${c.display} (project entry)`, c.abs, c.scope));
    }
  }
  for (const rel of [".claude/settings.json", ".claude/settings.local.json"]) {
    try {
      const doc = JSON.parse(await readFile(path.join(projectRoot, rel), "utf8")) as unknown;
      if (isObj(doc)) result.claudeSettings.push({ file: rel, enableAllProjectMcpServers: doc.enableAllProjectMcpServers === true });
    } catch {
      // absent or unreadable settings are covered by the agent-config audit
    }
  }
  return result;
}

const SECRET_KEY = /(token|secret|password|passwd|api[-_]?key|apikey|auth|credential|private|access[-_]?key|session|cookie|bearer|conn(ection)?[-_]?str|database[-_]?url|dsn)/i;
const REFERENCE = /^\s*(\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|\{env:[^}]+\}|env:[A-Z_]+|<[^>]+>|\*+|x{3,}|your[-_ ].*|changeme|placeholder)\s*$/i;
const SECRET_VALUE = /(sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(sk|rk)_(live|test)_[A-Za-z0-9]{16,}|npm_[A-Za-z0-9]{36}|[a-z]+:\/\/[^:\s/]+:[^@\s/]+@)/;

function looksLikeLiteralSecret(key: string, value: string): boolean {
  if (!value || REFERENCE.test(value)) return false;
  if (SECRET_VALUE.test(value)) return true;
  return SECRET_KEY.test(key) && value.length >= 12 && !/\s/.test(value) && !/^(true|false|\d+)$/i.test(value);
}

const RUNNERS: Record<string, { pkgArgIndex: (args: string[]) => number; ecosystem: string }> = {
  npx: { pkgArgIndex: (a) => a.findIndex((x) => !x.startsWith("-")), ecosystem: "npm" },
  bunx: { pkgArgIndex: (a) => a.findIndex((x) => !x.startsWith("-")), ecosystem: "npm" },
  pnpx: { pkgArgIndex: (a) => a.findIndex((x) => !x.startsWith("-")), ecosystem: "npm" },
  uvx: { pkgArgIndex: (a) => a.findIndex((x) => !x.startsWith("-")), ecosystem: "PyPI" },
  pipx: { pkgArgIndex: (a) => (a[0] === "run" ? a.slice(1).findIndex((x) => !x.startsWith("-")) + 1 : -1), ecosystem: "PyPI" },
};

function isPinned(spec: string, ecosystem: string): boolean {
  if (ecosystem === "npm") {
    const at = spec.lastIndexOf("@");
    if (at <= 0) return false; // no version (scoped packages start with @)
    const version = spec.slice(at + 1);
    return /^\d+\.\d+\.\d+/.test(version);
  }
  return /==\d/.test(spec) || /@\d+\.\d+/.test(spec);
}

/** Static analysis of one server definition. */
export function analyzeServer(s: McpServerConfig): RawFinding[] {
  const findings: RawFinding[] = [];
  const loc = [{ kind: "mcp_server" as const, serverName: s.name, path: s.source }];
  const base = (r: Omit<RawFinding, "category" | "locations">): RawFinding => ({ category: "mcp", locations: loc, ...r });
  const cmd = s.command ? path.basename(s.command) : "";

  // 1. Literal credentials in env, headers, args or URL.
  const literal: string[] = [];
  for (const [k, v] of Object.entries(s.env)) if (looksLikeLiteralSecret(k, v)) literal.push(`env.${k}`);
  for (const [k, v] of Object.entries(s.headers)) if (looksLikeLiteralSecret(k, v) || /^(bearer|basic)\s+[^$<{]/i.test(v)) literal.push(`headers.${k}`);
  s.args.forEach((a, i) => {
    const [flag, val] = a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [s.args[i - 1] ?? "", a];
    if (SECRET_VALUE.test(a) || (flag.startsWith("-") && looksLikeLiteralSecret(flag, val))) literal.push(`args[${i}]`);
  });
  if (s.url) {
    try {
      const u = new URL(s.url);
      if (u.password) literal.push("url (embedded credentials)");
      for (const [k, v] of u.searchParams) if (looksLikeLiteralSecret(k, v)) literal.push(`url query "${k}"`);
    } catch {
      // ignore unparsable URLs
    }
  }
  if (literal.length) {
    findings.push(
      base({
        title: `Hardcoded credential in MCP server "${s.name}" (${s.source})`,
        description: `The server definition contains literal credential values in ${literal.join(", ")}. Config files like ${s.source} are often committed or shared, and the value is passed to a third-party process.`,
        severity: "high",
        confidence: "medium",
        ruleId: "mungard.mcp.hardcoded-credential",
        evidence: [{ kind: "config_excerpt", description: `${s.source} → ${s.name}`, excerpt: literal.map((l) => `${l} = ${mask(l.startsWith("env.") ? s.env[l.slice(4)] ?? "" : "****")}`).join("\n") }],
        reproductionSteps: [`Open ${s.source} and inspect the "${s.name}" entry (${literal.join(", ")}).`],
        impact: "Anyone with access to the file (or the git history) can use the credential.",
        remediation:
          "Reference the value from the environment instead (Claude Code .mcp.json supports `${VAR}` expansion), add local config files to .gitignore, and ROTATE the credential if this file was ever committed or shared.",
        cwe: ["CWE-798"],
        fingerprintHint: literal.join(","),
      }),
    );
  }
  if (s.args.some((a, i) => /^--?(api[-_]?key|token|password|secret)$/i.test(a) && s.args[i + 1] && !REFERENCE.test(s.args[i + 1]!))) {
    findings.push(
      base({
        title: `Credential passed as a command-line argument to MCP server "${s.name}"`,
        description: "Command-line arguments are visible to other local users and processes (ps, /proc) and end up in shell history and logs.",
        severity: "medium",
        confidence: "medium",
        ruleId: "mungard.mcp.credential-in-args",
        remediation: "Pass credentials through environment variables instead of arguments.",
        cwe: ["CWE-214"],
      }),
    );
  }

  // 2. Unpinned packages fetched at launch (supply chain / rug pull).
  const runner = RUNNERS[cmd];
  if (runner) {
    const idx = runner.pkgArgIndex(s.args);
    const spec = idx >= 0 ? s.args[idx] : undefined;
    if (spec && !isPinned(spec, runner.ecosystem)) {
      findings.push(
        base({
          title: `MCP server "${s.name}" runs an unpinned package (${cmd} ${spec})`,
          description: `\`${cmd} ${spec}\` downloads and executes the latest published version every time the agent starts. A compromised or hijacked release would run with your user's permissions and see everything the agent sends to the server.`,
          severity: "medium",
          confidence: "high",
          ruleId: "mungard.mcp.unpinned-package",
          evidence: [{ kind: "config_excerpt", description: s.source, excerpt: `"command": "${s.command}", "args": ${JSON.stringify(s.args)}` }],
          reproductionSteps: [`Inspect "${s.name}" in ${s.source}.`],
          impact: "Supply-chain compromise of the package immediately compromises the developer machine.",
          remediation: `Pin an exact, reviewed version (e.g. ${spec.replace(/@latest$/, "")}@1.2.3) and update deliberately; prefer packages from publishers you trust.`,
          references: ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
          cwe: ["CWE-829", "CWE-494"],
          fingerprintHint: spec,
        }),
      );
    }
  }

  // 3. Shell wrappers and remote script execution.
  if (["sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"].includes(cmd)) {
    const script = s.args.join(" ");
    const piped = /\b(curl|wget|iwr)\b.*\|\s*(sh|bash|python|node|iex)/i.test(script);
    findings.push(
      base({
        title: `MCP server "${s.name}" is launched through a shell${piped ? " that pipes a remote script" : ""}`,
        description: `The command is \`${cmd} ${s.args.join(" ").slice(0, 200)}\`. Shell wrappers hide what is actually executed${piped ? " and here a script is downloaded and executed on every start" : ""}.`,
        severity: piped ? "high" : "low",
        confidence: "high",
        ruleId: piped ? "mungard.mcp.remote-script" : "mungard.mcp.shell-wrapper",
        remediation: "Invoke the server binary directly with a pinned version instead of a shell command line.",
        cwe: ["CWE-494"],
      }),
    );
  }

  // 4. Docker isolation weakened.
  if (cmd === "docker" && s.args.includes("run")) {
    const joined = s.args.join(" ");
    const issues = [
      /--privileged\b/.test(joined) ? "--privileged" : undefined,
      /docker\.sock/.test(joined) ? "mounts the Docker socket (root on host)" : undefined,
      /(-v|--volume|--mount)[ =]+(\/|~|\$HOME)(:|\s|,|$)/.test(joined) ? "mounts the host root or home directory" : undefined,
      /--(network|net)[ =]host\b/.test(joined) ? "--network host" : undefined,
      /--cap-add[ =]+(ALL|SYS_ADMIN)/i.test(joined) ? "adds powerful capabilities" : undefined,
    ].filter((x): x is string => !!x);
    if (issues.length) {
      findings.push(
        base({
          title: `MCP server "${s.name}" container weakens isolation (${issues.join(", ")})`,
          description: "The server runs in Docker, but with options that give it broad access to the host.",
          severity: issues.some((i) => /privileged|socket|root/.test(i)) ? "high" : "medium",
          confidence: "high",
          ruleId: "mungard.mcp.docker-isolation",
          remediation: "Remove privileged flags and host mounts; mount only the specific directories the server needs, read-only where possible.",
          cwe: ["CWE-250"],
        }),
      );
    }
    const image = s.args.find((a, i) => i > s.args.indexOf("run") && !a.startsWith("-") && !s.args[i - 1]?.match(/^-(e|v|p|w|u|-env|-volume|-name|-network|-mount|-user|-workdir|-entrypoint)$/));
    if (image && !image.includes("@sha256:") && (!image.includes(":") || image.endsWith(":latest"))) {
      findings.push(
        base({
          title: `MCP server "${s.name}" uses an unpinned container image (${image})`,
          description: "The image tag can change underneath you; a new push runs automatically on the next start.",
          severity: "low",
          confidence: "medium",
          ruleId: "mungard.mcp.unpinned-image",
          remediation: "Pin the image by digest (image@sha256:...) or at least an immutable version tag.",
          cwe: ["CWE-829"],
          fingerprintHint: image,
        }),
      );
    }
  }

  // 5. Broad filesystem access.
  const broad = s.args.filter((a) => a === "/" || a === "~" || a === os.homedir() || a === "$HOME" || /^[A-Z]:\\?$/i.test(a));
  if (broad.length && /file|fs|filesystem|desktop-commander/i.test(`${s.name} ${s.args.join(" ")}`)) {
    findings.push(
      base({
        title: `MCP server "${s.name}" has access to the whole filesystem or home directory`,
        description: `Arguments ${broad.join(", ")} grant the server (and any prompt injection reaching the agent) access to SSH keys, cloud credentials and other projects.`,
        severity: "medium",
        confidence: "medium",
        ruleId: "mungard.mcp.broad-filesystem",
        remediation: "Limit allowed directories to the current project.",
        cwe: ["CWE-732"],
      }),
    );
  }

  // 6. Remote servers.
  if (s.url) {
    try {
      const u = new URL(s.url);
      if (u.protocol === "http:" && !isLoopbackHost(u.hostname)) {
        findings.push(
          base({
            title: `MCP server "${s.name}" uses unencrypted HTTP (${u.host})`,
            description: "Tool calls, results and any credentials in headers travel in clear text.",
            severity: "high",
            confidence: "high",
            ruleId: "mungard.mcp.plain-http",
            remediation: "Use https:// for remote MCP servers.",
            cwe: ["CWE-319"],
          }),
        );
      } else if (!isLoopbackHost(u.hostname)) {
        findings.push(
          base({
            title: `Remote MCP server "${s.name}" (${u.host})`,
            description: "Data the agent passes to this server (code, file contents, secrets in context) leaves your machine and is processed by a third party. Its tool descriptions can change at any time.",
            severity: "info",
            confidence: "high",
            ruleId: "mungard.mcp.remote-server",
            remediation: "Confirm you trust the operator, review its data handling, and re-run `mungard mcp inspect --live` periodically to detect tool changes.",
            fingerprintHint: u.host,
          }),
        );
      }
    } catch {
      // ignore
    }
  }
  return findings;
}

const ToolDef = z.object({
  name: z.string(),
  description: z.string().optional(),
  inputSchema: z.unknown().optional(),
});
type ToolDef = z.infer<typeof ToolDef>;

function toolText(t: ToolDef): string {
  return `${t.description ?? ""}\n${JSON.stringify(t.inputSchema ?? {})}`;
}

function toolHash(t: ToolDef): string {
  return createHash("sha256").update(`${t.name}\u0000${toolText(t)}`).digest("hex").slice(0, 16);
}

async function listToolsLive(s: McpServerConfig, timeoutMs: number): Promise<ToolDef[]> {
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  const client = new Client({ name: "mungard-inspector", version: "0.1.0" });
  const resolveRefs = (v: string) => v.replace(/\$\{(?:env:)?([A-Z0-9_]+)\}/gi, (_, n: string) => process.env[n] ?? "");
  let transport;
  if (s.transport === "stdio" && s.command) {
    const { StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js");
    transport = new StdioClientTransport({
      command: s.command,
      args: s.args.map(resolveRefs),
      env: minimalEnv(Object.fromEntries(Object.entries(s.env).map(([k, v]) => [k, resolveRefs(v)]))),
      stderr: "ignore",
    });
  } else if ((s.transport === "http" || s.transport === "sse") && s.url) {
    const headers = Object.fromEntries(Object.entries(s.headers).map(([k, v]) => [k, resolveRefs(v)]));
    if (s.transport === "sse") {
      const { SSEClientTransport } = await import("@modelcontextprotocol/sdk/client/sse.js");
      transport = new SSEClientTransport(new URL(s.url), { requestInit: { headers } });
    } else {
      const { StreamableHTTPClientTransport } = await import("@modelcontextprotocol/sdk/client/streamableHttp.js");
      transport = new StreamableHTTPClientTransport(new URL(s.url), { requestInit: { headers } });
    }
  } else {
    throw new Error("unsupported transport");
  }
  const timeout = new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`timed out after ${timeoutMs / 1000}s`)), timeoutMs));
  try {
    await Promise.race([client.connect(transport), timeout]);
    const res = await Promise.race([client.listTools(), timeout]);
    return res.tools.map((t) => ToolDef.parse(t));
  } finally {
    await client.close().catch(() => undefined);
  }
}

/** Analyze live tool definitions for poisoning, shadowing and changes since the last baseline. */
export function analyzeTools(
  server: McpServerConfig,
  tools: ToolDef[],
  baseline: Record<string, string> | undefined,
  otherServersTools: Map<string, string[]>,
): RawFinding[] {
  const findings: RawFinding[] = [];
  const loc = [{ kind: "mcp_server" as const, serverName: server.name, path: server.source }];
  for (const t of tools) {
    const indicators = findTextIndicators(toolText(t));
    if (indicators.length) {
      const worst = indicators.some((i) => i.severity === "high") ? "high" : "medium";
      findings.push({
        title: `Possible tool poisoning in "${server.name}" tool "${t.name}"`,
        description: `The tool description/schema contains instructions aimed at the AI agent: ${indicators.map((i) => i.label).join("; ")}. Tool descriptions are injected into the agent's context and can steer it without the user noticing.`,
        category: "mcp",
        severity: worst,
        confidence: "medium",
        ruleId: "mungard.mcp.tool-poisoning",
        locations: loc,
        evidence: [{ kind: "config_excerpt", description: `Tool ${t.name} description (excerpts)`, excerpt: indicators.map((i) => `[${i.id}] ${i.excerpt}`).join("\n") }],
        reproductionSteps: [`Run \`mungard mcp inspect --live --server ${server.name}\` and read the description of tool "${t.name}".`],
        impact: "A malicious tool description can make the agent read secrets, call other tools, or exfiltrate data.",
        remediation: "Remove the server or pin a reviewed version. Report the package to its registry if the instructions look malicious.",
        cwe: ["CWE-1427"],
        fingerprintHint: t.name,
      });
    }
    const clash = [...otherServersTools.entries()].filter(([other, names]) => other !== server.name && names.includes(t.name)).map(([o]) => o);
    if (clash.length) {
      findings.push({
        title: `Tool name "${t.name}" is defined by multiple MCP servers (${[server.name, ...clash].join(", ")})`,
        description: "Duplicate tool names let one server shadow another, so the agent may call the wrong (possibly malicious) implementation.",
        category: "mcp",
        severity: "medium",
        confidence: "medium",
        ruleId: "mungard.mcp.tool-shadowing",
        locations: loc,
        remediation: "Remove one of the servers or ensure the client namespaces tools per server.",
        fingerprintHint: t.name,
      });
    }
    const prev = baseline?.[t.name];
    if (prev && prev !== toolHash(t)) {
      findings.push({
        title: `Tool "${t.name}" of "${server.name}" changed since the last inspection`,
        description: "The tool's description or input schema differs from the recorded baseline. Silent changes to approved tools are how 'rug pull' attacks work.",
        category: "mcp",
        severity: "medium",
        confidence: "high",
        ruleId: "mungard.mcp.tool-changed",
        locations: loc,
        remediation: "Review the new definition. If expected, re-run inspection to accept it as the new baseline.",
        fingerprintHint: `${t.name}:${toolHash(t)}`,
      });
    }
  }
  return findings;
}

export const mcpInspectorAdapter: SecurityAdapter<McpInspectInput> = {
  id: "mcp-inspector",
  name: "MCP configuration inspector (built in)",
  operation: "mcp_inspect",
  inputSchema: McpInspectInput,

  async healthCheck(): Promise<HealthStatus> {
    return { engine: "mcp-inspector", available: true, via: "builtin", detail: "Built-in MCP config and tool-definition analyzer." };
  },

  async run(rawInput, ctx): Promise<AdapterResult> {
    const started = Date.now();
    const input = McpInspectInput.parse(rawInput);
    const discovered = await discoverMcpConfigs(ctx.projectRoot, input.includeUserConfig);
    const findings: RawFinding[] = [];
    const gaps = [...discovered.errors];
    const coverage: string[] = [];

    for (const s of discovered.servers) findings.push(...analyzeServer(s));

    // Literal secrets in a committed project config are worse: escalate and say so.
    for (const f of findings.filter((x) => x.ruleId === "mungard.mcp.hardcoded-credential")) {
      const src = f.locations?.[0]?.path;
      const server = discovered.servers.find((s) => s.source === src && s.scope === "project");
      if (!server) continue;
      const git = await gitFileState(ctx.projectRoot, server.source);
      f.description += ` Git: ${git.isRepo ? `tracked=${git.tracked ? "YES" : "no"}, in history=${git.inHistory ? "YES" : "no"}, gitignored=${git.ignored ? "yes" : "NO"}` : "not a git repository"}.`;
      if (git.tracked || git.inHistory) {
        f.severity = "critical";
        f.confidence = "high";
        f.title = f.title.replace("Hardcoded credential", "Committed credential");
      }
    }
    for (const cs of discovered.claudeSettings.filter((c) => c.enableAllProjectMcpServers)) {
      findings.push({
        title: `Claude Code auto-approves all project MCP servers (${cs.file})`,
        description: "`enableAllProjectMcpServers: true` makes Claude Code start every server in .mcp.json without asking. A malicious commit or PR that adds a server would run code on every developer machine that opens the project.",
        category: "mcp",
        severity: "medium",
        confidence: "high",
        ruleId: "mungard.mcp.auto-approve-project-servers",
        locations: [{ kind: "config", path: cs.file }],
        remediation: "Remove enableAllProjectMcpServers and approve servers individually (enabledMcpjsonServers).",
      });
    }

    let liveData: Record<string, { tools?: string[]; error?: string }> = {};
    if (input.live) {
      const baselineFile = path.join(ctx.workspaceDir, "mcp-tool-baseline.json");
      let baseline: Record<string, Record<string, string>> = {};
      try {
        baseline = JSON.parse(await readFile(baselineFile, "utf8")) as typeof baseline;
      } catch {
        // first live inspection
      }
      const targets = discovered.servers.filter((s) => !input.servers || input.servers.includes(s.name));
      const toolsByServer = new Map<string, ToolDef[]>();
      for (const s of targets) {
        ctx.log(`mcp: starting "${s.name}" (${s.transport}) to list tools`);
        try {
          toolsByServer.set(s.name, await listToolsLive(s, 30_000));
          liveData[s.name] = { tools: toolsByServer.get(s.name)!.map((t) => t.name) };
        } catch (err) {
          liveData[s.name] = { error: (err as Error).message };
          gaps.push(`Live inspection of "${s.name}" failed: ${ctx.redact((err as Error).message)}`);
        }
      }
      const names = new Map([...toolsByServer.entries()].map(([k, v]) => [k, v.map((t) => t.name)]));
      for (const s of targets) {
        const tools = toolsByServer.get(s.name);
        if (!tools) continue;
        findings.push(...analyzeTools(s, tools, baseline[s.name], names));
        baseline[s.name] = Object.fromEntries(tools.map((t) => [t.name, toolHash(t)]));
      }
      await mkdir(ctx.workspaceDir, { recursive: true });
      await writeFile(baselineFile, JSON.stringify(baseline, null, 2), { mode: 0o600 });
      coverage.push(`Live tool inspection of ${toolsByServer.size}/${targets.length} server(s): tool poisoning indicators, name shadowing and changes since the last baseline.`);
    } else if (discovered.servers.length) {
      gaps.push("Tool descriptions were not inspected (static config analysis only). Run with --live to start the servers and check for tool poisoning; this executes the configured commands and requires approval.");
    }

    const inventory = discovered.servers.map((s) => ({
      name: s.name,
      source: s.source,
      scope: s.scope,
      transport: s.transport,
      command: s.command,
      args: s.args,
      url: s.url,
      envKeys: Object.keys(s.env),
      headerKeys: Object.keys(s.headers),
      live: liveData[s.name],
    }));
    const rawOutputPath = await writeEvidence(ctx, "mcp-inventory.json", { files: discovered.files, servers: inventory });
    for (const f of findings) f.evidence = [...(f.evidence ?? []), { kind: "config_excerpt", description: "MCP server inventory (values omitted)", path: rawOutputPath }];
    coverage.unshift(
      discovered.files.length
        ? `Static analysis of ${discovered.servers.length} MCP server definition(s) in ${discovered.files.join(", ")}.`
        : "No MCP configuration files were found in the project.",
    );
    if (!input.includeUserConfig) gaps.push("User-level MCP configs (~/.claude.json, Claude Desktop, Cursor) were not read; use --include-user-config.");
    return {
      engine: "mcp-inspector",
      engineVersion: "builtin",
      status: "succeeded",
      findings,
      coverage,
      gaps,
      rawOutputPath,
      durationMs: Date.now() - started,
      data: { servers: inventory, files: discovered.files },
    };
  },
};
