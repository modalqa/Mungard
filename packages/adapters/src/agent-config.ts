import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import type { RawFinding } from "@mungard/findings";
import { z } from "zod";
import { findTextIndicators } from "./injection.js";
import { type AdapterResult, type HealthStatus, type SecurityAdapter } from "./types.js";
import { gitFileState, writeEvidence } from "./util.js";

export const AgentConfigInput = z.object({});
export type AgentConfigInput = z.input<typeof AgentConfigInput>;

/** Files that AI coding agents load as instructions. */
const INSTRUCTION_FILES = [
  "CLAUDE.md",
  "CLAUDE.local.md",
  ".claude/CLAUDE.md",
  "AGENTS.md",
  "GEMINI.md",
  ".cursorrules",
  ".windsurfrules",
  ".clinerules",
  ".github/copilot-instructions.md",
];
const INSTRUCTION_DIRS = [".claude/commands", ".claude/agents", ".claude/skills", ".cursor/rules", ".github/instructions", ".github/prompts", ".clinerules"];
const SETTINGS_FILES = [".claude/settings.json", ".claude/settings.local.json"];

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => !!v && typeof v === "object" && !Array.isArray(v);

async function walk(dir: string, root: string, depth = 0, out: string[] = []): Promise<string[]> {
  if (depth > 4 || out.length > 300) return out;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) await walk(abs, root, depth + 1, out);
    else if (/\.(md|mdc|txt|json|ya?ml)$/i.test(e.name) || !e.name.includes(".")) out.push(path.relative(root, abs));
  }
  return out;
}

async function readSmall(file: string, max: number): Promise<string | undefined> {
  try {
    const s = await stat(file);
    if (!s.isFile() || s.size > max) return undefined;
    return await readFile(file, "utf8");
  } catch {
    return undefined;
  }
}

/** Permission rules that hand the agent unrestricted capabilities. */
const RISKY_ALLOW: { re: RegExp; label: string; severity: "high" | "medium" | "low" }[] = [
  { re: /^Bash$|^Bash\(\*\)$|^Bash\(\s*:\*\)$/, label: "any shell command", severity: "high" },
  { re: /^Bash\((curl|wget|nc|ncat|ssh|scp)[: ]/, label: "network transfer commands", severity: "medium" },
  { re: /^Bash\((rm|sudo|chmod|chown|dd|mkfs)[: ]/, label: "destructive or privileged commands", severity: "medium" },
  { re: /^Bash\((git push|npm publish|docker)[: ]/, label: "publishing / container commands", severity: "low" },
  { re: /^Bash\((python3?|node|bash|sh|zsh|eval|npx|bunx|uvx)[: ]/, label: "arbitrary interpreters (equivalent to any command)", severity: "medium" },
  { re: /^(Write|Edit|MultiEdit)$|^(Write|Edit)\(\*\*?\)$|^(Write|Edit)\(\/\*\*\)$/, label: "writing any file", severity: "low" },
  { re: /^WebFetch$/, label: "fetching any URL", severity: "low" },
  { re: /^mcp__[^_]+$/, label: "every tool of an MCP server", severity: "low" },
];

const EXFIL_IN_HOOK = /\b(curl|wget|nc|ncat|Invoke-WebRequest|iwr)\b[^\n]*(https?:\/\/|\d+\.\d+\.\d+\.\d+)/i;

function analyzeSettings(rel: string, doc: Json): RawFinding[] {
  const findings: RawFinding[] = [];
  const loc = [{ kind: "config" as const, path: rel }];
  const permissions = isObj(doc.permissions) ? doc.permissions : {};
  const allow = Array.isArray(permissions.allow) ? permissions.allow.map(String) : [];
  const deny = Array.isArray(permissions.deny) ? permissions.deny.map(String) : [];
  const mode = typeof permissions.defaultMode === "string" ? permissions.defaultMode : undefined;

  if (mode === "bypassPermissions") {
    findings.push({
      title: `Agent permission prompts are disabled (${rel}: defaultMode=bypassPermissions)`,
      description: "Claude Code will run every tool call, including shell commands and file writes, without asking. Any prompt injection from code, web pages or tool output can act immediately.",
      category: "agent_config",
      severity: "high",
      confidence: "high",
      ruleId: "mungard.agent.bypass-permissions",
      locations: loc,
      remediation: "Use the default mode (or acceptEdits) and allowlist only the specific commands you need. Run fully autonomous agents only inside an isolated container.",
      cwe: ["CWE-250"],
    });
  }
  for (const rule of allow) {
    const hit = RISKY_ALLOW.find((r) => r.re.test(rule.trim()));
    if (!hit) continue;
    findings.push({
      title: `Broad agent permission "${rule}" in ${rel}`,
      description: `This allow rule lets the agent use ${hit.label} without confirmation.`,
      category: "agent_config",
      severity: hit.severity,
      confidence: "high",
      ruleId: "mungard.agent.broad-allow",
      locations: loc,
      remediation: "Replace it with narrowly-scoped rules (e.g. `Bash(npm test:*)`) and keep risky commands on ask.",
      fingerprintHint: rule,
    });
  }
  const protectsEnv = deny.some((d) => /\.env/.test(d));
  if (!protectsEnv) {
    findings.push({
      title: `No deny rule protects .env / secret files from the agent (${rel})`,
      description: "Without a deny rule, the agent can read local secret files into its context (and send them to the model provider or to tools).",
      category: "agent_config",
      severity: "low",
      confidence: "medium",
      ruleId: "mungard.agent.no-secret-deny",
      locations: loc,
      remediation: 'Add deny rules such as "Read(./.env)", "Read(./.env.*)", "Read(./**/*.pem)" and "Read(~/.ssh/**)".',
    });
  }
  if (isObj(doc.env)) {
    for (const [k, v] of Object.entries(doc.env)) {
      if (typeof v === "string" && /(token|secret|key|password)/i.test(k) && v.length >= 12 && !/^\$\{?/.test(v)) {
        findings.push({
          title: `Literal credential in agent settings env "${k}" (${rel})`,
          description: "Settings files are commonly committed; a literal credential here is shared with everyone who has the repository.",
          category: "agent_config",
          severity: "high",
          confidence: "medium",
          ruleId: "mungard.agent.settings-secret",
          locations: loc,
          remediation: "Move the value to your shell environment or a secret manager and rotate it if this file was committed.",
          cwe: ["CWE-798"],
          fingerprintHint: k,
        });
      }
    }
  }
  if (isObj(doc.hooks)) {
    const commands: string[] = [];
    for (const groups of Object.values(doc.hooks)) {
      if (!Array.isArray(groups)) continue;
      for (const g of groups) {
        if (!isObj(g) || !Array.isArray(g.hooks)) continue;
        for (const h of g.hooks) if (isObj(h) && typeof h.command === "string") commands.push(h.command);
      }
    }
    for (const c of commands) {
      if (EXFIL_IN_HOOK.test(c) || /\|\s*(sh|bash)\b/.test(c)) {
        findings.push({
          title: `Agent hook sends data over the network or runs remote code (${rel})`,
          description: `Hook command: \`${c.slice(0, 200)}\`. Hooks run automatically with your permissions on agent events and receive tool inputs (which may contain code and secrets).`,
          category: "agent_config",
          severity: "high",
          confidence: "medium",
          ruleId: "mungard.agent.network-hook",
          locations: loc,
          remediation: "Review the hook. Remove it unless you trust the destination and know exactly what data it sends.",
          fingerprintHint: c.slice(0, 80),
        });
      }
    }
  }
  return findings;
}

export const agentConfigAdapter: SecurityAdapter<AgentConfigInput> = {
  id: "agent-config",
  name: "AI agent configuration auditor (built in)",
  operation: "agent_config_audit",
  inputSchema: AgentConfigInput,

  async healthCheck(): Promise<HealthStatus> {
    return { engine: "agent-config", available: true, via: "builtin", detail: "Built-in agent instruction and permission analyzer." };
  },

  async run(_input, ctx): Promise<AdapterResult> {
    const started = Date.now();
    const findings: RawFinding[] = [];
    const max = ctx.policy.limits.maxFileSizeBytes;
    const files = [...INSTRUCTION_FILES];
    for (const d of INSTRUCTION_DIRS) files.push(...(await walk(path.join(ctx.projectRoot, d), ctx.projectRoot)));
    const examined: string[] = [];

    for (const rel of [...new Set(files)]) {
      const text = await readSmall(path.join(ctx.projectRoot, rel), max);
      if (text === undefined) continue;
      examined.push(rel);
      const indicators = findTextIndicators(text);
      for (const ind of indicators) {
        findings.push({
          title: `${ind.label} in agent instructions (${rel}:${ind.line})`,
          description: `${rel} is loaded into the AI agent's context as trusted instructions. Line ${ind.line} matches the "${ind.id}" prompt-injection indicator. This may be legitimate (e.g. documentation about security), so review it.`,
          category: "agent_config",
          severity: ind.severity,
          confidence: ind.id === "invisible-unicode" ? "high" : "low",
          ruleId: `mungard.agent.instruction.${ind.id}`,
          locations: [{ kind: "file", path: rel, startLine: ind.line }],
          evidence: [{ kind: "code_snippet", description: `${rel}:${ind.line}`, excerpt: ctx.redact(ind.excerpt) }],
          reproductionSteps: [`Open ${rel} at line ${ind.line}${ind.id === "invisible-unicode" ? " in an editor that shows invisible characters (or run `cat -v`)." : "."}`],
          impact: "Instructions in these files steer the coding agent; hidden or malicious ones can make it leak secrets or run commands.",
          remediation:
            ind.id === "invisible-unicode"
              ? "Remove the invisible characters, then review who added them (git blame). Treat contributions that add hidden characters as malicious."
              : "Confirm the instruction is intended. Remove instructions that exfiltrate data, hide actions from the user, or disable safety checks.",
          cwe: ["CWE-1427"],
          fingerprintHint: `${ind.id}`,
        });
      }
    }

    for (const rel of SETTINGS_FILES) {
      const text = await readSmall(path.join(ctx.projectRoot, rel), max);
      if (text === undefined) continue;
      examined.push(rel);
      let doc: unknown;
      try {
        doc = JSON.parse(text);
      } catch {
        continue;
      }
      if (isObj(doc)) findings.push(...analyzeSettings(rel, doc));
      if (rel.endsWith("settings.local.json")) {
        const git = await gitFileState(ctx.projectRoot, rel);
        if (git.tracked) {
          findings.push({
            title: ".claude/settings.local.json is committed",
            description: "settings.local.json is meant for personal, machine-specific permissions and often contains broad allow rules or credentials. Committing it applies them to everyone.",
            category: "agent_config",
            severity: "low",
            confidence: "high",
            ruleId: "mungard.agent.local-settings-committed",
            locations: [{ kind: "file", path: rel }],
            remediation: "git rm --cached .claude/settings.local.json and add it to .gitignore.",
          });
        }
      }
    }
    const rawOutputPath = await writeEvidence(ctx, "agent-config-files.json", { examined });
    return {
      engine: "agent-config",
      engineVersion: "builtin",
      status: "succeeded",
      findings,
      coverage: [examined.length ? `Agent instruction/permission files reviewed: ${examined.join(", ")}.` : "No AI agent instruction or settings files were found."],
      gaps: ["Indicators are pattern-based; obfuscated or paraphrased injections can evade them. User-level agent settings (~/.claude) were not reviewed."],
      rawOutputPath,
      durationMs: Date.now() - started,
    };
  },
};
