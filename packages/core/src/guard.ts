import os from "node:os";
import path from "node:path";
import { isBlockedAddress } from "@mungard/policy-engine";

/**
 * Mungard Guard: a pre-execution check for AI coding agent actions, wired in
 * as a Claude Code PreToolUse hook (`mungard guard hook`). It returns
 * deny/ask/none for a proposed tool call. It is a guardrail, not a sandbox:
 * it inspects the request text and cannot see what a script will do.
 */

export type GuardDecision = "deny" | "ask" | "none";

export interface GuardResult {
  decision: GuardDecision;
  reasons: string[];
  rule?: string;
}

export interface GuardRequest {
  toolName: string;
  toolInput: Record<string, unknown>;
  cwd?: string;
}

const SECRET_FILE = /(^|[\s/"'=])(\.env(\.(?!example\b|sample\b|template\b|dist\b)[\w.-]+)?|id_rsa|id_ed25519|id_ecdsa|[\w.-]+\.pem|[\w.-]+\.p12|[\w.-]+\.pfx|\.aws\/credentials|\.netrc|\.git-credentials|\.npmrc|\.pypirc|\.docker\/config\.json|\.kube\/config|\.ssh\/[\w.-]+|credentials\.json|service[-_]account[\w.-]*\.json)(?=$|[\s"';|&)])/i;
const SECRET_FILE_SAFE = /\.(pub)$|\.env\.(example|sample|template|dist)$/i;

const STRONG_SECRET = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{60,}\b/,
  /\bsk-ant-[A-Za-z0-9_-]{30,}/,
  /\bsk-(proj-)?[A-Za-z0-9_-]{40,}/,
  /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/,
  /\bxox[abposr]-[A-Za-z0-9-]{20,}\b/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\bnpm_[A-Za-z0-9]{36}\b/,
];

interface Rule {
  id: string;
  decision: Exclude<GuardDecision, "none">;
  test: RegExp;
  reason: string;
}

const BASH_RULES: Rule[] = [
  { id: "self-approval", decision: "deny", test: /\bmungard\b[^\n;|&]*\bapprovals?\s+(approve|deny)\b/i, reason: "Approvals must be decided by a human, not by the agent." },
  {
    id: "workspace-tamper",
    decision: "deny",
    test: /\.mungard\/(approvals\.json|audit\.log\.jsonl|findings\.json)/i,
    reason: "The agent must not touch Mungard's approval queue, audit log or findings store directly.",
  },
  { id: "pipe-to-shell", decision: "deny", test: /\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(curl|wget)\b[^\n]*\|\s*(python3?|node|perl|ruby)\b/i, reason: "Downloading and executing a remote script." },
  { id: "rm-root", decision: "deny", test: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\s+(--no-preserve-root\s+)?(\/|~|\$HOME|\/\*|~\/\*)(\s|$)/, reason: "Recursive deletion of the filesystem root or home directory." },
  { id: "skip-permissions", decision: "deny", test: /--dangerously-skip-permissions|bypassPermissions/, reason: "Starting an agent with permission checks disabled." },
  { id: "reverse-shell", decision: "deny", test: /\b(nc|ncat|netcat)\b[^\n]*\s-e\s|\/dev\/tcp\/|\bsocat\b[^\n]*exec:/i, reason: "Looks like a reverse shell." },
  { id: "data-upload", decision: "ask", test: /\b(curl|wget|http|httpie)\b[^\n]*(\s(-d|--data[\w-]*|-F|--form|-T|--upload-file|--post-file|--post-data)[\s=])/i, reason: "Sends data to a remote server; confirm the destination and payload." },
  { id: "netcat", decision: "ask", test: /\b(nc|ncat|netcat|scp|rsync|sftp)\b\s/i, reason: "Network file transfer tool." },
  { id: "force-push", decision: "ask", test: /\bgit\s+push\b[^\n]*(\s--force(-with-lease)?\b|\s-f\b)/i, reason: "Force push can destroy remote history." },
  { id: "destructive-git", decision: "ask", test: /\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f[a-z]*d|clean\s+-[a-z]*d[a-z]*f|filter-branch|filter-repo)\b/i, reason: "Destructive git operation." },
  { id: "publish", decision: "ask", test: /\b(npm|pnpm|yarn)\s+publish\b|\bdocker\s+push\b|\bgh\s+release\s+create\b/i, reason: "Publishes artifacts outside this machine." },
  { id: "privileged", decision: "ask", test: /\bsudo\b|\bdocker\s+run\b[^\n]*(--privileged|docker\.sock)|\bchmod\s+(-R\s+)?777\b/i, reason: "Privileged or permission-weakening command." },
  { id: "env-dump", decision: "ask", test: /(^|[;&|]\s*)(printenv|env|set|export\s+-p)\s*($|[;&|>])/, reason: "Dumps environment variables (may contain secrets) into the agent context." },
  { id: "infra-destroy", decision: "ask", test: /\b(terraform\s+destroy|kubectl\s+delete|dropdb|DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE)\b/i, reason: "Destroys infrastructure or data." },
];

function fileGuard(toolName: string, filePath: string, cwd: string): GuardResult | undefined {
  const abs = path.resolve(cwd, filePath.replace(/^~(?=\/|$)/, os.homedir()));
  const rel = path.relative(cwd, abs).split(path.sep).join("/");
  const writing = toolName !== "Read";
  if (/(^|\/)\.mungard\/(approvals\.json|audit\.log\.jsonl|findings\.json|runs\/)/.test(rel)) {
    return { decision: "deny", reasons: ["The agent must not modify or read Mungard's approval queue, audit log or evidence store directly; use the Mungard MCP tools."], rule: "workspace-tamper" };
  }
  if (writing && /(^|\/)\.mungard\/config\.yaml$/.test(rel)) {
    return { decision: "ask", reasons: ["Changing Mungard's security policy/scope. A human should review this change."], rule: "policy-change" };
  }
  if (writing && /(^|\/)\.claude\/settings(\.local)?\.json$|(^|\/)\.mcp\.json$|(^|\/)\.cursor\/mcp\.json$|(^|\/)\.vscode\/mcp\.json$/.test(rel)) {
    return { decision: "ask", reasons: ["The agent is changing its own permissions, hooks or MCP servers."], rule: "agent-config-change" };
  }
  if (!SECRET_FILE_SAFE.test(abs) && SECRET_FILE.test(` ${abs}`)) {
    return { decision: toolName === "Read" ? "deny" : "ask", reasons: [`${path.basename(abs)} looks like a secrets/credentials file.`], rule: "secret-file" };
  }
  return undefined;
}

export function evaluateGuard(req: GuardRequest): GuardResult {
  const cwd = req.cwd ?? process.cwd();
  const input = req.toolInput ?? {};
  const str = (k: string) => (typeof input[k] === "string" ? (input[k] as string) : "");

  if (req.toolName === "Bash") {
    const cmd = str("command");
    const hits = BASH_RULES.filter((r) => r.test.test(cmd));
    const secretRead = SECRET_FILE.test(` ${cmd}`) && !/\.env\.(example|sample|template)/.test(cmd) && !/\.pub\b/.test(cmd);
    if (secretRead && /\b(cat|less|more|head|tail|grep|rg|awk|sed|base64|xxd|od|strings|cp|mv|scp|curl|source|\.)\b|<\s*\S/.test(cmd)) {
      hits.unshift({ id: "secret-file", decision: "deny", test: /./, reason: "Reads or copies a secrets/credentials file into the agent context." });
    }
    if (STRONG_SECRET.some((re) => re.test(cmd))) {
      hits.push({ id: "secret-in-command", decision: "ask", test: /./, reason: "The command contains what looks like a literal credential." });
    }
    const deny = hits.filter((h) => h.decision === "deny");
    if (deny.length) return { decision: "deny", reasons: deny.map((h) => h.reason), rule: deny[0]!.id };
    if (hits.length) return { decision: "ask", reasons: hits.map((h) => h.reason), rule: hits[0]!.id };
    return { decision: "none", reasons: [] };
  }

  if (["Read", "Write", "Edit", "MultiEdit", "NotebookEdit"].includes(req.toolName)) {
    const filePath = str("file_path") || str("notebook_path") || str("path");
    if (filePath) {
      const r = fileGuard(req.toolName, filePath, cwd);
      if (r) return r;
    }
    if (req.toolName !== "Read") {
      const edits = Array.isArray(input.edits) ? (input.edits as Record<string, unknown>[]).map((e) => String(e.new_string ?? "")) : [];
      const text = [str("content"), str("new_string"), str("new_source"), ...edits].join("\n");
      if (STRONG_SECRET.some((re) => re.test(text)) && !/\.(example|sample|template)$/.test(filePath)) {
        return {
          decision: "ask",
          reasons: ["The change writes what looks like a hardcoded credential into a file. Use an environment variable or secret manager instead; if this key is real, rotate it."],
          rule: "hardcoded-secret",
        };
      }
    }
    return { decision: "none", reasons: [] };
  }

  if (req.toolName === "WebFetch") {
    const url = str("url");
    try {
      const u = new URL(url);
      if (u.protocol !== "http:" && u.protocol !== "https:") return { decision: "deny", reasons: [`Protocol ${u.protocol} is not allowed.`], rule: "fetch-protocol" };
      if (isBlockedAddress(u.hostname)) return { decision: "deny", reasons: ["Fetching a cloud metadata / link-local address."], rule: "fetch-metadata" };
      if (/[?&](token|key|secret|password|session)=/i.test(u.search)) {
        return { decision: "ask", reasons: ["The URL carries what looks like a credential in its query string."], rule: "fetch-credential" };
      }
    } catch {
      return { decision: "none", reasons: [] };
    }
  }
  return { decision: "none", reasons: [] };
}

/** Claude Code PreToolUse hook output. `none` produces no output (normal permission flow). */
export function toClaudeCodeHookOutput(r: GuardResult): string | undefined {
  if (r.decision === "none") return undefined;
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: r.decision,
      permissionDecisionReason: `Mungard Guard (${r.rule}): ${r.reasons.join(" ")}`,
    },
  });
}

export function claudeCodeHookSettings(command = "mungard guard hook"): Record<string, unknown> {
  return {
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
          hooks: [{ type: "command", command, timeout: 10 }],
        },
      ],
    },
    permissions: {
      deny: ["Bash(mungard approvals approve:*)", "Bash(mungard approvals deny:*)", "Edit(.mungard/**)", "Write(.mungard/**)", "Read(./.env)", "Read(./.env.*)"],
    },
  };
}
