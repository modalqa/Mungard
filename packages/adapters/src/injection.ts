/**
 * Heuristics for instructions hidden in text that an AI agent will read:
 * agent instruction files (CLAUDE.md, .cursorrules...) and MCP tool
 * descriptions. These are indicators for human review, not proof.
 */

export interface TextIndicator {
  id: string;
  label: string;
  severity: "high" | "medium" | "low";
  /** 1-based line of the first match. */
  line: number;
  excerpt: string;
}

const INVISIBLE = /[\u{E0000}-\u{E007F}​-‏‪-‮⁠-⁤⁦-⁩﻿]/u;

const PHRASES: { id: string; label: string; severity: TextIndicator["severity"]; re: RegExp }[] = [
  { id: "override", label: "Attempts to override prior instructions", severity: "high", re: /\b(ignore|disregard|forget)\b.{0,30}\b(all|any|previous|prior|above|earlier|system)\b.{0,20}\b(instructions?|prompts?|rules?|guidelines)\b/i },
  { id: "concealment", label: "Asks the agent to hide actions from the user", severity: "high", re: /\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|reveal|notify|show)\b.{0,30}\b(the )?user\b/i },
  { id: "fake-tag", label: "Pseudo system/important tags used to smuggle instructions", severity: "medium", re: /<\s*\/?\s*(important|system|secret|instructions?|admin|override)\s*>/i },
  { id: "sensitive-files", label: "References credential or agent-config files", severity: "high", re: /(~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.npmrc|\.netrc|\.git-credentials|claude\.json|mcp\.json|\.env\b)/i },
  { id: "exfiltration", label: "Instructs sending data to an external destination", severity: "high", re: /\b(send|post|upload|forward|exfiltrate|transmit|leak)\b.{0,60}\b(https?:\/\/|webhook|endpoint|server|email)/i },
  { id: "pipe-to-shell", label: "Downloads and executes a remote script", severity: "high", re: /\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,200}\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|iex)\b/i },
  { id: "disable-safety", label: "Tells the agent to bypass permission or safety checks", severity: "medium", re: /(--dangerously-skip-permissions|bypassPermissions|skip (all )?(permission|confirmation|approval)s?|without (asking|confirmation|approval)|auto-?approve)/i },
  { id: "tool-precondition", label: "Requires reading/sending data before using a tool", severity: "medium", re: /\bbefore (using|calling|invoking)\b.{0,40}\b(read|include|pass|send|attach)\b/i },
  { id: "base64-blob", label: "Large encoded blob that may hide instructions", severity: "low", re: /[A-Za-z0-9+/]{300,}={0,2}/ },
];

export function findTextIndicators(text: string): TextIndicator[] {
  const out: TextIndicator[] = [];
  const lines = text.split("\n");
  const lineOf = (index: number) => text.slice(0, index).split("\n").length;
  const inv = text.match(INVISIBLE);
  if (inv && inv.index !== undefined) {
    const count = [...text].filter((ch) => INVISIBLE.test(ch)).length;
    const line = lineOf(inv.index);
    out.push({
      id: "invisible-unicode",
      label: `Contains ${count} invisible/bidirectional Unicode character(s) that can hide instructions from human reviewers`,
      severity: "high",
      line,
      excerpt: visualize((lines[line - 1] ?? "").slice(0, 200)),
    });
  }
  for (const p of PHRASES) {
    const m = p.re.exec(text);
    if (!m || m.index === undefined) continue;
    const line = lineOf(m.index);
    out.push({ id: p.id, label: p.label, severity: p.severity, line, excerpt: visualize((lines[line - 1] ?? "").trim().slice(0, 200)) });
  }
  return out;
}

/** Make invisible characters visible as <U+XXXX> so reviewers can see them. */
export function visualize(s: string): string {
  return [...s].map((ch) => (INVISIBLE.test(ch) ? `<U+${ch.codePointAt(0)!.toString(16).toUpperCase()}>` : ch)).join("");
}
