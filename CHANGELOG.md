# Changelog

## 0.1.0 (unreleased)

Initial MVP.

- CLI: `init`, `doctor`, `scan`, `audit`, `mcp inspect|serve|config`, `web-scan`, `api`, `authz`, `plan`, `findings`, `triage`, `remediate`, `retest`, `report`, `approvals`, `policy`, `audit-log`, `guard`.
- Engines: Semgrep (bundled Apache-2.0 JS/TS/Next.js rules), Gitleaks (tree + history), npm audit, OWASP ZAP (baseline/active/API via Docker), OpenAPI analyzer, HTTP header/CORS probe, multi-account authorization & business-logic tester, MCP config inspector (static + live tool inspection), AI agent config auditor.
- Policy engine with scope enforcement, always-gated risky operations, single-use parameter-bound approvals, redaction and an append-only audit log.
- Normalized, versioned finding schema (v1.0.0) with dedup, evidence, status workflow, triage (heuristic + Claude), remediation guidance and before/after retests.
- Reports: Markdown, JSON, SARIF 2.1.0.
- MCP server (stdio) with 20 narrowly scoped tools; Next.js web UI with chat (AI or offline mode), findings, approvals, runs and reports.
- Mungard Guard: Claude Code PreToolUse hook for agent actions.
