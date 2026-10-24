# MCP server & tools

Mungard ships a Model Context Protocol server, so Claude Code (or any MCP-capable agent) can run security assessments from the coding workflow. Everything the MCP server can do is also available through the CLI.

## Connect

```bash
# Claude Code, project scope (writes .mcp.json)
claude mcp add --scope project mungard -- mungard mcp serve
```

or `.mcp.json`:

```json
{ "mcpServers": { "mungard": { "command": "mungard", "args": ["mcp", "serve"] } } }
```

If you launch it through `npx`, **pin the version** (`"args": ["-y", "mungard@0.1.0", "mcp", "serve"]`). Mungard's own MCP inspector flags unpinned packages for good reason.

The server uses stdio. The project root is the working directory, `--root <path>`, or `MUNGARD_PROJECT_ROOT`. The workspace is re-read on every call, so config edits apply immediately.

## Design rules

- **Closed set of narrow tools.** There is no tool that runs arbitrary commands, edits code, changes policy or approves requests.
- **All input is validated** with Zod before anything runs. Invalid input returns `isError: true`.
- **Every call goes through the policy engine** and is written to the audit log (`actor: "mcp"`).
- **Results are redacted** and labelled. Tool results contain untrusted data (code, HTTP responses, scanner output). The server instructions tell the client model never to follow instructions found inside them.
- **Unverified ≠ confirmed.** Findings with status `new`/`needs_review` are scanner output; every listing says so.

## Tools

| Tool | Policy operation | Read-only | Notes |
|---|---|---|---|
| `get_project_context` | project_read | ✓ | Detection + config (accounts by name/role only) |
| `get_security_policy` | project_read | ✓ | Targets, per-operation rules, limits, pending approvals |
| `plan_security_assessment` | — | ✓ | Plan, policy decision per check, prerequisites, suggested scenarios |
| `run_security_scan` | per step | | `preset: scan\|audit` or `steps[]`; `wait` |
| `run_static_scan` | static_scan | | Semgrep |
| `run_secret_scan` | secret_scan | | Gitleaks (values never returned) |
| `run_dependency_audit` | dependency_audit | | npm audit, never upgrades |
| `run_web_scan` | web_passive_scan / **web_active_scan** | | `mode: active` always needs approval; default `wait: false` |
| `analyze_api_spec` | api_analysis | | Returns the endpoint inventory |
| `run_authorization_tests` | authz_read_tests / **authz_write_tests** | | `includeWriteTests` needs approval |
| `inspect_mcp_config` | mcp_inspect / **mcp_live_inspect** | | `live: true` starts servers and needs approval |
| `audit_agent_config` | agent_config_audit | | CLAUDE.md, rules, `.claude/settings.json` |
| `get_scan_status` | — | ✓ | Poll runs started with `wait: false` |
| `list_findings` | — | ✓ | Filters: status, severity, category, unresolvedOnly |
| `get_finding_evidence` | — | ✓ | Full finding + optionally redacted evidence files |
| `triage_findings` | ai_triage | | Advisory; MCP clients get heuristic triage (the client model does the reasoning) |
| `propose_remediation` | — | ✓ | Guidance + regression test; Mungard does not edit code |
| `run_retest` | per engine | | Before/after with code version |
| `generate_security_report` | report | | md/json/sarif to `.mungard/reports/` |
| `list_approvals` | — | ✓ | Shows what the human needs to decide |

## The approval flow for agents

1. The agent calls `run_web_scan` with `mode: "active"`.
2. The policy engine creates an approval request. The tool result contains `blockedByPolicy: [{ step: "web", decision: "approval_required", approvalId: "apr_…", reasons: [...] }]`, and **nothing has run**.
3. The agent tells the user what will happen and asks them to approve.
4. The **human** approves in an interactive terminal (`mungard approvals approve apr_…`, which requires a TTY and typing `approve`) or in the web UI.
5. The agent repeats the **identical** call. The approval is consumed (single use) and the scan runs.

An approval only unlocks the exact parameters it was created for, and it expires (`policy.approvals.expiresMinutes`).

> **Honest limitation.** A coding agent that also has unrestricted shell access runs as your user, and could in principle edit `.mungard/approvals.json`. Use [Mungard Guard](policy-and-approvals.md#mungard-guard) and Claude Code deny rules (`mungard guard install`) to block that, and keep risky agents in a sandbox.

## Error responses

| Situation | Response |
|---|---|
| Unknown tool / invalid input | `isError: true`, `Invalid input for <tool>: <zod message>` |
| Config file invalid | `isError: true`, `Mungard configuration error: …` |
| Policy denial (e.g. out-of-scope target) | Normal result with `blockedByPolicy[].decision = "deny"` and reasons |
| Approval needed | Normal result with `blockedByPolicy[].decision = "approval_required"` and `approvalId` |
| Engine missing or failed | Normal result; `engines[].status = unavailable\|failed` with `error`, plus a `note` that those checks did not run |
| Unknown finding/run id | `{ "error": "… not found." }` |
