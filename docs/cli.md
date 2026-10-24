# CLI reference

`mungard <command> [options]`. Every command that takes a project accepts either a positional `[path]` or `--root <path>`. The default is the current directory.

Progress is printed to **stderr** and results to **stdout**, so `--json` output can be piped.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (findings may exist but did not reach `--fail-on`) |
| 1 | Unresolved findings at or above `--fail-on`; a failed retest; a guard `check` that denied |
| 2 | Usage/configuration error, or an approval attempted from a non-interactive terminal |
| 3 | `--strict` and at least one engine failed or was unavailable |

## Setup

| Command | Description |
|---|---|
| `mungard init [path] [--target <url>] [--force]` | Detect the project and write `.mungard/config.yaml`. Never modifies source code. |
| `mungard doctor [path]` | Node version, config, engine health (local/Docker/built in), AI credentials, target scope and reachability. |
| `mungard engines` | List built-in engines and their policy operations. |
| `mungard plan [path] [--json]` | Show what an audit would run, the policy decision per check, missing prerequisites, and suggested authorization/business-logic scenarios (templates in `--json`). Runs nothing. |

## Assessments

Shared options for the commands below:

| Option | Description |
|---|---|
| `--fail-on <severity>` | Exit 1 if unresolved findings at/above `critical\|high\|medium\|low\|info` exist |
| `--format <md\|json\|sarif>` / `-o, --output <file>` | Also write a report |
| `--json` | Print the run and findings as JSON |
| `--strict` | Exit 3 if an engine failed or was unavailable (recommended in CI) |

| Command | Runs |
|---|---|
| `mungard scan [path] [--only sast,secrets,deps,...]` | Semgrep, Gitleaks (working tree + history), npm audit |
| `mungard audit [path]` | scan + agent config + MCP config + OpenAPI + headers + authz + passive ZAP. Options: `--target <url>`, `--no-dast`, `--no-runtime`, `--include-write-tests`, `--mcp-live`, `--include-user-config` |
| `mungard mcp inspect [path]` | MCP config analysis. `--live` starts servers to inspect tool definitions (approval required); `--server <names...>`; `--include-user-config` reads `~/.claude.json` (this project's entry only), Claude Desktop, Cursor, Windsurf, Gemini configs |
| `mungard web-scan [url] [--active]` | Header/CORS probe + OWASP ZAP baseline. `--active` sends attack payloads and always needs approval |
| `mungard api [spec]` | OpenAPI inventory and spec-level checks |
| `mungard authz [--include-write-tests] [--only <ids...>]` | Authorization checks, business-logic scenarios, anonymous probes of documented endpoints |

Valid step ids for `--only`: `sast, secrets, deps, agent, mcp, api, headers, web, authz`.

## Findings

| Command | Description |
|---|---|
| `mungard findings list [--status ...] [--severity ...] [--unresolved] [--json]` | Most severe first |
| `mungard findings show <id>` | Full finding (redacted) |
| `mungard findings set-status <id> <status> --reason "..."` | Human status change: `new, needs_review, confirmed, false_positive, accepted_risk, fixed`. `retested` can only be set by a passing retest |
| `mungard triage [ids...] [--no-ai] [--dry-run]` | Heuristic (+ AI if configured) triage. Advisory only. `--dry-run` prints the exact redacted payload that would be sent to the model |
| `mungard remediate <id>` | Fix guidance, affected code, regression test, retest command |
| `mungard retest <ids...>` | Re-runs only the producing engines/checks, records the git commit, compares before/after |
| `mungard report [--format md\|json\|sarif] [-o file] [--stdout]` | Report from the workspace |

## Approvals, policy, audit

| Command | Description |
|---|---|
| `mungard approvals list [--all]` | Pending (or all) approval requests |
| `mungard approvals approve <id> [--note]` | Interactive only: shows what will happen and asks you to type `approve` |
| `mungard approvals deny <id> [--note]` | Interactive only |
| `mungard policy` | Effective policy including per-operation rules |
| `mungard audit-log [-n 50]` | Recent audit entries |

## MCP server and guard

| Command | Description |
|---|---|
| `mungard mcp serve [--root <path>]` | MCP server over stdio. `MUNGARD_PROJECT_ROOT` also sets the root |
| `mungard mcp config` | Print client configuration snippets |
| `mungard guard hook` | Claude Code `PreToolUse` hook (reads JSON from stdin) |
| `mungard guard check <tool> '<json>'` | Evaluate a tool call manually |
| `mungard guard install` | Print the Claude Code settings that enable the hook and deny rules |
| `mungard ui` | How to start the web UI |

## CI example

```bash
mungard scan . --strict --fail-on high --format sarif --output mungard.sarif
```

Upload `mungard.sarif` with `github/codeql-action/upload-sarif`. This repository's own [CI workflow](../.github/workflows/ci.yml) does exactly that.
