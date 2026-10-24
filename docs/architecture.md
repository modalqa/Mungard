# Architecture

```
 ┌──────────────┐   ┌───────────────┐   ┌──────────────────────────┐
 │  CLI          │   │  MCP server    │   │  Web UI (Next.js)         │
 │  packages/cli │   │  stdio         │   │  chat · findings · approve│
 └──────┬───────┘   └──────┬────────┘   └────────────┬─────────────┘
        │                  │   tool registry (Zod)     │  chat agent (LLM provider)
        └──────────────────┴────────────┬─────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │ @mungard/core                  │
                         │  detect · plan · orchestrator  │
                         │  triage · retest · remediation │
                         │  report · guard · tools · agent│
                         └──────┬────────────────┬───────┘
                                │                │
              ┌─────────────────▼───┐   ┌────────▼────────────────────┐
              │ @mungard/policy-     │   │ @mungard/adapters            │
              │ engine               │   │  semgrep · gitleaks · npm    │
              │  scope · rules ·     │   │  audit · zap (docker) ·      │
              │  approvals · audit · │   │  openapi · http-probe ·      │
              │  redaction           │   │  authz · mcp-inspector ·     │
              └──────────────────────┘   │  agent-config                │
                                         └────────┬─────────────────────┘
                                                  ▼
                         ┌───────────────────────────────┐
                         │ @mungard/findings (schema v1)  │ ──► @mungard/reporting (md · json · sarif)
                         └───────────────────────────────┘
                                         │
                                 <project>/.mungard/  (local workspace)
```

## Packages

| Package | Responsibility |
|---|---|
| `@mungard/findings` | Versioned Zod schema, normalization, fingerprinting, deduplication, status workflow rules |
| `@mungard/policy-engine` | Policy schema, operation rules (with the always-gated floor), target scope + DNS check, approvals store, audit log, redaction |
| `@mungard/adapters` | One adapter per engine: input schema, health check, safe process execution (no shell, timeout, output cap, minimal env), output parser, normalized raw findings, coverage and gaps |
| `@mungard/reporting` | Markdown, JSON and SARIF renderers |
| `@mungard/core` | Config, project detection, workspace store (with a cross-process lock), orchestrator, planner, triage (heuristic + LLM), retest, remediation, report assembly, Mungard Guard, the shared **tool registry**, the chat agent and the LLM provider abstraction |
| `@mungard/mcp-server` | Registers the tool registry on an MCP server (stdio) |
| `mungard` (CLI) | Commander-based CLI on top of core |
| `@mungard/web` | Next.js 16 App Router UI and route handlers |

The **tool registry** (`packages/core/src/tools.ts`) is the single definition of what an agent may do. MCP and the chat UI both use it, so their capabilities and validation are identical.

## Execution model

1. An interface turns a request into steps (`sast, secrets, deps, agent, mcp, api, headers, web, authz`).
2. For each step the orchestrator builds the adapter input and asks the policy engine to authorize the **operation + target + exact parameters**.
3. Denied or approval-pending steps are recorded in the run (`blocked[]`) and reported as gaps. Nothing runs.
4. Allowed steps run their adapter with an `AdapterContext` (project root, policy, redactor, evidence directory, abort signal).
5. Raw findings are normalized, merged into the store by fingerprint, and the run record is saved **after each step**, so partial results survive a later failure.
6. Engine failures are captured per step and never discard other engines' results.

The chat agent uses the Anthropic Messages API with a manual streaming tool-use loop (`claude-opus-5-5` by default, adaptive thinking, `fallbacks: "default"`). Tool inputs are validated with Zod, and tool results are wrapped in `<untrusted_tool_output>`. History is append-only and kept in server memory for the session. Without credentials, the chat uses deterministic keyword routing (offline mode).

## PRD traceability (MVP)

| PRD requirement | Status | Where |
|---|---|---|
| FR-01 Project initialization | Implemented | `core/detect.ts`, `mungard init` |
| FR-02 Standalone chat | Implemented (AI + offline modes) | `core/agent.ts`, `apps/web` |
| FR-03 Coding agent integration (MCP) | Implemented | `mcp-server`, `core/tools.ts` |
| FR-04 SAST | Implemented (Semgrep + bundled rules) | `adapters/semgrep*.ts` |
| FR-05 Secret scanning | Implemented (tree + history, committed/ignored status) | `adapters/gitleaks.ts` |
| FR-06 Dependency scanning | Implemented for npm (`package-lock.json`) | `adapters/npm-audit.ts` |
| FR-07 DAST | Implemented (ZAP baseline; active with approval; API scan) | `adapters/zap.ts` |
| FR-08 REST API analysis | Implemented (OpenAPI 2/3 inventory, checks, anonymous probes) | `adapters/openapi.ts`, `authz.ts` |
| FR-09 Authn/authz testing | Implemented (multi-account, BOLA/IDOR, roles, tenants via checks) | `adapters/authz.ts` |
| FR-10 Business logic | Implemented (configured scenarios; suggestions require confirmation) | `authz.ts`, `core/plan.ts` |
| FR-11 Findings & evidence | Implemented | `findings`, `core/workspace.ts` |
| FR-12 AI triage | Implemented (heuristic + Claude, advisory) | `core/triage.ts`, `core/llm.ts` |
| FR-13 Remediation & retest | Implemented (guidance + retest; no automatic code edits) | `core/remediation.ts`, `core/retest.ts` |
| FR-14 Reporting | Implemented (md, json, sarif) | `reporting`, `core/report.ts` |
| FR-15 Policy & audit | Implemented | `policy-engine` |
| SR-01 … SR-09 | Implemented as described in [policy-and-approvals.md](policy-and-approvals.md) | |
| Playwright browser automation | **Not yet**: used only for testing the web UI; authenticated browser flows are on the roadmap | – |
| PostgreSQL persistent workspace | **Not needed for MVP**: filesystem workspace | – |
| Remote execution workers | **Out of MVP scope** (PRD 7.4) | – |

Positioning additions beyond the PRD: the **MCP inspector**, the **agent-config auditor** and **Mungard Guard** cover the "AI agent behavior and MCP integration" part of the product positioning.
