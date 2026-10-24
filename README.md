<p align="center">
  <img src="assets/logo.jpeg" alt="Mungard logo" width="260">
</p>

<h1 align="center">Mungard</h1>

<p align="center"><strong>Open-source AI security testing agent. Guard every agent action.</strong></p>

<p align="center">
  <a href="https://github.com/modalqa/Mungard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/modalqa/Mungard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
</p>

Mungard is a **security layer for AI coding agents**. It helps you test the security of your code, of your AI agent's configuration and behavior, and of your MCP integrations, using existing scanners, targeted tests, evidence for every finding, and human approval for anything risky.

```bash
mungard scan .          # source code, secrets and dependencies
mungard audit .         # everything: + agent config, MCP config, OpenAPI, runtime tests
mungard mcp inspect     # MCP server configurations (and, with approval, live tool definitions)
```

It runs **locally**. Source code, credentials, scan results and evidence stay on your machine. AI features are optional, and they only send redacted, minimized context to the model provider you configure.

---

## Why

AI coding agents write code fast, but they cannot guarantee it is secure. They also operate with real permissions: shell access, MCP servers, secrets in the environment. Mungard gives developers (and their agents) a structured security workflow:

**find → verify → fix → retest**, with a policy engine in front of every action.

| Principle | What it means in Mungard |
|---|---|
| **Local-first** | Everything lives in `<project>/.mungard/` (gitignored). No account required. |
| **AI-orchestrated, tool-executed** | AI plans and explains. Proven engines (Semgrep, Gitleaks, npm audit, OWASP ZAP) and deterministic built-in tests do the checking. |
| **Evidence-driven** | Every finding has a source, detection method, confidence, verification status and redacted evidence. Scanner output is never presented as "confirmed". |
| **Human-in-the-loop** | Active scans, state-changing tests and launching MCP servers require explicit human approval. Agents cannot approve their own requests. |
| **Extensible** | Engines are adapters with a schema, health check, timeout, parser and normalizer. |

## What it checks

| Area | Engine | Command |
|---|---|---|
| Static analysis (SQLi, command injection, path traversal, SSRF, XSS, JWT misuse, Next.js secret exposure…) | Semgrep with Mungard's bundled Apache-2.0 JS/TS rules | `mungard scan .` |
| Secrets in files **and git history** (reports whether each one is committed and/or gitignored) | Gitleaks | `mungard scan .` |
| Vulnerable dependencies | npm audit | `mungard scan .` |
| AI agent configuration: hidden Unicode and prompt injection in `CLAUDE.md`/`AGENTS.md`/rules, over-broad permissions, `bypassPermissions`, exfiltrating hooks | built in | `mungard audit .` |
| MCP configuration: hardcoded/committed credentials, unpinned `npx`/`uvx` packages, shell wrappers, privileged Docker, broad filesystem access, plain-HTTP remotes; live tool poisoning, shadowing and rug-pull detection | built in | `mungard mcp inspect` |
| OpenAPI analysis: endpoint inventory, auth requirements, BOLA candidates, spec-level issues | built in | `mungard api` |
| Security headers, cookies, CORS on the running app | built in | `mungard web-scan` |
| Web DAST (passive baseline; active scan only with approval) | OWASP ZAP (Docker) | `mungard web-scan [--active]` |
| Authentication, authorization (BOLA/IDOR, roles, tenants) and business-logic scenarios with real test accounts | built in | `mungard authz` |

Plus: AI-assisted triage, remediation guidance with regression tests, before/after **retests** tied to a git commit, and reports in **Markdown, JSON and SARIF**.

## Quick start

Requirements: **Node.js 22.12+** (24 recommended), git, and either the engines installed locally or **Docker** (Semgrep, Gitleaks and ZAP run from their official images when no local binary is found).

```bash
git clone https://github.com/modalqa/Mungard.git
cd Mungard
npm ci
npm run build
(cd packages/cli && npm link)  # puts `mungard` on your PATH (or run: node packages/cli/dist/index.js)

cd /path/to/your/app
mungard init .                 # detects the stack, writes .mungard/config.yaml (no source changes)
mungard doctor                 # checks engines, config, target, AI credentials
mungard scan .                 # SAST + secrets + dependencies
mungard audit .                # full assessment
mungard report --format md     # report in .mungard/reports/
```

Try it against the bundled, intentionally vulnerable fixtures:

```bash
node tests/fixtures/vulnerable-api/server.mjs 4010 &
export MUNGARD_ALICE_TOKEN=alice-token MUNGARD_BOB_TOKEN=bob-token
mungard audit tests/fixtures/vulnerable-api --no-dast
mungard mcp inspect tests/fixtures/vulnerable-app
```

## Use it from Claude Code (MCP)

```bash
claude mcp add --scope project mungard -- mungard mcp serve
```

Then ask Claude Code things like *"Plan a security assessment for this app"*, *"Check whether users can read other users' invoices"*, or *"Retest MG-1A2B3C4D5E after my fix"*. Mungard exposes narrowly scoped MCP tools (`plan_security_assessment`, `run_static_scan`, `run_web_scan`, `run_authorization_tests`, `inspect_mcp_config`, `list_findings`, `get_finding_evidence`, `propose_remediation`, `run_retest`, `generate_security_report`, …). It has no "run arbitrary command" tool and no "approve" tool. See [docs/mcp.md](docs/mcp.md).

### Guard the agent itself

`mungard guard` is a Claude Code `PreToolUse` hook that denies or asks before risky agent actions: reading `.env` or SSH keys, `curl … | sh`, self-approving Mungard requests, writing hardcoded credentials, force pushes, uploads to remote hosts. Run `mungard guard install` to print the settings snippet. See [docs/policy-and-approvals.md](docs/policy-and-approvals.md#mungard-guard).

## Standalone chat UI

```bash
MUNGARD_PROJECT_ROOT=/path/to/your/app npm run dev:web   # http://127.0.0.1:3737
```

The web UI (Next.js) provides a chat with the security agent, plus findings, approvals, runs and reports. With `ANTHROPIC_API_KEY` set (or `ant auth login`), the chat uses Claude (`claude-opus-5-5` by default, configurable). Without credentials it runs in **offline mode**: requests are routed to tools directly, with no AI interpretation. It binds to `127.0.0.1` only and rejects foreign `Host`/`Origin` headers.

## Safety model in one paragraph

Every operation goes through the **policy engine**: target allowlists (hosts and ports; production and cloud-metadata addresses blocked), per-operation rules (`allow` / `require_approval` / `deny`), time, rate and request limits, and redaction. **Active scans, state-changing tests and live MCP inspection always require approval**, and configuration cannot relax that. Approvals are single-use, expire, and are bound to the exact parameters. Tool output (code, web pages, scanner output) is treated as untrusted data, never as instructions. Everything is recorded in an append-only, redacted audit log. Details: [docs/policy-and-approvals.md](docs/policy-and-approvals.md).

## Documentation

- [Getting started](docs/getting-started.md)
- [CLI reference](docs/cli.md)
- [Configuration](docs/configuration.md)
- [MCP server & tools](docs/mcp.md)
- [Policy, approvals & Mungard Guard](docs/policy-and-approvals.md)
- [Findings, triage, retests & reports](docs/findings-and-reports.md)
- [Architecture](docs/architecture.md)
- [Writing an adapter](docs/adapters.md)
- [Coverage & limitations](docs/coverage-and-limitations.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Licensing of dependencies & engines](docs/licensing.md)
- [Product requirements (PRD)](docs/PRD.md)

## Limitations (read these)

Mungard reduces risk. It does **not** prove an application is secure, and it does not replace a penetration test. Scanners produce false positives and false negatives. Business-logic tests are only as good as the rules you confirm. See [docs/coverage-and-limitations.md](docs/coverage-and-limitations.md).

## Contributing & security

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability in Mungard itself, follow [SECURITY.md](SECURITY.md) and do not open a public issue.

## License

[Apache-2.0](LICENSE). Third-party engines keep their own licenses; see [NOTICE](NOTICE) and [docs/licensing.md](docs/licensing.md).
