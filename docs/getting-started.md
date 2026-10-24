# Getting started

This guide takes you from a fresh clone to your first report. It needs about 10 minutes, plus image downloads if you rely on Docker.

## 1. Requirements

| Requirement | Why | Check |
|---|---|---|
| Node.js **22.12+** (24 LTS recommended) | Mungard runtime | `node -v` |
| git | secret history scan, code version on retests | `git --version` |
| Docker *or* local engines | Semgrep, Gitleaks and OWASP ZAP | `docker info` |
| `package-lock.json` in your app | npm audit | `npm install --package-lock-only` |

Local engines are preferred when present: `brew install semgrep gitleaks` (macOS) or `pipx install semgrep`. OWASP ZAP always runs from the official `ghcr.io/zaproxy/zaproxy:stable` image.

Supported platforms: macOS and Linux. Windows has not been tested yet.

## 2. Install

```bash
git clone https://github.com/modalqa/Mungard.git
cd Mungard
npm ci                       # install scripts are disabled by .npmrc (supply-chain hardening)
npm run build
(cd packages/cli && npm link)
mungard --version
```

## 3. Initialize your project

```bash
cd /path/to/your/app
mungard init .
```

`init` detects languages, frameworks, the package manager, OpenAPI specs, routes, MCP configs and AI-agent files. It then writes `.mungard/config.yaml`. It never modifies application source code. The `.mungard/` directory contains its own `.gitignore`, so only `config.yaml` can be committed. Results, evidence and approvals stay local.

**Review the config before scanning.** In particular, check:

- `target.baseUrl` is your **local or staging** app (production is denied by default);
- `policy.targets.allowedHosts` / `allowedPorts`;
- `engines.semgrep.registryRules`: empty by default, which means Mungard's Apache-2.0 rules only. See [licensing](licensing.md) before adding Semgrep Registry packs.

## 4. Check the setup

```bash
mungard doctor
```

This shows which engines are available (local binary, Docker or built in), whether the target is in scope and reachable, and whether AI credentials were found.

## 5. Scan

```bash
mungard scan .                    # SAST + secrets + dependencies (fast, no running app needed)
mungard audit .                   # + agent config, MCP config, OpenAPI, runtime tests if the app runs
mungard mcp inspect               # MCP configs only
```

Each run prints which engines ran, which **did not run** (and why), what was blocked by policy, and the coverage gaps. A failed engine is never reported as "no issues".

## 6. Runtime and authorization tests

Start your app, then add test accounts. Credentials are always referenced from the environment:

```yaml
auth:
  accounts:
    - name: alice
      role: member
      headers: { Authorization: "Bearer ${env:MUNGARD_ALICE_TOKEN}" }
    - name: bob
      role: member
      headers: { Authorization: "Bearer ${env:MUNGARD_BOB_TOKEN}" }
authorization:
  checks:
    - id: invoice-ownership
      description: Members can only read their own invoices
      request: { method: GET, path: /api/invoices/inv_alice_1 }
      owner: alice
      denied: [bob, anonymous]
      sensitiveMarkers: ["alice@example.test"]
```

```bash
export MUNGARD_ALICE_TOKEN=... MUNGARD_BOB_TOKEN=...
mungard plan              # suggests checks and scenarios from your OpenAPI spec / routes
mungard authz             # read-only tests
mungard authz --include-write-tests   # state-changing scenarios: asks for approval first
mungard web-scan          # passive OWASP ZAP baseline + header/CORS checks
```

## 7. Review, fix, retest

```bash
mungard findings list --unresolved
mungard findings show MG-XXXXXXXXXX
mungard triage                      # advisory: likely true/false positive, missing evidence
mungard remediate MG-XXXXXXXXXX     # fix guidance + regression test
# ...apply the fix...
mungard retest MG-XXXXXXXXXX        # closes the finding only if the engine ran and the issue is gone
mungard report --format md          # or json / sarif
```

## 8. Connect your coding agent

```bash
claude mcp add --scope project mungard -- mungard mcp serve
mungard guard install                # optional: guardrail hook for Claude Code tool calls
```

Next: [CLI reference](cli.md) · [Configuration](configuration.md) · [MCP](mcp.md).
