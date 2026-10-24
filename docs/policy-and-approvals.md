# Policy, approvals & Mungard Guard

## The policy engine

Every operation, whether it comes from the CLI, MCP, chat or web UI, is authorized by one choke point: `PolicyEngine.authorize()` in `packages/policy-engine`. Adapters never decide scope themselves.

```
request ──► operation rule ──► target scope ──► allow
                 │                  │          └► approval required ──► human decides ──► single-use allow
                 └► deny            └► deny
```

### Operations

| Operation | Default | Can be relaxed to `allow`? |
|---|---|---|
| project_read, static_scan, secret_scan, dependency_audit, agent_config_audit, mcp_inspect, api_analysis, http_probe, web_passive_scan, authz_read_tests, ai_triage, retest, report, finding_update | allow | – |
| **web_active_scan** (ZAP attack payloads) | require_approval | **No** |
| **authz_write_tests** (POST/PUT/PATCH/DELETE as test users) | require_approval | **No** |
| **mcp_live_inspect** (launches third-party MCP servers) | require_approval | **No** |
| **code_modification**, **dependency_upgrade** | require_approval | **No** (Mungard itself never does either) |

Any operation can be set to `deny`.

### Target scope (SR-01)

- Only `http`/`https`, with no credentials in the URL.
- Host must match `allowedHosts` (exact or `*.domain` wildcard; the wildcard does not match the bare domain or look-alikes).
- Port must be in `allowedPorts` when that list is non-empty.
- `productionHosts` are denied unless `allowProduction: true`.
- Cloud metadata and link-local addresses (`169.254.169.254`, `fe80::/10`, `metadata.google.internal`…) are **always** blocked, including when a hostname *resolves* to them.
- Redirects are followed only when every hop is in scope; out-of-scope redirects are recorded, not followed.
- Built-in HTTP tests are rate-limited (`maxRequestsPerSecond`) and capped (`maxHttpRequests`).

### Execution isolation (SR-03)

- Engines are invoked as a fixed executable plus an argument array, **never through a shell**. The agent cannot inject commands.
- Each run has a timeout and an output cap; the whole process group is killed on timeout.
- Engines receive a **minimal environment** (no API keys from your shell).
- Docker engines run with `--cap-drop ALL`, `--security-opt no-new-privileges`, memory/CPU/PID limits, read-only source mounts, and `--network none` where possible (Semgrep with bundled rules only, Gitleaks).

## Approvals (SR-04)

- Created by the policy engine when a gated operation is requested.
- **Bound to the exact parameters** (operation + a SHA-256 of a canonical JSON of the parameters).
- **Single use**, and they **expire** (default 60 minutes).
- Decided only by a human:
  - CLI: `mungard approvals approve <id>`. Requires an interactive TTY, shows the operation, target and parameters, and asks you to type `approve`. Non-interactive invocations exit with code 2.
  - Web UI: the Approvals panel. The POST requires same-origin headers and an HttpOnly, SameSite=Strict session cookie issued by the running UI.
- Every request, decision and consumption is in the audit log.

**Threat model note.** Approval gates stop *model-initiated* risky actions that come through Mungard's interfaces (MCP, chat, CLI). They are not a sandbox: a process running as your OS user can read and write your files. Combine them with Mungard Guard and agent permission rules.

## Audit log (SR-06)

`.mungard/audit.log.jsonl` is append-only and redacted. It records agent requests (`agent_request`), policy decisions, approval requests/decisions/consumptions, tool start/finish/failure with status and finding counts, finding status changes, report generation, and guard decisions. View it with `mungard audit-log`.

## Redaction (SR-02)

Applied to logs, chat, MCP results, evidence files, reports and AI payloads. Built-in patterns cover private keys, AWS/GitHub/Anthropic/OpenAI/Stripe/Slack/Google/npm tokens, JWTs, Bearer/Basic credentials, `Authorization`/`Cookie`/`Set-Cookie` headers, URL credentials, and `password=`/`secret=`/`api_key=` assignments. Values of sensitive JSON keys (`password`, `token`, `authorization`, `cookie`…) are masked. Add your own patterns with `policy.redaction.extraPatterns`. Redaction is pattern-based: a safety net, not a guarantee.

## AI data minimization (SR-09)

- AI is optional. CLI, MCP and all scanners work without it.
- Only redacted finding summaries, evidence excerpts and (if `policy.ai.sendSourceCode: snippets`) up to `maxSnippetLines` lines around the finding are sent. Secret findings never include code.
- `mungard triage --dry-run` prints the exact payload before anything is sent.
- AI output is advisory: AI can never change a finding's status.

## Mungard Guard

Mungard Guard checks AI coding agent tool calls **before they run**. It is wired in as a Claude Code `PreToolUse` hook.

```bash
mungard guard install       # prints the settings snippet
```

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [{ "type": "command", "command": "mungard guard hook", "timeout": 10 }] }
    ]
  },
  "permissions": {
    "deny": ["Bash(mungard approvals approve:*)", "Bash(mungard approvals deny:*)",
             "Edit(.mungard/**)", "Write(.mungard/**)", "Read(./.env)", "Read(./.env.*)"]
  }
}
```

| Decision | Examples |
|---|---|
| **deny** | `mungard approvals approve …` (self-approval); touching `.mungard/approvals.json`, the audit log or the findings store; `cat .env`, `cat ~/.ssh/id_rsa`, reading `*.pem`, `.aws/credentials`, `.npmrc`; `curl … \| sh`; `rm -rf ~`; `--dangerously-skip-permissions`; reverse shells; WebFetch to metadata IPs |
| **ask** | uploads (`curl -d/-F/-T`), `nc`/`scp`/`rsync`, `git push --force`, `git reset --hard`, `npm publish`, `sudo`, privileged Docker, dumping the environment, `terraform destroy`/`DROP TABLE`; editing `.claude/settings*.json`, `.mcp.json` or `.mungard/config.yaml`; writing what looks like a hardcoded credential into a file |
| **none** | everything else; normal permission flow |

Test a rule without Claude Code: `mungard guard check Bash '{"command":"cat .env"}'`.

Guard decisions are written to the project's audit log when a `.mungard/` workspace exists. Guard only inspects the request text; it cannot see what a script does once it is running. Keep using sandboxes for autonomous agents.
