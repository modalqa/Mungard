# Security policy

Mungard is a security tool. We take vulnerabilities in Mungard itself seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://github.com/modalqa/Mungard/security/advisories/new).

Please include affected version/commit, impact, reproduction steps and any proof of concept.
We aim to acknowledge reports within 3 business days and to agree on a disclosure timeline with you.

## In scope

- Bypassing the policy engine: out-of-scope targets, gated operations running without approval, approval reuse.
- An agent (via MCP or chat) approving its own requests or executing arbitrary commands.
- Secrets or credentials leaking unredacted into logs, chat, reports, evidence or AI payloads.
- Command injection through engine invocation, path traversal through tool inputs.
- Web UI issues: DNS rebinding, CSRF, XSS through rendered tool output.
- Prompt injection from scanned content leading to actions outside the documented model.

## Out of scope

- Findings in `tests/fixtures/` (intentionally vulnerable, fake credentials).
- Vulnerabilities in third-party engines (Semgrep, Gitleaks, ZAP): report them upstream.
- The documented limitations in `docs/coverage-and-limitations.md` and `docs/policy-and-approvals.md`
  (e.g. processes running as the same OS user can modify workspace files).

## Supported versions

Only the latest release on `main` receives security fixes during the 0.x phase.
