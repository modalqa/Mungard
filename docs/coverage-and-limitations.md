# Coverage & limitations

Mungard is honest about what it did *not* test. Every run lists coverage gaps, and failed or unavailable engines are reported explicitly. This page summarizes the general limits.

## What a clean result means

"No findings" means **the checks that ran found nothing**. It does not mean the application is secure. Read the run's coverage section and gaps.

## Per engine

| Engine | Covers | Does not cover |
|---|---|---|
| Semgrep + bundled rules | 21 JS/TS/Next.js rules: eval/Function, command injection, SQL injection (incl. Prisma `$queryRawUnsafe`), NoSQL operator injection, XSS sinks, `NEXT_PUBLIC_` secrets, JWT hardcoded secrets/`none`/ignoreExpiration, TLS verification off, weak hashes, deprecated ciphers, unsafe deserialization, CORS `*`+credentials, insecure cookie flags, prototype pollution, mass assignment, taint-based path traversal / SSRF / open redirect | Other languages (unless you add registry or local rules), cross-file data flow beyond Semgrep CE's capabilities, authorization and business logic, exploitability |
| Gitleaks | Secrets in the working tree and full git history, with committed/gitignored status | Whether the secret is valid or revoked; secrets in binary files or outside the repo |
| npm audit | Packages with published advisories in `package-lock.json` (direct + transitive) | pnpm/yarn/bun lockfiles (reported as a gap), malicious or abandoned packages without advisories, whether the vulnerable function is reachable |
| OWASP ZAP baseline | Spider (time-limited) + passive rules on reachable pages | Pages behind login (no authenticated context yet), active attacks unless approved |
| OWASP ZAP active (approval) | Injection, XSS, path traversal and similar payloads on spidered pages | Logic flaws; unauthenticated by default |
| HTTP probe | Security headers, cookie flags, CORS reflection on the target URL | Other routes |
| OpenAPI analyzer | Inventory, auth requirements, unauthenticated mutations, API keys in query, plain-HTTP servers, Basic auth | What the server actually enforces (verify with authz tests) |
| Authorization tester | Configured ownership/role/tenant checks, configured business-logic scenarios, anonymous probes of documented GET endpoints without path parameters (max 50) | Endpoints you did not configure; resources without known ids; automatic discovery of business rules |
| MCP inspector (static) | Literal/committed credentials, credentials in args, unpinned npx/bunx/pnpx/uvx/pipx packages, shell wrappers and remote scripts, privileged Docker / socket / host mounts, unpinned images, broad filesystem access, plain-HTTP and remote servers, Claude Code auto-approval of project servers | Codex TOML configs; behavior of the server code itself |
| MCP inspector (live, approval) | Tool-description poisoning indicators, tool-name shadowing across servers, changes since the last baseline (rug pull) | Resources/prompts, runtime behavior, obfuscated injections |
| Agent-config auditor | Hidden/bidi Unicode, injection phrasing, exfiltration/sensitive-file instructions in CLAUDE.md, AGENTS.md, GEMINI.md, Cursor/Windsurf/Cline rules, Copilot instructions, Claude commands/agents/skills; `bypassPermissions`, broad allow rules, missing `.env` deny rules, network hooks, literal credentials, committed `settings.local.json` | User-level `~/.claude` settings; paraphrased or obfuscated injections (pattern-based) |

## General limitations

- **False positives and false negatives exist** for every engine. Triage helps prioritize but is advisory.
- **Business-logic testing** only tests rules you confirm. Suggestions from `mungard plan` are guesses until confirmed.
- **Redaction is pattern-based.** Unusual secret formats can slip through; add `policy.redaction.extraPatterns`.
- **ZAP and its scanner alerts overlap with the HTTP probe** (e.g. missing X-Content-Type-Options appears from both under different rule ids). They are not merged across engines yet.
- **Approval gates are not a sandbox** against processes running as your user (see [policy-and-approvals.md](policy-and-approvals.md)).
- **Windows** is untested. Docker host networking for ZAP uses `host.docker.internal` on macOS/Windows and `--network host` on Linux.
- **Playwright-driven authenticated browser testing** is not implemented yet (roadmap).
- Mungard does **not** replace professional penetration testing, threat modeling or code review.
