# Licensing of dependencies & engines

Mungard is licensed under **Apache-2.0**. This page records the license review of everything Mungard depends on or invokes. It was last checked on 2026-10-24 against the installed versions; re-check when you upgrade.

## Runtime npm dependencies (CLI, MCP server, core)

| Package | License | Commercial use |
|---|---|---|
| `@anthropic-ai/sdk` | Apache-2.0 | ✅ |
| `@modelcontextprotocol/sdk` | MIT | ✅ |
| `zod` | MIT | ✅ |
| `yaml` | ISC | ✅ |
| `commander` | MIT | ✅ |
| transitive dependencies of the above | MIT / ISC / BSD / Apache-2.0 | ✅ (enforced by `npm run licenses`) |

## Web UI and build tooling

| Package | License | Note |
|---|---|---|
| `next`, `react`, `react-dom`, `tailwindcss` | MIT | ✅ |
| `typescript`, `vitest` | Apache-2.0 / MIT | dev only |
| ⚠️ `sharp` / `@img/sharp-libvips-*` | **LGPL-3.0-or-later** (libvips) | Optional dependency of Next.js for image optimization. Mungard does not use `next/image`, and the library is dynamically linked and unmodified. LGPL allows commercial use; if you redistribute a bundle that includes it, comply with LGPL (provide the license and allow relinking). |
| ⚠️ `lightningcss` | **MPL-2.0** | Build-time CSS tool used by Tailwind 4; not shipped in the CLI. MPL-2.0 is file-level copyleft: commercial use is fine, but modifications to its files must be shared. |

These two are the only non-permissive licenses in the tree. `scripts/check-licenses.mjs` allows them by name with a documented reason and fails CI for anything else.

## Security engines (not bundled; installed by the user or pulled as Docker images)

| Engine | License | Notes |
|---|---|---|
| Semgrep Community Edition (engine) | LGPL-2.1 | Invoked as an external CLI/container; does not affect Mungard's license. |
| ⚠️ **Semgrep Registry rules** (`p/default`, `p/javascript`, …) | **Semgrep Rules License v1.0** | **Not commercial-friendly in all cases.** The license permits internal use but restricts offering the rules as part of a competing product or service. That is why Mungard **defaults to its own Apache-2.0 rules** and leaves `engines.semgrep.registryRules` empty. Enable registry packs only after you have checked that your use complies. *This needs verification by your legal team for your specific use.* |
| Gitleaks | MIT | ✅ |
| OWASP ZAP | Apache-2.0 | ✅ |
| npm CLI (`npm audit`) | Artistic-2.0 | ✅; note that npm audit sends your dependency tree to the npm registry |

## AI provider

Using Claude via the Anthropic API is governed by Anthropic's commercial terms, not by an open-source license. It is optional. Check your organization's data policies before enabling AI features (see `policy.ai` and `mungard triage --dry-run`).

## Checking yourself

```bash
npm run licenses          # fails on any license outside the allowlist / reviewed exceptions
```

CI also runs GitHub's dependency-review action on pull requests with the same license allowlist.
