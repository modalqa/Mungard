# Contributing to Mungard

Thanks for helping! Mungard is a security tool, so correctness and honesty about coverage matter more than feature count.

## Development setup

```bash
git clone https://github.com/modalqa/Mungard.git && cd Mungard
npm ci            # install scripts are disabled by .npmrc
npm run build     # TypeScript project references (packages/*)
npm test          # vitest: unit, security and integration tests
npm run typecheck
npm run build:web # Next.js UI
```

Requirements: Node.js 22.12+, git; Docker for engine-backed manual testing.

## Project layout

See [docs/architecture.md](docs/architecture.md). `tests/fixtures/` contains **intentionally vulnerable** apps with fake credentials. Never copy code from there.

## Guidelines

- **Every operation goes through the policy engine.** Never add an MCP tool or chat capability that runs arbitrary commands, edits source code, changes policy, or approves requests.
- **Never shell out with a string.** Use `runCommand(bin, args)`.
- **Redact** anything that is persisted, logged, returned to an agent or sent to a model.
- **No silent success.** If an engine did not run, say so (`unavailable`/`failed` + gap).
- **AI is advisory.** It must never change finding statuses.
- New engines: follow [docs/adapters.md](docs/adapters.md) and check the license first ([docs/licensing.md](docs/licensing.md)).
- Add tests for policy, parsers and normalizers. Security-relevant changes need tests in `tests/security/`.
- Keep dependencies minimal and permissively licensed; `npm run licenses` must pass.
- Code, comments and docs are in English.

## Pull requests

1. Open an issue first for larger changes.
2. Keep PRs focused; describe what changed, why, and how you tested it.
3. CI must pass: build, typecheck, tests, npm audit, license check, Gitleaks, Mungard self-scan, CodeQL.

By contributing you agree that your contributions are licensed under Apache-2.0.
