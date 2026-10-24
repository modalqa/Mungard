# Troubleshooting

Start with `mungard doctor`: it shows what is missing and how to fix it.

| Symptom | Cause | Fix |
|---|---|---|
| `semgrep … UNAVAILABLE` | No local Semgrep and Docker not running | `brew install semgrep` / `pipx install semgrep`, or start Docker |
| Semgrep via Docker fails with a mount error | Docker Desktop cannot access the project path | Add the path under Docker Desktop → Settings → Resources → File sharing |
| `npm-audit skipped: No package-lock.json` | npm audit needs a lockfile | `npm install --package-lock-only`. pnpm/yarn projects: run `pnpm audit` / `yarn npm audit` yourself (reported as a gap) |
| `npm audit failed … registry` | No network / registry blocked | Retry with network access; npm audit sends your dependency tree to the npm registry |
| ZAP: `Target … is not reachable` | App not running, wrong port | Start the app and check `target.baseUrl`; `mungard doctor` tests reachability |
| ZAP report empty / container can't reach localhost | Container networking | macOS/Windows: Mungard rewrites localhost to `host.docker.internal`; make sure your dev server accepts connections on it. Linux: `--network host` is used |
| `Host … is not in policy.targets.allowedHosts` | Target out of scope (by design) | Add the host (and port) to the policy, only for systems you are authorized to test |
| `… requires human approval` | Gated operation | `mungard approvals list`, then `mungard approvals approve <id>` in an interactive terminal (or the web UI), then repeat the identical command |
| `Approvals must be decided in an interactive terminal` | Approve was run by a script or agent | Run it yourself in a terminal |
| Authorization check `inconclusive: the owner could not access the resource` | Wrong test data or credentials | Fix the resource id / token; the owner's baseline must succeed |
| `Account "x" is missing environment variable(s)` | `${env:NAME}` not set | `export NAME=...` before running |
| Chat says "AI mode is off" | No credentials, or `policy.ai.enabled: false` / `ai.provider: none` | Set `ANTHROPIC_API_KEY` or run `ant auth login`, then restart the web UI |
| Web UI returns 403 | Accessed via a different host name or port | Use `http://127.0.0.1:3737` or `http://localhost:3737`; set `MUNGARD_WEB_PORT` if you change the port |
| `Timed out waiting for workspace lock` | Another Mungard process is writing, or a crash left a lock | Wait; stale locks older than 60 s are removed automatically (`.mungard/.lock`) |
| `Invalid .mungard/config.yaml: …` | Schema validation error | The message names the field; compare with [configuration.md](configuration.md) |
| Retest says `INCONCLUSIVE` | The engine/check did not complete, so absence proves nothing | Fix the engine problem shown in the run and retest again |

## Getting more detail

- `mungard <command> --json`: full run record, including per-engine errors.
- `.mungard/runs/<runId>/run.json` and `evidence/`: raw (redacted) engine output.
- `mungard audit-log`: every policy decision and tool run.
