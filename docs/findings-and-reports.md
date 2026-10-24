# Findings, triage, retests & reports

## Normalized finding schema (v1.0.0)

Every engine's output is converted to one schema (`packages/findings/src/schema.ts`, `FINDING_SCHEMA_VERSION = "1.0.0"`):

| Field | Meaning |
|---|---|
| `id` | `MG-` + 10 hex characters, stable across runs (derived from the fingerprint) |
| `fingerprint` | Hash of category, rule, locations (file without line number, endpoint, package, MCP server) and a hint (e.g. the matched source line). Used for dedup and before/after comparison |
| `title`, `description`, `impact`, `remediation`, `references`, `cwe` | Human-readable details |
| `category` | sast, secret, dependency, dast, api, authn, authz, business_logic, headers, mcp, agent_config, config |
| `severity` | critical, high, medium, low, info (Mungard's normalized value) |
| `confidence` | high, medium, low |
| `status` | see below |
| `sources[]` | Every engine/run that reported it: `engine`, `engineVersion`, `ruleId`, `runId`, and **`originalSeverity`** exactly as the scanner reported it |
| `locations[]` | file + lines, endpoint + method, package + version, MCP server + config file, URL |
| `evidence[]` | `scanner_output`, `code_snippet`, `http_exchange`, `config_excerpt`, `note`; each has a redacted excerpt and/or a workspace path |
| `reproductionSteps[]` | How to reproduce |
| `triage` | Advisory triage (heuristic or AI), never authoritative |
| `retest` | `not_retested \| passed \| failed \| inconclusive`, run id, code version |
| `history[]` | Every status change with actor (`human`/`tool`), reason and timestamp |

Duplicates (same fingerprint) are merged: sources, locations and evidence are unioned, the stronger severity and confidence win, and the id, status and history are kept.

## Statuses

| Status | Set by | Meaning |
|---|---|---|
| `new` | engine | Not reviewed yet. **Unverified** |
| `needs_review` | human, tool | Needs a human or more evidence |
| `confirmed` | human (with evidence), or a deterministic verification test | Verified. Never set by AI or by a plain scanner |
| `false_positive` | human | Dismissed |
| `accepted_risk` | human | Acknowledged, not fixing now |
| `fixed` | human | Fix reported; **still unresolved** until a retest passes |
| `retested` | retest only | Retest ran and the issue is gone (closed) |

Enforced rules: AI can never change a status; `confirmed` requires at least one evidence item; `retested` requires a passing retest run; every change needs a reason.

**Which findings are "verified"?** Runtime authorization checks and business-logic scenarios. These are deterministic tests of rules *you* configured, and they mark a finding `confirmed` only when the violation is proven with captured request/response evidence (for example, owner-only data appears in another user's response). Everything else starts as `new`.

## Triage

`mungard triage` (or the `triage_findings` tool) produces, per finding: an assessment (`likely_true_positive | likely_false_positive | uncertain`), a priority (`p0`–`p3`), a rationale, supporting evidence, missing evidence and verification steps.

- **Heuristic triage** always runs offline. For example, findings that live only in test or fixture files are marked likely false positives; findings verified at runtime are marked likely true positives.
- **AI triage** runs when a model is configured. It uses structured output, batches of 15, and a minimized, redacted payload (preview it with `--dry-run`). IDs invented by the model are ignored. AI may *suggest* `needs_review`; it never sets a status and never suggests `confirmed`.

## Remediation

`mungard remediate <id>` / `propose_remediation` returns the affected locations with code context, fix guidance, a regression-test example for the vulnerability class, and the retest command. **Mungard does not modify code.** Your coding agent or editor applies the change, under its own approval prompts.

## Retests

`mungard retest <ids...>` / `run_retest`:

1. Re-runs only the engines that produced the findings. For authorization findings, it re-runs only the exact checks or scenarios.
2. Records the code version (`git rev-parse HEAD`, with `-dirty` when the tree has uncommitted changes).
3. Compares before and after:
   - **failed**: the same fingerprint, or the same rule at the same file/endpoint/package, is still reported;
   - **inconclusive**: the engine did not complete, or (for runtime checks) the producing check did not run and pass;
   - **passed**: the engine completed and the issue is gone. Only then does the finding become `retested`.
4. A `fixed` (or previously `retested`) finding whose retest fails goes back to `needs_review`, so it is shown as unresolved.

Retest history is stored in `.mungard/retests.json` and included in reports.

## Reports

`mungard report --format md|json|sarif` (or `generate_security_report`) writes to `.mungard/reports/` by default. Every report is redacted again before writing.

Markdown and JSON reports contain:

- scope and targets (allowed hosts/ports, production allowed?, runtime targets actually tested);
- test runs with timestamps and code versions, plus each engine with version, status, finding count and duration;
- what was tested (coverage) and **engines that did not complete** (their checks did NOT run);
- coverage gaps and limitations;
- findings by severity, with evidence, reproduction steps, triage (marked advisory) and remediation;
- a list of unverified findings;
- retest results (before → after, code version).

**SARIF 2.1.0**: one rule per rule id. Results carry `security-severity`, `partialFingerprints.mungardFingerprint`, status and confidence. File findings have physical locations; endpoint/MCP findings use logical locations. False positives, accepted risks and retested findings are excluded. Upload the file to GitHub code scanning with `github/codeql-action/upload-sarif`.

## Workspace layout

```
.mungard/
├── .gitignore            # ignores everything except config.yaml
├── config.yaml
├── findings.json         # normalized findings (schema v1)
├── retests.json
├── approvals.json        # 0600
├── audit.log.jsonl       # 0600, append-only, redacted
├── mcp-tool-baseline.json  # tool-definition hashes from live MCP inspection
├── runs/<runId>/run.json
├── runs/<runId>/evidence/*.json   # raw engine output + HTTP exchanges, redacted
└── reports/
```
