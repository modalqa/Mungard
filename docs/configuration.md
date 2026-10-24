# Configuration

Mungard reads `<project>/.mungard/config.yaml`. Every field is optional; missing values fall back to the **safe defaults** shown here. The schema is validated with Zod (`packages/core/src/config.ts`, `packages/policy-engine/src/policy.ts`), and invalid files are rejected with the exact path of the error.

```yaml
version: 1

project:
  name: my-app
  frameworks: [Next.js]            # filled by `mungard init`

target:
  baseUrl: http://localhost:3000   # runtime target; omit to skip runtime tests
  openapi: openapi.yaml            # relative to the project root

policy:
  targets:
    allowedHosts: [localhost, 127.0.0.1, "::1"]   # exact or "*.staging.example.test"
    allowedPorts: [3000]           # empty = any port on an allowed host
    productionHosts: [app.example.com]
    allowProduction: false         # production hosts are denied unless true
  operations:                      # allow | require_approval | deny
    static_scan: allow
    # web_active_scan, authz_write_tests, mcp_live_inspect, code_modification and
    # dependency_upgrade can never be set to "allow" (always gated).
  limits:
    toolTimeoutSeconds: 600
    activeScanMaxMinutes: 10
    spiderMaxMinutes: 2
    maxRequestsPerSecond: 5        # built-in HTTP tests
    maxHttpRequests: 500           # per run
    maxFileSizeBytes: 1000000
    maxEvidenceBytes: 16000
    maxOutputBytes: 67108864
  approvals:
    expiresMinutes: 60
  redaction:
    extraPatterns: ["ACME-[0-9]{6}"]   # additional regexes masked everywhere
  ai:
    enabled: true
    sendSourceCode: snippets       # none | snippets
    maxSnippetLines: 30

engines:
  semgrep:
    enabled: true
    registryRules: []              # e.g. ["p/default"]; see docs/licensing.md
    localRules: []                 # your own rule files (relative paths)
    exclude: []                    # e.g. ["tests/fixtures"]
  gitleaks:
    enabled: true
    history: true                  # scan full git history
    excludePaths: []               # Go RE2 regexes, e.g. ["(^|/)tests/fixtures/"]
  npmAudit:
    enabled: true
    omitDev: false
  zap:
    enabled: true

auth:
  accounts:
    - name: alice                  # [a-zA-Z0-9_-]
      role: member
      tenant: acme
      headers:
        Authorization: "Bearer ${env:MUNGARD_ALICE_TOKEN}"   # never put literal secrets here

authorization:
  checks: []                       # see below
  scenarios: []                    # see below

ai:
  provider: anthropic              # anthropic | none
  model: claude-opus-5-5
  effort: medium                   # low | medium | high | xhigh | max
```

## Authorization checks

A check asserts that the `owner` can access a resource and that every account in `denied` cannot. `anonymous` is a built-in account with no credentials.

```yaml
authorization:
  checks:
    - id: invoice-ownership                  # [a-zA-Z0-9_.-]
      description: Members can only read their own invoices
      request: { method: GET, path: /api/invoices/inv_alice_1, headers: {} }
      owner: alice
      allowed: [admin]                        # optional
      denied: [bob, anonymous]
      sensitiveMarkers: ["alice@example.test"] # strings that only appear in the owner's data
      severity: high
```

**How results are judged.** A status code alone is never treated as proof:

- 401/403/404, 3xx (login redirect) or other 4xx → **pass**;
- 2xx **and** an owner marker in the body (or a body identical to the owner's) → **violation**, reported as `confirmed` with the request/response evidence;
- 2xx without owner data → **suspicious**, reported as `new` with low confidence for manual review;
- 5xx or a network error → **inconclusive**, listed as a coverage gap.

Checks using `POST/PUT/PATCH/DELETE` only run with `--include-write-tests`, and that requires approval.

## Business-logic scenarios

```yaml
authorization:
  scenarios:
    - id: no-shipping-unpaid-orders
      description: An order cannot be shipped before it is paid
      assumptions: ["Orders must be paid before they can be shipped."]
      confirmed: true                        # unconfirmed scenarios are reported, not executed
      severity: high
      steps:
        - as: alice
          request: { method: POST, path: /api/orders, json: { item: book } }
          capture: { orderId: id }           # dotted path into the JSON response
          expect: { statusIn: [201] }
        - as: alice
          request: { method: POST, path: "/api/orders/{{orderId}}/ship" }
          expect: { statusIn: [400, 402, 403, 409, 422] }   # or statusNotIn / bodyNotContains
```

`mungard plan --json` generates templates for both from your OpenAPI spec or detected routes. They are marked `needsConfirmation` because Mungard cannot know your business rules.

## Environment variables

| Variable | Used for |
|---|---|
| `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` / `ant auth login` profile | AI chat and AI triage (optional) |
| `MUNGARD_PROJECT_ROOT` | Project root for `mungard mcp serve` and the web UI |
| Anything referenced as `${env:NAME}` | Test account credentials |
| `NO_COLOR` | Disable colored CLI output |

Engines run with a **minimal environment** (`PATH`, `HOME`, locale and Docker variables only), so secrets in your shell are not passed to third-party tools.
