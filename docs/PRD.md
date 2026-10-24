> This is the English translation of the original PRD, which was written in Indonesian. The implementation status of each requirement is tracked in `docs/architecture.md` and `docs/coverage-and-limitations.md`.

# Product Requirements Document (PRD)
# Mungard: Open-Source AI Security Testing Agent

**Status:** Draft v1.0  
**Product Type:** Open-Source Developer Security Tool  
**Target Users:** Developers, AI-assisted developers, vibe coders, security engineers  
**Primary Interface:** Standalone Chat UI + CLI + MCP Server  
**Deployment Model:** Local-first, self-hosted  
**Primary Language:** TypeScript  
**Frontend & Backend:** Next.js  
**Product Name:** Mungard

## Positioning

Mungard is a security layer for AI coding agents. It helps test the security of code, AI agent behavior and MCP integrations through scanners, targeted tests, evidence for every finding, and human approval.

Tagline: *Guard every agent action.*

Example CLI:

    mungard scan .
    mungard audit .
    mungard mcp inspect

---

## 1. Product Overview

### 1.1 Product Vision

Build an open-source security testing platform that lets developers use AI coding agents to test the security of the applications they are building.

Developers do not need to be security experts or master a large number of security tools. They only need to connect a coding agent, define the testing target and scope, and then ask the agent to run a security assessment.

The platform orchestrates existing security tools, collects the results, analyzes the evidence, prioritizes findings, assists with verification, and provides remediation recommendations that can be retested.

The product does not build a new security scanner from scratch. Its focus is integrating scanners, providing application context to the AI, and turning scan results into a structured security testing workflow.

### 1.2 Problem Statement

Developers building applications with Claude Code or other coding agents face several problems:

1. A coding agent cannot guarantee that the code it generates is secure based on code review alone.
2. Developers have to install, configure, and run a variety of security tools separately.
3. Scanner results often require security expertise to interpret.
4. Scanner findings may be false positives or may not yet be proven exploitable.
5. Runtime testing requires a running application, test accounts, data, and a suitable environment.
6. Authentication, authorization, tenant isolation, and business logic issues are not always found by generic scanners.
7. The remediation and regression testing process is not yet integrated with the coding agent workflow.

### 1.3 Product Goals

- Make it easy for developers to run security testing without managing many tools manually.
- Integrate security testing with Claude Code and coding agents that support MCP.
- Support testing of both source code and running web/API applications.
- Help find and verify authentication, authorization, and business logic issues.
- Provide evidence that can be reviewed and reproduced.
- Support the find issue → verify → fix → retest cycle.
- Provide a local-first experience that can be run from a cloned repository.
- Keep the testing environment secure and prevent dangerous actions without approval.

### 1.4 Non-Goals

The MVP is not intended to:

- Replace professional penetration testers.
- Guarantee that an application is free of all vulnerabilities.
- Perform unrestricted automated exploitation.
- Perform broad network or cloud infrastructure scanning.
- Be a multi-tenant vulnerability management SaaS as the main product.
- Build a proprietary security engine from scratch.
- Make mobile application security a focus of the MVP.
- Run active testing against targets without authorization.

---

## 2. Target Users

### 2.1 Primary Persona: AI-Assisted Developer

Developers who use Claude Code, Cursor, or other coding agents to build SaaS products, web apps, and APIs.

Needs:
- Run security assessments from within the coding workflow.
- Understand findings in plain, easy-to-understand language.
- Get remediation recommendations that fit the source code.
- Retest after fixing.

### 2.2 Secondary Persona: Indie Hacker / Vibe Coder

Developers or product builders who do not have a dedicated security engineer.

Needs:
- Simple installation.
- Minimal configuration.
- Security checks with safe defaults.
- Reports that explain impact and remediation steps.

### 2.3 Secondary Persona: Security Engineer / QA Engineer

Engineers who need automation for security regression testing.

Needs:
- Control over testing scope and methods.
- CI/CD integration.
- Evidence and reproduction of findings.
- Consistent, auditable results.

---

## 3. Product Principles

### 3.1 Local-First

By default, source code, credentials, scan results, and test evidence stay in the user's environment.

Processing by an AI model may send context to the model provider, depending on configuration. Therefore, sending source code, logs, and sensitive data must be limited, sanitized, and explained to the user.

### 3.2 AI-Orchestrated, Tool-Executed

The AI decides which steps are relevant and analyzes the results. Security tools still perform the technical checks they are responsible for.

The AI must not claim that a vulnerability is valid merely because a scanner reported it.

### 3.3 Evidence-Driven

Every finding must have evidence, a source, a detection method, a confidence level, and a verification status.

### 3.4 Human-in-the-Loop

The user controls targets, scope, access, and risky actions. Code fixes and active testing that may modify data require approval according to policy.

### 3.5 Extensible

Security engines, coding agents, and integration adapters must be addable without overhauling the core application.

---

## 4. MVP Scope

### 4.1 Core Capabilities

The MVP includes:

1. Project workspace and project configuration.
2. Standalone AI chat interface.
3. MCP server for coding agents.
4. CLI for setup and running scans.
5. Source code security scanning.
6. Secret scanning.
7. Dependency vulnerability scanning.
8. Web application DAST.
9. REST API analysis and testing.
10. Authentication and authorization testing.
11. Business logic testing for defined scenarios.
12. Evidence collection and normalized findings.
13. AI-assisted triage and false-positive assessment.
14. Remediation suggestions and retesting.
15. Security policies, audit logs, and approval workflow.
16. Export of test result reports.

### 4.2 Initial Technology Support

Initial priorities:

- Next.js and Node.js.
- TypeScript and JavaScript.
- REST APIs, with OpenAPI where available.
- PostgreSQL or other databases reachable through the application under test.
- Local applications running on localhost or an authorized staging environment.

The architecture must allow other frameworks to be added without requiring all of them to be supported on day one.

### 4.3 Initial Security Engines

| Capability | Initial integration |
|---|---|
| Static analysis | Semgrep |
| Secret detection | Gitleaks |
| Dependency audit | npm audit |
| Web DAST | OWASP ZAP |
| Browser automation | Playwright |
| API specification | OpenAPI parser and validator |
| Finding format | Internal normalized schema, SARIF export where applicable |

Tool versions and their compatibility must be confirmed during implementation. Every integration must have a health check and failure handling.

---

## 5. Functional Requirements

### FR-01: Project Initialization

The user can initialize a security testing project from an application repository.

Features:
- Detect the framework and programming language.
- Identify the package manager and dependency files.
- Identify application routes and configuration where possible.
- Detect whether an OpenAPI specification is available.
- Offer a configuration based on the detection results.
- Store the project configuration locally.

Acceptance criteria:
- The project can be initialized without making any changes to the application source code.
- The detection results show the framework and the relevant security engines.
- The user can review the configuration before running a scan.

### FR-02: Standalone Chat Interface

The user can interact with the security agent through a standalone chat UI.

Example requests:

- "Scan this application for vulnerabilities."
- "Check whether every endpoint validates authorization."
- "Test whether a user can read resources belonging to another user."
- "Analyze the scan results and prioritize the riskiest findings."
- "Create a test plan for the admin and member roles."
- "Verify the fix I just made."

The chat must display:
- The test plan.
- The tools that will be run.
- Execution status.
- Results and evidence.
- Approval requests when required.
- A final summary and next-step recommendations.

Acceptance criteria:
- The agent does not claim a scan succeeded if the tool failed or was unavailable.
- The agent can explain coverage limitations.
- Risky actions are not executed based solely on model instructions without passing through the policy engine.

### FR-03: Coding Agent Integration

The product provides an MCP server that compatible coding agents can use.

Initial capabilities:
- Read the project security configuration.
- Run permitted checks.
- Check scan status.
- Read findings.
- Access sanitized evidence.
- Request further analysis.
- Request a retest of findings that have been fixed.

The CLI must provide the same core capabilities so that the product remains usable without MCP.

Acceptance criteria:
- Claude Code can connect to the local MCP server.
- The user can run a security assessment through the coding agent's chat.
- MCP tools expose only operations that have been defined and validated.
- All state-changing operations have scope and permission validation.

### FR-04: Static Application Security Testing

The system runs SAST against the source code.

Coverage:
- Injection patterns supported by rules.
- Risks from using dangerous functions or APIs.
- Certain input validation errors.
- Improper security configuration.
- Insecure coding patterns available in the engine.

The system stores the file, code location, rule, severity, and raw scanner output.

Acceptance criteria:
- Results can be linked to a file and code location.
- Duplicate findings can be merged without losing evidence references.
- The user can distinguish between scanner results and AI verification results.

### FR-05: Secret Scanning

The system checks for indications of secrets in the source code and repository, according to configuration.

Coverage:
- API keys.
- Tokens.
- Password literals.
- Private keys.
- Secrets supported by the engine.

Acceptance criteria:
- Secrets are not displayed in full in chat or reports.
- Output and logs do not leak credentials.
- The system recommends credential rotation when a valid secret appears to have been leaked.

### FR-06: Dependency Vulnerability Scanning

The system checks for dependencies with known vulnerabilities.

Coverage:
- npm dependency audit.
- Manifests and lockfiles.
- Available severity and advisories.
- Direct and transitive dependencies, if supported by the engine.

Acceptance criteria:
- Findings show the package, version, advisory, and upgrade recommendation when available.
- The system does not run automatic dependency upgrades without approval.

### FR-07: Dynamic Application Security Testing

The system can test a running web application using OWASP ZAP.

Features:
- Target URL and port.
- Verification that the target is in scope.
- Passive scan.
- Controlled spidering.
- Active scan as a separate operation with explicit approval.
- Storage of results and reports.
- Limits on scan duration and intensity.

Acceptance criteria:
- The target must be configured and approved.
- Testing against production is not enabled by default.
- If the application cannot be reached, the system reports the failure clearly.
- The report explains which types of scan were actually run.

### FR-08: REST API Security Testing

The system analyzes an OpenAPI specification or an API that can be legitimately observed.

Coverage:
- Endpoint inventory.
- HTTP methods and parameters.
- Request/response schemas.
- Authentication requirements.
- Basic input validation.
- Error handling.
- Security headers and related configuration.
- Endpoint testing within scope.

Acceptance criteria:
- The system produces a list of endpoints and their check status.
- Endpoints that cannot be tested are given a clear status.
- Credentials and sensitive data are sanitized from evidence.

### FR-09: Authentication and Authorization Testing

The system supports testing using accounts and roles provided by the user.

Coverage:
- Authentication enforcement.
- Session handling and access control.
- Role-based authorization.
- Resource ownership.
- BOLA/IDOR on relevant endpoints.
- Tenant isolation for multi-tenant applications.
- Cross-role access.

Acceptance criteria:
- Testing uses dummy accounts or authorized accounts.
- The system does not treat the HTTP status alone as sufficient evidence in all cases.
- Findings include the tester's role identity, the resource tested, the relevant request/response, and the impact.
- Tests that require multiple accounts or datasets explain their prerequisites.

### FR-10: Business Logic Security Testing

The agent builds scenarios based on routes, source code, the API specification, and known business rules.

Examples:
- A regular user attempts to perform an admin action.
- A user attempts to access a resource they do not own.
- A business state change is performed without meeting its prerequisites.
- Sensitive endpoints are called in an unintended order.
- Ownership validation or quantity limits are not enforced consistently.

Acceptance criteria:
- The agent explains the assumptions and business rules it used.
- Scenarios that require business rules not yet known are flagged for user confirmation.
- No vulnerability is claimed as confirmed without sufficient evidence.

### FR-11: Findings and Evidence Management

All engines produce a consistent finding format.

Minimum fields:
- Finding ID.
- Title.
- Description.
- Severity.
- Confidence.
- Verification status.
- Detection source.
- Affected file, endpoint, or resource.
- Evidence references.
- Reproduction steps.
- Potential impact.
- Remediation guidance.
- Retest status.

Finding statuses:
- New.
- Needs Review.
- Confirmed.
- False Positive.
- Accepted Risk.
- Fixed.
- Retested.

Acceptance criteria:
- The user can trace the origin of every finding.
- Findings that have not been verified are not labeled confirmed.
- Evidence can be read without displaying secrets unnecessarily.

### FR-12: AI-Assisted Triage

The AI analyzes findings from scanners together with source code context.

Tasks:
- Group related findings.
- Assess their likely relevance to the application.
- Identify missing evidence.
- Suggest verification steps.
- Explain risks in plain, easy-to-understand language.
- Propose remediation priorities.

Acceptance criteria:
- The scanner's severity remains available as source data.
- The AI must not silently upgrade a finding's status to confirmed.
- AI output states the reasoning and evidence supporting its conclusions.

### FR-13: Remediation and Retesting

The system helps developers fix findings.

Features:
- Provide remediation recommendations.
- Show the affected files or endpoints.
- Propose regression tests.
- Re-run relevant scans.
- Compare results before and after the fix.

Acceptance criteria:
- Source code modifications require approval according to policy.
- A retest records the code version or commit that was tested.
- A finding is declared fixed only after the appropriate verification criteria are met.
- Fixes that have not succeeded remain displayed as unresolved.

### FR-14: Reporting

The system generates Markdown and JSON reports.

The report contains:
- Scope and targets.
- Testing time.
- Tools and versions used.
- Types of testing performed.
- Findings by severity.
- Evidence and reproduction steps.
- Findings that could not yet be verified.
- Coverage gaps.
- Remediation recommendations.
- Retest results.

SARIF may be provided for compatibility with code analysis tooling that supports it.

### FR-15: Security Policy and Audit Log

The system must have a policy engine to control operations.

Minimum controls:
- Allowed targets.
- Allowed ports and scope.
- Allowed tool operations.
- Scan intensity and timeout.
- File size and execution duration limits.
- Approval for active scans and actions that may modify data.
- Sanitization of credentials and evidence.
- Audit log of agent actions and tool results.

---

## 6. User Journey

### Journey A: First-Time Setup

1. The developer clones the repository.
2. The developer runs the setup command.
3. The system checks the runtime and dependencies.
4. The developer initializes the application project.
5. The system detects the framework and relevant configuration.
6. The developer connects Claude Code via MCP or uses the chat UI.
7. The developer reviews the security policy.
8. The system is ready to accept security assessment requests.

### Journey B: Security Assessment

1. The developer requests a scan.
2. The agent reads the project configuration.
3. The agent builds a check plan.
4. The policy engine validates the scope and operations.
5. The security engines run the checks.
6. The system collects results and evidence.
7. The agent performs triage and identifies what needs verification.
8. The developer reviews the report.
9. The developer decides on fixes and retests.

### Journey C: Verify and Retest

1. The developer selects a finding.
2. The agent examines the related code.
3. The agent suggests changes and test cases.
4. The developer approves the changes.
5. The system runs the relevant regression tests and security scans.
6. The system compares the results.
7. The finding is updated based on the retest evidence.

---

## 7. Technical Architecture

### 7.1 Architecture Overview

The product uses a modular architecture with a single main orchestrator.

Components:
- Next.js frontend.
- Next.js backend/API.
- Chat orchestration layer.
- MCP server.
- CLI.
- Project context analyzer.
- Policy engine.
- Security engine adapters.
- Isolated execution workers.
- Findings and evidence processor.
- Reporting module.

### 7.2 Technology Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js + React |
| Backend | Next.js Route Handlers / server-side services |
| Language | TypeScript |
| UI styling | Tailwind CSS |
| Validation | Zod |
| Chat streaming | Server-Sent Events or another suitable streaming mechanism |
| MCP | TypeScript MCP SDK |
| Database | PostgreSQL when needed for a persistent workspace |
| Local project state | Filesystem and local configuration |
| Security engines | Semgrep, Gitleaks, npm audit, OWASP ZAP |
| Browser automation | Playwright |
| Execution isolation | Docker or a suitable sandbox worker |
| Testing | Vitest and Playwright |
| Reporting | Markdown, JSON, SARIF |

The frontend and backend both use Next.js and TypeScript. Python/FastAPI is not used as the product backend.

### 7.3 Execution Model

Security engines are run through isolated adapters.

Each adapter has:
- Input schema.
- Scope validation.
- Timeout.
- Resource limits.
- Exit code handling.
- Output parser.
- Error handling.
- Normalized findings.

The core orchestrator must not directly execute arbitrary shell commands generated by the model. The agent may only invoke operations that have been defined and that pass through the policy engine.

### 7.4 Local-First and Self-Hosted Modes

Initial modes:
- Local CLI for the user's repository.
- Local MCP server for coding agents.
- Local chat UI for standalone workflows.
- Execution worker for running security tools.

Persistent storage must be configurable. Users are not required to use a hosted account for core features.

For the MVP, local execution is the primary path. Remote execution support can be developed later, once its security boundaries and authentication have been defined.

---

## 8. MCP Interface

The MCP server provides tools with narrow, well-defined responsibilities.

Example conceptual tools:

- `get_project_context`
- `get_security_policy`
- `plan_security_assessment`
- `run_static_scan`
- `run_secret_scan`
- `run_dependency_audit`
- `run_web_scan`
- `analyze_api_spec`
- `run_authorization_tests`
- `get_scan_status`
- `list_findings`
- `get_finding_evidence`
- `propose_remediation`
- `run_retest`
- `generate_security_report`

Tools that perform scans must accept a validated target or project ID, not arbitrary shell commands.

Tools that run active scans or may modify data must require permission according to policy.

Tool definitions, the permission model, and error responses must be documented so that other MCP-capable coding agents can use them.

---

## 9. Security and Privacy Requirements

Because this product runs security tools and accesses source code, the security of the product itself must be a priority.

### SR-01: Target Scope Enforcement
All targets must be validated before scanning. Redirects to out-of-scope targets must be handled according to policy.

### SR-02: Secret Redaction
Credentials, tokens, cookies, and sensitive data must be masked in logs, chat, and reports.

### SR-03: Execution Isolation
Scanners and test scripts run with least privilege and resource limits.

### SR-04: Approval Gates
Active scanning, source code changes, and actions that may modify or delete data require approval according to policy.

### SR-05: No Unrestricted Exploitation
The MVP does not provide autonomous unrestricted exploitation or automated attacks against unauthorized targets.

### SR-06: Auditability
The system records agent requests, policy decisions, tool operations, execution status, and significant results.

### SR-07: Untrusted Tool Output
Scanner results, web page content, repositories, and API responses are treated as untrusted data, not as instructions for the agent.

### SR-08: Safe Defaults
The default target is a local or staging application that has been explicitly authorized. Active scans and destructive operations are not enabled by default.

### SR-09: Data Minimization
Only the necessary context is sent to the AI model. Users must be able to understand what data will be processed by the model provider.

---

## 10. Non-Functional Requirements

### Performance
- The CLI can start checks without requiring the dashboard to start.
- Long-running scans must provide informative status and errors.
- Partial results can be saved when some engines fail.

### Reliability
- The failure of one engine must not delete the results of other engines.
- Processes can be stopped safely.
- Scan results have consistent IDs and metadata.

### Maintainability
- Security engines are integrated through adapters.
- The core does not depend on a single scanner or AI model.
- The finding schema is versioned.
- Unit tests are available for the policy engine, parsers, and normalizers.

### Portability
- The CLI and core support macOS and Linux as initial priorities.
- Windows support can be added once dependency compatibility has been verified.
- Docker is an option for isolating engines that require a special runtime.

### Usability
- Users can run basic checks with a single command.
- Errors explain the cause and the recovery steps.
- Advanced configuration remains available without being a prerequisite for initial use.

---

## 11. MVP Acceptance Criteria

The MVP is considered ready for initial release when:

1. Developers can clone and run setup on a supported environment.
2. A project can be initialized and the main framework is detected.
3. Claude Code can connect via MCP.
4. The CLI can run security scans standalone.
5. SAST, secret scanning, and dependency audit produce reports.
6. OWASP ZAP can check a running local application.
7. The system can analyze an OpenAPI specification.
8. Authorization testing can use two or more test accounts when the scenario requires it.
9. Findings have evidence, severity, confidence, and verification status.
10. The AI can analyze findings without automatically assuming all scanner results are correct.
11. Developers can fix findings and run a retest.
12. Active scans and risky actions are protected by policy and approval.
13. Credentials are not displayed in full in reports or logs.
14. Documentation for setup, configuration, troubleshooting, and coverage limitations is available.
15. Automated tests cover the policy engine, scope enforcement, finding normalization, and MCP tools.

---

## 12. Roadmap

### Phase 1 — Foundation
- Repository structure.
- CLI.
- Project initialization.
- Configuration schema.
- Security engine adapter interface.
- SAST, secret scanning, dependency audit.
- JSON and Markdown reporting.

### Phase 2 — Agent Integration
- MCP server.
- Claude Code integration.
- Standalone chat UI.
- Agent orchestration.
- Scan status and findings API.
- Policy engine and approval flow.

### Phase 3 — Runtime Security
- Local application detection.
- OWASP ZAP integration.
- OpenAPI analysis.
- Playwright integration.
- Evidence collection and deduplication.

### Phase 4 — Contextual Security Testing
- Authentication and authorization scenarios.
- BOLA/IDOR testing using test accounts.
- Tenant isolation checks.
- Business logic test planning.
- Finding verification workflow.

### Phase 5 — Remediation and Retesting
- Fix suggestions.
- Regression test generation.
- Retest workflow.
- Before/after comparison.
- SARIF export and CI integration.

### Phase 6 — Community and Extensibility
- Contributor documentation.
- Adapter development guide.
- Additional framework support.
- Additional coding agent integrations.
- Community test fixtures and benchmarks.

---

## 13. Success Metrics

Initial success metrics:

- Setup succeeds on supported environments without undocumented developer intervention.
- Coding agents successfully call MCP tools and receive structured results.
- Security engines produce reports that can be traced back to their source.
- Confirmed findings have sufficient evidence.
- Users can run a retest after fixing.
- No out-of-scope operation gets past policy enforcement in the product's security testing.
- Contributors can add a new adapter without changing the core orchestration.

Numeric targets for setup time, integration success rate, and verification quality will be set once an initial testing baseline is available.

---

## 14. Open-Source Strategy

### Repository Structure

Conceptual structure:

```text
mungard/
├── apps/
│   └── web/                 # Next.js chat UI and backend
├── packages/
│   ├── core/                # Orchestration and domain logic
│   ├── cli/                 # CLI
│   ├── mcp-server/          # MCP integration
│   ├── policy-engine/       # Scope and permissions
│   ├── findings/            # Finding schemas and normalization
│   ├── adapters/            # Security engine adapters
│   └── reporting/           # Markdown, JSON, SARIF
├── tests/
│   ├── fixtures/
│   ├── integration/
│   └── security/
├── docs/
├── scripts/
├── LICENSE
└── README.md
```

The structure may be adjusted to packaging and deployment needs during implementation.

### Distribution

- Public GitHub repository.
- README with a quick start.
- Docker-based setup for engines that require isolation.
- Example Claude Code configuration.
- MCP and CLI documentation.
- Sample reports and test fixtures.
- Contribution guide and security disclosure policy.

### Licensing

The project's primary license must be decided before release. The license of each dependency and security engine must be checked separately. All dependencies and integrations must have license compatibility appropriate for the product's distribution.

---

## 15. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| False positives from scanners or AI | Evidence-based verification and confidence classification |
| False negatives | Coverage reporting, rule updates, and a combination of static/runtime testing |
| Active scans damaging data | Approval gates, test environments, rate limits, and safe defaults |
| Credentials leaking into logs or the model | Redaction, data minimization, and local-first execution |
| Prompt injection from source code or scan results | Treat all tool output as untrusted data |
| Security tools using different formats | Adapter interface and normalized finding schema |
| Inconsistent user environments | Health checks, containerized engines, and compatibility documentation |
| AI producing incorrect fixes | Human approval, regression tests, and retesting |
| Product scope too broad | MVP focus on web/API before mobile and infrastructure testing |

---

## 16. Final Product Definition

This product is an **open-source, local-first AI Security Testing Agent** that connects coding agents with existing security testing tools.

Its core value is not merely running scanners, but orchestrating checks based on application context, collecting evidence, helping verify findings, and connecting security testing with remediation and retesting.

The MVP prioritizes web application and REST API security for developers who use AI coding tools. The MCP integration, CLI, and standalone chat interface make the product usable both as part of a coding agent workflow and on its own.

Final principle: the AI directs and analyzes; security engines run the checks; the policy engine constrains actions; evidence forms the basis of conclusions; and the developer retains control over changes and risky testing.
