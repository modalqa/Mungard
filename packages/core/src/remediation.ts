import path from "node:path";
import { readSnippet } from "@mungard/adapters";
import type { Finding } from "@mungard/findings";
import type { Workspace } from "./workspace.js";

export interface RemediationProposal {
  findingId: string;
  title: string;
  affected: string[];
  codeContext?: string;
  guidance: string;
  regressionTest: { description: string; example: string };
  retestCommand: string;
  /** Mungard never edits code itself; the coding agent applies changes under its own permission prompts. */
  approvalNote: string;
}

const RULE_TESTS: { match: RegExp; description: string; example: string }[] = [
  {
    match: /sql-injection/,
    description: "A query with a quote-breaking payload must not change the result set.",
    example: `it("does not allow SQL injection in name", async () => {\n  const res = await request(app).get("/api/users").query({ name: "x' OR '1'='1" });\n  expect(res.body).toEqual([]);\n});`,
  },
  {
    match: /child-process-injection/,
    description: "Shell metacharacters in input must not execute extra commands.",
    example: `it("rejects shell metacharacters", async () => {\n  const res = await request(app).get("/api/ping").query({ host: "127.0.0.1; id" });\n  expect(res.status).toBe(400);\n});`,
  },
  {
    match: /tainted-path/,
    description: "Path traversal sequences must be rejected.",
    example: `it("blocks path traversal", async () => {\n  const res = await request(app).get("/api/download").query({ file: "../../etc/passwd" });\n  expect(res.status).toBe(400);\n});`,
  },
  {
    match: /open-redirect/,
    description: "Redirects to external hosts must be refused.",
    example: `it("does not redirect off-site", async () => {\n  const res = await request(app).get("/go").query({ next: "https://evil.example" });\n  expect(res.headers.location ?? "").not.toMatch(/^https?:\\/\\/evil/);\n});`,
  },
  {
    match: /ssrf/,
    description: "Requests to internal or metadata addresses must be refused.",
    example: `it("blocks SSRF to metadata", async () => {\n  const res = await request(app).get("/api/proxy").query({ url: "http://169.254.169.254/" });\n  expect(res.status).toBe(400);\n});`,
  },
];

function categoryTest(f: Finding): { description: string; example: string } {
  const rule = f.sources.map((s) => s.ruleId ?? "").join(" ");
  const specific = RULE_TESTS.find((t) => t.match.test(rule));
  if (specific) return specific;
  const ep = f.locations.find((l) => l.kind === "endpoint");
  switch (f.category) {
    case "authz":
    case "authn":
      return {
        description: "Another user (and an anonymous client) must be denied access to the owner's resource.",
        example: `it("denies access to another user's resource", async () => {\n  const res = await request(app)\n    .${(ep?.method ?? "GET").toLowerCase()}("${ep?.path ?? "/api/resource/OWNED_BY_ALICE"}")\n    .set("Authorization", \`Bearer \${bobToken}\`);\n  expect([403, 404]).toContain(res.status);\n});`,
      };
    case "business_logic":
      return { description: "Encode the violated business rule as an integration test of the same request sequence.", example: "// Re-run the scenario steps from the finding and assert the expected rejection status." };
    case "secret":
      return { description: "Prevent regressions with a pre-commit/CI secret scan.", example: "gitleaks git . --redact   # or: mungard scan --only secrets --fail-on high" };
    case "dependency":
      return { description: "Fail CI when vulnerable dependencies are introduced.", example: "npm audit --audit-level=high   # or: mungard scan --only deps --fail-on high" };
    case "headers":
    case "dast":
      return { description: "Assert the security header on responses.", example: `it("sets security headers", async () => {\n  const res = await fetch(baseUrl);\n  expect(res.headers.get("content-security-policy")).toBeTruthy();\n});` };
    default:
      return { description: "Re-run the Mungard check in CI.", example: "mungard audit . --fail-on high" };
  }
}

export async function proposeRemediation(ws: Workspace, findingId: string): Promise<RemediationProposal> {
  const f = await ws.getFinding(findingId);
  if (!f) throw new Error(`Finding ${findingId} not found.`);
  const file = f.locations.find((l) => l.kind === "file" && l.path);
  const codeContext =
    file?.path && f.category !== "secret"
      ? await readSnippet(path.join(ws.root, file.path), file.startLine, ws.redact, { context: 8, maxFileSizeBytes: ws.config.policy.limits.maxFileSizeBytes })
      : undefined;
  return {
    findingId: f.id,
    title: f.title,
    affected: f.locations.map((l) => [l.method, l.path ?? l.url ?? l.packageName ?? l.serverName, l.startLine ? `line ${l.startLine}` : undefined].filter(Boolean).join(" ")),
    codeContext,
    guidance: f.remediation || "No engine-specific guidance; see the finding description.",
    regressionTest: categoryTest(f),
    retestCommand: `mungard retest ${f.id}`,
    approvalNote:
      "Mungard does not modify source code. Apply the change through your coding agent or editor (code changes require your approval), then run the retest command.",
  };
}
