import { cp, mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "@mungard/mcp-server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
let client: Client;
let root: string;

function json(res: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  const content = res.content as { type: string; text: string }[];
  return JSON.parse(content[0]!.text) as Record<string, unknown>;
}

beforeAll(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "mungard-mcp-"));
  await cp(path.resolve(here, "../fixtures/vulnerable-app"), root, { recursive: true });
  const server = createMcpServer({ root });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  client = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([server.connect(serverT), client.connect(clientT)]);
});

afterAll(async () => {
  await client?.close();
});

describe("MCP server (FR-03)", () => {
  it("exposes only the defined tools and no approval tool", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    for (const expected of [
      "get_project_context",
      "get_security_policy",
      "plan_security_assessment",
      "run_static_scan",
      "run_secret_scan",
      "run_dependency_audit",
      "run_web_scan",
      "analyze_api_spec",
      "run_authorization_tests",
      "get_scan_status",
      "list_findings",
      "get_finding_evidence",
      "propose_remediation",
      "run_retest",
      "generate_security_report",
      "inspect_mcp_config",
      "audit_agent_config",
    ]) {
      expect(names).toContain(expected);
    }
    expect(names.some((n) => /approve|exec|shell|command/i.test(n))).toBe(false);
  });

  it("rejects invalid input", async () => {
    const res = await client.callTool({ name: "run_retest", arguments: { findingIds: [] } });
    expect(res.isError).toBe(true);
  });

  it("inspects MCP config and agent config without external engines", async () => {
    const mcp = json(await client.callTool({ name: "inspect_mcp_config", arguments: {} }));
    const ids = (mcp.findings as { title: string }[]).map((f) => f.title).join("\n");
    expect(ids).toMatch(/Committed credential|Hardcoded credential/);
    expect(ids).toMatch(/unpinned package/);
    const agent = json(await client.callTool({ name: "audit_agent_config", arguments: {} }));
    expect((agent.findings as { title: string }[]).some((f) => /invisible/.test(f.title))).toBe(true);
  });

  it("returns an approval request for active scans instead of running them", async () => {
    const res = json(await client.callTool({ name: "run_web_scan", arguments: { target: "http://localhost:3000", mode: "active", wait: true } }));
    const blocked = res.blockedByPolicy as { step: string; decision: string; approvalId?: string }[];
    expect(blocked.find((b) => b.step === "web")?.decision).toBe("approval_required");
  });

  it("denies out-of-scope targets", async () => {
    const res = json(await client.callTool({ name: "run_web_scan", arguments: { target: "https://example.com", mode: "passive", wait: true } }));
    const blocked = res.blockedByPolicy as { decision: string }[];
    expect(blocked.every((b) => b.decision === "deny")).toBe(true);
  });

  it("lists findings and evidence, never secret values", async () => {
    const list = json(await client.callTool({ name: "list_findings", arguments: { limit: 100 } }));
    expect((list.findings as unknown[]).length).toBeGreaterThan(0);
    const first = (list.findings as { id: string }[])[0]!;
    const ev = await client.callTool({ name: "get_finding_evidence", arguments: { findingId: first.id, includeEvidenceFiles: true } });
    const text = (ev.content as { text: string }[])[0]!.text;
    expect(text).not.toContain("fixture-not-a-real-token-7f3a9c2e1b");
  });
});
