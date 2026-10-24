import { cp, mkdtemp, readFile, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Workspace, buildReportInput, runAssessment, runRetest } from "@mungard/core";
import { renderMarkdown, renderSarif } from "@mungard/reporting";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.resolve(here, "../fixtures/vulnerable-api");

let root: string;
let close: () => Promise<void>;

beforeAll(async () => {
  const { createServer } = (await import(path.join(fixture, "server.mjs"))) as { createServer: () => import("node:http").Server };
  const server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  close = () => new Promise((r) => server.close(() => r()));
  root = await mkdtemp(path.join(os.tmpdir(), "mungard-it-"));
  await cp(fixture, root, { recursive: true });
  const cfgPath = path.join(root, ".mungard/config.yaml");
  const cfg = (await readFile(cfgPath, "utf8")).replaceAll("4010", String(port));
  await writeFile(cfgPath, cfg);
  process.env.MUNGARD_ALICE_TOKEN = "alice-token";
  process.env.MUNGARD_BOB_TOKEN = "bob-token";
});

afterAll(async () => {
  await close?.();
});

describe("runtime authorization testing against the vulnerable fixture API", () => {
  it("confirms BOLA with evidence, finds the auth bypass and avoids false positives", async () => {
    const ws = await Workspace.open(root);
    const { run, findings } = await runAssessment(ws, { kind: "test", steps: ["api", "authz", "headers"], actor: "cli" });
    expect(run.status).toBe("completed");
    const bola = findings.find((f) => f.sources[0]?.ruleId === "mungard.authz.invoice-ownership");
    expect(bola?.status).toBe("confirmed");
    expect(bola?.evidence.some((e) => e.kind === "http_exchange")).toBe(true);
    // Correctly protected resource: no finding.
    expect(findings.some((f) => f.sources[0]?.ruleId === "mungard.authz.project-ownership")).toBe(false);
    expect(findings.some((f) => f.sources[0]?.ruleId === "mungard.authn.spec-mismatch" && f.locations[0]?.path === "/api/reports/summary")).toBe(true);
    expect(findings.some((f) => f.sources[0]?.ruleId === "mungard.http.cors-reflection")).toBe(true);
    // The data-changing scenario must not run without approval.
    expect(findings.some((f) => f.category === "business_logic")).toBe(false);
    // Bearer tokens never appear in stored evidence or reports.
    const report = renderMarkdown(await buildReportInput(ws));
    expect(report).not.toContain("alice-token");
    expect(report).not.toContain("bob-token");
    expect(renderSarif(await buildReportInput(ws))).toContain('"version": "2.1.0"');
  });

  it("requires approval for state-changing scenarios, then detects the business-logic flaw", async () => {
    const ws = await Workspace.open(root);
    const first = await runAssessment(ws, { kind: "test", steps: ["authz"], options: { includeWriteTests: true }, actor: "mcp" });
    expect(first.run.blocked[0]?.decision).toBe("approval_required");
    const approvalId = first.run.blocked[0]!.approvalId!;
    await ws.approvals.decide(approvalId, "approved", "human:test");
    const second = await runAssessment(ws, { kind: "test", steps: ["authz"], options: { includeWriteTests: true }, actor: "mcp" });
    const logic = second.findings.find((f) => f.category === "business_logic");
    expect(logic?.status).toBe("confirmed");
    expect(logic?.title).toMatch(/cannot be shipped before it is paid/);
  });

  it("retest keeps unfixed findings unresolved", async () => {
    const ws = await Workspace.open(root);
    const all = await ws.loadFindings();
    const bola = all.find((f) => f.sources[0]?.ruleId === "mungard.authz.invoice-ownership")!;
    const bypass = all.find((f) => f.sources[0]?.ruleId === "mungard.authn.spec-mismatch")!;
    const r = await runRetest(ws, [bola.id, bypass.id], { actor: "cli" });
    expect(r.comparisons.map((c) => c.after)).toEqual(["failed", "failed"]);
    const after = await ws.getFinding(bola.id);
    expect(after?.status).toBe("confirmed");
    expect(after?.retest.status).toBe("failed");
  });
});
