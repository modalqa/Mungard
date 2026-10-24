import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  ApprovalStore,
  AuditLog,
  PolicyEngine,
  checkRedirect,
  checkTarget,
  hashParams,
  operationRule,
  parsePolicy,
  resolveWithinRoot,
} from "@mungard/policy-engine";
import { describe, expect, it } from "vitest";

const policy = parsePolicy({});

describe("target scope enforcement (SR-01)", () => {
  it("allows localhost by default", () => {
    expect(checkTarget("http://localhost:3000/", policy).allowed).toBe(true);
    expect(checkTarget("http://127.0.0.1:8080/api", policy).allowed).toBe(true);
  });

  it("denies hosts that are not allowlisted", () => {
    const d = checkTarget("https://example.com/", policy);
    expect(d.allowed).toBe(false);
    expect(d.reasons.join(" ")).toMatch(/allowedHosts/);
  });

  it("always blocks cloud metadata addresses, even if allowlisted", () => {
    const p = parsePolicy({ targets: { allowedHosts: ["169.254.169.254"] } });
    expect(checkTarget("http://169.254.169.254/latest/meta-data", p).allowed).toBe(false);
  });

  it("rejects non-http protocols and credentials in URLs", () => {
    expect(checkTarget("file:///etc/passwd", policy).allowed).toBe(false);
    expect(checkTarget("http://user:pass@localhost:3000/", policy).allowed).toBe(false);
    expect(checkTarget("not a url", policy).allowed).toBe(false);
  });

  it("enforces the port allowlist", () => {
    const p = parsePolicy({ targets: { allowedPorts: [3000] } });
    expect(checkTarget("http://localhost:3000", p).allowed).toBe(true);
    expect(checkTarget("http://localhost:5432", p).allowed).toBe(false);
    expect(checkTarget("http://localhost", p).allowed).toBe(false); // implicit port 80
  });

  it("supports wildcard hosts without matching the bare domain or look-alikes", () => {
    const p = parsePolicy({ targets: { allowedHosts: ["*.staging.example.test"] } });
    expect(checkTarget("https://app.staging.example.test", p).allowed).toBe(true);
    expect(checkTarget("https://staging.example.test", p).allowed).toBe(false);
    expect(checkTarget("https://evilstaging.example.test", p).allowed).toBe(false);
  });

  it("denies production hosts unless explicitly allowed", () => {
    const p = parsePolicy({ targets: { allowedHosts: ["app.example.test"], productionHosts: ["app.example.test"] } });
    expect(checkTarget("https://app.example.test", p).allowed).toBe(false);
    const p2 = parsePolicy({ targets: { allowedHosts: ["app.example.test"], productionHosts: ["app.example.test"], allowProduction: true } });
    expect(checkTarget("https://app.example.test", p2).allowed).toBe(true);
  });

  it("refuses redirects that leave the scope", () => {
    expect(checkRedirect("http://localhost:3000/login", "/dashboard", policy).allowed).toBe(true);
    expect(checkRedirect("http://localhost:3000/login", "https://evil.example/", policy).allowed).toBe(false);
  });

  it("confines paths to the project root", () => {
    expect(resolveWithinRoot("/srv/app", "openapi.yaml")).toBe(path.resolve("/srv/app/openapi.yaml"));
    expect(() => resolveWithinRoot("/srv/app", "../../etc/passwd")).toThrow(/escapes/);
    expect(() => resolveWithinRoot("/srv/app", "/etc/passwd")).toThrow(/escapes/);
  });
});

describe("operation rules (SR-04, SR-08)", () => {
  it("gates active and destructive operations by default", () => {
    expect(operationRule(policy, "static_scan")).toBe("allow");
    expect(operationRule(policy, "web_active_scan")).toBe("require_approval");
    expect(operationRule(policy, "authz_write_tests")).toBe("require_approval");
    expect(operationRule(policy, "mcp_live_inspect")).toBe("require_approval");
    expect(operationRule(policy, "code_modification")).toBe("require_approval");
  });

  it("cannot relax always-gated operations to allow via config", () => {
    const p = parsePolicy({ operations: { web_active_scan: "allow", code_modification: "allow" } });
    expect(operationRule(p, "web_active_scan")).toBe("require_approval");
    expect(operationRule(p, "code_modification")).toBe("require_approval");
  });

  it("lets config deny any operation", () => {
    expect(operationRule(parsePolicy({ operations: { static_scan: "deny" } }), "static_scan")).toBe("deny");
  });
});

async function engine(p = policy) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "mungard-test-"));
  const approvals = new ApprovalStore(path.join(dir, "approvals.json"));
  const audit = new AuditLog(path.join(dir, "audit.log.jsonl"));
  return { pe: new PolicyEngine(p, approvals, audit), approvals, audit };
}

describe("policy engine and approvals", () => {
  it("allows permitted operations and audits the decision", async () => {
    const { pe, audit } = await engine();
    const d = await pe.authorize({ operation: "static_scan", actor: "mcp", summary: "x", params: {} });
    expect(d.kind).toBe("allow");
    const log = await audit.read();
    expect(log.at(-1)).toMatchObject({ event: "policy_decision", decision: "allow", operation: "static_scan" });
  });

  it("denies out-of-scope targets even for allowed operations", async () => {
    const { pe } = await engine();
    const d = await pe.authorize({ operation: "http_probe", actor: "mcp", summary: "x", target: "https://example.com", params: {} });
    expect(d.kind).toBe("deny");
  });

  it("requires approval, then allows exactly once with identical parameters", async () => {
    const { pe, approvals } = await engine();
    const req = { operation: "web_active_scan" as const, actor: "mcp" as const, summary: "active", target: "http://localhost:3000", params: { target: "http://localhost:3000", mode: "active" } };
    const first = await pe.authorize(req);
    expect(first.kind).toBe("approval_required");
    if (first.kind !== "approval_required") return;

    // Repeating before approval does not create a second request.
    const again = await pe.authorize(req);
    expect(again.kind === "approval_required" && again.approval.id).toBe(first.approval.id);

    await approvals.decide(first.approval.id, "approved", "human:test");

    // Different parameters are not unlocked by this approval.
    const other = await pe.authorize({ ...req, params: { target: "http://localhost:3000", mode: "active", extra: 1 } });
    expect(other.kind).toBe("approval_required");

    expect((await pe.authorize(req)).kind).toBe("allow");
    // Single use.
    expect((await pe.authorize(req)).kind).toBe("approval_required");
  });

  it("denied approvals never unlock the operation", async () => {
    const { pe, approvals } = await engine();
    const req = { operation: "authz_write_tests" as const, actor: "chat" as const, summary: "w", params: { a: 1 } };
    const first = await pe.authorize(req);
    if (first.kind !== "approval_required") throw new Error("expected approval");
    await approvals.decide(first.approval.id, "denied", "human:test");
    expect((await pe.authorize(req)).kind).toBe("approval_required");
    await expect(approvals.decide(first.approval.id, "approved", "human:test")).rejects.toThrow(/not pending/);
  });

  it("expires approvals", async () => {
    const { pe, approvals } = await engine(parsePolicy({ approvals: { expiresMinutes: 1 } }));
    const req = { operation: "web_active_scan" as const, actor: "mcp" as const, summary: "a", params: { x: 1 } };
    const first = await pe.authorize(req);
    if (first.kind !== "approval_required") throw new Error("expected approval");
    await approvals.decide(first.approval.id, "approved", "human:test");
    const realNow = Date.now;
    Date.now = () => realNow() + 2 * 60_000;
    const RealDate = Date;
    // Shift "new Date()" too.
    globalThis.Date = class extends RealDate {
      constructor(...args: ConstructorParameters<typeof Date>) {
        super(...(args.length ? args : [realNow() + 2 * 60_000]) as [number]);
      }
    } as DateConstructor;
    try {
      expect((await pe.authorize(req)).kind).toBe("approval_required");
      expect((await approvals.get(first.approval.id))?.status).toBe("expired");
    } finally {
      globalThis.Date = RealDate;
      Date.now = realNow;
    }
  });

  it("hashes parameters independently of key order", () => {
    expect(hashParams("static_scan", { a: 1, b: [1, 2] })).toBe(hashParams("static_scan", { b: [1, 2], a: 1 }));
    expect(hashParams("static_scan", { a: 1 })).not.toBe(hashParams("secret_scan", { a: 1 }));
  });
});
