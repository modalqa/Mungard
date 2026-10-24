import { createRedactor, redact, redactDeep, truncate } from "@mungard/policy-engine";
import { describe, expect, it } from "vitest";

// Built at runtime so this file does not itself contain secret-shaped literals.
const fake = (prefix: string, n: number, ch = "a") => prefix + ch.repeat(n);

describe("secret redaction (SR-02)", () => {
  it.each([
    ["anthropic", fake("sk-ant-api03-", 40)],
    ["github", fake("ghp_", 36, "B")],
    ["aws", `AKIA${"Z".repeat(16)}`],
    ["stripe", fake("sk_live_", 24, "x")],
    ["slack", fake("xoxb-1234-", 20, "c")],
    ["jwt", `eyJ${"a".repeat(20)}.eyJ${"b".repeat(20)}.${"c".repeat(20)}`],
  ])("masks %s tokens", (_name, token) => {
    const out = redact(`token=${token} trailing`);
    expect(out).not.toContain(token);
    expect(out).toContain("[REDACTED]");
  });

  it("masks authorization and cookie headers but keeps header names", () => {
    const out = redact("Authorization: Bearer abcdefghijklmnop\nCookie: session=supersecretvalue123");
    expect(out).toContain("Authorization:");
    expect(out).not.toContain("abcdefghijklmnop");
    expect(out).not.toContain("supersecretvalue123");
  });

  it("masks credentials embedded in URLs", () => {
    const out = redact("postgres://admin:hunter2hunter2@db.local:5432/app");
    expect(out).not.toContain("hunter2hunter2");
    expect(out).toContain("postgres://admin:");
  });

  it("masks private keys", () => {
    const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----";
    expect(redact(key)).not.toContain("MIIEow");
  });

  it("redacts sensitive keys deeply in objects", () => {
    const out = redactDeep({ headers: { authorization: "Bearer zzzzzzzzzzzz", accept: "json" }, nested: [{ password: "p4ssw0rd!!" }] });
    expect(JSON.stringify(out)).not.toContain("zzzzzzzzzzzz");
    expect(JSON.stringify(out)).not.toContain("p4ssw0rd!!");
    expect(out.headers.accept).toBe("json");
  });

  it("applies custom patterns from config", () => {
    const r = createRedactor(["ACME-[0-9]{6}"]);
    expect(r("id ACME-123456 ok")).not.toContain("ACME-123456");
  });

  it("is idempotent", () => {
    const once = redact(`x ${fake("ghp_", 36, "Q")}`);
    expect(redact(once)).toBe(once);
  });

  it("truncates long evidence", () => {
    expect(truncate("a".repeat(100), 10)).toMatch(/truncated 90 bytes/);
  });
});
