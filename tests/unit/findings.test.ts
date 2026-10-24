import { Finding, dedupeFindings, normalizeFinding, transitionStatus, type RawFinding } from "@mungard/findings";
import { describe, expect, it } from "vitest";

const raw = (over: Partial<RawFinding> = {}): RawFinding => ({
  title: "Sql injection in src/a.ts",
  description: "d",
  category: "sast",
  severity: "high",
  confidence: "medium",
  ruleId: "mungard.js.sql-injection",
  locations: [{ kind: "file", path: "src/a.ts", startLine: 10 }],
  evidence: [{ kind: "scanner_output", description: "semgrep" }],
  fingerprintHint: "db.query(`SELECT ${x}`)",
  ...over,
});

describe("normalization (FR-11)", () => {
  it("produces a schema-valid finding with status new and a stable id", () => {
    const f = normalizeFinding(raw(), { engine: "semgrep", runId: "run_1" });
    expect(Finding.parse(f)).toBeTruthy();
    expect(f.status).toBe("new");
    expect(f.id).toMatch(/^MG-[0-9A-F]{10}$/);
    expect(f.sources[0]).toMatchObject({ engine: "semgrep", runId: "run_1", ruleId: "mungard.js.sql-injection" });
  });

  it("keeps the fingerprint stable when only line numbers change", () => {
    const a = normalizeFinding(raw(), { engine: "semgrep", runId: "r1" });
    const b = normalizeFinding(raw({ locations: [{ kind: "file", path: "src/a.ts", startLine: 42 }] }), { engine: "semgrep", runId: "r2" });
    expect(a.fingerprint).toBe(b.fingerprint);
  });

  it("never marks an unverified finding confirmed", () => {
    expect(normalizeFinding(raw({ verified: false }), { engine: "x", runId: "r" }).status).toBe("new");
    // verified without evidence is not enough
    expect(normalizeFinding(raw({ verified: true, evidence: [] }), { engine: "x", runId: "r" }).status).toBe("new");
    const v = normalizeFinding(raw({ verified: true }), { engine: "authz", runId: "r" });
    expect(v.status).toBe("confirmed");
    expect(v.history[0]).toMatchObject({ actor: "tool", to: "confirmed" });
  });

  it("merges duplicates without losing sources or evidence (FR-04)", () => {
    const a = normalizeFinding(raw(), { engine: "semgrep", runId: "r1" });
    const b = normalizeFinding(raw({ severity: "critical", evidence: [{ kind: "note", description: "second" }] }), { engine: "semgrep", runId: "r2" });
    const [m] = dedupeFindings([a, b]);
    expect(m!.sources).toHaveLength(2);
    expect(m!.evidence.map((e) => e.description)).toEqual(expect.arrayContaining(["semgrep", "second"]));
    expect(m!.severity).toBe("critical");
    expect(m!.id).toBe(a.id);
  });
});

describe("status workflow", () => {
  const base = normalizeFinding(raw(), { engine: "semgrep", runId: "r1" });

  it("AI can never change a status (FR-12)", () => {
    expect(() => transitionStatus(base, "confirmed", { actor: "ai", reason: "looks bad" })).toThrow(/advisory/);
    expect(() => transitionStatus(base, "false_positive", { actor: "ai", reason: "looks fine" })).toThrow(/advisory/);
  });

  it("confirmation requires evidence", () => {
    const noEvidence = { ...base, evidence: [] };
    expect(() => transitionStatus(noEvidence, "confirmed", { actor: "human", reason: "I checked" })).toThrow(/evidence/);
  });

  it("retested requires a passing retest run and cannot be set by humans", () => {
    expect(() => transitionStatus(base, "retested", { actor: "human", reason: "trust me" })).toThrow();
    expect(() => transitionStatus(base, "retested", { actor: "tool", reason: "retest" })).toThrow(/retest/);
    expect(transitionStatus(base, "retested", { actor: "tool", reason: "retest", retestRunId: "run_2" }).status).toBe("retested");
  });

  it("records history with a required reason", () => {
    expect(() => transitionStatus(base, "false_positive", { actor: "human", reason: " " })).toThrow(/reason/);
    const f = transitionStatus(base, "false_positive", { actor: "human", reason: "test fixture" });
    expect(f.history.at(-1)).toMatchObject({ from: "new", to: "false_positive", actor: "human", reason: "test fixture" });
  });
});
