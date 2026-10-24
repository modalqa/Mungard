import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  Finding,
  dedupeFindings,
  mergeFindings,
  sortFindings,
  transitionStatus,
  type Actor,
  type FindingStatus,
  type Triage,
} from "@mungard/findings";
import { ApprovalStore, AuditLog, PolicyEngine, createRedactor, type AuditActor, type Redactor } from "@mungard/policy-engine";
import type { EngineRunSummary, RetestComparison } from "@mungard/reporting";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { z } from "zod";
import { parseConfig, type ProjectConfig } from "./config.js";

export const WORKSPACE_DIR = ".mungard";

export const RunRecord = z.object({
  id: z.string(),
  kind: z.string(),
  status: z.enum(["running", "completed", "failed", "cancelled"]),
  actor: z.string(),
  startedAt: z.string(),
  finishedAt: z.string().optional(),
  codeVersion: z.string().optional(),
  targets: z.array(z.string()).default([]),
  steps: z.array(z.string()).default([]),
  engines: z.array(z.custom<EngineRunSummary>()).default([]),
  findingIds: z.array(z.string()).default([]),
  /** Steps blocked by policy: denied, or waiting for approval. */
  blocked: z
    .array(z.object({ step: z.string(), decision: z.string(), reasons: z.array(z.string()), approvalId: z.string().optional() }))
    .default([]),
  error: z.string().optional(),
});
export type RunRecord = z.infer<typeof RunRecord>;

const FindingsFile = z.object({ version: z.literal(1), findings: z.array(Finding) });
const RetestsFile = z.object({ version: z.literal(1), retests: z.array(z.custom<RetestComparison>()) });

const WORKSPACE_GITIGNORE = `# Mungard workspace: scan results, evidence and approvals stay local.
*
!.gitignore
!config.yaml
`;

async function atomicWrite(file: string, content: string): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tmp, content, { mode: 0o600 });
  await rename(tmp, file);
}

/** Cross-process lock (CLI, MCP server and web UI may share a workspace). */
async function withLock<T>(lockDir: string, fn: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + 15_000;
  for (;;) {
    try {
      await mkdir(lockDir);
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      try {
        const s = await stat(lockDir);
        if (Date.now() - s.mtimeMs > 60_000) await rm(lockDir, { recursive: true, force: true }); // stale lock
      } catch {
        // lock vanished; retry
      }
      if (Date.now() > deadline) throw new Error(`Timed out waiting for workspace lock ${lockDir}.`);
      await new Promise((r) => setTimeout(r, 50 + Math.random() * 100));
    }
  }
  try {
    return await fn();
  } finally {
    await rm(lockDir, { recursive: true, force: true });
  }
}

/**
 * The local workspace (`<project>/.mungard`). Everything Mungard produces
 * stays here: config, findings, run records, evidence, approvals, audit log.
 */
export class Workspace {
  readonly dir: string;
  readonly redact: Redactor;
  readonly approvals: ApprovalStore;
  readonly audit: AuditLog;
  readonly policyEngine: PolicyEngine;

  private constructor(
    readonly root: string,
    readonly config: ProjectConfig,
  ) {
    this.dir = path.join(root, WORKSPACE_DIR);
    this.redact = createRedactor(config.policy.redaction.extraPatterns);
    this.approvals = new ApprovalStore(path.join(this.dir, "approvals.json"));
    this.audit = new AuditLog(path.join(this.dir, "audit.log.jsonl"), this.redact);
    this.policyEngine = new PolicyEngine(config.policy, this.approvals, this.audit);
  }

  static configPath(root: string): string {
    return path.join(path.resolve(root), WORKSPACE_DIR, "config.yaml");
  }

  static async exists(root: string): Promise<boolean> {
    try {
      await stat(Workspace.configPath(root));
      return true;
    } catch {
      return false;
    }
  }

  /** Open a workspace. Without a config file, safe defaults are used (nothing is written). */
  static async open(root: string): Promise<Workspace> {
    const abs = path.resolve(root);
    let raw: unknown = {};
    try {
      raw = parseYaml(await readFile(Workspace.configPath(abs), "utf8"), { maxAliasCount: 50 }) ?? {};
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new Error(`Invalid ${WORKSPACE_DIR}/config.yaml: ${(err as Error).message}`);
      }
    }
    let config: ProjectConfig;
    try {
      config = parseConfig(raw);
    } catch (err) {
      throw new Error(`Invalid ${WORKSPACE_DIR}/config.yaml: ${(err as Error).message}`);
    }
    return new Workspace(abs, config);
  }

  static async writeConfig(root: string, config: ProjectConfig, header?: string): Promise<string> {
    const file = Workspace.configPath(root);
    const dir = path.dirname(file);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await writeFile(path.join(dir, ".gitignore"), WORKSPACE_GITIGNORE, { mode: 0o644 });
    await atomicWrite(file, `${header ?? ""}${stringifyYaml(config, { lineWidth: 120 })}`);
    return file;
  }

  private file(...parts: string[]): string {
    return path.join(this.dir, ...parts);
  }

  async ensure(): Promise<void> {
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    try {
      await stat(this.file(".gitignore"));
    } catch {
      await writeFile(this.file(".gitignore"), WORKSPACE_GITIGNORE, { mode: 0o644 });
    }
  }

  // ---------- findings ----------

  async loadFindings(): Promise<Finding[]> {
    try {
      return FindingsFile.parse(JSON.parse(await readFile(this.file("findings.json"), "utf8"))).findings;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw new Error(`Findings store is corrupt (${this.file("findings.json")}): ${(err as Error).message}`);
    }
  }

  private async saveFindings(findings: Finding[]): Promise<void> {
    await atomicWrite(this.file("findings.json"), JSON.stringify({ version: 1, findings: sortFindings(findings) }, null, 2));
  }

  async updateFindings<T>(fn: (findings: Finding[]) => Promise<{ findings: Finding[]; result: T }> | { findings: Finding[]; result: T }): Promise<T> {
    await this.ensure();
    return withLock(this.file(".lock"), async () => {
      const { findings, result } = await fn(await this.loadFindings());
      await this.saveFindings(findings);
      return result;
    });
  }

  /** Merge new findings into the store; duplicates keep all evidence and sources. */
  async mergeFindings(incoming: Finding[]): Promise<Finding[]> {
    return this.updateFindings((existing) => {
      const byFp = new Map(existing.map((f) => [f.fingerprint, f]));
      const touched: Finding[] = [];
      for (const f of dedupeFindings(incoming)) {
        const prev = byFp.get(f.fingerprint);
        const merged = prev ? mergeFindings(prev, f) : f;
        byFp.set(f.fingerprint, merged);
        touched.push(merged);
      }
      return { findings: [...byFp.values()], result: touched };
    });
  }

  async getFinding(id: string): Promise<Finding | undefined> {
    const all = await this.loadFindings();
    return all.find((f) => f.id === id || f.fingerprint === id);
  }

  async setFindingStatus(id: string, to: FindingStatus, actor: Actor, reason: string, via: AuditActor, retestRunId?: string): Promise<Finding> {
    const updated = await this.updateFindings((all) => {
      const idx = all.findIndex((f) => f.id === id);
      if (idx < 0) throw new Error(`Finding ${id} not found.`);
      const next = transitionStatus(all[idx]!, to, { actor, reason, retestRunId });
      all[idx] = next;
      return { findings: all, result: next };
    });
    await this.audit.write({ actor: via, event: "finding_status_changed", details: { findingId: id, to, actor, reason } });
    return updated;
  }

  async setTriage(triage: Map<string, Triage>): Promise<void> {
    await this.updateFindings((all) => ({
      findings: all.map((f) => (triage.has(f.id) ? { ...f, triage: triage.get(f.id) } : f)),
      result: undefined,
    }));
  }

  // ---------- runs ----------

  runDir(runId: string): string {
    return this.file("runs", runId);
  }

  async saveRun(run: RunRecord): Promise<void> {
    await atomicWrite(path.join(this.runDir(run.id), "run.json"), JSON.stringify(run, null, 2));
  }

  async getRun(runId: string): Promise<RunRecord | undefined> {
    if (!/^[a-zA-Z0-9_-]+$/.test(runId)) return undefined;
    try {
      return RunRecord.parse(JSON.parse(await readFile(path.join(this.runDir(runId), "run.json"), "utf8")));
    } catch {
      return undefined;
    }
  }

  async listRuns(limit = 50): Promise<RunRecord[]> {
    let ids: string[];
    try {
      ids = await readdir(this.file("runs"));
    } catch {
      return [];
    }
    const runs = (await Promise.all(ids.map((id) => this.getRun(id)))).filter((r): r is RunRecord => !!r);
    return runs.sort((a, b) => b.startedAt.localeCompare(a.startedAt)).slice(0, limit);
  }

  // ---------- retests ----------

  async loadRetests(): Promise<RetestComparison[]> {
    try {
      return RetestsFile.parse(JSON.parse(await readFile(this.file("retests.json"), "utf8"))).retests;
    } catch {
      return [];
    }
  }

  async addRetests(items: RetestComparison[]): Promise<void> {
    await withLock(this.file(".lock-retests"), async () => {
      const all = [...(await this.loadRetests()), ...items];
      await atomicWrite(this.file("retests.json"), JSON.stringify({ version: 1, retests: all }, null, 2));
    });
  }

  /**
   * Read an evidence file referenced by a finding. Only paths inside the
   * workspace are allowed; content is re-redacted on the way out.
   */
  async readEvidence(relPath: string, maxBytes = 64 * 1024): Promise<string> {
    const abs = path.resolve(this.dir, relPath);
    const rel = path.relative(this.dir, abs);
    if (rel.startsWith("..") || path.isAbsolute(rel) || !rel.startsWith(`runs${path.sep}`)) {
      throw new Error("Evidence path must point inside the workspace runs directory.");
    }
    const content = await readFile(abs, "utf8");
    const clipped = content.length > maxBytes ? `${content.slice(0, maxBytes)}\n…[truncated]` : content;
    return this.redact(clipped);
  }
}
