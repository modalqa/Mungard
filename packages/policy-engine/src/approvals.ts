import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { Operation } from "./policy.js";

export const ApprovalStatus = z.enum(["pending", "approved", "denied", "consumed", "expired"]);
export type ApprovalStatus = z.infer<typeof ApprovalStatus>;

export const ApprovalRequest = z.object({
  id: z.string(),
  operation: Operation,
  /** Human-readable summary of what will happen. */
  summary: z.string(),
  target: z.string().optional(),
  /** Hash of the exact parameters; an approval only unlocks the identical request. */
  paramsHash: z.string(),
  params: z.record(z.string(), z.unknown()),
  requestedBy: z.string(),
  requestedAt: z.string(),
  expiresAt: z.string(),
  status: ApprovalStatus,
  decidedBy: z.string().optional(),
  decidedAt: z.string().optional(),
  decisionNote: z.string().optional(),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequest>;

const ApprovalFile = z.object({ version: z.literal(1), approvals: z.array(ApprovalRequest) });

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function hashParams(operation: Operation, params: Record<string, unknown>): string {
  return createHash("sha256").update(`${operation}\u0000${stableStringify(params)}`).digest("hex");
}

/**
 * File-backed approval queue (SR-04). Agents can *request* approvals; only
 * human-facing interfaces (interactive CLI, local web UI) can decide them.
 * Approvals are single-use, time-limited and bound to the exact parameters.
 */
export class ApprovalStore {
  constructor(private readonly file: string) {}

  private async load(): Promise<ApprovalRequest[]> {
    try {
      const parsed = ApprovalFile.parse(JSON.parse(await readFile(this.file, "utf8")));
      return parsed.approvals;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw new Error(`Approval store ${this.file} is unreadable: ${(err as Error).message}`);
    }
  }

  private async save(approvals: ApprovalRequest[]): Promise<void> {
    await mkdir(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify({ version: 1, approvals }, null, 2), { mode: 0o600 });
    await rename(tmp, this.file);
  }

  private expire(approvals: ApprovalRequest[], now: Date): boolean {
    let changed = false;
    for (const a of approvals) {
      if ((a.status === "pending" || a.status === "approved") && new Date(a.expiresAt) < now) {
        a.status = "expired";
        changed = true;
      }
    }
    return changed;
  }

  async list(filter?: ApprovalStatus): Promise<ApprovalRequest[]> {
    const approvals = await this.load();
    if (this.expire(approvals, new Date())) await this.save(approvals);
    return filter ? approvals.filter((a) => a.status === filter) : approvals;
  }

  async get(id: string): Promise<ApprovalRequest | undefined> {
    return (await this.list()).find((a) => a.id === id);
  }

  /** Request approval, reusing an identical pending/approved request if present. */
  async request(input: {
    operation: Operation;
    summary: string;
    target?: string;
    params: Record<string, unknown>;
    requestedBy: string;
    expiresMinutes: number;
  }): Promise<ApprovalRequest> {
    const approvals = await this.load();
    const now = new Date();
    this.expire(approvals, now);
    const paramsHash = hashParams(input.operation, input.params);
    const existing = approvals.find(
      (a) => a.paramsHash === paramsHash && (a.status === "pending" || a.status === "approved"),
    );
    if (existing) return existing;
    const req: ApprovalRequest = {
      id: `apr_${randomBytes(6).toString("hex")}`,
      operation: input.operation,
      summary: input.summary,
      target: input.target,
      paramsHash,
      params: input.params,
      requestedBy: input.requestedBy,
      requestedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + input.expiresMinutes * 60_000).toISOString(),
      status: "pending",
    };
    approvals.push(req);
    await this.save(approvals);
    return req;
  }

  async decide(id: string, decision: "approved" | "denied", decidedBy: string, note?: string): Promise<ApprovalRequest> {
    const approvals = await this.load();
    this.expire(approvals, new Date());
    const req = approvals.find((a) => a.id === id);
    if (!req) throw new Error(`Approval ${id} not found.`);
    if (req.status !== "pending") throw new Error(`Approval ${id} is ${req.status}, not pending.`);
    req.status = decision;
    req.decidedBy = decidedBy;
    req.decidedAt = new Date().toISOString();
    req.decisionNote = note;
    await this.save(approvals);
    return req;
  }

  /**
   * Atomically consume an approved request matching these exact parameters.
   * Returns the approval when the operation may proceed, otherwise undefined.
   */
  async consume(operation: Operation, params: Record<string, unknown>): Promise<ApprovalRequest | undefined> {
    const approvals = await this.load();
    this.expire(approvals, new Date());
    const paramsHash = hashParams(operation, params);
    const req = approvals.find((a) => a.paramsHash === paramsHash && a.status === "approved");
    if (!req) {
      await this.save(approvals);
      return undefined;
    }
    req.status = "consumed";
    await this.save(approvals);
    return req;
  }
}
