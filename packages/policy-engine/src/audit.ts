import { appendFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { redactDeep, type Redactor, redact } from "./redact.js";

export type AuditActor = "cli" | "mcp" | "chat" | "web" | "guard" | "system";

export interface AuditEvent {
  ts: string;
  actor: AuditActor;
  event:
    | "policy_decision"
    | "tool_started"
    | "tool_finished"
    | "tool_failed"
    | "approval_requested"
    | "approval_decided"
    | "approval_consumed"
    | "finding_status_changed"
    | "agent_request"
    | "report_generated"
    | "config_changed"
    | "guard_decision";
  operation?: string;
  target?: string;
  decision?: string;
  runId?: string;
  details?: Record<string, unknown>;
}

/** Append-only JSONL audit log (SR-06). Every entry is redacted before it is written. */
export class AuditLog {
  constructor(
    private readonly file: string,
    private readonly redactor: Redactor = redact,
  ) {}

  async write(event: Omit<AuditEvent, "ts">): Promise<void> {
    const entry = redactDeep({ ts: new Date().toISOString(), ...event }, this.redactor);
    await mkdir(path.dirname(this.file), { recursive: true });
    await appendFile(this.file, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
  }

  async read(limit = 200): Promise<AuditEvent[]> {
    try {
      const lines = (await readFile(this.file, "utf8")).split("\n").filter(Boolean);
      return lines.slice(-limit).map((l) => JSON.parse(l) as AuditEvent);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }
}
