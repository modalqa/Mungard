import type { Actor, Finding, FindingStatus } from "./schema.js";

export class StatusTransitionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StatusTransitionError";
  }
}

/**
 * Who may move a finding into which status.
 *
 * - AI may never change a status. Triage output is advisory (FR-12).
 * - Tools may only flag for review, confirm with captured evidence, or close
 *   a finding as `retested` after a passing retest.
 * - Humans may set anything except `retested`, which requires a retest.
 */
const ALLOWED_TARGETS: Record<Actor, readonly FindingStatus[]> = {
  ai: [],
  tool: ["new", "needs_review", "confirmed", "retested"],
  human: ["new", "needs_review", "confirmed", "false_positive", "accepted_risk", "fixed"],
};

export interface TransitionOptions {
  actor: Actor;
  reason: string;
  now?: string;
  /** Required for tool-driven `retested`: the retest run that verified the fix. */
  retestRunId?: string;
}

export function assertTransition(finding: Finding, to: FindingStatus, opts: TransitionOptions): void {
  if (!opts.reason.trim()) {
    throw new StatusTransitionError("A reason is required for every status change.");
  }
  if (!ALLOWED_TARGETS[opts.actor].includes(to)) {
    throw new StatusTransitionError(
      opts.actor === "ai"
        ? "AI output is advisory and cannot change a finding status. A human must review it."
        : `Actor "${opts.actor}" cannot set status "${to}".`,
    );
  }
  if (to === "confirmed" && finding.evidence.length === 0) {
    throw new StatusTransitionError("A finding cannot be confirmed without at least one evidence reference.");
  }
  if (to === "retested" && !opts.retestRunId) {
    throw new StatusTransitionError("Status 'retested' requires a passing retest run.");
  }
}

/** Returns a new finding with the status changed and the change recorded in history. */
export function transitionStatus(finding: Finding, to: FindingStatus, opts: TransitionOptions): Finding {
  assertTransition(finding, to, opts);
  if (finding.status === to) return finding;
  const at = opts.now ?? new Date().toISOString();
  return {
    ...finding,
    status: to,
    history: [...finding.history, { from: finding.status, to, actor: opts.actor, reason: opts.reason, at }],
  };
}
