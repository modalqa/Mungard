import { ApprovalStore, type ApprovalRequest } from "./approvals.js";
import { AuditLog, type AuditActor } from "./audit.js";
import { operationRule, type Operation, type SecurityPolicy } from "./policy.js";
import { checkTarget, resolveAndCheckTarget } from "./scope.js";

export type PolicyDecision =
  | { kind: "allow"; reasons: string[] }
  | { kind: "deny"; reasons: string[] }
  | { kind: "approval_required"; reasons: string[]; approval: ApprovalRequest };

export interface AuthorizeRequest {
  operation: Operation;
  actor: AuditActor;
  /** Short description shown to the human approving the request. */
  summary: string;
  target?: string;
  /** The exact parameters; approvals are bound to them. */
  params: Record<string, unknown>;
}

/**
 * Single choke point for every operation (FR-15). Interfaces (CLI, MCP, chat)
 * call {@link PolicyEngine.authorize} before running anything; adapters never
 * decide scope on their own.
 */
export class PolicyEngine {
  constructor(
    readonly policy: SecurityPolicy,
    readonly approvals: ApprovalStore,
    readonly audit: AuditLog,
  ) {}

  async authorize(req: AuthorizeRequest): Promise<PolicyDecision> {
    const decision = await this.evaluate(req);
    await this.audit.write({
      actor: req.actor,
      event: "policy_decision",
      operation: req.operation,
      target: req.target,
      decision: decision.kind,
      details: { reasons: decision.reasons, ...(decision.kind === "approval_required" ? { approvalId: decision.approval.id } : {}) },
    });
    return decision;
  }

  private async evaluate(req: AuthorizeRequest): Promise<PolicyDecision> {
    const rule = operationRule(this.policy, req.operation);
    if (rule === "deny") {
      return { kind: "deny", reasons: [`Operation ${req.operation} is denied by policy.operations.`] };
    }
    if (req.target !== undefined) {
      const scope = await resolveAndCheckTarget(req.target, this.policy);
      if (!scope.allowed) return { kind: "deny", reasons: scope.reasons };
    }
    if (rule === "allow") return { kind: "allow", reasons: [`Operation ${req.operation} is allowed by policy.`] };

    const consumed = await this.approvals.consume(req.operation, req.params);
    if (consumed) {
      await this.audit.write({
        actor: req.actor,
        event: "approval_consumed",
        operation: req.operation,
        target: req.target,
        details: { approvalId: consumed.id, decidedBy: consumed.decidedBy },
      });
      return { kind: "allow", reasons: [`Approved by ${consumed.decidedBy ?? "a human"} (${consumed.id}).`] };
    }
    const approval = await this.approvals.request({
      operation: req.operation,
      summary: req.summary,
      target: req.target,
      params: req.params,
      requestedBy: req.actor,
      expiresMinutes: this.policy.approvals.expiresMinutes,
    });
    await this.audit.write({
      actor: req.actor,
      event: "approval_requested",
      operation: req.operation,
      target: req.target,
      details: { approvalId: approval.id, summary: req.summary },
    });
    return {
      kind: "approval_required",
      approval,
      reasons: [
        `Operation ${req.operation} requires human approval. Approve it with \`mungard approvals approve ${approval.id}\` ` +
          `in an interactive terminal or in the Mungard web UI, then repeat the identical request.`,
      ],
    };
  }

  /** Synchronous scope check for redirect handling and pre-flight validation. */
  inScope(url: string): boolean {
    return checkTarget(url, this.policy).allowed;
  }
}
