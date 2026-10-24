import { redactDeep } from "@mungard/policy-engine";
import { z } from "zod";
import { guard, readJson } from "@/lib/server/guard";
import { hasValidSessionCookie } from "@/lib/server/session-token";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DecisionBody = z.object({
  decision: z.enum(["approved", "denied"]),
  note: z.string().trim().max(1000).optional(),
});

/**
 * Human approval channel. This endpoint is deliberately not exposed as a chat
 * or MCP tool: the agent can request approvals, never grant them. Besides the
 * shared Host/Origin/Content-Type guard it requires the per-process session
 * cookie (see lib/server/session-token.ts for what that does and does not
 * protect against).
 */
export async function POST(request: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const denied = guard(request, { json: true });
  if (denied) return denied;
  if (!hasValidSessionCookie(request)) {
    return Response.json({ error: "forbidden", reason: "Missing or invalid UI session cookie." }, { status: 403 });
  }
  const { id } = await ctx.params;
  if (!/^apr_[a-f0-9]{1,64}$/.test(id)) return jsonError(400, "Invalid approval id.");
  const parsed = DecisionBody.safeParse(await readJson(request));
  if (!parsed.success) return jsonError(400, 'Body must be {decision: "approved"|"denied", note?: string}.');
  try {
    const ws = await openWorkspace();
    const decided = await ws.approvals.decide(id, parsed.data.decision, "human:web-ui", parsed.data.note || undefined);
    await ws.audit.write({
      actor: "web",
      event: "approval_decided",
      operation: decided.operation,
      target: decided.target,
      decision: decided.status,
      details: { approvalId: decided.id, note: parsed.data.note },
    });
    return Response.json({ approval: redactDeep(decided, ws.redact) });
  } catch (err) {
    const message = errorMessage(err);
    return jsonError(/not found/i.test(message) ? 404 : 409, message);
  }
}
