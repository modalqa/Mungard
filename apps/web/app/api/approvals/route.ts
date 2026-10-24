import { redactDeep } from "@mungard/policy-engine";
import { guard } from "@/lib/server/guard";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const STATUSES = new Set(["pending", "approved", "denied", "consumed", "expired"]);

/** GET /api/approvals?status=pending (default: all, newest first). */
export async function GET(request: Request): Promise<Response> {
  const denied = guard(request);
  if (denied) return denied;
  const status = new URL(request.url).searchParams.get("status") ?? undefined;
  if (status && !STATUSES.has(status)) return jsonError(400, "Invalid status filter.");
  try {
    const ws = await openWorkspace();
    const list = await ws.approvals.list(status as Parameters<typeof ws.approvals.list>[0]);
    const sorted = [...list].sort((a, b) => b.requestedAt.localeCompare(a.requestedAt));
    return Response.json({ approvals: redactDeep(sorted, ws.redact) });
  } catch (err) {
    return jsonError(500, errorMessage(err));
  }
}
