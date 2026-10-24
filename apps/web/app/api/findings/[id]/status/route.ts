import { redactDeep } from "@mungard/policy-engine";
import { z } from "zod";
import { guard, readJson } from "@/lib/server/guard";
import { HUMAN_STATUSES } from "@/lib/statuses";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";


const StatusBody = z.object({
  status: z.enum(HUMAN_STATUSES),
  reason: z.string().trim().min(3, "A reason is required.").max(2000),
});

export async function POST(request: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const denied = guard(request, { json: true });
  if (denied) return denied;
  const { id } = await ctx.params;
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) return jsonError(400, "Invalid finding id.");
  const parsed = StatusBody.safeParse(await readJson(request));
  if (!parsed.success) {
    return jsonError(400, parsed.error.issues.map((i) => i.message).join("; ") || "Invalid body.");
  }
  try {
    const ws = await openWorkspace();
    const updated = await ws.setFindingStatus(id, parsed.data.status, "human", parsed.data.reason, "web");
    return Response.json({ finding: redactDeep(updated, ws.redact) });
  } catch (err) {
    const message = errorMessage(err);
    return jsonError(/not found/i.test(message) ? 404 : 409, message);
  }
}
