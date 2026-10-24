import { redactDeep } from "@mungard/policy-engine";
import { guard } from "@/lib/server/guard";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const denied = guard(request);
  if (denied) return denied;
  const { id } = await ctx.params;
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) return jsonError(400, "Invalid finding id.");
  try {
    const ws = await openWorkspace();
    const finding = await ws.getFinding(id);
    if (!finding) return jsonError(404, `Finding ${id} not found.`);
    return Response.json({ finding: redactDeep(finding, ws.redact) });
  } catch (err) {
    return jsonError(500, errorMessage(err));
  }
}
