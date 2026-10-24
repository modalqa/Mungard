import { guard } from "@/lib/server/guard";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/findings/[id]/evidence?ref=<evidenceId>
 * Returns the redacted content of an evidence file. Only paths recorded on
 * the finding are readable, and `readEvidence` confines them to the
 * workspace runs directory.
 */
export async function GET(request: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const denied = guard(request);
  if (denied) return denied;
  const { id } = await ctx.params;
  const ref = new URL(request.url).searchParams.get("ref") ?? "";
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(id) || !/^[A-Za-z0-9_.:-]{1,128}$/.test(ref)) return jsonError(400, "Invalid id or ref.");
  try {
    const ws = await openWorkspace();
    const finding = await ws.getFinding(id);
    const evidence = finding?.evidence.find((e) => e.id === ref);
    if (!evidence?.path) return jsonError(404, "Evidence file not found.");
    const content = await ws.readEvidence(evidence.path);
    return Response.json({ id: evidence.id, path: ws.redact(evidence.path), content });
  } catch (err) {
    return jsonError(500, errorMessage(err));
  }
}
