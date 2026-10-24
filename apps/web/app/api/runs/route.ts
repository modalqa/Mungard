import { redactDeep } from "@mungard/policy-engine";
import { guard } from "@/lib/server/guard";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const denied = guard(request);
  if (denied) return denied;
  try {
    const ws = await openWorkspace();
    const runs = await ws.listRuns(30);
    return Response.json({ runs: redactDeep(runs, ws.redact) });
  } catch (err) {
    return jsonError(500, errorMessage(err));
  }
}
