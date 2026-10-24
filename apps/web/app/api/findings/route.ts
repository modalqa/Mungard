import { redactDeep } from "@mungard/policy-engine";
import { guard } from "@/lib/server/guard";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Summary list; the detail view loads the full record from /api/findings/[id]. */
export async function GET(request: Request): Promise<Response> {
  const denied = guard(request);
  if (denied) return denied;
  try {
    const ws = await openWorkspace();
    const findings = (await ws.loadFindings()).map((f) => ({
      id: f.id,
      title: f.title,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      status: f.status,
      engines: [...new Set(f.sources.map((s) => s.engine))],
      location: f.locations[0],
      retest: f.retest.status,
      triage: f.triage ? { assessment: f.triage.assessment, priority: f.triage.priority, source: f.triage.source } : undefined,
      lastSeen: f.lastSeen,
    }));
    return Response.json({ findings: redactDeep(findings, ws.redact) });
  } catch (err) {
    return jsonError(500, errorMessage(err));
  }
}
