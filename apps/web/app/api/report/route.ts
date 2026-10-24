import { buildReportInput, renderReport } from "@mungard/core";
import { guard } from "@/lib/server/guard";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** GET /api/report[?download=1] - Markdown report built from the workspace (redacted by buildReportInput). */
export async function GET(request: Request): Promise<Response> {
  const denied = guard(request);
  if (denied) return denied;
  try {
    const ws = await openWorkspace();
    const markdown = ws.redact(renderReport(await buildReportInput(ws), "md"));
    const download = new URL(request.url).searchParams.get("download") === "1";
    const headers: Record<string, string> = { "Content-Type": "text/markdown; charset=utf-8", "Cache-Control": "no-store" };
    if (download) {
      const stamp = new Date().toISOString().slice(0, 10);
      headers["Content-Disposition"] = `attachment; filename="mungard-report-${stamp}.md"`;
    }
    return new Response(markdown, { headers });
  } catch (err) {
    return jsonError(500, errorMessage(err));
  }
}
