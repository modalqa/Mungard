import { MUNGARD_VERSION, anthropicCredentialsAvailable, detectProject } from "@mungard/core";
import { guard } from "@/lib/server/guard";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const denied = guard(request);
  if (denied) return denied;
  try {
    const ws = await openWorkspace();
    const configured = ws.config.project.name !== "project";
    const name = configured ? ws.config.project.name : (await detectProject(ws.root)).name;
    const credentials = anthropicCredentialsAvailable();
    const aiEnabled = ws.config.ai.provider === "anthropic" && ws.config.policy.ai.enabled;
    const mode = aiEnabled && credentials ? "ai" : "offline";
    const pending = await ws.approvals.list("pending");
    return Response.json({
      name: ws.redact(name),
      root: ws.redact(ws.root),
      version: MUNGARD_VERSION,
      mode,
      model: mode === "ai" ? ws.config.ai.model : undefined,
      aiEnabledInConfig: aiEnabled,
      credentialsAvailable: credentials,
      sendSourceCode: ws.config.policy.ai.sendSourceCode,
      pendingApprovals: pending.length,
    });
  } catch (err) {
    return jsonError(500, errorMessage(err));
  }
}
