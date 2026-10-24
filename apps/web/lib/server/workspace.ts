import { Workspace } from "@mungard/core";

/** Project the UI serves. Fixed at process start; never taken from the request. */
export function projectRoot(): string {
  return process.env.MUNGARD_PROJECT_ROOT ?? process.cwd();
}

/** Open the workspace fresh for each request so CLI/MCP changes are visible. */
export function openWorkspace(): Promise<Workspace> {
  return Workspace.open(projectRoot());
}

export function jsonError(status: number, message: string): Response {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
