import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { redactDeep, type Redactor } from "@mungard/policy-engine";
import { findExecutable, runCommand } from "./exec.js";

/** Write a redacted JSON evidence file and return its workspace-relative path. */
export async function writeEvidence(
  ctx: { evidenceDir: string; workspaceDir: string; redact: Redactor },
  name: string,
  data: unknown,
): Promise<string> {
  await mkdir(ctx.evidenceDir, { recursive: true, mode: 0o700 });
  const safeName = name.replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 120);
  const file = path.join(ctx.evidenceDir, safeName);
  const content = typeof data === "string" ? ctx.redact(data) : JSON.stringify(redactDeep(data, ctx.redact), null, 2);
  await writeFile(file, content, { mode: 0o600 });
  return path.relative(ctx.workspaceDir, file);
}

/** Read a few lines around a location, redacted, for code-snippet evidence. */
export async function readSnippet(
  file: string,
  line: number | undefined,
  redact: Redactor,
  opts: { context?: number; maxFileSizeBytes?: number } = {},
): Promise<string | undefined> {
  try {
    const s = await stat(file);
    if (s.size > (opts.maxFileSizeBytes ?? 1_000_000)) return undefined;
    const lines = (await readFile(file, "utf8")).split("\n");
    const ctxLines = opts.context ?? 3;
    const center = Math.max(1, line ?? 1);
    const from = Math.max(1, center - ctxLines);
    const to = Math.min(lines.length, center + ctxLines);
    const out: string[] = [];
    for (let i = from; i <= to; i++) out.push(`${String(i).padStart(5)} | ${lines[i - 1] ?? ""}`);
    return redact(out.join("\n"));
  } catch {
    return undefined;
  }
}

/** Trimmed text of one source line (used as stable fingerprint material). */
export async function readLine(file: string, line: number, maxFileSizeBytes = 1_000_000): Promise<string | undefined> {
  try {
    const s = await stat(file);
    if (s.size > maxFileSizeBytes) return undefined;
    return (await readFile(file, "utf8")).split("\n")[line - 1]?.trim();
  } catch {
    return undefined;
  }
}

export interface GitFileState {
  isRepo: boolean;
  tracked: boolean;
  ignored: boolean;
  /** True when the file appears in at least one commit. */
  inHistory: boolean;
}

/** Whether a file is tracked, gitignored, or present in history. Used for secret findings. */
export async function gitFileState(projectRoot: string, relPath: string): Promise<GitFileState> {
  const git = await findExecutable("git");
  const none = { isRepo: false, tracked: false, ignored: false, inHistory: false };
  if (!git) return none;
  const opts = { cwd: projectRoot, timeoutMs: 15_000, maxOutputBytes: 1024 * 1024 };
  try {
    const repo = await runCommand(git, ["rev-parse", "--is-inside-work-tree"], opts);
    if (repo.exitCode !== 0) return none;
    const [tracked, ignored, history] = await Promise.all([
      runCommand(git, ["ls-files", "--error-unmatch", "--", relPath], opts),
      runCommand(git, ["check-ignore", "-q", "--", relPath], opts),
      runCommand(git, ["log", "--all", "--format=%H", "-n", "1", "--", relPath], opts),
    ]);
    return {
      isRepo: true,
      tracked: tracked.exitCode === 0,
      ignored: ignored.exitCode === 0,
      inHistory: history.exitCode === 0 && history.stdout.trim().length > 0,
    };
  } catch {
    return none;
  }
}

/** Current commit (with a `-dirty` suffix for uncommitted changes), if in a git repo. */
export async function gitCodeVersion(projectRoot: string): Promise<string | undefined> {
  const git = await findExecutable("git");
  if (!git) return undefined;
  const opts = { cwd: projectRoot, timeoutMs: 15_000, maxOutputBytes: 4 * 1024 * 1024 };
  try {
    const head = await runCommand(git, ["rev-parse", "HEAD"], opts);
    if (head.exitCode !== 0) return undefined;
    const status = await runCommand(git, ["status", "--porcelain", "--untracked-files=no"], opts);
    return `${head.stdout.trim()}${status.stdout.trim() ? "-dirty" : ""}`;
  } catch {
    return undefined;
  }
}

export function relativeTo(root: string, file: string): string {
  const rel = path.relative(root, path.resolve(root, file));
  return rel.split(path.sep).join("/");
}
