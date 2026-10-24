import { spawn } from "node:child_process";
import { access, constants } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export interface RunOptions {
  cwd?: string;
  timeoutMs: number;
  maxOutputBytes: number;
  /** Extra environment variables. The parent environment is NOT inherited wholesale. */
  env?: Record<string, string>;
  signal?: AbortSignal;
  stdin?: string;
}

export interface RunResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
}

/** Variables passed through to engines. Credentials in the parent env are not leaked to tools. */
const PASSTHROUGH_ENV = ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "USER", "SHELL", "DOCKER_HOST", "DOCKER_CONFIG", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "SystemRoot"];

export function minimalEnv(extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of PASSTHROUGH_ENV) {
    const v = process.env[key];
    if (v !== undefined) env[key] = v;
  }
  return { ...env, ...extra };
}

/**
 * Run a fixed executable with an argument vector. Never uses a shell, so
 * model- or user-supplied strings cannot inject commands (PRD 7.3, SR-03).
 * Enforces a timeout and an output cap, and kills the whole process group.
 */
export function runCommand(command: string, args: string[], opts: RunOptions): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: opts.cwd,
      env: minimalEnv(opts.env),
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    let bytes = 0;
    let truncated = false;
    let timedOut = false;
    let settled = false;

    const kill = () => {
      if (child.pid === undefined || child.exitCode !== null) return;
      try {
        if (process.platform !== "win32") process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, opts.timeoutMs);
    const onAbort = () => kill();
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    const collect = (which: "out" | "err") => (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > opts.maxOutputBytes) {
        truncated = true;
        kill();
        return;
      }
      if (which === "out") stdout += chunk.toString("utf8");
      else stderr += chunk.toString("utf8");
    };
    child.stdout.on("data", collect("out"));
    child.stderr.on("data", collect("err"));
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      reject(err);
    });
    child.on("close", (exitCode) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      resolve({ exitCode, stdout, stderr, timedOut, truncated });
    });
    if (opts.stdin !== undefined) child.stdin.end(opts.stdin);
    else child.stdin.end();
  });
}

/** Locate an executable on PATH without invoking a shell. */
export async function findExecutable(name: string): Promise<string | undefined> {
  const exts = process.platform === "win32" ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";") : [""];
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = path.join(dir, name + ext);
      try {
        await access(candidate, constants.X_OK);
        return candidate;
      } catch {
        // keep looking
      }
    }
  }
  return undefined;
}

/** Version string from `<bin> --version` style output, or undefined. */
export async function probeVersion(bin: string, args: string[] = ["--version"]): Promise<string | undefined> {
  try {
    const r = await runCommand(bin, args, { timeoutMs: 20_000, maxOutputBytes: 64 * 1024 });
    const text = `${r.stdout}\n${r.stderr}`;
    return text.match(/v?(\d+\.\d+\.\d+[\w.-]*)/)?.[1];
  } catch {
    return undefined;
  }
}

export async function dockerAvailable(): Promise<boolean> {
  const docker = await findExecutable("docker");
  if (!docker) return false;
  try {
    const r = await runCommand(docker, ["info", "--format", "{{.ServerVersion}}"], { timeoutMs: 15_000, maxOutputBytes: 64 * 1024 });
    return r.exitCode === 0;
  } catch {
    return false;
  }
}

/** Hardened defaults for every engine container (SR-03). */
export function dockerBaseArgs(opts: { memory?: string; cpus?: string; network?: string } = {}): string[] {
  const args = [
    "run",
    "--rm",
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--pids-limit",
    "512",
    "--memory",
    opts.memory ?? "2g",
    "--cpus",
    opts.cpus ?? "2",
  ];
  if (opts.network) args.push("--network", opts.network);
  if (process.platform === "linux" && typeof process.getuid === "function" && typeof process.getgid === "function") {
    args.push("--user", `${process.getuid()}:${process.getgid()}`);
  }
  return args;
}

export const isMac = os.platform() === "darwin";
