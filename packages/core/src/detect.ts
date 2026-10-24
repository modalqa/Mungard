import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { discoverMcpConfigs } from "@mungard/adapters";

export interface ProjectDetection {
  root: string;
  name: string;
  languages: string[];
  frameworks: string[];
  packageManager?: "npm" | "pnpm" | "yarn" | "bun";
  dependencyFiles: string[];
  openapiSpecs: string[];
  routes: { method: string; path: string; file: string }[];
  mcpConfigFiles: string[];
  agentFiles: string[];
  isGitRepo: boolean;
  suggestedBaseUrl?: string;
  recommendedEngines: { engine: string; reason: string }[];
  notes: string[];
}

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage", ".mungard", ".turbo", ".vercel", "out", "vendor", ".venv", "venv"]);

const FRAMEWORK_DEPS: Record<string, string> = {
  next: "Next.js",
  react: "React",
  express: "Express",
  fastify: "Fastify",
  "@nestjs/core": "NestJS",
  hono: "Hono",
  koa: "Koa",
  "@remix-run/node": "Remix",
  "@sveltejs/kit": "SvelteKit",
  nuxt: "Nuxt",
  vue: "Vue",
  "@prisma/client": "Prisma",
  "drizzle-orm": "Drizzle",
  mongoose: "Mongoose",
  pg: "PostgreSQL (pg)",
  typeorm: "TypeORM",
  sequelize: "Sequelize",
  "next-auth": "NextAuth.js",
  "@auth/core": "Auth.js",
  "@supabase/supabase-js": "Supabase",
  "@clerk/nextjs": "Clerk",
  "@modelcontextprotocol/sdk": "MCP SDK",
  "@anthropic-ai/sdk": "Anthropic SDK",
  openai: "OpenAI SDK",
  ai: "Vercel AI SDK",
};

async function exists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

/** Bounded recursive file listing that skips vendored/generated directories. */
async function listFiles(root: string, maxFiles = 5000): Promise<string[]> {
  const out: string[] = [];
  const queue = [root];
  while (queue.length && out.length < maxFiles) {
    const dir = queue.shift()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !e.name.startsWith(".") || e.name === ".claude" || e.name === ".cursor" || e.name === ".github") queue.push(path.join(dir, e.name));
      } else if (e.isFile()) {
        out.push(path.relative(root, path.join(dir, e.name)).split(path.sep).join("/"));
        if (out.length >= maxFiles) break;
      }
    }
  }
  return out;
}

function nextRoute(file: string): string | undefined {
  // app router: app/api/users/[id]/route.ts -> /api/users/{id}
  const app = file.match(/^(?:src\/)?app\/(.*)\/route\.(t|j)sx?$/);
  if (app) {
    const segs = app[1]!.split("/").filter((s) => !/^\(.*\)$/.test(s) && !s.startsWith("@"));
    return `/${segs.map((s) => s.replace(/^\[\.\.\.(.+)\]$/, "{$1*}").replace(/^\[(.+)\]$/, "{$1}")).join("/")}`;
  }
  const pages = file.match(/^(?:src\/)?pages\/(api\/.*)\.(t|j)sx?$/);
  if (pages) return `/${pages[1]!.replace(/\/index$/, "").replace(/\[(.+?)\]/g, "{$1}")}`;
  return undefined;
}

export async function detectProject(root: string): Promise<ProjectDetection> {
  const abs = path.resolve(root);
  const files = await listFiles(abs);
  const det: ProjectDetection = {
    root: abs,
    name: path.basename(abs),
    languages: [],
    frameworks: [],
    dependencyFiles: [],
    openapiSpecs: [],
    routes: [],
    mcpConfigFiles: [],
    agentFiles: [],
    isGitRepo: await exists(path.join(abs, ".git")),
    recommendedEngines: [],
    notes: [],
  };

  let pkg: { name?: string; dependencies?: Record<string, string>; devDependencies?: Record<string, string>; scripts?: Record<string, string> } | undefined;
  try {
    pkg = JSON.parse(await readFile(path.join(abs, "package.json"), "utf8"));
  } catch {
    // not a Node.js project (or unreadable package.json)
  }
  if (pkg?.name) det.name = pkg.name;
  const deps = { ...(pkg?.dependencies ?? {}), ...(pkg?.devDependencies ?? {}) };
  for (const [dep, label] of Object.entries(FRAMEWORK_DEPS)) if (dep in deps) det.frameworks.push(label);

  for (const [lock, pm] of [["package-lock.json", "npm"], ["pnpm-lock.yaml", "pnpm"], ["yarn.lock", "yarn"], ["bun.lockb", "bun"], ["bun.lock", "bun"]] as const) {
    if (files.includes(lock)) {
      det.packageManager ??= pm;
      det.dependencyFiles.push(lock);
    }
  }
  for (const f of ["package.json", "requirements.txt", "pyproject.toml", "go.mod", "Gemfile", "composer.json", "pom.xml", "Cargo.toml"]) {
    if (files.includes(f)) det.dependencyFiles.push(f);
  }
  const exts = new Set(files.map((f) => path.extname(f)));
  if (exts.has(".ts") || exts.has(".tsx")) det.languages.push("TypeScript");
  if (exts.has(".js") || exts.has(".jsx") || exts.has(".mjs") || exts.has(".cjs")) det.languages.push("JavaScript");
  if (exts.has(".py")) det.languages.push("Python");
  if (exts.has(".go")) det.languages.push("Go");

  det.openapiSpecs = files.filter((f) => /(^|\/)(openapi|swagger)[^/]*\.(ya?ml|json)$/i.test(f)).slice(0, 10);
  for (const f of det.openapiSpecs) {
    // Confirm the file is really a spec (cheap check on the first bytes).
    try {
      const head = (await readFile(path.join(abs, f), "utf8")).slice(0, 2000);
      if (!/(openapi|swagger)["']?\s*[:=]/.test(head)) det.openapiSpecs = det.openapiSpecs.filter((x) => x !== f);
    } catch {
      det.openapiSpecs = det.openapiSpecs.filter((x) => x !== f);
    }
  }

  for (const f of files) {
    const route = nextRoute(f);
    if (!route) continue;
    let methods = ["*"];
    try {
      const src = await readFile(path.join(abs, f), "utf8");
      const found = [...src.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g)].map((m) => m[1]!);
      if (found.length) methods = found;
    } catch {
      // keep "*"
    }
    for (const method of methods) det.routes.push({ method, path: route, file: f });
  }
  // Express/Fastify/Hono style routes (best effort).
  for (const f of files.filter((x) => /\.(m|c)?(j|t)s$/.test(x) && !/(\.test\.|\.spec\.|__tests__)/.test(x)).slice(0, 400)) {
    if (det.routes.length > 500) break;
    try {
      const s = await stat(path.join(abs, f));
      if (s.size > 300_000) continue;
      const src = await readFile(path.join(abs, f), "utf8");
      for (const m of src.matchAll(/\b(?:app|router|server|fastify)\.(get|post|put|patch|delete)\(\s*["'`](\/[^"'`]*)["'`]/g)) {
        det.routes.push({ method: m[1]!.toUpperCase(), path: m[2]!.replace(/:([A-Za-z0-9_]+)/g, "{$1}"), file: f });
      }
    } catch {
      // ignore unreadable files
    }
  }

  det.mcpConfigFiles = (await discoverMcpConfigs(abs, false)).files;
  det.agentFiles = files.filter((f) =>
    /^(CLAUDE\.md|CLAUDE\.local\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.github\/copilot-instructions\.md|\.claude\/settings(\.local)?\.json)$/.test(f) ||
    /^\.claude\/(commands|agents|skills)\//.test(f) ||
    /^\.cursor\/rules\//.test(f),
  );

  const dev = pkg?.scripts?.dev ?? "";
  const port = dev.match(/(?:-p|--port)[ =](\d{2,5})/)?.[1];
  if (det.frameworks.includes("Next.js")) det.suggestedBaseUrl = `http://localhost:${port ?? "3000"}`;
  else if (port) det.suggestedBaseUrl = `http://localhost:${port}`;

  const rec = det.recommendedEngines;
  rec.push({ engine: "semgrep", reason: `Static analysis for ${det.languages.join("/") || "source code"}.` });
  rec.push({ engine: "gitleaks", reason: det.isGitRepo ? "Secret detection in the working tree and git history." : "Secret detection in the working tree." });
  if (det.dependencyFiles.includes("package-lock.json")) rec.push({ engine: "npm-audit", reason: "package-lock.json found." });
  else if (pkg) det.notes.push("No package-lock.json: npm audit needs one (`npm install --package-lock-only`).");
  rec.push({ engine: "agent-config", reason: det.agentFiles.length ? `Agent files found: ${det.agentFiles.slice(0, 5).join(", ")}.` : "Checks for AI agent instruction/permission files." });
  if (det.mcpConfigFiles.length) rec.push({ engine: "mcp-inspector", reason: `MCP configs found: ${det.mcpConfigFiles.join(", ")}.` });
  if (det.openapiSpecs.length) rec.push({ engine: "openapi", reason: `OpenAPI spec found: ${det.openapiSpecs[0]}.` });
  if (det.suggestedBaseUrl) {
    rec.push({ engine: "http-probe", reason: `Runtime header checks against ${det.suggestedBaseUrl} once the app is running.` });
    rec.push({ engine: "zap", reason: "Passive web DAST (OWASP ZAP baseline) once the app is running; requires Docker." });
  }
  if (det.routes.length) rec.push({ engine: "authz", reason: `${det.routes.length} route(s) detected; configure test accounts to test authorization.` });
  if (det.languages.includes("Python") || det.languages.includes("Go")) {
    det.notes.push("Mungard's MVP rules and dependency audit focus on JavaScript/TypeScript; other languages have reduced coverage.");
  }
  return det;
}
