"use client";

import type { ReactNode } from "react";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-red-700 text-white dark:bg-red-600",
  high: "bg-red-100 text-red-800 ring-1 ring-red-300 dark:bg-red-950 dark:text-red-300 dark:ring-red-800",
  medium: "bg-amber-100 text-amber-900 ring-1 ring-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:ring-amber-800",
  low: "bg-blue-100 text-blue-800 ring-1 ring-blue-300 dark:bg-blue-950 dark:text-blue-300 dark:ring-blue-800",
  info: "bg-zinc-100 text-zinc-700 ring-1 ring-zinc-300 dark:bg-zinc-800 dark:text-zinc-300 dark:ring-zinc-700",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info}`}>
      {severity}
    </span>
  );
}

const STATUS_CLASS: Record<string, string> = {
  new: "text-zinc-700 bg-zinc-100 dark:text-zinc-300 dark:bg-zinc-800",
  needs_review: "text-amber-800 bg-amber-50 dark:text-amber-300 dark:bg-amber-950",
  confirmed: "text-red-800 bg-red-50 dark:text-red-300 dark:bg-red-950",
  false_positive: "text-zinc-500 bg-zinc-50 line-through dark:text-zinc-500 dark:bg-zinc-900",
  accepted_risk: "text-purple-800 bg-purple-50 dark:text-purple-300 dark:bg-purple-950",
  fixed: "text-sky-800 bg-sky-50 dark:text-sky-300 dark:bg-sky-950",
  retested: "text-emerald-800 bg-emerald-50 dark:text-emerald-300 dark:bg-emerald-950",
  // approvals
  pending: "text-amber-800 bg-amber-50 dark:text-amber-300 dark:bg-amber-950",
  approved: "text-emerald-800 bg-emerald-50 dark:text-emerald-300 dark:bg-emerald-950",
  denied: "text-red-800 bg-red-50 dark:text-red-300 dark:bg-red-950",
  consumed: "text-zinc-600 bg-zinc-100 dark:text-zinc-400 dark:bg-zinc-800",
  expired: "text-zinc-500 bg-zinc-100 dark:text-zinc-500 dark:bg-zinc-800",
  // engines / runs
  succeeded: "text-emerald-800 bg-emerald-50 dark:text-emerald-300 dark:bg-emerald-950",
  completed: "text-emerald-800 bg-emerald-50 dark:text-emerald-300 dark:bg-emerald-950",
  partial: "text-amber-800 bg-amber-50 dark:text-amber-300 dark:bg-amber-950",
  failed: "text-white bg-red-700 dark:bg-red-700",
  unavailable: "text-white bg-zinc-600 dark:bg-zinc-600",
  skipped: "text-zinc-600 bg-zinc-100 dark:text-zinc-400 dark:bg-zinc-800",
  running: "text-sky-800 bg-sky-50 dark:text-sky-300 dark:bg-sky-950",
  cancelled: "text-zinc-600 bg-zinc-100 dark:text-zinc-400 dark:bg-zinc-800",
  // retest
  passed: "text-emerald-800 bg-emerald-50 dark:text-emerald-300 dark:bg-emerald-950",
  inconclusive: "text-amber-800 bg-amber-50 dark:text-amber-300 dark:bg-amber-950",
  not_retested: "text-zinc-600 bg-zinc-100 dark:text-zinc-400 dark:bg-zinc-800",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`inline-block whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-medium ${STATUS_CLASS[status] ?? STATUS_CLASS.new}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function Card({ title, actions, children, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900 ${className ?? ""}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-2 border-b border-zinc-200 px-4 py-2.5 dark:border-zinc-800">
          <h2 className="text-sm font-semibold">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Button({
  children,
  variant = "secondary",
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost" }) {
  const styles = {
    primary: "bg-brand-600 text-white hover:bg-brand-700 disabled:bg-brand-600/50",
    secondary: "border border-zinc-300 bg-white text-zinc-800 hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:bg-zinc-800",
    danger: "bg-red-700 text-white hover:bg-red-800 disabled:bg-red-700/50",
    ghost: "text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-800",
  }[variant];
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-600 disabled:cursor-not-allowed disabled:opacity-60 ${styles} ${className ?? ""}`}
    >
      {children}
    </button>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div role="alert" className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
      {message}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-zinc-500 dark:text-zinc-400">{children}</p>;
}

export function JsonBlock({ value, max = 4000 }: { value: unknown; max?: number }) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const clipped = text.length > max ? `${text.slice(0, max)}\n... [truncated, ${text.length - max} more characters]` : text;
  return <pre className="max-h-80 overflow-auto rounded-md bg-zinc-100 p-2 font-mono text-xs whitespace-pre-wrap break-all dark:bg-zinc-950">{clipped}</pre>;
}

export const inputClass =
  "rounded-md border border-zinc-300 bg-white px-2 py-1.5 text-sm text-zinc-900 focus:border-brand-600 focus:outline-none focus:ring-1 focus:ring-brand-600 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100";

export function formatLocation(loc?: {
  kind: string;
  path?: string;
  startLine?: number;
  method?: string;
  url?: string;
  packageName?: string;
  packageVersion?: string;
  serverName?: string;
}): string {
  if (!loc) return "-";
  if (loc.kind === "file" || loc.kind === "config") return `${loc.path ?? ""}${loc.startLine ? `:${loc.startLine}` : ""}`;
  if (loc.kind === "endpoint") return `${loc.method ?? ""} ${loc.path ?? loc.url ?? ""}`.trim();
  if (loc.kind === "package") return `${loc.packageName ?? ""}${loc.packageVersion ? `@${loc.packageVersion}` : ""}`;
  if (loc.kind === "mcp_server") return `MCP ${loc.serverName ?? ""}${loc.path ? ` (${loc.path})` : ""}`;
  return loc.url ?? loc.path ?? loc.kind;
}
