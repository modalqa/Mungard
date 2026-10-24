"use client";

import { useCallback, useEffect, useState } from "react";
import { getJson } from "@/lib/client/api";
import type { Meta } from "@/lib/client/types";
import { ApprovalsPanel } from "./ApprovalsPanel";
import { ChatPanel, type ChatMode } from "./ChatPanel";
import { FindingsPanel } from "./FindingsPanel";
import { RunsPanel } from "./RunsPanel";
import { ErrorBox } from "./ui";

const TABS = [
  { id: "chat", label: "Chat" },
  { id: "findings", label: "Findings" },
  { id: "approvals", label: "Approvals" },
  { id: "runs", label: "Runs & Report" },
] as const;
type TabId = (typeof TABS)[number]["id"];

function ModeBadge({ mode }: { mode?: ChatMode }) {
  if (!mode) return null;
  return mode.mode === "ai" ? (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden />
      AI mode{mode.model ? `: ${mode.model}` : ""}
    </span>
  ) : (
    <span
      className="inline-flex items-center gap-1.5 rounded-full bg-zinc-200 px-2.5 py-0.5 text-xs font-medium text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
      title="No model credentials found or AI disabled in policy. The chat routes keywords directly to Mungard tools."
    >
      <span className="h-1.5 w-1.5 rounded-full bg-zinc-500" aria-hidden />
      Offline mode
    </span>
  );
}

export function MungardApp() {
  const [tab, setTab] = useState<TabId>("chat");
  const [meta, setMeta] = useState<Meta>();
  const [metaError, setMetaError] = useState<string>();
  const [mode, setMode] = useState<ChatMode>();

  const loadMeta = useCallback(() => {
    getJson<Meta>("/api/meta")
      .then((m) => {
        setMeta(m);
        setMode((prev) => prev ?? { mode: m.mode, model: m.model });
        setMetaError(undefined);
      })
      .catch((e: Error) => setMetaError(e.message));
  }, []);

  useEffect(() => {
    // Obtain the HttpOnly session cookie required for approval decisions.
    void getJson("/api/session").catch(() => undefined);
    loadMeta();
    const fromHash = window.location.hash.slice(1);
    if (TABS.some((t) => t.id === fromHash)) setTab(fromHash as TabId);
  }, [loadMeta]);

  const selectTab = (id: TabId) => {
    setTab(id);
    history.replaceState(null, "", `#${id}`);
    if (id === "approvals") loadMeta();
  };

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mx-auto flex max-w-screen-2xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
          <div className="flex items-center gap-2.5">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/logo.jpeg" alt="Mungard logo" width={36} height={36} className="h-9 w-9 rounded-md object-cover" />
            <div>
              <div className="flex items-baseline gap-2">
                <span className="text-lg font-bold tracking-tight">Mungard</span>
                {meta && <span className="text-xs text-zinc-500">v{meta.version}</span>}
              </div>
              <div className="text-xs text-brand-600 dark:text-brand-400">Guard every agent action</div>
            </div>
          </div>
          <div className="min-w-0 border-l border-zinc-200 pl-4 dark:border-zinc-800">
            <div className="truncate text-sm font-medium">{meta?.name ?? "..."}</div>
            <div className="truncate font-mono text-xs text-zinc-500" title={meta?.root}>
              {meta?.root ?? ""}
            </div>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <ModeBadge mode={mode} />
          </div>
          <p className="w-full text-xs text-zinc-500 dark:text-zinc-400">
            Local-first: findings, evidence and approvals stay on this machine.
            {mode?.mode === "ai" ? " AI mode sends redacted context to the configured model provider." : " AI mode (when enabled) sends redacted context to the configured model provider."}
          </p>
        </div>
        <nav className="mx-auto flex max-w-screen-2xl gap-1 px-4" aria-label="Sections">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => selectTab(t.id)}
              aria-current={tab === t.id ? "page" : undefined}
              className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium ${
                tab === t.id
                  ? "border-brand-600 text-brand-700 dark:text-brand-400"
                  : "border-transparent text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"
              }`}
            >
              {t.label}
              {t.id === "approvals" && meta && meta.pendingApprovals > 0 && (
                <span className="ml-1.5 rounded-full bg-brand-600 px-1.5 py-0.5 text-[10px] font-bold text-white">{meta.pendingApprovals}</span>
              )}
            </button>
          ))}
        </nav>
      </header>
      <main className="mx-auto w-full max-w-screen-2xl flex-1 p-4">
        {metaError && (
          <div className="mb-3">
            <ErrorBox message={`Could not load project info: ${metaError}`} />
          </div>
        )}
        {/* Chat stays mounted so an in-flight turn is not lost when switching tabs. */}
        <div hidden={tab !== "chat"}>
          <ChatPanel onMode={setMode} />
        </div>
        {tab === "findings" && <FindingsPanel />}
        {tab === "approvals" && <ApprovalsPanel onChanged={loadMeta} />}
        {tab === "runs" && <RunsPanel />}
      </main>
    </div>
  );
}
