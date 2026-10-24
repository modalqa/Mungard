"use client";

import { useCallback, useEffect, useState } from "react";
import { formatDate, getJson } from "@/lib/client/api";
import type { Run } from "@/lib/client/types";
import { Markdown } from "./Markdown";
import { Button, Card, Empty, ErrorBox, StatusBadge } from "./ui";

const ENGINE_NOTE: Record<string, string> = {
  failed: "did not complete - its area is NOT covered",
  unavailable: "not installed / not reachable - did not run",
  skipped: "skipped - did not run",
  partial: "ran with gaps",
};

function RunCard({ run }: { run: Run }) {
  return (
    <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium">{run.kind}</span>
        <StatusBadge status={run.status} />
        <span className="font-mono text-xs text-zinc-500">{run.id}</span>
        <span className="ml-auto text-xs text-zinc-500">
          {formatDate(run.startedAt)} · {run.actor} · {run.findingIds.length} findings
        </span>
      </div>
      {run.targets.length > 0 && <p className="mt-1 font-mono text-xs break-all text-zinc-500">Targets: {run.targets.join(", ")}</p>}
      {run.error && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{run.error}</p>}
      {run.engines.length > 0 && (
        <table className="mt-2 w-full text-xs">
          <thead className="text-left text-zinc-500">
            <tr>
              <th className="py-1 pr-2 font-medium">Engine</th>
              <th className="py-1 pr-2 font-medium">Status</th>
              <th className="py-1 pr-2 font-medium">Findings</th>
              <th className="py-1 font-medium">Notes</th>
            </tr>
          </thead>
          <tbody>
            {run.engines.map((e, i) => (
              <tr key={i} className="border-t border-zinc-100 align-top dark:border-zinc-800">
                <td className="py-1 pr-2 font-mono">
                  {e.engine}
                  {e.engineVersion ? ` ${e.engineVersion}` : ""}
                </td>
                <td className="py-1 pr-2">
                  <StatusBadge status={e.status} />
                </td>
                <td className="py-1 pr-2">{e.status === "succeeded" || e.status === "partial" ? e.findingCount : "-"}</td>
                <td className="py-1">
                  {ENGINE_NOTE[e.status] && <span className={e.status === "partial" ? "text-amber-700 dark:text-amber-400" : "font-medium text-red-700 dark:text-red-400"}>{ENGINE_NOTE[e.status]}. </span>}
                  {e.error && <span className="break-all">{e.error} </span>}
                  {e.gaps.length > 0 && <span className="text-zinc-500">Gaps: {e.gaps.join("; ")}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {run.blocked.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-xs text-amber-800 dark:text-amber-400">
          {run.blocked.map((b, i) => (
            <li key={i}>
              Blocked: <span className="font-mono">{b.step}</span> ({b.decision}){b.approvalId ? `, approval ${b.approvalId}` : ""}: {b.reasons.join("; ")}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function RunsPanel() {
  const [runs, setRuns] = useState<Run[]>();
  const [error, setError] = useState<string>();
  const [report, setReport] = useState<string>();
  const [reportError, setReportError] = useState<string>();
  const [raw, setRaw] = useState(false);
  const [loadingReport, setLoadingReport] = useState(false);

  const load = useCallback(() => {
    getJson<{ runs: Run[] }>("/api/runs")
      .then((r) => {
        setRuns(r.runs);
        setError(undefined);
      })
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const loadReport = async () => {
    setLoadingReport(true);
    setReportError(undefined);
    try {
      const res = await fetch("/api/report", { cache: "no-store" });
      if (!res.ok) throw new Error(`Report failed (${res.status}).`);
      setReport(await res.text());
    } catch (e) {
      setReportError((e as Error).message);
    } finally {
      setLoadingReport(false);
    }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card
        title="Recent runs"
        actions={
          <Button variant="ghost" onClick={load}>
            Refresh
          </Button>
        }
      >
        <p className="mb-3 text-xs text-zinc-500 dark:text-zinc-400">
          Engines marked failed, unavailable or skipped did not run (or did not finish): their areas are coverage gaps, not evidence of security.
        </p>
        {error && <ErrorBox message={error} />}
        {!runs && !error && <Empty>Loading...</Empty>}
        {runs && runs.length === 0 && <Empty>No runs yet. Ask the agent to scan this app.</Empty>}
        <div className="max-h-[calc(100vh-16rem)] space-y-3 overflow-auto">{runs?.map((r) => <RunCard key={r.id} run={r} />)}</div>
      </Card>
      <Card
        title="Report"
        actions={
          <>
            {report && (
              <Button variant="ghost" onClick={() => setRaw((v) => !v)}>
                {raw ? "Rendered" : "Raw Markdown"}
              </Button>
            )}
            <Button variant="secondary" onClick={() => void loadReport()} disabled={loadingReport}>
              {loadingReport ? "Building..." : report ? "Rebuild" : "Build report"}
            </Button>
            <a
              href="/api/report?download=1"
              className="inline-flex items-center rounded-md bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
              download
            >
              Download .md
            </a>
          </>
        }
      >
        {reportError && <ErrorBox message={reportError} />}
        {!report && !reportError && <Empty>Build the Markdown report to preview it here. It is generated locally from the workspace and redacted.</Empty>}
        {report && (
          <div className="max-h-[calc(100vh-16rem)] overflow-auto text-sm">
            {raw ? <pre className="font-mono text-xs whitespace-pre-wrap">{report}</pre> : <Markdown text={report} />}
          </div>
        )}
      </Card>
    </div>
  );
}
