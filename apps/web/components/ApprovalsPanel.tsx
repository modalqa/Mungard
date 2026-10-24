"use client";

import { useCallback, useEffect, useState } from "react";
import { formatDate, getJson, postJson } from "@/lib/client/api";
import type { Approval } from "@/lib/client/types";
import { Button, Card, Empty, ErrorBox, JsonBlock, StatusBadge, inputClass } from "./ui";

function ApprovalCard({ approval, onDecided }: { approval: Approval; onDecided: () => void }) {
  const [pending, setPending] = useState<"approved" | "denied">();
  const [note, setNote] = useState("");
  const [error, setError] = useState<string>();
  const [saving, setSaving] = useState(false);
  const expired = new Date(approval.expiresAt).getTime() < Date.now();

  const confirm = async () => {
    if (!pending) return;
    setSaving(true);
    setError(undefined);
    try {
      // Make sure the HttpOnly session cookie is present (e.g. after a server restart).
      await getJson("/api/session");
      await postJson(`/api/approvals/${encodeURIComponent(approval.id)}`, { decision: pending, note: note.trim() || undefined });
      onDecided();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded bg-brand-50 px-1.5 py-0.5 font-mono text-xs font-semibold text-brand-700 dark:bg-brand-900/40 dark:text-brand-400">
          {approval.operation}
        </span>
        <StatusBadge status={approval.status} />
        <span className="font-mono text-xs text-zinc-500">{approval.id}</span>
      </div>
      <p className="mt-2 text-sm font-medium whitespace-pre-wrap">{approval.summary}</p>
      <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 text-xs">
        <dt className="text-zinc-500">Target</dt>
        <dd className="font-mono break-all">{approval.target ?? "-"}</dd>
        <dt className="text-zinc-500">Requested by</dt>
        <dd>
          {approval.requestedBy} at {formatDate(approval.requestedAt)}
        </dd>
        <dt className="text-zinc-500">Expires</dt>
        <dd className={expired ? "text-red-600" : ""}>{formatDate(approval.expiresAt)}</dd>
        {approval.decidedBy && (
          <>
            <dt className="text-zinc-500">Decided</dt>
            <dd>
              {approval.decidedBy} at {formatDate(approval.decidedAt)}
              {approval.decisionNote ? ` - ${approval.decisionNote}` : ""}
            </dd>
          </>
        )}
      </dl>
      <details className="mt-2">
        <summary className="cursor-pointer text-xs text-zinc-500">Exact parameters (the approval only unlocks these)</summary>
        <div className="mt-1">
          <JsonBlock value={approval.params} />
        </div>
      </details>

      {approval.status === "pending" && (
        <div className="mt-3">
          {!pending ? (
            <div className="flex gap-2">
              <Button variant="primary" onClick={() => setPending("approved")} disabled={expired}>
                Approve...
              </Button>
              <Button variant="secondary" onClick={() => setPending("denied")}>
                Deny...
              </Button>
            </div>
          ) : (
            <div
              className={`space-y-2 rounded-md border p-3 ${pending === "approved" ? "border-brand-600 bg-brand-50 dark:bg-brand-900/20" : "border-zinc-300 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-950"}`}
            >
              <p className="text-sm">
                {pending === "approved" ? (
                  <>
                    <strong>Approve this operation?</strong> Mungard will be allowed to run <span className="font-mono">{approval.operation}</span> once, with exactly the
                    parameters above, against <span className="font-mono">{approval.target ?? "the configured target"}</span>. Only approve targets you own or are authorized to
                    test.
                  </>
                ) : (
                  <strong>Deny this operation?</strong>
                )}
              </p>
              <input value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} placeholder="Optional note for the audit log" className={`${inputClass} w-full`} />
              {error && <ErrorBox message={error} />}
              <div className="flex gap-2">
                <Button variant={pending === "approved" ? "primary" : "danger"} onClick={() => void confirm()} disabled={saving}>
                  {saving ? "Saving..." : pending === "approved" ? "Confirm approval" : "Confirm denial"}
                </Button>
                <Button variant="ghost" onClick={() => setPending(undefined)} disabled={saving}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function ApprovalsPanel({ onChanged }: { onChanged: () => void }) {
  const [approvals, setApprovals] = useState<Approval[]>();
  const [error, setError] = useState<string>();
  const [showAll, setShowAll] = useState(false);

  const load = useCallback(() => {
    getJson<{ approvals: Approval[] }>(showAll ? "/api/approvals" : "/api/approvals?status=pending")
      .then((r) => {
        setApprovals(r.approvals);
        setError(undefined);
      })
      .catch((e: Error) => setError(e.message));
  }, [showAll]);

  useEffect(load, [load]);

  return (
    <Card
      title="Approvals"
      actions={
        <>
          <label className="flex items-center gap-1.5 text-xs">
            <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> Show decided / expired
          </label>
          <Button variant="ghost" onClick={load}>
            Refresh
          </Button>
        </>
      }
    >
      <p className="mb-3 text-xs text-zinc-500 dark:text-zinc-400">
        This is the human approval channel. The agent can request risky operations (active scans, state-changing tests, live MCP inspection) but can never approve them.
        Approvals are single-use, time-limited and bound to the exact parameters. You can also decide in a terminal with{" "}
        <code className="font-mono">mungard approvals approve &lt;id&gt;</code>.
      </p>
      {error && <ErrorBox message={error} />}
      {!approvals && !error && <Empty>Loading...</Empty>}
      {approvals && approvals.length === 0 && <Empty>{showAll ? "No approval requests." : "No pending approvals."}</Empty>}
      <div className="space-y-3">
        {approvals?.map((a) => (
          <ApprovalCard
            key={`${a.id}-${a.status}`}
            approval={a}
            onDecided={() => {
              load();
              onChanged();
            }}
          />
        ))}
      </div>
    </Card>
  );
}
