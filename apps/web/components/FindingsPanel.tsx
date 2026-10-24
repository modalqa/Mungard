"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { formatDate, getJson, postJson } from "@/lib/client/api";
import type { Finding, FindingSummary } from "@/lib/client/types";
import { ALL_STATUSES, HUMAN_STATUSES, SEVERITIES, SEVERITY_RANK } from "@/lib/statuses";
import { Button, Card, Empty, ErrorBox, JsonBlock, SeverityBadge, StatusBadge, formatLocation, inputClass } from "./ui";

/** Engines that verify behaviour against user-defined expectations (vs. pattern scanners). */
const VERIFICATION_ENGINES = new Set(["authz", "http-probe"]);

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-4">
      <h3 className="mb-1.5 text-xs font-semibold tracking-wide text-zinc-500 uppercase dark:text-zinc-400">{title}</h3>
      {children}
    </div>
  );
}

function EvidenceItem({ findingId, ev }: { findingId: string; ev: Finding["evidence"][number] }) {
  const [content, setContent] = useState<string>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const load = async () => {
    setLoading(true);
    setError(undefined);
    try {
      const r = await getJson<{ content: string }>(`/api/findings/${encodeURIComponent(findingId)}/evidence?ref=${encodeURIComponent(ev.id)}`);
      setContent(r.content);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  return (
    <li className="rounded-md border border-zinc-200 p-2 dark:border-zinc-800">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="rounded bg-zinc-100 px-1.5 py-0.5 font-mono dark:bg-zinc-800">{ev.kind}</span>
        <span>{ev.description}</span>
        {ev.path && content === undefined && (
          <Button variant="ghost" className="ml-auto !px-2 !py-0.5 text-xs" onClick={() => void load()} disabled={loading}>
            {loading ? "Loading..." : "Load evidence file"}
          </Button>
        )}
      </div>
      {ev.excerpt && <pre className="mt-1.5 overflow-x-auto rounded bg-zinc-100 p-2 font-mono text-xs whitespace-pre-wrap dark:bg-zinc-950">{ev.excerpt}</pre>}
      {ev.path && <div className="mt-1 font-mono text-[11px] text-zinc-500">{ev.path}</div>}
      {content !== undefined && <div className="mt-1.5"><JsonBlock value={content} max={20000} /></div>}
      {error && <div className="mt-1.5"><ErrorBox message={error} /></div>}
    </li>
  );
}

function StatusForm({ finding, onUpdated }: { finding: Finding; onUpdated: (f: Finding) => void }) {
  const [status, setStatus] = useState<string>(finding.status === "retested" ? "fixed" : finding.status);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const [saving, setSaving] = useState(false);
  const unchanged = status === finding.status;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (reason.trim().length < 3) {
      setError("Please give a reason (at least 3 characters). It is stored in the finding history and audit log.");
      return;
    }
    setSaving(true);
    setError(undefined);
    try {
      const r = await postJson<{ finding: Finding }>(`/api/findings/${encodeURIComponent(finding.id)}/status`, { status, reason: reason.trim() });
      setReason("");
      onUpdated(r.finding);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-2 rounded-md border border-zinc-200 p-3 dark:border-zinc-800">
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-sm" htmlFor="status-select">
          New status
        </label>
        <select id="status-select" value={status} onChange={(e) => setStatus(e.target.value)} className={inputClass}>
          {HUMAN_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s.replace(/_/g, " ")}
            </option>
          ))}
        </select>
      </div>
      <textarea
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        rows={2}
        maxLength={2000}
        required
        placeholder="Reason (required), e.g. 'Verified manually: endpoint returns other users' orders'"
        className={`${inputClass} w-full`}
        aria-label="Reason"
      />
      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        &quot;retested&quot; cannot be set by hand: it is set only when a retest run verifies the fix. &quot;fixed&quot; stays unresolved until then.
      </p>
      {error && <ErrorBox message={error} />}
      <Button type="submit" variant="primary" disabled={saving || unchanged}>
        {saving ? "Saving..." : "Update status"}
      </Button>
    </form>
  );
}

function FindingDetail({ id, onChanged }: { id: string; onChanged: () => void }) {
  const [finding, setFinding] = useState<Finding>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    let cancelled = false;
    setFinding(undefined);
    setError(undefined);
    getJson<{ finding: Finding }>(`/api/findings/${encodeURIComponent(id)}`)
      .then((r) => !cancelled && setFinding(r.finding))
      .catch((e: Error) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (error) return <ErrorBox message={error} />;
  if (!finding) return <Empty>Loading finding...</Empty>;

  const verified = finding.sources.some((s) => VERIFICATION_ENGINES.has(s.engine));
  return (
    <div className="text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <StatusBadge status={finding.status} />
        <span className="font-mono text-xs text-zinc-500">{finding.id}</span>
        <span className="text-xs text-zinc-500">
          {finding.category} · confidence {finding.confidence}
        </span>
      </div>
      <h2 className="mt-2 text-base font-semibold">{finding.title}</h2>
      {(finding.status === "new" || finding.status === "needs_review") && (
        <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">Unverified {verified ? "" : "scanner "}output: not a confirmed vulnerability.</p>
      )}
      <p className="mt-2 whitespace-pre-wrap">{finding.description}</p>

      {finding.impact && (
        <Section title="Impact">
          <p className="whitespace-pre-wrap">{finding.impact}</p>
        </Section>
      )}

      <Section title="Sources">
        <ul className="space-y-1">
          {finding.sources.map((s, i) => (
            <li key={i} className="flex flex-wrap items-center gap-2">
              <span
                className={`rounded px-1.5 py-0.5 text-xs ${VERIFICATION_ENGINES.has(s.engine) ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300" : "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"}`}
              >
                {VERIFICATION_ENGINES.has(s.engine) ? "verification" : "scanner"}
              </span>
              <span className="font-mono text-xs">
                {s.engine}
                {s.engineVersion ? ` ${s.engineVersion}` : ""}
              </span>
              {s.ruleId && <span className="font-mono text-xs text-zinc-500">{s.ruleId}</span>}
              {s.originalSeverity && <span className="text-xs text-zinc-500">engine severity: {s.originalSeverity}</span>}
              <span className="font-mono text-xs text-zinc-500">{s.runId}</span>
            </li>
          ))}
        </ul>
      </Section>

      {finding.locations.length > 0 && (
        <Section title="Locations">
          <ul className="space-y-0.5 font-mono text-xs">
            {finding.locations.map((l, i) => (
              <li key={i}>{formatLocation(l)}</li>
            ))}
          </ul>
        </Section>
      )}

      {finding.evidence.length > 0 && (
        <Section title="Evidence">
          <ul className="space-y-2">
            {finding.evidence.map((ev) => (
              <EvidenceItem key={ev.id} findingId={finding.id} ev={ev} />
            ))}
          </ul>
        </Section>
      )}

      {finding.reproductionSteps.length > 0 && (
        <Section title="Reproduction steps">
          <ol className="list-decimal space-y-1 pl-5">
            {finding.reproductionSteps.map((s, i) => (
              <li key={i} className="whitespace-pre-wrap">
                {s}
              </li>
            ))}
          </ol>
        </Section>
      )}

      {finding.remediation && (
        <Section title="Remediation">
          <p className="whitespace-pre-wrap">{finding.remediation}</p>
        </Section>
      )}

      {(finding.cwe.length > 0 || finding.references.length > 0) && (
        <Section title="References">
          {finding.cwe.length > 0 && <p className="text-xs">{finding.cwe.join(", ")}</p>}
          <ul className="mt-1 space-y-0.5 text-xs break-all">
            {finding.references.map((r, i) => (
              <li key={i} className="font-mono">
                {r}
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section title="Triage (advisory)">
        {finding.triage ? (
          <div className="rounded-md border border-dashed border-zinc-300 p-2 dark:border-zinc-700">
            <p className="text-xs text-zinc-500">
              Advisory only, never changes the status. Source: {finding.triage.source}
              {finding.triage.model ? ` (${finding.triage.model})` : ""} · {formatDate(finding.triage.at)}
            </p>
            <p className="mt-1">
              <strong>{finding.triage.assessment.replace(/_/g, " ")}</strong> · priority {finding.triage.priority}
              {finding.triage.suggestedStatus ? ` · suggests "${finding.triage.suggestedStatus}"` : ""}
            </p>
            <p className="mt-1 whitespace-pre-wrap">{finding.triage.rationale}</p>
            {finding.triage.missingEvidence.length > 0 && (
              <>
                <p className="mt-1 text-xs font-semibold">Missing evidence</p>
                <ul className="list-disc pl-5 text-xs">
                  {finding.triage.missingEvidence.map((m, i) => (
                    <li key={i}>{m}</li>
                  ))}
                </ul>
              </>
            )}
            {finding.triage.verificationSteps.length > 0 && (
              <>
                <p className="mt-1 text-xs font-semibold">Verification steps</p>
                <ol className="list-decimal pl-5 text-xs">
                  {finding.triage.verificationSteps.map((m, i) => (
                    <li key={i}>{m}</li>
                  ))}
                </ol>
              </>
            )}
          </div>
        ) : (
          <p className="text-xs text-zinc-500">Not triaged yet. Ask the agent to &quot;triage findings&quot;.</p>
        )}
      </Section>

      <Section title="Retest">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <StatusBadge status={finding.retest.status} />
          {finding.retest.runId && <span className="font-mono">{finding.retest.runId}</span>}
          {finding.retest.codeVersion && <span className="font-mono">code {finding.retest.codeVersion}</span>}
          {finding.retest.at && <span>{formatDate(finding.retest.at)}</span>}
        </div>
        {finding.retest.notes && <p className="mt-1 text-xs whitespace-pre-wrap">{finding.retest.notes}</p>}
      </Section>

      <Section title="History">
        {finding.history.length === 0 ? (
          <p className="text-xs text-zinc-500">No status changes.</p>
        ) : (
          <ul className="space-y-1 text-xs">
            {finding.history.map((h, i) => (
              <li key={i}>
                <span className="text-zinc-500">{formatDate(h.at)}</span> · {h.from} → <strong>{h.to}</strong> by {h.actor}: {h.reason}
              </li>
            ))}
          </ul>
        )}
        <p className="mt-1 text-xs text-zinc-500">
          First seen {formatDate(finding.firstSeen)} · last seen {formatDate(finding.lastSeen)}
        </p>
      </Section>

      <Section title="Change status">
        <StatusForm
          key={`${finding.id}-${finding.status}-${finding.history.length}`}
          finding={finding}
          onUpdated={(f) => {
            setFinding(f);
            onChanged();
          }}
        />
      </Section>
    </div>
  );
}

export function FindingsPanel() {
  const [findings, setFindings] = useState<FindingSummary[]>();
  const [error, setError] = useState<string>();
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("unresolved");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string>();

  const load = useCallback(() => {
    getJson<{ findings: FindingSummary[] }>("/api/findings")
      .then((r) => {
        setFindings(r.findings);
        setError(undefined);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(load, [load]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (findings ?? [])
      .filter((f) => severity === "all" || f.severity === severity)
      .filter((f) =>
        status === "all" ? true : status === "unresolved" ? ["new", "needs_review", "confirmed", "fixed"].includes(f.status) : f.status === status,
      )
      .filter((f) => !q || f.title.toLowerCase().includes(q) || f.id.toLowerCase().includes(q) || formatLocation(f.location).toLowerCase().includes(q))
      .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) || a.title.localeCompare(b.title));
  }, [findings, severity, status, query]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings ?? []) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      <Card
        title={`Findings${findings ? ` (${filtered.length} of ${findings.length})` : ""}`}
        actions={
          <Button variant="ghost" onClick={load}>
            Refresh
          </Button>
        }
      >
        <div className="mb-3 flex flex-wrap gap-2">
          <select aria-label="Severity filter" value={severity} onChange={(e) => setSeverity(e.target.value)} className={inputClass}>
            <option value="all">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s} ({counts[s] ?? 0})
              </option>
            ))}
          </select>
          <select aria-label="Status filter" value={status} onChange={(e) => setStatus(e.target.value)} className={inputClass}>
            <option value="unresolved">Unresolved</option>
            <option value="all">All statuses</option>
            {ALL_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s.replace(/_/g, " ")}
              </option>
            ))}
          </select>
          <input aria-label="Search" placeholder="Search title, id, location" value={query} onChange={(e) => setQuery(e.target.value)} className={`${inputClass} min-w-40 flex-1`} />
        </div>
        {error && <ErrorBox message={error} />}
        {!findings && !error && <Empty>Loading...</Empty>}
        {findings && filtered.length === 0 && <Empty>No findings match these filters.</Empty>}
        {filtered.length > 0 && (
          <div className="max-h-[calc(100vh-17rem)] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-white text-left text-xs text-zinc-500 dark:bg-zinc-900">
                <tr>
                  <th className="py-1.5 pr-2 font-medium">Severity</th>
                  <th className="py-1.5 pr-2 font-medium">Finding</th>
                  <th className="py-1.5 pr-2 font-medium">Status</th>
                  <th className="hidden py-1.5 font-medium xl:table-cell">Engine</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelected(f.id)}
                    className={`cursor-pointer border-t border-zinc-100 align-top hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-800/60 ${selected === f.id ? "bg-brand-50 dark:bg-brand-900/30" : ""}`}
                  >
                    <td className="py-2 pr-2">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-2 pr-2">
                      <button type="button" className="text-left font-medium hover:underline" onClick={() => setSelected(f.id)}>
                        {f.title}
                      </button>
                      <div className="font-mono text-xs break-all text-zinc-500">
                        {f.id} · {formatLocation(f.location)}
                      </div>
                    </td>
                    <td className="py-2 pr-2">
                      <StatusBadge status={f.status} />
                    </td>
                    <td className="hidden py-2 font-mono text-xs text-zinc-500 xl:table-cell">{f.engines.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="Detail">
        {selected ? <FindingDetail id={selected} onChanged={load} /> : <Empty>Select a finding to see evidence, triage and history.</Empty>}
      </Card>
    </div>
  );
}
