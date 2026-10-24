"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ChatEvent } from "@/lib/client/types";
import { Markdown } from "./Markdown";
import { Button, ErrorBox, JsonBlock, inputClass } from "./ui";

type Part =
  | { kind: "text"; text: string }
  | { kind: "tool"; id: string; name: string; input: unknown; result?: string; isError?: boolean }
  | { kind: "notice"; text: string }
  | { kind: "error"; text: string };

type Message = { role: "user"; text: string } | { role: "assistant"; parts: Part[]; done: boolean };

const STARTERS = [
  "Plan a security assessment",
  "Scan this app",
  "Inspect MCP config",
  "Test authorization",
  "List findings",
  "Generate a report",
];

export interface ChatMode {
  mode: "ai" | "offline";
  model?: string;
}

function ToolCard({ part }: { part: Extract<Part, { kind: "tool" }> }) {
  const state = part.result === undefined ? "running" : part.isError ? "error" : "done";
  return (
    <details className="my-2 rounded-md border border-zinc-200 bg-zinc-50 text-sm dark:border-zinc-800 dark:bg-zinc-950">
      <summary className="flex cursor-pointer items-center gap-2 px-3 py-2 select-none">
        <span className="font-mono text-xs text-zinc-500">tool</span>
        <span className="font-mono font-medium">{part.name}</span>
        <span
          className={`ml-auto rounded px-1.5 py-0.5 text-xs ${
            state === "running"
              ? "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300"
              : state === "error"
                ? "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300"
                : "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"
          }`}
        >
          {state === "running" ? "running..." : state === "error" ? "error" : "done"}
        </span>
      </summary>
      <div className="space-y-2 border-t border-zinc-200 px-3 py-2 dark:border-zinc-800">
        <div>
          <div className="mb-1 text-xs font-semibold text-zinc-500">Input</div>
          <JsonBlock value={part.input} max={2000} />
        </div>
        {part.result !== undefined && (
          <div>
            <div className="mb-1 text-xs font-semibold text-zinc-500">Result (untrusted data, redacted)</div>
            <JsonBlock value={part.result} max={6000} />
          </div>
        )}
      </div>
    </details>
  );
}

function applyEvent(parts: Part[], e: ChatEvent): Part[] {
  const next = [...parts];
  switch (e.type) {
    case "text": {
      const last = next[next.length - 1];
      if (last?.kind === "text") next[next.length - 1] = { kind: "text", text: last.text + e.delta };
      else next.push({ kind: "text", text: e.delta });
      return next;
    }
    case "tool_call":
      next.push({ kind: "tool", id: e.id, name: e.name, input: e.input });
      return next;
    case "tool_result": {
      const idx = next.findIndex((p) => p.kind === "tool" && p.id === e.id);
      if (idx >= 0) next[idx] = { ...(next[idx] as Extract<Part, { kind: "tool" }>), result: e.content, isError: e.isError };
      else next.push({ kind: "tool", id: e.id, name: e.name, input: undefined, result: e.content, isError: e.isError });
      return next;
    }
    case "notice":
      next.push({ kind: "notice", text: e.message });
      return next;
    case "error":
      next.push({ kind: "error", text: e.message });
      return next;
    default:
      return next;
  }
}

export function ChatPanel({ onMode }: { onMode: (m: ChatMode) => void }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const sessionId = useRef<string | undefined>(undefined);
  const abortRef = useRef<AbortController | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [messages]);

  useEffect(() => () => abortRef.current?.abort(), []);

  const updateAssistant = useCallback((fn: (m: Extract<Message, { role: "assistant" }>) => Extract<Message, { role: "assistant" }>) => {
    setMessages((prev) => {
      const copy = [...prev];
      const last = copy[copy.length - 1];
      if (last?.role === "assistant") copy[copy.length - 1] = fn(last);
      return copy;
    });
  }, []);

  const send = useCallback(
    async (text: string) => {
      const message = text.trim();
      if (!message || busy) return;
      setError(undefined);
      setInput("");
      setBusy(true);
      setMessages((prev) => [...prev, { role: "user", text: message }, { role: "assistant", parts: [], done: false }]);
      const controller = new AbortController();
      abortRef.current = controller;
      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
          credentials: "same-origin",
          body: JSON.stringify({ message, sessionId: sessionId.current }),
          signal: controller.signal,
        });
        if (!res.ok || !res.body) {
          const data = (await res.json().catch(() => ({}))) as { error?: string; reason?: string };
          throw new Error(data.reason ?? data.error ?? `Chat request failed (${res.status}).`);
        }
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buffer = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += value;
          let sep: number;
          while ((sep = buffer.indexOf("\n\n")) >= 0) {
            const frame = buffer.slice(0, sep);
            buffer = buffer.slice(sep + 2);
            const data = frame
              .split("\n")
              .filter((l) => l.startsWith("data:"))
              .map((l) => l.slice(5).trimStart())
              .join("\n");
            if (!data) continue;
            let event: ChatEvent;
            try {
              event = JSON.parse(data) as ChatEvent;
            } catch {
              continue;
            }
            if (event.type === "session") {
              sessionId.current = event.id;
              onMode({ mode: event.mode, model: event.model });
            } else {
              updateAssistant((m) => ({ ...m, parts: applyEvent(m.parts, event) }));
            }
          }
        }
      } catch (err) {
        if ((err as Error).name === "AbortError") {
          updateAssistant((m) => ({ ...m, parts: [...m.parts, { kind: "notice", text: "Stopped." }] }));
        } else {
          setError((err as Error).message);
        }
      } finally {
        updateAssistant((m) => ({ ...m, done: true }));
        abortRef.current = null;
        setBusy(false);
      }
    },
    [busy, onMode, updateAssistant],
  );

  const reset = () => {
    abortRef.current?.abort();
    sessionId.current = undefined;
    setMessages([]);
    setError(undefined);
  };

  return (
    <div className="flex h-[calc(100vh-11rem)] min-h-[28rem] flex-col rounded-lg border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex-1 space-y-4 overflow-y-auto p-4" aria-live="polite">
        {messages.length === 0 && (
          <div className="mx-auto max-w-xl py-10 text-center">
            <h2 className="text-lg font-semibold">What should Mungard test?</h2>
            <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
              The agent can only use Mungard tools. Risky operations create approval requests that only you can approve in the Approvals tab.
            </p>
            <div className="mt-5 flex flex-wrap justify-center gap-2">
              {STARTERS.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => void send(s)}
                  className="rounded-full border border-zinc-300 px-3 py-1.5 text-sm hover:border-brand-600 hover:text-brand-700 dark:border-zinc-700 dark:hover:border-brand-400 dark:hover:text-brand-400"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}
        {messages.map((m, mi) =>
          m.role === "user" ? (
            <div key={mi} className="flex justify-end">
              <div className="max-w-[85%] rounded-lg bg-brand-600 px-3 py-2 text-sm whitespace-pre-wrap text-white">{m.text}</div>
            </div>
          ) : (
            <div key={mi} className="max-w-[95%] text-sm">
              {m.parts.length === 0 && !m.done && <div className="animate-pulse text-zinc-500">Thinking...</div>}
              {m.parts.map((p, pi) => {
                if (p.kind === "text") return <Markdown key={pi} text={p.text} />;
                if (p.kind === "tool") return <ToolCard key={pi} part={p} />;
                if (p.kind === "notice")
                  return (
                    <div key={pi} className="my-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-300">
                      {p.text}
                    </div>
                  );
                return (
                  <div key={pi} className="my-2">
                    <ErrorBox message={p.text} />
                  </div>
                );
              })}
            </div>
          ),
        )}
        {error && <ErrorBox message={error} />}
        <div ref={endRef} />
      </div>
      <form
        className="flex items-end gap-2 border-t border-zinc-200 p-3 dark:border-zinc-800"
        onSubmit={(e) => {
          e.preventDefault();
          void send(input);
        }}
      >
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void send(input);
            }
          }}
          rows={2}
          maxLength={8000}
          placeholder="Ask Mungard to plan, scan, inspect or explain... (Enter to send, Shift+Enter for a new line)"
          className={`${inputClass} flex-1 resize-none`}
          aria-label="Message"
        />
        <div className="flex flex-col gap-1">
          {busy ? (
            <Button variant="secondary" onClick={() => abortRef.current?.abort()}>
              Stop
            </Button>
          ) : (
            <Button type="submit" variant="primary" disabled={!input.trim()}>
              Send
            </Button>
          )}
          <Button variant="ghost" onClick={reset} disabled={busy && messages.length === 0}>
            New chat
          </Button>
        </div>
      </form>
    </div>
  );
}
