"use client";

import { Fragment, type ReactNode } from "react";

/**
 * Minimal, safe Markdown renderer. It builds React elements only (React
 * escapes all text), never uses dangerouslySetInnerHTML, and only turns
 * http(s) URLs into links. Supported: headings, paragraphs, fenced code,
 * bullet/numbered lists, blockquotes, horizontal rules, pipe tables,
 * inline code, bold, italic and links.
 */

const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(\[[^\]\n]+\]\([^)\s]+\))|(\*[^*\s][^*\n]*\*)|(_[^_\s][^_\n]*_)/g;

function safeHref(url: string): string | undefined {
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}

function inline(text: string, keyPrefix: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let i = 0;
  for (const m of text.matchAll(INLINE)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push(text.slice(last, idx));
    const tok = m[0];
    const key = `${keyPrefix}-${i++}`;
    if (m[1]) {
      out.push(
        <code key={key} className="rounded bg-zinc-200/70 px-1 py-0.5 font-mono text-[0.85em] dark:bg-zinc-800">
          {tok.slice(1, -1)}
        </code>,
      );
    } else if (m[2]) {
      out.push(<strong key={key}>{inline(tok.slice(2, -2), key)}</strong>);
    } else if (m[3]) {
      const close = tok.indexOf("](");
      const label = tok.slice(1, close);
      const href = safeHref(tok.slice(close + 2, -1));
      out.push(
        href ? (
          <a key={key} href={href} target="_blank" rel="noopener noreferrer" className="text-brand-600 underline dark:text-brand-400">
            {label}
          </a>
        ) : (
          <span key={key}>{label}</span>
        ),
      );
    } else {
      out.push(<em key={key}>{tok.slice(1, -1)}</em>);
    }
    last = idx + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function splitRow(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((c) => c.trim());
}

const isTableSep = (line: string) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(line);

export function Markdown({ text, className }: { text: string; className?: string }) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let k = 0;
  const key = () => `b${k++}`;

  while (i < lines.length) {
    const line = lines[i]!;

    if (/^\s*```/.test(line)) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i]!)) body.push(lines[i++]!);
      i++;
      blocks.push(
        <pre key={key()} className="my-2 overflow-x-auto rounded-md bg-zinc-900 p-3 font-mono text-xs text-zinc-100">
          {body.join("\n")}
        </pre>,
      );
      continue;
    }

    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      const level = h[1]!.length;
      const cls = level <= 1 ? "text-xl font-semibold mt-4 mb-2" : level === 2 ? "text-lg font-semibold mt-4 mb-2" : "text-base font-semibold mt-3 mb-1";
      const k2 = key();
      blocks.push(
        <div key={k2} role="heading" aria-level={level} className={cls}>
          {inline(h[2]!, k2)}
        </div>,
      );
      i++;
      continue;
    }

    if (/^\s*([-*_])\s*\1\s*\1[\s\-*_]*$/.test(line)) {
      blocks.push(<hr key={key()} className="my-3 border-zinc-300 dark:border-zinc-700" />);
      i++;
      continue;
    }

    if (line.includes("|") && i + 1 < lines.length && isTableSep(lines[i + 1]!)) {
      const head = splitRow(line);
      const rows: string[][] = [];
      i += 2;
      while (i < lines.length && lines[i]!.includes("|") && lines[i]!.trim() !== "") rows.push(splitRow(lines[i++]!));
      const k2 = key();
      blocks.push(
        <div key={k2} className="my-2 overflow-x-auto">
          <table className="min-w-full border-collapse text-sm">
            <thead>
              <tr>
                {head.map((c, ci) => (
                  <th key={ci} className="border-b border-zinc-300 px-2 py-1 text-left font-semibold dark:border-zinc-700">
                    {inline(c, `${k2}h${ci}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri} className="border-b border-zinc-200 dark:border-zinc-800">
                  {r.map((c, ci) => (
                    <td key={ci} className="px-2 py-1 align-top">
                      {inline(c, `${k2}r${ri}c${ci}`)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    if (/^\s*[-*+]\s+/.test(line) || /^\s*\d+[.)]\s+/.test(line)) {
      const ordered = /^\s*\d+[.)]\s+/.test(line);
      const items: string[] = [];
      const re = ordered ? /^\s*\d+[.)]\s+/ : /^\s*[-*+]\s+/;
      while (i < lines.length && re.test(lines[i]!)) {
        let item = lines[i]!.replace(re, "");
        i++;
        // continuation lines (indented, not a new item)
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]!) && !re.test(lines[i]!)) item += ` ${lines[i++]!.trim()}`;
        items.push(item);
      }
      const k2 = key();
      const children = items.map((it, ii) => <li key={ii}>{inline(it, `${k2}-${ii}`)}</li>);
      blocks.push(
        ordered ? (
          <ol key={k2} className="my-2 list-decimal space-y-1 pl-6">
            {children}
          </ol>
        ) : (
          <ul key={k2} className="my-2 list-disc space-y-1 pl-6">
            {children}
          </ul>
        ),
      );
      continue;
    }

    if (/^\s*>/.test(line)) {
      const body: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i]!)) body.push(lines[i++]!.replace(/^\s*>\s?/, ""));
      const k2 = key();
      blocks.push(
        <blockquote key={k2} className="my-2 border-l-4 border-zinc-300 pl-3 text-zinc-600 dark:border-zinc-700 dark:text-zinc-400">
          {inline(body.join(" "), k2)}
        </blockquote>,
      );
      continue;
    }

    if (line.trim() === "") {
      i++;
      continue;
    }

    const para: string[] = [];
    while (
      i < lines.length &&
      lines[i]!.trim() !== "" &&
      !/^\s*```/.test(lines[i]!) &&
      !/^#{1,6}\s/.test(lines[i]!) &&
      !/^\s*[-*+]\s+/.test(lines[i]!) &&
      !/^\s*\d+[.)]\s+/.test(lines[i]!) &&
      !/^\s*>/.test(lines[i]!) &&
      !(lines[i]!.includes("|") && i + 1 < lines.length && isTableSep(lines[i + 1]!))
    ) {
      para.push(lines[i++]!);
    }
    const k2 = key();
    blocks.push(
      <p key={k2} className="my-2 whitespace-pre-wrap">
        {para.map((p, pi) => (
          <Fragment key={pi}>
            {pi > 0 && "\n"}
            {inline(p, `${k2}-${pi}`)}
          </Fragment>
        ))}
      </p>,
    );
  }

  return <div className={`break-words leading-relaxed ${className ?? ""}`}>{blocks}</div>;
}
