"use client";

/** Small fetch helpers for the same-origin API. */

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function parse<T>(res: Response): Promise<T> {
  const data = (await res.json().catch(() => ({}))) as { error?: string; reason?: string };
  if (!res.ok) throw new ApiError(data.reason ?? data.error ?? `Request failed (${res.status})`, res.status);
  return data as T;
}

export async function getJson<T>(url: string): Promise<T> {
  return parse<T>(await fetch(url, { cache: "no-store", credentials: "same-origin" }));
}

export async function postJson<T>(url: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body),
    signal,
  });
  return parse<T>(res);
}

export function formatDate(iso?: string): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}\n... [truncated, ${text.length - max} more characters]` : text;
}
