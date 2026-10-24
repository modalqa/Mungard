import { runChatTurn } from "@mungard/core";
import { z } from "zod";
import { guard, readJson } from "@/lib/server/guard";
import { errorMessage, jsonError, openWorkspace } from "@/lib/server/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ChatBody = z.object({
  message: z.string().trim().min(1).max(8000),
  sessionId: z
    .string()
    .regex(/^chat_[a-f0-9]{12}$/)
    .optional(),
});

/**
 * One chat turn, streamed as Server-Sent Events. Each event is a JSON object
 * from `runChatTurn` (session, text, tool_call, tool_result, notice), followed
 * by `{type:"done"}` or `{type:"error"}`. Everything is redacted before it is
 * written to the stream.
 */
export async function POST(request: Request): Promise<Response> {
  const denied = guard(request, { json: true });
  if (denied) return denied;
  const parsed = ChatBody.safeParse(await readJson(request));
  if (!parsed.success) return jsonError(400, "Body must be {message: string, sessionId?: string}.");

  let ws: Awaited<ReturnType<typeof openWorkspace>>;
  try {
    ws = await openWorkspace();
  } catch (err) {
    return jsonError(500, errorMessage(err));
  }

  const encoder = new TextEncoder();
  const abort = new AbortController();
  const onClientAbort = () => abort.abort();
  request.signal.addEventListener("abort", onClientAbort, { once: true });

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let closed = false;
      const send = (event: unknown) => {
        if (closed) return;
        try {
          const safe = ws.redact(JSON.stringify(event));
          controller.enqueue(encoder.encode(`data: ${safe}\n\n`));
        } catch {
          closed = true;
        }
      };
      try {
        await runChatTurn({
          ws,
          sessionId: parsed.data.sessionId,
          message: parsed.data.message,
          onEvent: send,
          signal: abort.signal,
        });
        send({ type: "done" });
      } catch (err) {
        send({ type: "error", message: abort.signal.aborted ? "Request cancelled." : errorMessage(err) });
      } finally {
        request.signal.removeEventListener("abort", onClientAbort);
        if (!closed) {
          closed = true;
          try {
            controller.close();
          } catch {
            // already closed by the runtime
          }
        }
      }
    },
    cancel() {
      abort.abort();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
