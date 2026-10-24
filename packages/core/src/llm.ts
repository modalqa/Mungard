import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Anthropic from "@anthropic-ai/sdk";
import { betaZodOutputFormat } from "@anthropic-ai/sdk/helpers/beta/zod";
import { AiTriageResponse, TRIAGE_SYSTEM_PROMPT, type TriagePayloadItem } from "./triage.js";

export interface AgentToolSpec {
  name: string;
  description: string;
  /** JSON Schema (object) for the tool input. */
  inputSchema: Record<string, unknown>;
}

export interface AgentToolResult {
  content: string;
  isError: boolean;
}

export type AgentEvent =
  | { type: "text"; delta: string }
  | { type: "tool_call"; id: string; name: string; input: unknown }
  | { type: "tool_result"; id: string; name: string; isError: boolean; content: string }
  | { type: "notice"; message: string };

export interface AgentTurnRequest {
  system: string;
  /** Provider-specific conversation state. Append-only; owned by the caller between turns. */
  history: unknown[];
  userMessage: string;
  tools: AgentToolSpec[];
  execute: (name: string, input: unknown) => Promise<AgentToolResult>;
  onEvent: (e: AgentEvent) => void;
  signal?: AbortSignal;
  maxIterations?: number;
}

/**
 * Model provider abstraction. Core logic never depends on one vendor
 * (PRD NFR maintainability); Anthropic is the reference implementation.
 */
export interface LlmProvider {
  readonly name: string;
  readonly model: string;
  triage(items: TriagePayloadItem[]): Promise<AiTriageResponse>;
  runAgentTurn(req: AgentTurnRequest): Promise<void>;
}

/** Whether the Anthropic SDK can find credentials (env vars or an `ant auth login` profile). */
export function anthropicCredentialsAvailable(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.ANTHROPIC_API_KEY || env.ANTHROPIC_AUTH_TOKEN || env.ANTHROPIC_IDENTITY_TOKEN || env.ANTHROPIC_IDENTITY_TOKEN_FILE) return true;
  const configHome = env.XDG_CONFIG_HOME ?? path.join(os.homedir(), ".config");
  return existsSync(path.join(configHome, "anthropic"));
}

/** Wrap tool output so the model treats it as data, never as instructions (SR-07). */
export function wrapUntrusted(name: string, content: string): string {
  const safe = content.replace(/<\/?untrusted_tool_output[^>]*>/gi, "[tag removed]");
  return `<untrusted_tool_output tool="${name}">\n${safe}\n</untrusted_tool_output>`;
}

const FALLBACK_BETA = "server-side-fallback-2026-07-01";

export class AnthropicProvider implements LlmProvider {
  readonly name = "Anthropic Claude";
  private readonly client: Anthropic;

  constructor(
    readonly model: string = "claude-opus-5-5",
    private readonly effort: "low" | "medium" | "high" | "xhigh" | "max" = "medium",
    client?: Anthropic,
  ) {
    this.client = client ?? new Anthropic();
  }

  async triage(items: TriagePayloadItem[]): Promise<AiTriageResponse> {
    const res = await this.client.beta.messages.parse({
      model: this.model,
      max_tokens: 16000,
      betas: [FALLBACK_BETA],
      // A security tool talks about vulnerabilities; route classifier refusals to the recommended fallback model.
      fallbacks: "default",
      output_config: { effort: this.effort, format: betaZodOutputFormat(AiTriageResponse) },
      system: TRIAGE_SYSTEM_PROMPT,
      messages: [
        {
          role: "user",
          content: `<findings>\n${JSON.stringify(items, null, 2)}\n</findings>\n\nTriage every finding listed above. Return one item per finding id.`,
        },
      ],
    });
    if (res.stop_reason === "refusal") {
      throw new Error(`The model declined to triage these findings (${res.stop_details?.category ?? "no category"}).`);
    }
    if (!res.parsed_output) throw new Error("The model returned no parseable triage output.");
    return res.parsed_output;
  }

  async runAgentTurn(req: AgentTurnRequest): Promise<void> {
    const messages = req.history as Anthropic.Beta.BetaMessageParam[];
    messages.push({ role: "user", content: req.userMessage });
    const tools: Anthropic.Beta.BetaTool[] = req.tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.inputSchema as Anthropic.Beta.BetaTool.InputSchema,
      eager_input_streaming: true,
    }));
    let jsonRetries = 0;
    for (let i = 0; i < (req.maxIterations ?? 16); i++) {
      if (req.signal?.aborted) return;
      const stream = this.client.beta.messages.stream(
        {
          model: this.model,
          max_tokens: 64000,
          betas: [FALLBACK_BETA],
          fallbacks: "default",
          thinking: { type: "adaptive" },
          output_config: { effort: this.effort },
          system: [{ type: "text", text: req.system, cache_control: { type: "ephemeral" } }],
          tools,
          messages,
        },
        { signal: req.signal },
      );
      stream.on("text", (delta) => req.onEvent({ type: "text", delta }));
      let message: Anthropic.Beta.BetaMessage;
      try {
        message = await stream.finalMessage();
        jsonRetries = 0;
      } catch (err) {
        // Only an unparseable streamed tool input is retried; API errors propagate.
        if (err instanceof Anthropic.APIError || req.signal?.aborted || jsonRetries++ >= 2) throw err;
        req.onEvent({ type: "notice", message: "Model produced an unparseable tool call; retrying." });
        continue;
      }
      messages.push({ role: "assistant", content: message.content });
      if (message.stop_reason === "refusal") {
        req.onEvent({ type: "notice", message: `The model declined this request (${message.stop_details?.category ?? "unspecified"}).` });
        return;
      }
      if (message.stop_reason === "pause_turn") continue;
      const toolUses = message.content.filter((b): b is Anthropic.Beta.BetaToolUseBlock => b.type === "tool_use");
      if (toolUses.length === 0) return;
      const truncated = message.stop_reason === "max_tokens";
      const results = await Promise.all(
        toolUses.map(async (t): Promise<Anthropic.Beta.BetaToolResultBlockParam> => {
          req.onEvent({ type: "tool_call", id: t.id, name: t.name, input: t.input });
          const r: AgentToolResult = truncated
            ? { content: "Tool input was truncated (max_tokens); the tool was not run. Retry with a shorter input.", isError: true }
            : await req.execute(t.name, t.input).catch((err: unknown) => ({ content: (err as Error).message, isError: true }));
          req.onEvent({ type: "tool_result", id: t.id, name: t.name, isError: r.isError, content: r.content });
          return { type: "tool_result", tool_use_id: t.id, is_error: r.isError, content: wrapUntrusted(t.name, r.content) };
        }),
      );
      messages.push({ role: "user", content: results });
    }
    req.onEvent({ type: "notice", message: "Stopped after the maximum number of tool iterations for one message." });
  }
}

/** Provider from config, or undefined when AI is disabled or no credentials are available. */
export function createLlmProvider(ai: { provider: "anthropic" | "none"; model: string; effort: "low" | "medium" | "high" | "xhigh" | "max" }, enabled: boolean): LlmProvider | undefined {
  if (!enabled || ai.provider === "none") return undefined;
  if (!anthropicCredentialsAvailable()) return undefined;
  return new AnthropicProvider(ai.model, ai.effort);
}
