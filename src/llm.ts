import type { Env } from "./env";
import { recordUsage, type EventWriter } from "./events";
import { readChatStream } from "./stream";

export const DEFAULT_MODEL = "@cf/zai-org/glm-4.7-flash";

export interface CompletionOptions {
  runId: string;
  agent: string;
  messages: { role: "system" | "user"; content: string }[];
  maxTokens: number;
  /** Disable the reasoning phase for cheap, mechanical tasks. */
  thinking?: boolean;
}

/**
 * Streams a chat completion, mirroring reasoning and output into the
 * live feed and recording the neurons spent. Returns the answer text.
 */
export async function streamCompletion(
  env: Env,
  events: EventWriter,
  options: CompletionOptions,
): Promise<string> {
  const model = env.AI_MODEL || DEFAULT_MODEL;

  const stream = (await env.AI.run(model as any, {
    stream: true,
    max_completion_tokens: options.maxTokens,
    ...(options.thinking === false
      ? { chat_template_kwargs: { enable_thinking: false } }
      : {}),
    messages: options.messages,
  } as any)) as unknown as ReadableStream<Uint8Array>;

  let output = "";
  let incremental = 0;
  let total = 0;
  try {
    for await (const delta of readChatStream(stream)) {
      if (delta.reasoning) await events.stream("thinking", delta.reasoning);
      if (delta.content) {
        output += delta.content;
        await events.stream("output", delta.content);
      }
      incremental += delta.neurons ?? 0;
      total = delta.totalNeurons ?? total;
    }
    await events.flush();
  } finally {
    // Spend counts even when the call fails or is cut off.
    await recordUsage(
      env.DB,
      options.runId,
      options.agent,
      model,
      total || incremental,
    );
  }

  return output;
}
