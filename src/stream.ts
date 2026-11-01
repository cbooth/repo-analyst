export interface StreamDelta {
  reasoning?: string;
  content?: string;
  /** Neurons billed for this chunk (per-chunk usage). */
  neurons?: number;
  /** Neurons billed for the whole request (final summary chunk). */
  totalNeurons?: number;
}

/**
 * Parses one SSE line from a chat-completions stream. Tolerates both
 * the OpenAI-style `choices[0].delta` shape and the older
 * `{ "response": "..." }` shape Workers AI uses for some models.
 */
export function parseSseLine(line: string): StreamDelta | null {
  if (!line.startsWith("data:")) return null;

  const payload = line.slice(5).trim();
  if (!payload || payload === "[DONE]") return null;

  let json: any;
  try {
    json = JSON.parse(payload);
  } catch {
    return null;
  }

  const delta = json?.choices?.[0]?.delta;
  const reasoning = delta?.reasoning_content ?? delta?.reasoning;
  const content = delta?.content ?? json?.response;

  const out: StreamDelta = {};
  if (typeof reasoning === "string" && reasoning) {
    out.reasoning = reasoning;
  }
  if (typeof content === "string" && content) {
    out.content = content;
  }

  // Per-token chunks carry `choices` and an incremental figure; the final
  // summary chunk has no `choices` and carries the request total.
  const neurons = json?.usage?.neurons;
  if (typeof neurons === "number" && neurons > 0) {
    if (Array.isArray(json.choices)) out.neurons = neurons;
    else out.totalNeurons = neurons;
  }

  return Object.keys(out).length ? out : null;
}

export async function* readChatStream(
  body: ReadableStream<Uint8Array>,
): AsyncGenerator<StreamDelta> {
  // Decoding by hand avoids a TransformStream hop per chunk; the stream
  // arrives as thousands of tiny chunks and CPU time is metered.
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      let start = 0;
      let newline: number;
      while ((newline = buffer.indexOf("\n", start)) >= 0) {
        const delta = parseSseLine(buffer.slice(start, newline).trim());
        start = newline + 1;
        if (delta) yield delta;
      }
      buffer = buffer.slice(start);
    }

    buffer += decoder.decode();
    const tail = parseSseLine(buffer.trim());
    if (tail) yield tail;
  } finally {
    reader.releaseLock();
  }
}
