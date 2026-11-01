import type { EventKind } from "./env";
import { redactSecrets } from "./security";

const FLUSH_INTERVAL_MS = 800;
const FLUSH_CHARS = 400;
const MAX_STREAM_CHARS: Record<"thinking" | "output", number> = {
  thinking: 80_000,
  output: 20_000,
};

type StreamKind = keyof typeof MAX_STREAM_CHARS;

/**
 * Writes an agent's progress to D1 so the UI can tail it. Streamed text
 * is batched; failures never propagate into the analysis itself.
 */
export class EventWriter {
  private pending: { kind: StreamKind; text: string } | null = null;
  private lastFlush = Date.now();
  private written: Record<StreamKind, number> = {
    thinking: 0,
    output: 0,
  };

  constructor(
    private readonly db: D1Database,
    private readonly runId: string,
    private readonly agent: string,
  ) {}

  async emit(kind: EventKind, content: string): Promise<void> {
    await this.flush();
    await this.insert(kind, content);
  }

  async stream(kind: StreamKind, text: string): Promise<void> {
    if (this.pending && this.pending.kind !== kind) await this.flush();

    const room = MAX_STREAM_CHARS[kind] - this.written[kind];
    if (room <= 0) return;

    this.pending ??= { kind, text: "" };
    this.pending.text += text.slice(0, room);
    this.written[kind] += Math.min(text.length, room);

    if (
      this.pending.text.length >= FLUSH_CHARS ||
      Date.now() - this.lastFlush >= FLUSH_INTERVAL_MS
    ) {
      await this.flush();
    }
  }

  async flush(): Promise<void> {
    const pending = this.pending;
    this.pending = null;
    this.lastFlush = Date.now();
    if (pending?.text) await this.insert(pending.kind, pending.text);
  }

  private async insert(kind: EventKind, content: string) {
    try {
      await this.db
        .prepare(
          `INSERT INTO agent_events
             (run_id, agent, kind, content, created_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .bind(
          this.runId,
          this.agent,
          kind,
          redactSecrets(content),
          new Date().toISOString(),
        )
        .run();
    } catch (error) {
      console.warn("agent event write failed", error);
    }
  }
}

/** Records Workers AI spend so the UI can show a daily meter. */
export async function recordUsage(
  db: D1Database,
  runId: string,
  agent: string,
  model: string,
  neurons: number,
): Promise<void> {
  if (!(neurons > 0)) return;
  try {
    await db
      .prepare(
        `INSERT INTO ai_usage (run_id, agent, model, neurons, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(runId, agent, model, neurons, new Date().toISOString())
      .run();
  } catch (error) {
    console.warn("usage write failed", error);
  }
}
