import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import type { EventEnvelope, EventType, RunOrigin } from "@precedent/contracts";

export type EventListener = (event: EventEnvelope) => void;

export class EventBus {
  private readonly events: EventEnvelope[] = [];
  private readonly listeners = new Set<EventListener>();
  private sequence = 0;

  constructor(private readonly journalPath?: string) {
    if (journalPath && existsSync(journalPath)) {
      for (const line of readFileSync(journalPath, "utf8")
        .split("\n")
        .filter(Boolean)) {
        const event = JSON.parse(line) as EventEnvelope;
        this.events.push(event);
        this.sequence = Math.max(this.sequence, event.sequence);
      }
    }
  }

  publish(
    runId: string,
    origin: RunOrigin,
    type: EventType,
    payload: Record<string, unknown>,
  ): EventEnvelope {
    const event: EventEnvelope = {
      eventId: randomUUID(),
      runId,
      sequence: ++this.sequence,
      timestamp: new Date().toISOString(),
      type,
      origin,
      payload,
    };

    if (this.journalPath) {
      mkdirSync(dirname(this.journalPath), { recursive: true });
      appendFileSync(this.journalPath, JSON.stringify(event) + "\n", {
        mode: 0o600,
      });
    }
    this.events.push(event);
    for (const listener of this.listeners) {
      listener(event);
    }
    return event;
  }

  replay(afterSequence = 0): EventEnvelope[] {
    return this.events.filter((event) => event.sequence > afterSequence);
  }

  subscribe(listener: EventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}

export const eventBus = new EventBus(
  fileURLToPath(new URL("../../../data/events.jsonl", import.meta.url)),
);
