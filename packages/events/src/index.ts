import { randomUUID } from "node:crypto";
import type { EventEnvelope, EventType, RunOrigin } from "@precedent/contracts";

export type EventListener = (event: EventEnvelope) => void;

export class EventBus {
  private readonly events: EventEnvelope[] = [];
  private readonly listeners = new Set<EventListener>();
  private sequence = 0;

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

export const eventBus = new EventBus();
