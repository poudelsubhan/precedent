import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { EventBus } from "./index.js";
it("event restart preserves order, cursor and original run origin", () => {
  const file = join(
    mkdtempSync(join(tmpdir(), "precedent-events-")),
    "events.jsonl",
  );
  const first = new EventBus(file);
  const one = first.publish("run", "HISTORICAL_REPLAY", "RUN_STARTED", {});
  const restored = new EventBus(file);
  const two = restored.publish("run", "LIVE_AGENT", "RUN_COMPLETED", {});
  expect(restored.replay(one.sequence)).toEqual([two]);
  expect(restored.replay()[0]?.origin).toBe("HISTORICAL_REPLAY");
  expect(two.sequence).toBe(one.sequence + 1);
});
