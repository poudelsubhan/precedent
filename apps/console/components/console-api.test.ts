import { describe, expect, it } from "vitest";
import { LatestRequest, decodeResponse } from "./console-api";
import { EvaluationSchema, EventEnvelopeSchema } from "@precedent/contracts";

describe("console request ownership", () => {
  it("a slow older selection cannot overwrite the newer decision", async () => {
    const requests = new LatestRequest();
    let resolveA!: (value: string) => void;
    const responseA = new Promise<string>((resolve) => {
      resolveA = resolve;
    });
    let selected = "";
    const currentA = requests.begin();
    const pendingA = responseA.then((value) => {
      if (currentA()) selected = value;
    });
    const currentB = requests.begin();
    if (currentB()) selected = "decision B";
    resolveA("decision A");
    await pendingA;
    expect(selected).toBe("decision B");
  });
  it("reset or unmount prevents outstanding responses from updating the view", () => {
    const requests = new LatestRequest();
    const current = requests.begin();
    requests.cancel();
    expect(current()).toBe(false);
    expect(requests.begin()()).toBe(true);
  });
  it("rejects malformed evaluation and event payloads before displaying them", () => {
    expect(
      EvaluationSchema.safeParse({ evaluationId: "looks-valid" }).success,
    ).toBe(false);
    expect(
      EventEnvelopeSchema.safeParse({ origin: "LIVE_AGENT", sequence: -1 })
        .success,
    ).toBe(false);
  });
});

it("the adapter rejects incomplete decision facts and accepts empty case collections", () => {
  expect(() =>
    decodeResponse("/api/decisions/test", {
      evaluation: { evaluationId: "test" },
    }),
  ).toThrow("incomplete or incompatible");
  expect(decodeResponse("/api/cases", { cases: [] })).toEqual({ cases: [] });
});
