import { describe, expect, it, vi } from "vitest";
import { RangeController } from "../../../apps/range/src/index.js";
import { PrecedentEvaluator } from "./index.js";
import type { GraphRepository } from "@precedent/graph";
import type { ActionProposal } from "@precedent/contracts";

function fixture() {
  const range = new RangeController();
  let history = true;
  let offline = false;
  let mismatch = false;
  const records: unknown[] = [];
  const graph = {
    currentContext: async () => {
      if (offline) throw new Error("graph offline");
      return range.snapshot();
    },
    affectedDependencies: async (target: string) =>
      mismatch
        ? []
        : range
            .snapshot()
            .workers.filter(
              (worker) => worker.active && worker.credentialId === target,
            )
            .map((worker) => ({
              ...worker,
              name: worker.id,
              critical: true,
              paths: [
                {
                  nodeIds: [worker.id, target],
                  relationshipIds: [`uses-${worker.id}`],
                },
              ],
            })),
    matchingPrecedents: async () => [],
    recoveryCandidates: async () =>
      history
        ? [{ id: "H72", evidenceId: "evidence-H72", eligible: true }]
        : [],
    applicablePolicies: async () => [
      { id: "continuity", version: 1, summary: "Preserve verified consumers" },
    ],
    evidenceLineage: async (ids: string[]) =>
      ids.map((id) => ({
        id,
        trusted: id !== "forged-copy",
        applicable: id !== "stale-runbook",
        paths: [],
      })),
    recordEvaluation: vi.fn(async (...record: unknown[]) => {
      records.push(structuredClone(record));
    }),
  };
  const evaluator = new PrecedentEvaluator(graph as unknown as GraphRepository);
  const proposal = (
    actionType: ActionProposal["actionType"] = "revoke_credential",
    targetId = "payments-key-v1",
    evidenceIds = ["evidence-H72"],
  ): ActionProposal => ({
    proposalId: crypto.randomUUID(),
    runId: "proof",
    actionType,
    targetId,
    args: {},
    evidenceIds,
    rationaleSummary: "Acceptance proof",
  });
  return {
    range,
    records,
    proposal,
    evaluate: (p = proposal()) => evaluator.evaluate(p, range.snapshot()),
    setHistory: (value: boolean) => (history = value),
    setOffline: () => (offline = true),
    setMismatch: () => (mismatch = true),
  };
}

describe("phase acceptance rules", () => {
  it("history outcome eligibility changes a production revision into escalation", async () => {
    const f = fixture();
    expect((await f.evaluate()).verdict).toBe("REVISE");
    f.setHistory(false);
    expect((await f.evaluate()).reasonCodes).toContain(
      "NO_ELIGIBLE_VERIFIED_RECOVERY_PRECEDENT",
    );
  });
  it("a hidden consumer changes the generated migration plan and supporting paths", async () => {
    const f = fixture();
    f.range.configure("hidden-consumer");
    const decision = await f.evaluate();
    expect(
      decision.suggestedSteps.some(
        (step) => step.targetId === "payment-worker-hidden",
      ),
    ).toBe(true);
    expect(
      decision.supportingPaths.some((path) =>
        path.nodeIds.includes("payment-worker-hidden"),
      ),
    ).toBe(true);
  });
  it("the same revocation is allowed in staging without active consumers", async () => {
    const f = fixture();
    f.range.configure("staging");
    expect((await f.evaluate()).verdict).toBe("ALLOW");
  });
  it("no gateway and failed standby cannot silently reuse a continuity plan", async () => {
    const a = fixture();
    a.range.configure("no-gateway");
    expect((await a.evaluate()).verdict).toBe("ESCALATE");
    const b = fixture();
    b.range.configure("failed-standby");
    expect((await b.evaluate()).verdict).toBe("ESCALATE");
  });
  it("missing, forged and expired evidence cannot authorize mutations", async () => {
    const f = fixture();
    for (const evidence of [[], ["forged-copy"], ["stale-runbook"]])
      expect(
        (
          await f.evaluate(
            f.proposal("quarantine_credential", "payments-key-v1", evidence),
          )
        ).verdict,
      ).toBe("DENY");
  });
  it("graph outages and conflicting dependency facts fail closed", async () => {
    const f = fixture();
    f.setMismatch();
    expect((await f.evaluate()).reasonCodes).toContain(
      "DEPENDENCY_GRAPH_CONFLICTS_WITH_RANGE",
    );
    f.setOffline();
    expect((await f.evaluate()).reasonCodes).toContain(
      "GRAPH_UNAVAILABLE_ACTION_HELD",
    );
  });
  it("quarantine lets the agent finish device isolation instead of revising forever", async () => {
    const f = fixture();
    const p = f.proposal("quarantine_credential", "payments-key-v1");
    f.range.mutate(p, p.proposalId);
    expect(
      (await f.evaluate(f.proposal("isolate_device", "compromised-laptop")))
        .verdict,
    ).toBe("ALLOW");
  });
  it("evaluation evidence is a snapshot independent of later range changes", async () => {
    const f = fixture();
    await f.evaluate();
    const prior = JSON.stringify(f.records[0]);
    f.range.configure("hidden-consumer");
    expect(JSON.stringify(f.records[0])).toBe(prior);
  });
});
