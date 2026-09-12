import { describe, expect, it, vi } from "vitest";
import type { ActionProposal, RangeSnapshot } from "@precedent/contracts";
import type { GraphRepository, HistoricalCase } from "@precedent/graph";
import { PrecedentEvaluator } from "./index.js";

const snapshot: RangeSnapshot = {
  scenarioVersion: 1,
  policyVersion: 1,
  compromisedDeviceIsolated: false,
  hostileSessionsInvalidated: false,
  credentialState: "ACTIVE",
  activeCredentialId: "payments-key-v1",
  workers: [
    {
      id: "payment-worker-a",
      credentialId: "payments-key-v1",
      active: true,
      verified: false,
    },
    {
      id: "payment-worker-b",
      credentialId: "payments-key-v1",
      active: true,
      verified: false,
    },
  ],
};

const h89: HistoricalCase = {
  id: "H89",
  actionType: "isolate_device",
  outcome: "INSUFFICIENT",
  verified: true,
  trustedGatewayRequired: false,
  offDeviceReplay: true,
  summary: "Copied credential replay continued after device isolation.",
  paths: [],
};

const proposal = (
  actionType: ActionProposal["actionType"],
  targetId: string,
  evidenceIds = ["evidence-H72"],
): ActionProposal => ({
  proposalId: `${actionType}-${targetId}`,
  runId: "evaluator-test",
  actionType,
  targetId,
  args: {},
  evidenceIds,
  rationaleSummary: "Evaluator test action.",
});

function evaluator(precedents: HistoricalCase[] = []) {
  const graph = {
    affectedDependencies: vi.fn(async () => []),
    matchingPrecedents: vi.fn(async () => precedents),
    applicablePolicies: vi.fn(async () => [
      {
        id: "continuity-active-consumers-v1",
        version: 1,
        summary: "Migrate active consumers before revocation.",
      },
    ]),
    evidenceLineage: vi.fn(async (ids: string[]) =>
      ids.map((id) => ({
        id,
        sourceId: "incident-registry",
        sourceName: "Security Incident Registry",
        trusted: id !== "forged-runbook",
        verifiedBy: id === "forged-runbook" ? null : "verification-H72",
        contentHash: id,
      })),
    ),
    recordEvaluation: vi.fn(async () => undefined),
  };
  return new PrecedentEvaluator(graph as unknown as GraphRepository);
}

describe("PrecedentEvaluator", () => {
  it("rejects untrusted evidence before considering the requested action", async () => {
    const result = await evaluator().evaluate(
      proposal("disable_service", "ledger-service", ["forged-runbook"]),
      snapshot,
    );

    expect(result.verdict).toBe("DENY");
    expect(result.reasonCodes).toEqual(["UNTRUSTED_OR_MISSING_EVIDENCE"]);
    expect(result.rejectedEvidenceIds).toEqual(["forged-runbook"]);
  });

  it("requires staged recovery rather than revoking an in-use credential", async () => {
    const result = await evaluator().evaluate(
      proposal("revoke_credential", "payments-key-v1"),
      snapshot,
    );

    expect(result.verdict).toBe("REVISE");
    expect(result.reasonCodes).toContain("ACTIVE_CRITICAL_CONSUMERS");
    expect(result.suggestedSteps.map((step) => step.actionType)).toEqual([
      "quarantine_credential",
      "invalidate_session",
      "isolate_device",
      "create_credential",
      "deploy_credential",
      "verify_consumer",
      "switch_traffic",
      "deploy_credential",
      "verify_consumer",
      "revoke_credential",
    ]);
  });

  it("does not accept device-only containment after verified off-device replay", async () => {
    const result = await evaluator([h89]).evaluate(
      proposal("isolate_device", "compromised-laptop"),
      snapshot,
    );

    expect(result.verdict).toBe("REVISE");
    expect(result.reasonCodes).toContain("OFF_DEVICE_CREDENTIAL_REPLAY");
    expect(result.suggestedSteps.map((step) => step.actionType)).toEqual([
      "quarantine_credential",
      "invalidate_session",
      "isolate_device",
    ]);
  });
});
