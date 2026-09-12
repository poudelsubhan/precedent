import { describe, expect, it } from "vitest";
import type { ActionProposal } from "@precedent/contracts";
import { RangeController } from "./index.js";

const proposal = (
  actionType: ActionProposal["actionType"],
  targetId: string,
  args: Record<string, unknown> = {},
): ActionProposal => ({
  proposalId: `${actionType}-${targetId}`,
  runId: "range-test",
  actionType,
  targetId,
  args,
  evidenceIds: ["evidence-H72"],
  rationaleSummary: "Controlled range test action.",
});

const mutate = (range: RangeController, action: ActionProposal) =>
  range.mutate(action, action.proposalId);

describe("RangeController", () => {
  it("blocks immediate revocation while payment workers use the old credential", () => {
    const range = new RangeController();

    expect(() =>
      mutate(range, proposal("revoke_credential", "payments-key-v1")),
    ).toThrow("active payment consumer still depends on the old credential");
    expect(range.snapshot().credentialState).toBe("ACTIVE");
  });

  it("keeps counterfactual state isolated from the live range", () => {
    const liveRange = new RangeController();
    const counterfactualRange = new RangeController();

    counterfactualRange.counterfactualMutate(
      proposal("revoke_credential", "payments-key-v1"),
      "counterfactual-revoke",
    );

    expect(liveRange.snapshot().credentialState).toBe("ACTIVE");
    expect(counterfactualRange.snapshot().credentialState).toBe("REVOKED");
    expect(counterfactualRange.paymentProbe("comparison").success).toBe(false);
    expect(counterfactualRange.attackerProbe("comparison").success).toBe(false);
    expect(counterfactualRange.ledgerProbe("comparison").success).toBe(true);
  });

  it("returns the original outcome for an exact idempotent replay", () => {
    const range = new RangeController();
    const action = proposal("quarantine_credential", "payments-key-v1");

    const first = range.mutate(action, "quarantine-key");
    const replay = range.mutate(action, "quarantine-key");

    expect(replay).toEqual(first);
    expect(range.snapshot().scenarioVersion).toBe(first.scenarioVersion);
    expect(() =>
      range.mutate(
        { ...action, rationaleSummary: "A different request." },
        "quarantine-key",
      ),
    ).toThrow("idempotency key was reused for a different mutation");
  });

  it("advances the scenario version when resetting to the baseline", () => {
    const range = new RangeController();
    mutate(range, proposal("quarantine_credential", "payments-key-v1"));

    const reset = range.reset();

    expect(reset.scenarioVersion).toBe(3);
    expect(reset.credentialState).toBe("ACTIVE");
  });

  it("preserves payments while migrating, verifying, and revoking the old credential", () => {
    const range = new RangeController();

    mutate(range, proposal("quarantine_credential", "payments-key-v1"));
    mutate(range, proposal("invalidate_session", "hostile-session"));
    mutate(range, proposal("isolate_device", "compromised-laptop"));
    mutate(range, proposal("create_credential", "payments-key-v2"));
    mutate(
      range,
      proposal("deploy_credential", "payment-worker-b", {
        consumerId: "payment-worker-b",
        credentialId: "payments-key-v2",
      }),
    );
    mutate(
      range,
      proposal("verify_consumer", "payment-worker-b", {
        consumerId: "payment-worker-b",
      }),
    );
    mutate(
      range,
      proposal("switch_traffic", "payment-worker-b", {
        workerId: "payment-worker-b",
      }),
    );
    mutate(
      range,
      proposal("deploy_credential", "payment-worker-a", {
        consumerId: "payment-worker-a",
        credentialId: "payments-key-v2",
      }),
    );
    mutate(
      range,
      proposal("verify_consumer", "payment-worker-a", {
        consumerId: "payment-worker-a",
      }),
    );
    mutate(range, proposal("revoke_credential", "payments-key-v1"));

    expect(range.snapshot().credentialState).toBe("REVOKED");
    expect(range.paymentProbe("recovery").success).toBe(true);
    expect(range.attackerProbe("recovery").success).toBe(false);
    expect(range.ledgerProbe("recovery").success).toBe(true);
  });
});
