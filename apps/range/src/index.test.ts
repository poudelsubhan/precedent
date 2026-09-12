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

describe("RangeController", () => {
  it("blocks immediate revocation while payment workers use the old credential", () => {
    const range = new RangeController();

    expect(() =>
      range.mutate(proposal("revoke_credential", "payments-key-v1")),
    ).toThrow("active payment consumer still depends on the old credential");
    expect(range.snapshot().credentialState).toBe("ACTIVE");
  });

  it("models immediate revocation only in the isolated counterfactual range", () => {
    const range = new RangeController();

    range.counterfactualMutate(
      proposal("revoke_credential", "payments-key-v1"),
    );

    expect(range.snapshot().credentialState).toBe("REVOKED");
    expect(range.paymentProbe("comparison").success).toBe(false);
    expect(range.attackerProbe("comparison").success).toBe(false);
    expect(range.ledgerProbe("comparison").success).toBe(true);
  });

  it("preserves payments while migrating, verifying, and revoking the old credential", () => {
    const range = new RangeController();

    range.mutate(proposal("quarantine_credential", "payments-key-v1"));
    range.mutate(proposal("invalidate_session", "hostile-session"));
    range.mutate(proposal("isolate_device", "compromised-laptop"));
    range.mutate(proposal("create_credential", "payments-key-v2"));
    range.mutate(
      proposal("deploy_credential", "payment-worker-b", {
        consumerId: "payment-worker-b",
        credentialId: "payments-key-v2",
      }),
    );
    range.mutate(
      proposal("verify_consumer", "payment-worker-b", {
        consumerId: "payment-worker-b",
      }),
    );
    range.mutate(
      proposal("switch_traffic", "payment-worker-b", {
        workerId: "payment-worker-b",
      }),
    );
    range.mutate(
      proposal("deploy_credential", "payment-worker-a", {
        consumerId: "payment-worker-a",
        credentialId: "payments-key-v2",
      }),
    );
    range.mutate(
      proposal("verify_consumer", "payment-worker-a", {
        consumerId: "payment-worker-a",
      }),
    );
    range.mutate(proposal("revoke_credential", "payments-key-v1"));

    expect(range.snapshot().credentialState).toBe("REVOKED");
    expect(range.paymentProbe("recovery").success).toBe(true);
    expect(range.attackerProbe("recovery").success).toBe(false);
    expect(range.ledgerProbe("recovery").success).toBe(true);
  });
});
