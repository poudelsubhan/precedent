import { randomUUID } from "node:crypto";
import type {
  ActionProposal,
  Evaluation,
  RangeSnapshot,
  SupportingPath,
} from "@precedent/contracts";
import { GraphRepository, type HistoricalCase } from "@precedent/graph";

const authorizationLifetimeMs = 5 * 60 * 1_000;

export class PrecedentEvaluator {
  constructor(private readonly graph: GraphRepository) {}

  async evaluate(
    proposal: ActionProposal,
    snapshot: RangeSnapshot,
  ): Promise<Evaluation> {
    const [dependencies, precedents, policies, lineage] = await Promise.all([
      this.graph.affectedDependencies(proposal.targetId),
      this.graph.matchingPrecedents(proposal),
      this.graph.applicablePolicies(),
      this.graph.evidenceLineage(proposal.evidenceIds),
    ]);

    const rejectedEvidenceIds = [
      ...proposal.evidenceIds.filter(
        (id) => !lineage.some((item) => item.id === id),
      ),
      ...lineage.filter((item) => !item.trusted).map((item) => item.id),
    ];
    const policyIds = policies.map((policy) => policy.id);
    const currentPaths = dependencies.flatMap((dependency) => dependency.paths);
    const casePaths = precedents.flatMap((precedent) => precedent.paths);

    const evaluation = this.decide({
      proposal,
      snapshot,
      precedents,
      policyIds,
      rejectedEvidenceIds,
      supportingPaths: [...currentPaths, ...casePaths],
    });

    await this.graph.recordEvaluation(evaluation, proposal);
    return evaluation;
  }

  private decide(input: {
    proposal: ActionProposal;
    snapshot: RangeSnapshot;
    precedents: HistoricalCase[];
    policyIds: string[];
    rejectedEvidenceIds: string[];
    supportingPaths: SupportingPath[];
  }): Evaluation {
    const {
      proposal,
      snapshot,
      precedents,
      policyIds,
      rejectedEvidenceIds,
      supportingPaths,
    } = input;
    const base = {
      evaluationId: randomUUID(),
      proposalId: proposal.proposalId,
      policyIds,
      precedentIds: precedents.map((precedent) => precedent.id),
      rejectedEvidenceIds,
      supportingPaths,
      scenarioVersion: snapshot.scenarioVersion,
      policyVersion: snapshot.policyVersion,
      expiresAt: new Date(Date.now() + authorizationLifetimeMs).toISOString(),
    };

    if (rejectedEvidenceIds.length > 0) {
      return {
        ...base,
        verdict: "DENY",
        reasonCodes: ["UNTRUSTED_OR_MISSING_EVIDENCE"],
        suggestedSteps: [],
      };
    }

    if (proposal.actionType === "disable_service") {
      return {
        ...base,
        verdict: "DENY",
        reasonCodes: ["CRITICAL_SERVICE_PROTECTED"],
        suggestedSteps: [],
      };
    }

    if (proposal.actionType === "revoke_credential") {
      const activeOldKeyConsumers = snapshot.workers.filter(
        (worker) => worker.active && worker.credentialId === proposal.targetId,
      );
      if (activeOldKeyConsumers.length > 0) {
        return {
          ...base,
          verdict: "REVISE",
          reasonCodes: [
            "ACTIVE_CRITICAL_CONSUMERS",
            "CONTINUITY_POLICY_REQUIRES_MIGRATION",
          ],
          suggestedSteps: this.recoverySequence(proposal),
        };
      }
      return this.allow(base);
    }

    if (
      proposal.actionType === "isolate_device" &&
      !snapshot.compromisedDeviceIsolated
    ) {
      const offDeviceReplay = precedents.some(
        (precedent) =>
          precedent.id === "H89" &&
          precedent.verified &&
          precedent.offDeviceReplay &&
          precedent.outcome === "INSUFFICIENT",
      );
      if (offDeviceReplay) {
        return {
          ...base,
          verdict: "REVISE",
          reasonCodes: [
            "OFF_DEVICE_CREDENTIAL_REPLAY",
            "DEVICE_ISOLATION_INSUFFICIENT",
          ],
          suggestedSteps: [
            this.action(
              proposal.runId,
              "quarantine_credential",
              "payments-key-v1",
              {},
              "Restrict the compromised credential at the trusted gateway.",
            ),
            this.action(
              proposal.runId,
              "invalidate_session",
              "hostile-session",
              {},
              "Invalidate known hostile sessions.",
            ),
            proposal,
          ],
        };
      }
    }

    if (proposal.actionType === "quarantine_credential") {
      if (snapshot.credentialState === "ACTIVE") {
        return this.allow(base);
      }
      return this.deny(base, "CREDENTIAL_STATE_CHANGED");
    }

    if (proposal.actionType === "create_credential") {
      if (snapshot.activeCredentialId === "payments-key-v1") {
        return this.allow(base);
      }
      return this.deny(base, "REPLACEMENT_CREDENTIAL_ALREADY_EXISTS");
    }

    if (proposal.actionType === "deploy_credential") {
      const consumerId = this.stringArgument(proposal, "consumerId");
      const credentialId = this.stringArgument(proposal, "credentialId");
      const consumer = snapshot.workers.find(
        (worker) => worker.id === consumerId,
      );
      if (
        consumer &&
        credentialId === "payments-key-v2" &&
        snapshot.activeCredentialId === "payments-key-v2"
      ) {
        return this.allow(base);
      }
      return this.escalate(
        base,
        "REPLACEMENT_CREDENTIAL_OR_CONSUMER_UNAVAILABLE",
      );
    }

    if (proposal.actionType === "verify_consumer") {
      const consumerId = this.stringArgument(proposal, "consumerId");
      const consumer = snapshot.workers.find(
        (worker) => worker.id === consumerId,
      );
      if (consumer?.credentialId === "payments-key-v2") {
        return this.allow(base);
      }
      return this.escalate(base, "CONSUMER_NOT_MIGRATED");
    }

    if (proposal.actionType === "switch_traffic") {
      const workerId = this.stringArgument(proposal, "workerId");
      const consumer = snapshot.workers.find(
        (worker) => worker.id === workerId,
      );
      if (consumer?.verified && consumer.credentialId === "payments-key-v2") {
        return this.allow(base);
      }
      return this.escalate(base, "REPLACEMENT_CONSUMER_NOT_VERIFIED");
    }

    if (proposal.actionType === "invalidate_session") {
      if (!snapshot.hostileSessionsInvalidated) {
        return this.allow(base);
      }
      return this.deny(base, "SESSIONS_ALREADY_INVALIDATED");
    }

    if (proposal.actionType === "isolate_device") {
      if (!snapshot.compromisedDeviceIsolated) {
        return this.allow(base);
      }
      return this.deny(base, "DEVICE_ALREADY_ISOLATED");
    }

    return this.escalate(base, "NO_AUTHORIZED_RECOVERY_PATH");
  }

  private allow(
    base: Omit<Evaluation, "verdict" | "reasonCodes" | "suggestedSteps">,
  ): Evaluation {
    return {
      ...base,
      verdict: "ALLOW",
      reasonCodes: ["CURRENT_PRECONDITIONS_VERIFIED"],
      suggestedSteps: [],
    };
  }

  private deny(
    base: Omit<Evaluation, "verdict" | "reasonCodes" | "suggestedSteps">,
    reasonCode: string,
  ): Evaluation {
    return {
      ...base,
      verdict: "DENY",
      reasonCodes: [reasonCode],
      suggestedSteps: [],
    };
  }

  private escalate(
    base: Omit<Evaluation, "verdict" | "reasonCodes" | "suggestedSteps">,
    reasonCode: string,
  ): Evaluation {
    return {
      ...base,
      verdict: "ESCALATE",
      reasonCodes: [reasonCode],
      suggestedSteps: [],
    };
  }

  private recoverySequence(proposal: ActionProposal): ActionProposal[] {
    return [
      this.action(
        proposal.runId,
        "quarantine_credential",
        "payments-key-v1",
        {},
        "Restrict copied credential use while preserving authenticated payment workloads.",
      ),
      this.action(
        proposal.runId,
        "invalidate_session",
        "hostile-session",
        {},
        "Invalidate known hostile sessions.",
      ),
      this.action(
        proposal.runId,
        "isolate_device",
        "compromised-laptop",
        {},
        "Contain the originating device after off-device replay is addressed.",
      ),
      this.action(
        proposal.runId,
        "create_credential",
        "payments-key-v2",
        {},
        "Provision a replacement payment credential.",
      ),
      this.action(
        proposal.runId,
        "deploy_credential",
        "payment-worker-b",
        { consumerId: "payment-worker-b", credentialId: "payments-key-v2" },
        "Deploy the replacement credential to the standby worker.",
      ),
      this.action(
        proposal.runId,
        "verify_consumer",
        "payment-worker-b",
        { consumerId: "payment-worker-b" },
        "Verify payment processing through the replacement worker.",
      ),
      this.action(
        proposal.runId,
        "switch_traffic",
        "payment-worker-b",
        { workerId: "payment-worker-b" },
        "Route traffic to the verified replacement worker.",
      ),
      this.action(
        proposal.runId,
        "deploy_credential",
        "payment-worker-a",
        { consumerId: "payment-worker-a", credentialId: "payments-key-v2" },
        "Migrate the remaining payment worker.",
      ),
      this.action(
        proposal.runId,
        "verify_consumer",
        "payment-worker-a",
        { consumerId: "payment-worker-a" },
        "Verify the remaining migrated consumer.",
      ),
      this.action(
        proposal.runId,
        "revoke_credential",
        "payments-key-v1",
        {},
        "Revoke the old credential after every active consumer has migrated.",
      ),
    ];
  }

  private action(
    runId: string,
    actionType: ActionProposal["actionType"],
    targetId: string,
    args: Record<string, unknown>,
    rationaleSummary: string,
  ): ActionProposal {
    return {
      proposalId: randomUUID(),
      runId,
      actionType,
      targetId,
      args,
      evidenceIds: ["evidence-H72"],
      rationaleSummary,
    };
  }

  private stringArgument(
    proposal: ActionProposal,
    name: string,
  ): string | null {
    const argument = proposal.args[name];
    return typeof argument === "string" ? argument : null;
  }
}
