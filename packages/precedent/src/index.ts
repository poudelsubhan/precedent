import { randomUUID } from "node:crypto";
import type {
  ActionProposal,
  Evaluation,
  RangeSnapshot,
} from "@precedent/contracts";
import {
  GraphRepository,
  queryDefinitions,
  type DecisionTrace,
  type HistoricalCase,
} from "@precedent/graph";

export class PrecedentEvaluator {
  constructor(private readonly graph: GraphRepository) {}

  async evaluate(
    proposal: ActionProposal,
    snapshot: RangeSnapshot,
  ): Promise<Evaluation> {
    const base: Evaluation = {
      evaluationId: randomUUID(),
      proposalId: proposal.proposalId,
      verdict: "ESCALATE",
      reasonCodes: [],
      policyIds: [],
      precedentIds: [],
      rejectedEvidenceIds: [],
      supportingPaths: [],
      suggestedSteps: [],
      scenarioVersion: snapshot.scenarioVersion,
      policyVersion: snapshot.policyVersion,
      expiresAt: new Date(Date.now() + 300000).toISOString(),
    };
    let facts;
    try {
      const [
        context,
        dependencies,
        precedents,
        policies,
        evidence,
        candidates,
      ] = await Promise.all([
        this.graph.currentContext(),
        this.graph.affectedDependencies(proposal.targetId),
        this.graph.matchingPrecedents(proposal),
        this.graph.applicablePolicies(),
        this.graph.evidenceLineage(proposal.evidenceIds),
        this.graph.recoveryCandidates(proposal, snapshot),
      ]);
      facts = {
        context,
        dependencies,
        precedents,
        policies,
        evidence,
        candidates,
      };
    } catch {
      return { ...base, reasonCodes: ["GRAPH_UNAVAILABLE_ACTION_HELD"] };
    }
    const {
      context,
      dependencies,
      precedents,
      policies,
      evidence,
      candidates,
    } = facts;
    const selected = candidates.find((item) => item.eligible);
    base.policyIds = policies.map((item) => item.id);
    base.precedentIds = [
      ...new Set([
        ...precedents.map((item) => item.id),
        ...(selected ? [selected.id] : []),
      ]),
    ];
    base.rejectedEvidenceIds = proposal.evidenceIds.filter(
      (id) =>
        !evidence.some(
          (item) => item.id === id && item.trusted && item.applicable !== false,
        ),
    );
    base.supportingPaths = [
      ...dependencies.flatMap((item) => item.paths),
      ...precedents.flatMap((item) => item.paths),
      ...evidence.flatMap((item) => item.paths ?? []),
    ];
    const decide = (
      verdict: Evaluation["verdict"],
      reasons: string[],
      suggestedSteps: ActionProposal[] = [],
    ) => Object.assign(base, { verdict, reasonCodes: reasons, suggestedSteps });
    const allow = () => decide("ALLOW", ["CURRENT_PRECONDITIONS_VERIFIED"]);
    const held = (reason: string) => decide("ESCALATE", [reason]);
    const active = snapshot.workers.filter((worker) => worker.active);
    const consumerId = proposal.args.consumerId;
    const consumer = active.find((worker) => worker.id === consumerId);
    const targetForAction: Partial<
      Record<ActionProposal["actionType"], string>
    > = {
      quarantine_credential: "payments-key-v1",
      revoke_credential: "payments-key-v1",
      create_credential: "payments-key-v2",
      isolate_device: "compromised-laptop",
      invalidate_session: "hostile-session",
      disable_service: "ledger-service",
    };
    if (proposal.evidenceIds.length === 0 || base.rejectedEvidenceIds.length) {
      decide("DENY", [
        evidence.some((item) => item.applicable === false)
          ? "STALE_OR_INAPPLICABLE_EVIDENCE"
          : "UNTRUSTED_OR_MISSING_EVIDENCE",
      ]);
    } else if (
      !context ||
      context.scenarioVersion !== snapshot.scenarioVersion ||
      context.policyVersion !== snapshot.policyVersion ||
      !Number.isFinite(Date.parse(context.observedAt ?? "")) ||
      Date.now() - Date.parse(context.observedAt ?? "") > 30000 ||
      policies.length === 0
    ) {
      held("CURRENT_GRAPH_CONTEXT_MISSING_STALE_OR_CONFLICTING");
    } else if (
      targetForAction[proposal.actionType] &&
      targetForAction[proposal.actionType] !== proposal.targetId
    ) {
      decide("DENY", ["ACTION_TARGET_MISMATCH"]);
    } else if (proposal.actionType === "disable_service") {
      decide("DENY", ["CRITICAL_SERVICE_PROTECTED"]);
    } else if (proposal.actionType === "revoke_credential") {
      const rangeConsumers = active.filter(
        (worker) => worker.credentialId === proposal.targetId,
      );
      const graphIds = dependencies
        .map((item) => item.id)
        .sort()
        .join(",");
      const rangeIds = rangeConsumers
        .map((item) => item.id)
        .sort()
        .join(",");
      if (graphIds !== rangeIds) held("DEPENDENCY_GRAPH_CONFLICTS_WITH_RANGE");
      else if (dependencies.length) {
        if (!snapshot.trustedGateway)
          held("NO_TRUSTED_GATEWAY_EMERGENCY_POLICY_REQUIRED");
        else if (!selected) held("NO_ELIGIBLE_VERIFIED_RECOVERY_PRECEDENT");
        else {
          const steps = this.recoverySequence(proposal, snapshot, selected);
          if (!steps.length) held("NO_HEALTHY_STANDBY_FOR_CONTINUOUS_RECOVERY");
          else
            decide(
              "REVISE",
              [
                "ACTIVE_CRITICAL_CONSUMERS",
                "CONTINUITY_POLICY_REQUIRES_MIGRATION",
              ],
              steps,
            );
        }
      } else if (active.some((worker) => !worker.verified))
        held("MIGRATED_CONSUMER_NOT_VERIFIED");
      else allow();
    } else if (proposal.actionType === "isolate_device") {
      if (snapshot.compromisedDeviceIsolated)
        decide("DENY", ["DEVICE_ALREADY_ISOLATED"]);
      else if (snapshot.attackActive && snapshot.credentialState === "ACTIVE") {
        if (!snapshot.trustedGateway || !selected)
          held("NO_AUTHORIZED_OFF_DEVICE_CONTAINMENT_PATH");
        else
          decide(
            "REVISE",
            ["OFF_DEVICE_CREDENTIAL_REPLAY", "DEVICE_ISOLATION_INSUFFICIENT"],
            this.recoverySequence(proposal, snapshot, selected).slice(0, 3),
          );
      } else allow();
    } else if (proposal.actionType === "quarantine_credential") {
      if (!snapshot.trustedGateway) held("TRUSTED_GATEWAY_UNAVAILABLE");
      else if (snapshot.credentialState !== "ACTIVE")
        decide("DENY", ["CREDENTIAL_STATE_CHANGED"]);
      else allow();
    } else if (proposal.actionType === "invalidate_session") {
      if (snapshot.hostileSessionsInvalidated)
        decide("DENY", ["SESSIONS_ALREADY_INVALIDATED"]);
      else allow();
    } else if (proposal.actionType === "create_credential") {
      if (snapshot.activeCredentialId === "payments-key-v2")
        decide("DENY", ["REPLACEMENT_CREDENTIAL_ALREADY_EXISTS"]);
      else allow();
    } else if (proposal.actionType === "deploy_credential") {
      if (
        !consumer ||
        consumer.id !== proposal.targetId ||
        proposal.args.credentialId !== "payments-key-v2" ||
        snapshot.activeCredentialId !== "payments-key-v2"
      )
        held("REPLACEMENT_CREDENTIAL_OR_CONSUMER_UNAVAILABLE");
      else if (snapshot.failedWorkerIds.includes(consumer.id))
        held("CONSUMER_UNHEALTHY");
      else allow();
    } else if (proposal.actionType === "verify_consumer") {
      if (
        !consumer ||
        consumer.id !== proposal.targetId ||
        consumer.credentialId !== "payments-key-v2" ||
        snapshot.failedWorkerIds.includes(consumer.id)
      )
        held("CONSUMER_NOT_MIGRATED_OR_UNHEALTHY");
      else allow();
    } else if (proposal.actionType === "switch_traffic") {
      const worker = active.find((item) => item.id === proposal.args.workerId);
      if (
        !worker ||
        worker.id !== proposal.targetId ||
        !worker.verified ||
        worker.credentialId !== "payments-key-v2" ||
        snapshot.failedWorkerIds.includes(worker.id)
      )
        held("REPLACEMENT_CONSUMER_NOT_VERIFIED");
      else allow();
    } else held("NO_AUTHORIZED_RECOVERY_PATH");
    const trace: DecisionTrace = {
      queryId: `decision-trace-${base.evaluationId}`,
      queries: Object.entries(queryDefinitions).map(([id, cypher]) => ({
        id,
        cypher,
        parameters: {
          credentialId: proposal.targetId,
          actionType: proposal.actionType,
        },
      })),
      graphVersion: {
        scenarioVersion: snapshot.scenarioVersion,
        policyVersion: snapshot.policyVersion,
      },
      snapshot,
      facts: { dependencies, precedents, evidence },
      policies,
      candidates,
      supportingPaths: base.supportingPaths,
      recordedAt: new Date().toISOString(),
    };
    await this.graph.recordEvaluation(base, proposal, trace);
    return base;
  }

  private recoverySequence(
    proposal: ActionProposal,
    snapshot: RangeSnapshot,
    precedent: HistoricalCase,
  ): ActionProposal[] {
    const active = snapshot.workers.filter((worker) => worker.active);
    const standby = active.find(
      (worker) =>
        worker.id !== snapshot.trafficWorkerId &&
        !snapshot.failedWorkerIds.includes(worker.id),
    );
    if (!standby) return [];
    const steps: ActionProposal[] = [];
    const add = (
      actionType: ActionProposal["actionType"],
      targetId: string,
      args: Record<string, unknown> = {},
    ) =>
      steps.push({
        proposalId: randomUUID(),
        runId: proposal.runId,
        actionType,
        targetId,
        args,
        evidenceIds: [precedent.evidenceId ?? `evidence-${precedent.id}`],
        rationaleSummary: `Apply verified ${precedent.id} recovery after checking current ${targetId} preconditions.`,
      });
    if (snapshot.credentialState === "ACTIVE")
      add("quarantine_credential", "payments-key-v1");
    if (!snapshot.hostileSessionsInvalidated)
      add("invalidate_session", "hostile-session");
    if (!snapshot.compromisedDeviceIsolated)
      add("isolate_device", "compromised-laptop");
    if (snapshot.activeCredentialId !== "payments-key-v2")
      add("create_credential", "payments-key-v2");
    for (const worker of [
      standby,
      ...active.filter((item) => item.id !== standby.id),
    ]) {
      if (snapshot.failedWorkerIds.includes(worker.id)) return [];
      if (worker.credentialId !== "payments-key-v2")
        add("deploy_credential", worker.id, {
          consumerId: worker.id,
          credentialId: "payments-key-v2",
        });
      if (!worker.verified || worker.credentialId !== "payments-key-v2")
        add("verify_consumer", worker.id, { consumerId: worker.id });
      if (worker.id === standby.id && snapshot.trafficWorkerId !== standby.id)
        add("switch_traffic", worker.id, { workerId: worker.id });
    }
    if (snapshot.credentialState !== "REVOKED")
      add("revoke_credential", "payments-key-v1");
    return steps;
  }
}
