import { createHash, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { config } from "dotenv";
import Fastify from "fastify";
import {
  ActionProposalSchema,
  BrokerExecutionRequestSchema,
  EventTypeSchema,
  type ActionAuthorization,
  type ActionProposal,
  type Evaluation,
  type ExecutionReceipt,
  type RangeSnapshot,
  type RunOrigin,
} from "@precedent/contracts";
import { eventBus } from "@precedent/events";
import { GraphRepository } from "@precedent/graph";
import { PrecedentEvaluator } from "@precedent/precedent";
import { createRangeClient } from "@precedent/range";

config({ path: fileURLToPath(new URL("../../../.env", import.meta.url)) });

const brokerToken =
  process.env.BROKER_RUNNER_TOKEN ?? "precedent-local-runner-token";
const rangeToken =
  process.env.RANGE_BROKER_TOKEN ?? "precedent-local-range-token";
const rangeUrl = process.env.RANGE_URL ?? "http://127.0.0.1:3002";
const consoleUrl = process.env.CONSOLE_URL ?? "http://localhost:3000";
const graph = GraphRepository.fromEnvironment();
const evaluator = new PrecedentEvaluator(graph);
const range = createRangeClient(rangeUrl, rangeToken);
const server = Fastify({ logger: true });

const authorizations = new Map<string, ActionAuthorization>();
const evaluations = new Map<
  string,
  { evaluation: Evaluation; proposal: ActionProposal }
>();
const receipts = new Map<string, ExecutionReceipt>();
const promotedRunIds = new Set<string>();
let mutationQueue = Promise.resolve();

const asOrigin = (value: unknown): RunOrigin =>
  value === "HISTORICAL_REPLAY" || value === "COUNTERFACTUAL"
    ? value
    : "LIVE_AGENT";

const canonicalize = (value: unknown): string => {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalize(nested)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
};

const argumentHash = (proposal: ActionProposal): string =>
  createHash("sha256")
    .update(
      canonicalize({
        actionType: proposal.actionType,
        targetId: proposal.targetId,
        args: proposal.args,
      }),
    )
    .digest("hex");

const runnerOnly = async (request: {
  headers: Record<string, string | string[] | undefined>;
}) => {
  if (request.headers["x-precedent-runner-token"] !== brokerToken) {
    throw Object.assign(
      new Error("Broker actions require a trusted runner identity."),
      {
        statusCode: 401,
      },
    );
  }
};

const currentRange = async (): Promise<RangeSnapshot> => {
  const snapshot = await range.snapshot();
  await graph.syncRange(snapshot);
  return snapshot;
};

const currentAlerts = async () => {
  const snapshot = await currentRange();
  const activeOldKeyConsumers = snapshot.workers.filter(
    (worker) => worker.active && worker.credentialId === "payments-key-v1",
  );
  return {
    snapshot,
    alerts: [
      {
        id: "compromised-payments-key",
        severity:
          snapshot.credentialState === "ACTIVE" ? "CRITICAL" : "CONTAINED",
        summary:
          snapshot.credentialState === "ACTIVE"
            ? "A copied payments credential is usable from an independent attacker process."
            : "The copied payments credential is no longer usable by the attacker process.",
        targetId: "payments-key-v1",
      },
      {
        id: "active-payment-consumers",
        severity: activeOldKeyConsumers.length > 0 ? "HIGH" : "RESOLVED",
        summary:
          activeOldKeyConsumers.length > 0
            ? `${activeOldKeyConsumers.length} active payment consumer(s) still depend on payments-key-v1.`
            : "No active payment consumer depends on payments-key-v1.",
        targetId: "payments-key-v1",
        consumerIds: activeOldKeyConsumers.map((worker) => worker.id),
      },
    ],
  };
};

const historicalH41Proposal = (runId: string): ActionProposal =>
  ActionProposalSchema.parse({
    proposalId: `historical-H41-${randomUUID()}`,
    runId,
    actionType: "revoke_credential",
    targetId: "payments-key-v1",
    args: {},
    evidenceIds: ["evidence-H41"],
    rationaleSummary:
      "Historical proposal replay: immediately revoke the compromised payment credential.",
  });

const decisionTrace = async (
  proposal: ActionProposal,
  evaluation: Evaluation,
) => {
  const [dependencies, precedents, policies, evidence] = await Promise.all([
    graph.affectedDependencies(proposal.targetId),
    graph.matchingPrecedents(proposal),
    graph.applicablePolicies(),
    graph.evidenceLineage(proposal.evidenceIds),
  ]);
  return {
    queryId: `decision-trace-${evaluation.evaluationId}`,
    graphVersion: {
      scenarioVersion: evaluation.scenarioVersion,
      policyVersion: evaluation.policyVersion,
    },
    facts: { dependencies, precedents, evidence },
    policies,
    supportingPaths: evaluation.supportingPaths,
  };
};

const verifyAndPromoteRecovery = async (
  runId: string,
  origin: RunOrigin,
  snapshot: RangeSnapshot,
): Promise<void> => {
  if (snapshot.credentialState !== "REVOKED" || promotedRunIds.has(runId)) {
    return;
  }
  const [payment, attacker, ledger] = await Promise.all([
    range.paymentProbe(runId),
    range.attackerProbe(runId),
    range.ledgerProbe(runId),
  ]);
  for (const probe of [payment, attacker, ledger]) {
    publish(runId, origin, "PROBE_RECORDED", { probe });
  }
  if (!payment.success || attacker.success || !ledger.success) {
    return;
  }
  const promoted = await graph.promoteSuccessfulRecovery(runId);
  promotedRunIds.add(runId);
  publish(runId, origin, "PRECEDENT_PROMOTED", {
    ...promoted,
    verificationScope: "demo-environment",
    probes: [payment, attacker, ledger],
  });
};

const publish = (
  runId: string,
  origin: RunOrigin,
  type: Parameters<typeof eventBus.publish>[2],
  payload: Record<string, unknown>,
): void => {
  eventBus.publish(runId, origin, type, payload);
};

const runMutation = async <T>(operation: () => Promise<T>): Promise<T> => {
  const next = mutationQueue.then(operation, operation);
  mutationQueue = next.then(
    () => undefined,
    () => undefined,
  );
  return next;
};

server.addHook("onRequest", async (_request, reply) => {
  reply.header("access-control-allow-origin", consoleUrl);
  reply.header(
    "access-control-allow-headers",
    "content-type,x-precedent-runner-token,last-event-id",
  );
  reply.header("access-control-allow-methods", "GET,POST,OPTIONS");
});

server.options("/*", async (_request, reply) => reply.status(204).send());

server.get("/health", async () => ({ status: "ok" }));

server.get("/events", async (request, reply) => {
  const afterSequence = Number(request.headers["last-event-id"] ?? 0);
  reply.hijack();
  reply.raw.writeHead(200, {
    "access-control-allow-origin": consoleUrl,
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "content-type": "text/event-stream",
  });
  for (const event of eventBus.replay(
    Number.isFinite(afterSequence) ? afterSequence : 0,
  )) {
    reply.raw.write(
      `id: ${event.sequence}\nevent: precedent\ndata: ${JSON.stringify(event)}\n\n`,
    );
  }
  const unsubscribe = eventBus.subscribe((event) => {
    reply.raw.write(
      `id: ${event.sequence}\nevent: precedent\ndata: ${JSON.stringify(event)}\n\n`,
    );
  });
  request.raw.on("close", unsubscribe);
});

server.get("/api/decisions/:evaluationId", async (request) => {
  const evaluationId = (request.params as { evaluationId: string })
    .evaluationId;
  const record = evaluations.get(evaluationId);
  if (!record) {
    throw Object.assign(new Error("Decision not found."), { statusCode: 404 });
  }
  return {
    proposal: record.proposal,
    evaluation: record.evaluation,
    trace: await decisionTrace(record.proposal, record.evaluation),
    receipts: [...receipts.values()].filter(
      (receipt) => receipt.proposalId === record.proposal.proposalId,
    ),
  };
});

server.get("/api/snapshot", async () => currentRange());
server.get("/api/alerts", async () => currentAlerts());
server.get("/api/topology", async () => {
  const snapshot = await currentRange();
  return { topology: await graph.topology(), snapshot };
});
server.get("/api/cases", async () => ({
  cases: await graph.historicalCases(),
}));
server.get("/api/policies", async () => ({
  policies: await graph.applicablePolicies(),
}));
server.get("/api/evidence/:evidenceId", async (request) => {
  const evidenceId = (request.params as { evidenceId: string }).evidenceId;
  const evidence = await graph.evidenceLineage([evidenceId]);
  if (evidence.length === 0) {
    throw Object.assign(new Error("Evidence not found."), { statusCode: 404 });
  }
  return { evidence: evidence[0] };
});

server.post("/api/probes", { preHandler: runnerOnly }, async (request) => {
  const body = request.body as {
    runId?: string;
    origin?: unknown;
    probeClass?: unknown;
  };
  if (!body.runId || typeof body.probeClass !== "string") {
    throw Object.assign(new Error("runId and probeClass are required."), {
      statusCode: 400,
    });
  }
  const origin = asOrigin(body.origin);
  const probe =
    body.probeClass === "LEGITIMATE_PAYMENT"
      ? await range.paymentProbe(body.runId)
      : body.probeClass === "ATTACKER"
        ? await range.attackerProbe(body.runId)
        : body.probeClass === "LEDGER"
          ? await range.ledgerProbe(body.runId)
          : null;
  if (!probe) {
    throw Object.assign(new Error("Unknown probe class."), { statusCode: 400 });
  }
  publish(body.runId, origin, "PROBE_RECORDED", { probe });
  return probe;
});

server.post("/api/events", { preHandler: runnerOnly }, async (request) => {
  const body = request.body as {
    runId?: string;
    origin?: unknown;
    type?: unknown;
    payload?: unknown;
  };
  if (!body.runId || !EventTypeSchema.safeParse(body.type).success) {
    throw Object.assign(
      new Error("runId and a valid event type are required."),
      {
        statusCode: 400,
      },
    );
  }
  publish(
    body.runId,
    asOrigin(body.origin),
    body.type as Parameters<typeof eventBus.publish>[2],
    body.payload && typeof body.payload === "object"
      ? (body.payload as Record<string, unknown>)
      : {},
  );
  return { accepted: true };
});

server.post("/api/replays/h41", { preHandler: runnerOnly }, async (request) => {
  const body = request.body as { runId?: unknown };
  if (typeof body.runId !== "string" || body.runId.length === 0) {
    throw Object.assign(new Error("runId is required."), { statusCode: 400 });
  }
  const proposal = historicalH41Proposal(body.runId);
  const evaluation = await evaluator.evaluate(proposal, await currentRange());
  evaluations.set(evaluation.evaluationId, { proposal, evaluation });
  publish(body.runId, "HISTORICAL_REPLAY", "ACTION_PROPOSED", {
    proposal,
    historicalCaseId: "H41",
  });
  publish(body.runId, "HISTORICAL_REPLAY", "EVALUATION_CREATED", {
    evaluation,
  });
  if (evaluation.verdict !== "ALLOW") {
    publish(body.runId, "HISTORICAL_REPLAY", "ACTION_DENIED", {
      proposalId: proposal.proposalId,
      evaluationId: evaluation.evaluationId,
      verdict: evaluation.verdict,
      reasonCodes: evaluation.reasonCodes,
      historicalCaseId: "H41",
    });
  }
  return {
    proposal,
    evaluation,
    trace: await decisionTrace(proposal, evaluation),
  };
});

server.post(
  "/api/evidence/forged-runbook",
  { preHandler: runnerOnly },
  async (request) => {
    const body = request.body as { runId?: unknown; origin?: unknown };
    if (typeof body.runId !== "string" || body.runId.length === 0) {
      throw Object.assign(new Error("runId is required."), { statusCode: 400 });
    }
    const origin = asOrigin(body.origin);
    const proposal = ActionProposalSchema.parse({
      proposalId: `forged-runbook-${randomUUID()}`,
      runId: body.runId,
      actionType: "disable_service",
      targetId: "ledger-service",
      args: {},
      evidenceIds: ["forged-runbook"],
      rationaleSummary:
        "Injected runbook claims approval to disable the ledger service.",
    });
    const evaluation = await evaluator.evaluate(proposal, await currentRange());
    evaluations.set(evaluation.evaluationId, { proposal, evaluation });
    const evidence = await graph.evidenceLineage(["forged-runbook"]);
    publish(body.runId, origin, "ACTION_PROPOSED", {
      proposal,
      injected: true,
    });
    publish(body.runId, origin, "EVALUATION_CREATED", { evaluation });
    publish(body.runId, origin, "EVIDENCE_REJECTED", {
      evidenceId: "forged-runbook",
      lineage: evidence[0] ?? null,
      reasonCodes: evaluation.reasonCodes,
    });
    publish(body.runId, origin, "ACTION_DENIED", {
      proposalId: proposal.proposalId,
      evaluationId: evaluation.evaluationId,
      verdict: evaluation.verdict,
      reasonCodes: evaluation.reasonCodes,
    });
    return {
      proposal,
      evaluation,
      trace: await decisionTrace(proposal, evaluation),
    };
  },
);

server.post(
  "/api/comparisons/h41",
  { preHandler: runnerOnly },
  async (request) => {
    const body = request.body as { runId?: unknown };
    if (typeof body.runId !== "string" || body.runId.length === 0) {
      throw Object.assign(new Error("runId is required."), { statusCode: 400 });
    }
    const proposal = historicalH41Proposal(body.runId);
    const before = await range.resetCounterfactual();
    publish(body.runId, "COUNTERFACTUAL", "ACTION_PROPOSED", {
      proposal,
      historicalCaseId: "H41",
      projected: true,
    });
    const outcome = await range.counterfactualMutate(proposal, randomUUID());
    const snapshot = await range.counterfactualSnapshot();
    const [payment, attacker, ledger] = await Promise.all([
      range.counterfactualPaymentProbe(body.runId),
      range.counterfactualAttackerProbe(body.runId),
      range.counterfactualLedgerProbe(body.runId),
    ]);
    publish(body.runId, "COUNTERFACTUAL", "ACTION_EXECUTED", {
      proposal,
      outcome,
      projected: true,
      bypassedContinuityGuard: true,
    });
    for (const probe of [payment, attacker, ledger]) {
      publish(body.runId, "COUNTERFACTUAL", "PROBE_RECORDED", {
        probe,
        projected: true,
      });
    }
    return {
      label: "Projected in model",
      before,
      proposal,
      outcome,
      snapshot,
      probes: [payment, attacker, ledger],
    };
  },
);

server.post("/api/evaluate", { preHandler: runnerOnly }, async (request) => {
  const body = request.body as {
    proposal?: unknown;
    toolCallId?: unknown;
    origin?: unknown;
  };
  const proposal = ActionProposalSchema.parse(body.proposal);
  if (typeof body.toolCallId !== "string" || body.toolCallId.length === 0) {
    throw Object.assign(new Error("toolCallId is required."), {
      statusCode: 400,
    });
  }
  const origin = asOrigin(body.origin);
  const snapshot = await currentRange();
  const evaluation = await evaluator.evaluate(proposal, snapshot);
  evaluations.set(evaluation.evaluationId, { evaluation, proposal });
  publish(proposal.runId, origin, "ACTION_PROPOSED", { proposal });
  publish(proposal.runId, origin, "EVALUATION_CREATED", { evaluation });
  if (evaluation.rejectedEvidenceIds.length > 0) {
    publish(proposal.runId, origin, "EVIDENCE_REJECTED", {
      evidenceIds: evaluation.rejectedEvidenceIds,
      reasonCodes: evaluation.reasonCodes,
    });
  }

  if (evaluation.verdict !== "ALLOW") {
    publish(proposal.runId, origin, "ACTION_DENIED", {
      proposalId: proposal.proposalId,
      evaluationId: evaluation.evaluationId,
      verdict: evaluation.verdict,
      reasonCodes: evaluation.reasonCodes,
    });
    return { evaluation, authorization: null };
  }

  const authorization: ActionAuthorization = {
    authorizationId: randomUUID(),
    evaluationId: evaluation.evaluationId,
    proposalId: proposal.proposalId,
    runId: proposal.runId,
    actorId: "qoder-runner",
    toolCallId: body.toolCallId,
    actionType: proposal.actionType,
    targetId: proposal.targetId,
    argumentHash: argumentHash(proposal),
    scenarioVersion: evaluation.scenarioVersion,
    policyVersion: evaluation.policyVersion,
    expiresAt: evaluation.expiresAt,
    consumedAt: null,
  };
  authorizations.set(authorization.authorizationId, authorization);
  return { evaluation, authorization };
});

server.post("/api/execute", { preHandler: runnerOnly }, async (request) => {
  const executionRequest = BrokerExecutionRequestSchema.parse(request.body);
  const origin = asOrigin((request.body as { origin?: unknown }).origin);
  return runMutation(async () => {
    const authorization = authorizations.get(executionRequest.authorizationId);
    if (!authorization) {
      throw Object.assign(new Error("Authorization does not exist."), {
        statusCode: 403,
      });
    }
    if (authorization.consumedAt) {
      throw Object.assign(
        new Error("Authorization has already been consumed."),
        {
          statusCode: 409,
        },
      );
    }
    if (new Date(authorization.expiresAt).getTime() <= Date.now()) {
      throw Object.assign(new Error("Authorization has expired."), {
        statusCode: 403,
      });
    }
    if (
      authorization.proposalId !== executionRequest.proposal.proposalId ||
      authorization.runId !== executionRequest.proposal.runId ||
      authorization.toolCallId !== executionRequest.toolCallId ||
      authorization.actionType !== executionRequest.proposal.actionType ||
      authorization.targetId !== executionRequest.proposal.targetId ||
      authorization.argumentHash !== argumentHash(executionRequest.proposal)
    ) {
      throw Object.assign(
        new Error("Authorization does not match the requested action."),
        {
          statusCode: 403,
        },
      );
    }

    const evaluationRecord = evaluations.get(authorization.evaluationId);
    if (!evaluationRecord || evaluationRecord.evaluation.verdict !== "ALLOW") {
      throw Object.assign(
        new Error("Execution requires an allowed evaluation."),
        {
          statusCode: 403,
        },
      );
    }

    const snapshot = await currentRange();
    if (
      snapshot.scenarioVersion !== authorization.scenarioVersion ||
      snapshot.policyVersion !== authorization.policyVersion
    ) {
      throw Object.assign(
        new Error("Range state changed; reevaluation is required."),
        {
          statusCode: 409,
        },
      );
    }

    const idempotencyKey = randomUUID();
    authorization.consumedAt = new Date().toISOString();
    publish(
      executionRequest.proposal.runId,
      origin,
      "ACTION_EXECUTION_INTENDED",
      {
        proposalId: executionRequest.proposal.proposalId,
        authorizationId: authorization.authorizationId,
        idempotencyKey,
      },
    );

    try {
      const outcome = await range.mutate(
        executionRequest.proposal,
        idempotencyKey,
      );
      const currentSnapshot = await range.snapshot();
      await graph.syncRange(currentSnapshot);
      const receipt: ExecutionReceipt = {
        receiptId: randomUUID(),
        authorizationId: authorization.authorizationId,
        proposalId: executionRequest.proposal.proposalId,
        runId: executionRequest.proposal.runId,
        actionType: executionRequest.proposal.actionType,
        targetId: executionRequest.proposal.targetId,
        idempotencyKey,
        status: "SUCCEEDED",
        executedAt: new Date().toISOString(),
        details: outcome.details,
      };
      receipts.set(receipt.receiptId, receipt);
      await graph.recordReceipt(receipt);
      publish(receipt.runId, origin, "ACTION_EXECUTED", { receipt });
      try {
        await verifyAndPromoteRecovery(receipt.runId, origin, currentSnapshot);
      } catch (error) {
        server.log.error(
          error,
          "Recovery verification could not promote a precedent.",
        );
      }
      return { receipt, snapshot: currentSnapshot };
    } catch (error) {
      const ambiguous =
        error instanceof TypeError ||
        (error as { name?: string }).name === "AbortError";
      const receipt: ExecutionReceipt = {
        receiptId: randomUUID(),
        authorizationId: authorization.authorizationId,
        proposalId: executionRequest.proposal.proposalId,
        runId: executionRequest.proposal.runId,
        actionType: executionRequest.proposal.actionType,
        targetId: executionRequest.proposal.targetId,
        idempotencyKey,
        status: ambiguous ? "UNKNOWN" : "FAILED",
        executedAt: new Date().toISOString(),
        details: {
          message: error instanceof Error ? error.message : "Execution failed.",
        },
      };
      receipts.set(receipt.receiptId, receipt);
      await graph.recordReceipt(receipt);
      publish(
        receipt.runId,
        origin,
        ambiguous ? "ACTION_UNKNOWN" : "ACTION_EXECUTED",
        {
          receipt,
        },
      );
      if (ambiguous) {
        return { receipt, snapshot: null };
      }
      throw error;
    }
  });
});

server.post("/api/range/reset", { preHandler: runnerOnly }, async (request) => {
  const body = request.body as { runId?: string; origin?: unknown };
  if (!body.runId) {
    throw Object.assign(new Error("runId is required."), { statusCode: 400 });
  }
  const snapshot = await range.reset();
  await graph.syncRange(snapshot);
  publish(body.runId, asOrigin(body.origin), "RANGE_RESET", {
    snapshot,
    memoryPreserved: true,
  });
  return snapshot;
});

server.setErrorHandler((error, _request, reply) => {
  const message =
    error instanceof Error ? error.message : "Broker request failed.";
  reply
    .status((error as { statusCode?: number }).statusCode ?? 500)
    .send({ message });
});

await graph.verifyConnectivity();
await graph.initialize();
await graph.seed();
const port = Number(process.env.BROKER_PORT ?? 3001);
await server.listen({ host: "127.0.0.1", port });
