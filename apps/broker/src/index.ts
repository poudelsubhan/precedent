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
  type ExecutionIntent,
  type ExecutionReceipt,
  type RangeSnapshot,
  type RunOrigin,
} from "@precedent/contracts";
import { eventBus } from "@precedent/events";
import { GraphRepository } from "@precedent/graph";
import { PrecedentEvaluator } from "@precedent/precedent";
import { createRangeClient } from "@precedent/range";

config({ path: fileURLToPath(new URL("../../../.env", import.meta.url)) });

const requiredEnvironment = (name: string): string => {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be configured.`);
  }
  return value;
};

const brokerToken = requiredEnvironment("BROKER_RUNNER_TOKEN");
const rangeToken = requiredEnvironment("RANGE_BROKER_TOKEN");
const rangeUrl = process.env.RANGE_URL ?? "http://127.0.0.1:3002";
const consoleUrl = process.env.CONSOLE_URL ?? "http://localhost:3000";
const graph = GraphRepository.fromEnvironment();
const evaluator = new PrecedentEvaluator(graph);
const range = createRangeClient(rangeUrl, rangeToken);
const server = Fastify({ logger: true });

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

const matchesAuthorization = (
  authorization: ActionAuthorization,
  authorizedProposal: ActionProposal,
  proposal: ActionProposal,
  toolCallId: string,
): boolean =>
  authorization.proposalId === proposal.proposalId &&
  authorization.runId === proposal.runId &&
  authorization.toolCallId === toolCallId &&
  authorization.actionType === proposal.actionType &&
  authorization.targetId === proposal.targetId &&
  authorization.argumentHash === argumentHash(proposal) &&
  canonicalize(authorizedProposal) === canonicalize(proposal);

const receiptFor = (
  intent: ExecutionIntent,
  status: ExecutionReceipt["status"],
  details: Record<string, unknown>,
  receiptId: string = randomUUID(),
): ExecutionReceipt => ({
  receiptId,
  authorizationId: intent.authorizationId,
  proposalId: intent.proposalId,
  runId: intent.runId,
  actionType: intent.actionType,
  targetId: intent.targetId,
  idempotencyKey: intent.idempotencyKey,
  status,
  executedAt: new Date().toISOString(),
  details,
});

const isAmbiguousTransportFailure = (error: unknown): boolean =>
  error instanceof TypeError ||
  ["AbortError", "TimeoutError"].includes(
    (error as { name?: string }).name ?? "",
  );

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
  const stored = await graph.findEvaluation(evaluation.evaluationId);
  if (stored?.trace) return stored.trace;
  return {
    queryId: `legacy-${evaluation.evaluationId}`,
    graphVersion: {
      scenarioVersion: evaluation.scenarioVersion,
      policyVersion: evaluation.policyVersion,
    },
    facts: { dependencies: [], precedents: [], evidence: [] },
    policies: [],
    supportingPaths: evaluation.supportingPaths,
    legacy: true,
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
  const promoted = await graph.promoteSuccessfulRecovery(runId, snapshot, [
    payment,
    attacker,
    ledger,
  ]);
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
  const record = await graph.findEvaluation(evaluationId);
  if (!record) {
    throw Object.assign(new Error("Decision not found."), { statusCode: 404 });
  }
  return {
    proposal: record.proposal,
    evaluation: record.evaluation,
    trace: await decisionTrace(record.proposal, record.evaluation),
    receipts: await graph.receiptsForProposal(record.proposal.proposalId),
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
  await graph.recordEvaluation(evaluation, proposal);
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
    await graph.recordEvaluation(evaluation, proposal);
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
    const before = await range.cloneCounterfactual(await currentRange());
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
      label: "Independent HTTP counterfactual from cloned live snapshot",
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
  await graph.recordEvaluation(evaluation, proposal);
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
  await graph.recordAuthorization(authorization, proposal);
  return { evaluation, authorization };
});

server.post("/api/execute", { preHandler: runnerOnly }, async (request) => {
  const executionRequest = BrokerExecutionRequestSchema.parse(request.body);
  const origin = asOrigin((request.body as { origin?: unknown }).origin);
  return runMutation(async () => {
    const authorizedAction = await graph.findAuthorizedAction(
      executionRequest.authorizationId,
    );
    if (!authorizedAction) {
      throw Object.assign(new Error("Authorization does not exist."), {
        statusCode: 403,
      });
    }
    if (authorizedAction.evaluation.verdict !== "ALLOW") {
      throw Object.assign(
        new Error("Execution requires an allowed evaluation."),
        {
          statusCode: 403,
        },
      );
    }
    if (
      !matchesAuthorization(
        authorizedAction.authorization,
        authorizedAction.proposal,
        executionRequest.proposal,
        executionRequest.toolCallId,
      )
    ) {
      throw Object.assign(
        new Error("Authorization does not match the requested action."),
        {
          statusCode: 403,
        },
      );
    }

    let intentRecord = await graph.findExecutionIntent(
      authorizedAction.authorization.authorizationId,
    );
    if (
      intentRecord?.receipt?.status === "SUCCEEDED" ||
      intentRecord?.receipt?.status === "FAILED"
    ) {
      return {
        receipt: intentRecord.receipt,
        snapshot:
          intentRecord.receipt.status === "SUCCEEDED"
            ? await currentRange()
            : null,
      };
    }

    if (intentRecord) {
      const saved = await range.mutationResult(
        authorizedAction.proposal,
        intentRecord.intent.idempotencyKey,
      );
      if (!saved)
        throw Object.assign(
          new Error(
            "Execution outcome remains unknown; automatic retry is held.",
          ),
          { statusCode: 409 },
        );
      const receipt = receiptFor(
        intentRecord.intent,
        "SUCCEEDED",
        { ...saved.details, reconciled: true },
        intentRecord.receipt?.receiptId,
      );
      await graph.recordReceipt(intentRecord.intent.intentId, receipt);
      const reconciledSnapshot = await currentRange();
      publish(receipt.runId, origin, "ACTION_EXECUTED", { receipt });
      await verifyAndPromoteRecovery(receipt.runId, origin, reconciledSnapshot);
      return { receipt, snapshot: reconciledSnapshot };
    }

    const snapshot = await currentRange();
    if (
      snapshot.scenarioVersion !==
        authorizedAction.authorization.scenarioVersion ||
      snapshot.policyVersion !== authorizedAction.authorization.policyVersion
    ) {
      throw Object.assign(
        new Error("Range state changed; reevaluation is required."),
        {
          statusCode: 409,
        },
      );
    }

    if (!intentRecord) {
      const currentEvaluation = await evaluator.evaluate(
        authorizedAction.proposal,
        snapshot,
      );
      if (currentEvaluation.verdict !== "ALLOW")
        throw Object.assign(
          new Error(
            "Current policy or evidence no longer authorizes this action.",
          ),
          { statusCode: 409 },
        );
      if (
        new Date(authorizedAction.authorization.expiresAt).getTime() <=
        Date.now()
      ) {
        throw Object.assign(new Error("Authorization has expired."), {
          statusCode: 403,
        });
      }
      const intent: ExecutionIntent = {
        intentId: authorizedAction.authorization.authorizationId,
        authorizationId: authorizedAction.authorization.authorizationId,
        proposalId: authorizedAction.proposal.proposalId,
        runId: authorizedAction.proposal.runId,
        actionType: authorizedAction.proposal.actionType,
        targetId: authorizedAction.proposal.targetId,
        idempotencyKey: randomUUID(),
        createdAt: new Date().toISOString(),
      };
      const claimedIntent = await graph.claimExecutionIntent(
        intent,
        new Date().toISOString(),
      );
      if (claimedIntent) {
        intentRecord = { intent: claimedIntent, receipt: null };
        if (claimedIntent.idempotencyKey === intent.idempotencyKey) {
          publish(
            authorizedAction.proposal.runId,
            origin,
            "ACTION_EXECUTION_INTENDED",
            {
              proposalId: authorizedAction.proposal.proposalId,
              authorizationId: authorizedAction.authorization.authorizationId,
              idempotencyKey: claimedIntent.idempotencyKey,
            },
          );
        }
      } else {
        intentRecord = await graph.findExecutionIntent(
          authorizedAction.authorization.authorizationId,
        );
        if (!intentRecord) {
          throw Object.assign(
            new Error("Authorization has already been consumed."),
            {
              statusCode: 409,
            },
          );
        }
      }
    }

    if (
      intentRecord.receipt?.status === "SUCCEEDED" ||
      intentRecord.receipt?.status === "FAILED"
    ) {
      return {
        receipt: intentRecord.receipt,
        snapshot:
          intentRecord.receipt.status === "SUCCEEDED"
            ? await currentRange()
            : null,
      };
    }

    const { intent, receipt: previousReceipt } = intentRecord;
    let mutationApplied = false;
    try {
      const outcome = await range.mutate(
        authorizedAction.proposal,
        intent.idempotencyKey,
      );
      mutationApplied = true;
      const currentSnapshot = await range.snapshot();
      await graph.syncRange(currentSnapshot);
      const receipt = receiptFor(
        intent,
        "SUCCEEDED",
        outcome.details,
        previousReceipt?.receiptId,
      );
      await graph.recordReceipt(intent.intentId, receipt);
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
      const ambiguous = mutationApplied || isAmbiguousTransportFailure(error);
      const receipt = receiptFor(
        intent,
        ambiguous ? "UNKNOWN" : "FAILED",
        {
          message: error instanceof Error ? error.message : "Execution failed.",
        },
        previousReceipt?.receiptId,
      );
      try {
        await graph.recordReceipt(intent.intentId, receipt);
      } catch (persistenceError) {
        server.log.error(
          persistenceError,
          "Execution receipt could not be persisted for recovery.",
        );
        throw error;
      }
      publish(
        receipt.runId,
        origin,
        ambiguous ? "ACTION_UNKNOWN" : "ACTION_EXECUTED",
        { receipt },
      );
      return { receipt, snapshot: null };
    }
  });
});

server.post("/api/range/reset", { preHandler: runnerOnly }, async (request) => {
  const body = request.body as { runId?: string; origin?: unknown };
  if (!body.runId) {
    throw Object.assign(new Error("runId is required."), { statusCode: 400 });
  }
  return runMutation(async () => {
    const snapshot = await range.reset();
    await graph.syncRange(snapshot);
    publish(body.runId as string, asOrigin(body.origin), "RANGE_RESET", {
      snapshot,
      memoryPreserved: true,
    });
    return snapshot;
  });
});

server.get("/api/response-context", async () => {
  const snapshot = await currentRange();
  const candidates = await graph.recoveryCandidates(
    historicalH41Proposal("context-read"),
    snapshot,
  );
  const evidence = await graph.evidenceLineage([
    "evidence-H41",
    "evidence-H72",
    "evidence-H89",
    "stale-runbook",
    "forged-copy",
    ...candidates.map((item) => item.evidenceId ?? `evidence-${item.id}`),
  ]);
  return {
    snapshot,
    policies: await graph.applicablePolicies(),
    candidates,
    evidence,
    staleRunbook: {
      evidenceId: "stale-runbook",
      status: "VERIFIED_BUT_EXPIRED",
      text: "Old procedure recommends immediate revocation. It predates current shared payment workers and is not applicable authority.",
    },
    objective:
      "Contain copied credential use, preserve legitimate payments when controls permit, verify payment/attacker/ledger outcomes. Cite an exact trusted and applicable evidence ID for every action.",
  };
});
server.get("/api/metrics", async () => range.metrics());
server.get("/api/events", async (request) => ({
  events: eventBus.replay(
    Number((request.query as { after?: string }).after ?? 0),
  ),
}));
server.get("/api/runs/:runId/report", async (request) => {
  const runId = (request.params as { runId: string }).runId;
  const events = eventBus.replay().filter((event) => event.runId === runId);
  const ids = [
    ...new Set(
      events
        .map(
          (event) =>
            (event.payload.evaluation as Evaluation | undefined)?.evaluationId,
        )
        .filter((id): id is string => Boolean(id)),
    ),
  ];
  const decisions = await Promise.all(
    ids.map(async (id) => {
      const record = await graph.findEvaluation(id);
      return record
        ? {
            ...record,
            receipts: await graph.receiptsForProposal(
              record.proposal.proposalId,
            ),
          }
        : null;
    }),
  );
  return {
    runId,
    exportedAt: new Date().toISOString(),
    events,
    decisions,
    metrics: await range.metrics(),
    learnedCases: events
      .filter((event) => event.type === "PRECEDENT_PROMOTED")
      .map((event) => event.payload.caseId),
  };
});
server.post(
  "/api/range/configure",
  { preHandler: runnerOnly },
  async (request) =>
    runMutation(async () => {
      const body = request.body as {
        variant: string;
        runId: string;
        fullReset?: boolean;
      };
      if (body.fullReset) {
        await graph.resetFixtureMemory();
        promotedRunIds.clear();
      }
      const snapshot = await range.configure(body.variant);
      await graph.syncRange(snapshot);
      publish(body.runId, "LIVE_AGENT", "RANGE_RESET", {
        snapshot,
        memoryPreserved: !body.fullReset,
        variant: body.variant,
      });
      return snapshot;
    }),
);
server.post(
  "/api/proofs/history",
  { preHandler: runnerOnly },
  async (request) => {
    const body = request.body as {
      caseId: string;
      verified: boolean;
      outcome: string;
    };
    await graph.setHistoricalOutcome(body.caseId, body.verified, body.outcome);
    return { updated: true };
  },
);

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
await graph.initializeExperience();
const port = Number(process.env.BROKER_PORT ?? 3001);
await server.listen({ host: "127.0.0.1", port });
