import { z } from "zod";

export const RunOriginSchema = z.enum([
  "LIVE_AGENT",
  "HISTORICAL_REPLAY",
  "COUNTERFACTUAL",
]);
export type RunOrigin = z.infer<typeof RunOriginSchema>;

export const ActionTypeSchema = z.enum([
  "isolate_device",
  "invalidate_session",
  "quarantine_credential",
  "create_credential",
  "deploy_credential",
  "verify_consumer",
  "switch_traffic",
  "revoke_credential",
  "disable_service",
]);
export type ActionType = z.infer<typeof ActionTypeSchema>;

export const ActionProposalSchema = z.object({
  proposalId: z.string().min(1),
  runId: z.string().min(1),
  actionType: ActionTypeSchema,
  targetId: z.string().min(1),
  args: z.record(z.string(), z.unknown()),
  evidenceIds: z.array(z.string().min(1)),
  rationaleSummary: z.string().min(1).max(1_500),
});
export type ActionProposal = z.infer<typeof ActionProposalSchema>;

export const SupportingPathSchema = z.object({
  nodeIds: z.array(z.string().min(1)).min(1),
  relationshipIds: z.array(z.string().min(1)),
});
export type SupportingPath = z.infer<typeof SupportingPathSchema>;

export const VerdictSchema = z.enum(["ALLOW", "REVISE", "DENY", "ESCALATE"]);
export type Verdict = z.infer<typeof VerdictSchema>;

export const EvaluationSchema = z.object({
  evaluationId: z.string().min(1),
  proposalId: z.string().min(1),
  verdict: VerdictSchema,
  reasonCodes: z.array(z.string().min(1)),
  policyIds: z.array(z.string().min(1)),
  precedentIds: z.array(z.string().min(1)),
  rejectedEvidenceIds: z.array(z.string().min(1)),
  supportingPaths: z.array(SupportingPathSchema),
  suggestedSteps: z.array(ActionProposalSchema),
  scenarioVersion: z.number().int().positive(),
  policyVersion: z.number().int().positive(),
  expiresAt: z.string().datetime({ offset: true }),
});
export type Evaluation = z.infer<typeof EvaluationSchema>;

export const EventTypeSchema = z.enum([
  "RUN_STARTED",
  "ACTION_PROPOSED",
  "EVALUATION_CREATED",
  "ACTION_DENIED",
  "ACTION_EXECUTION_INTENDED",
  "ACTION_EXECUTED",
  "ACTION_UNKNOWN",
  "PROBE_RECORDED",
  "EVIDENCE_REJECTED",
  "PRECEDENT_PROMOTED",
  "RANGE_RESET",
  "RUN_COMPLETED",
]);
export type EventType = z.infer<typeof EventTypeSchema>;

export const EventEnvelopeSchema = z.object({
  eventId: z.string().min(1),
  runId: z.string().min(1),
  sequence: z.number().int().positive(),
  timestamp: z.string().datetime({ offset: true }),
  type: EventTypeSchema,
  origin: RunOriginSchema,
  payload: z.record(z.string(), z.unknown()),
});
export type EventEnvelope = z.infer<typeof EventEnvelopeSchema>;

export const ActionAuthorizationSchema = z.object({
  authorizationId: z.string().min(1),
  evaluationId: z.string().min(1),
  proposalId: z.string().min(1),
  runId: z.string().min(1),
  actorId: z.string().min(1),
  toolCallId: z.string().min(1),
  actionType: ActionTypeSchema,
  targetId: z.string().min(1),
  argumentHash: z.string().regex(/^[a-f0-9]{64}$/),
  scenarioVersion: z.number().int().positive(),
  policyVersion: z.number().int().positive(),
  expiresAt: z.string().datetime({ offset: true }),
  consumedAt: z.string().datetime({ offset: true }).nullable(),
});
export type ActionAuthorization = z.infer<typeof ActionAuthorizationSchema>;

export const ExecutionIntentSchema = z.object({
  intentId: z.string().min(1),
  authorizationId: z.string().min(1),
  proposalId: z.string().min(1),
  runId: z.string().min(1),
  actionType: ActionTypeSchema,
  targetId: z.string().min(1),
  idempotencyKey: z.string().min(1),
  createdAt: z.string().datetime({ offset: true }),
});
export type ExecutionIntent = z.infer<typeof ExecutionIntentSchema>;

export const ExecutionStatusSchema = z.enum(["SUCCEEDED", "FAILED", "UNKNOWN"]);
export type ExecutionStatus = z.infer<typeof ExecutionStatusSchema>;

export const ExecutionReceiptSchema = z.object({
  receiptId: z.string().min(1),
  authorizationId: z.string().min(1),
  proposalId: z.string().min(1),
  runId: z.string().min(1),
  actionType: ActionTypeSchema,
  targetId: z.string().min(1),
  idempotencyKey: z.string().min(1),
  status: ExecutionStatusSchema,
  executedAt: z.string().datetime({ offset: true }),
  details: z.record(z.string(), z.unknown()),
});
export type ExecutionReceipt = z.infer<typeof ExecutionReceiptSchema>;

export const ProbeClassSchema = z.enum([
  "LEGITIMATE_PAYMENT",
  "ATTACKER",
  "LEDGER",
]);
export type ProbeClass = z.infer<typeof ProbeClassSchema>;

export const ProbeResultSchema = z.object({
  probeId: z.string().min(1),
  runId: z.string().min(1),
  probeClass: ProbeClassSchema,
  success: z.boolean(),
  observedAt: z.string().datetime({ offset: true }),
  details: z.record(z.string(), z.unknown()),
});
export type ProbeResult = z.infer<typeof ProbeResultSchema>;

export const BrokerExecutionRequestSchema = z.object({
  proposal: ActionProposalSchema,
  authorizationId: z.string().min(1),
  toolCallId: z.string().min(1),
});
export type BrokerExecutionRequest = z.infer<
  typeof BrokerExecutionRequestSchema
>;

export const RangeSnapshotSchema = z.object({
  scenarioVersion: z.number().int().positive(),
  policyVersion: z.number().int().positive(),
  compromisedDeviceIsolated: z.boolean(),
  hostileSessionsInvalidated: z.boolean(),
  credentialState: z.enum(["ACTIVE", "QUARANTINED", "REVOKED"]),
  activeCredentialId: z.string().min(1),
  trustedGateway: z.boolean().default(true),
  attackActive: z.boolean().default(true),
  environment: z.enum(["production", "staging"]).default("production"),
  trafficWorkerId: z.string().default("payment-worker-a"),
  ledgerEnabled: z.boolean().default(true),
  failedWorkerIds: z.array(z.string()).default([]),
  observedAt: z.string().optional(),
  workers: z.array(
    z.object({
      id: z.string().min(1),
      credentialId: z.string().min(1),
      active: z.boolean(),
      verified: z.boolean(),
    }),
  ),
});
export type RangeSnapshot = z.infer<typeof RangeSnapshotSchema>;

export const MutationOutcomeSchema = z.object({
  stateChanged: z.boolean(),
  scenarioVersion: z.number().int().positive(),
  details: z.record(z.string(), z.unknown()),
});
export type MutationOutcome = z.infer<typeof MutationOutcomeSchema>;
