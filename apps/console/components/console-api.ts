import { z } from "zod";
import {
  ActionProposalSchema,
  EvaluationSchema,
  RangeSnapshotSchema,
  SupportingPathSchema,
} from "@precedent/contracts";
import type {
  ActionProposal,
  Evaluation,
  RangeSnapshot,
} from "@precedent/contracts";
export type GraphView = "CURRENT" | "HISTORY" | "PROVENANCE";

export type TopologyNode = {
  id: string;
  name: string;
  assetClass: string;
  critical: boolean;
  active: boolean;
  verified: boolean;
  status: string;
  credentialId: string;
};

export type TopologyEdge = {
  id: string;
  sourceId: string;
  targetId: string;
  type: string;
};

export type Alert = {
  id: string;
  severity: string;
  summary: string;
  targetId: string;
  consumerIds?: string[];
};

export type HistoricalCase = {
  id: string;
  actionType: string;
  outcome: "RECOVERED" | "OUTAGE" | "INSUFFICIENT" | "NO_IMPACT";
  verified: boolean;
  trustedGatewayRequired: boolean;
  offDeviceReplay: boolean;
  summary: string;
  paths: Array<{ nodeIds: string[]; relationshipIds: string[] }>;
};

export type Policy = {
  id: string;
  version: number;
  summary: string;
};

export type EvidenceLineage = {
  id: string;
  sourceId: string;
  sourceName: string;
  trusted: boolean;
  verifiedBy: string | null;
  contentHash: string;
};

export type Decision = {
  proposal: ActionProposal;
  evaluation: Evaluation;
  trace: {
    queryId: string;
    graphVersion: { scenarioVersion: number; policyVersion: number };
    facts: {
      dependencies: Array<{
        id: string;
        name: string;
        critical: boolean;
        active: boolean;
      }>;
      precedents: HistoricalCase[];
      evidence: EvidenceLineage[];
    };
    policies: Policy[];
    supportingPaths: Array<{ nodeIds: string[]; relationshipIds: string[] }>;
  };
  receipts: Array<{ receiptId: string; status: string; executedAt: string }>;
};

export type Probe = {
  probeId: string;
  probeClass: "LEGITIMATE_PAYMENT" | "ATTACKER" | "LEDGER";
  success: boolean;
  observedAt: string;
};

export type Dashboard = {
  alerts: Alert[];
  snapshot: RangeSnapshot | null;
  topology: { nodes: TopologyNode[]; edges: TopologyEdge[] };
  cases: HistoricalCase[];
  policies: Policy[];
};

const policySchema = z.object({
  id: z.string(),
  version: z.number(),
  summary: z.string(),
});
const caseSchema = z.object({
  id: z.string(),
  actionType: z.string(),
  outcome: z.enum(["RECOVERED", "OUTAGE", "INSUFFICIENT", "NO_IMPACT"]),
  verified: z.boolean(),
  trustedGatewayRequired: z.boolean(),
  offDeviceReplay: z.boolean(),
  summary: z.string(),
  paths: z.array(SupportingPathSchema),
});
const lineageSchema = z.object({
  id: z.string(),
  sourceId: z.string(),
  sourceName: z.string(),
  trusted: z.boolean(),
  verifiedBy: z.string().nullable(),
  contentHash: z.string(),
});
const dependencySchema = z.object({
  id: z.string(),
  name: z.string(),
  critical: z.boolean(),
  active: z.boolean(),
});
const decisionSchema = z.object({
  proposal: ActionProposalSchema,
  evaluation: EvaluationSchema,
  trace: z.object({
    queryId: z.string(),
    graphVersion: z.object({
      scenarioVersion: z.number(),
      policyVersion: z.number(),
    }),
    facts: z.object({
      dependencies: z.array(dependencySchema),
      precedents: z.array(caseSchema),
      evidence: z.array(lineageSchema),
    }),
    policies: z.array(policySchema),
    supportingPaths: z.array(SupportingPathSchema),
  }),
  receipts: z.array(
    z.object({
      receiptId: z.string(),
      status: z.enum(["SUCCEEDED", "FAILED", "UNKNOWN"]),
      executedAt: z.string(),
    }),
  ),
});
const alertsSchema = z.object({
  alerts: z.array(
    z.object({
      id: z.string(),
      severity: z.string(),
      summary: z.string(),
      targetId: z.string(),
      consumerIds: z.array(z.string()).optional(),
    }),
  ),
  snapshot: RangeSnapshotSchema,
});
const topologySchema = z.object({
  snapshot: RangeSnapshotSchema,
  topology: z.object({
    nodes: z.array(
      dependencySchema.extend({
        assetClass: z.string(),
        verified: z.boolean(),
        status: z.string(),
        credentialId: z.string(),
      }),
    ),
    edges: z.array(
      z.object({
        id: z.string(),
        sourceId: z.string(),
        targetId: z.string(),
        type: z.string(),
      }),
    ),
  }),
});

export function decodeResponse(path: string, value: unknown): unknown {
  const schema = path.startsWith("/api/decisions/")
    ? decisionSchema
    : path === "/api/alerts"
      ? alertsSchema
      : path === "/api/topology"
        ? topologySchema
        : path === "/api/cases"
          ? z.object({ cases: z.array(caseSchema) })
          : path === "/api/policies"
            ? z.object({ policies: z.array(policySchema) })
            : z.object({ runId: z.string().min(1) }).passthrough();
  const decoded = schema.safeParse(value);
  if (!decoded.success)
    throw new Error(
      "The service returned incomplete or incompatible data. Refresh to reconnect.",
    );
  return decoded.data;
}

export async function requestJson<T>(
  baseUrl: string,
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    signal: init.signal ?? AbortSignal.timeout(30_000),
    headers: { "content-type": "application/json", ...init.headers },
  });
  if (!response.ok) {
    const message =
      response.status === 401 || response.status === 403
        ? "This operation was not authorized. Check the local service configuration."
        : response.status === 404
          ? "This decision is no longer available. Select another event."
          : response.status === 409
            ? "The state changed. Refresh before trying the action again."
            : response.status === 429
              ? "The service is busy. Try again shortly."
              : "The service could not complete the request. Check that the broker, runner, and graph are available.";
    throw new Error(message);
  }
  return decodeResponse(path, await response.json()) as T;
}

/** An async response may update the view only while its request is current. */
export class LatestRequest {
  private generation = 0;
  begin(): () => boolean {
    const generation = ++this.generation;
    return () => generation === this.generation;
  }
  cancel(): void {
    ++this.generation;
  }
}
