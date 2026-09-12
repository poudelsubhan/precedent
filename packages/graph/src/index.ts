import neo4j, { type Driver } from "neo4j-driver";
import type {
  ActionProposal,
  Evaluation,
  ExecutionReceipt,
  RangeSnapshot,
  SupportingPath,
} from "@precedent/contracts";

export type ActiveConsumer = {
  id: string;
  name: string;
  critical: boolean;
  active: boolean;
  credentialId: string;
  paths: SupportingPath[];
};

export type HistoricalCase = {
  id: string;
  actionType: string;
  outcome: "RECOVERED" | "OUTAGE" | "INSUFFICIENT" | "NO_IMPACT";
  verified: boolean;
  trustedGatewayRequired: boolean;
  offDeviceReplay: boolean;
  summary: string;
  paths: SupportingPath[];
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

export type Topology = {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
};

type GraphNode = { properties: Record<string, unknown> };
type GraphRelationship = { properties: Record<string, unknown> };

type GraphConfig = {
  uri: string;
  username: string;
  password: string;
  database: string;
};

const asString = (value: unknown): string => String(value ?? "");
const asBoolean = (value: unknown): boolean => value === true;

function nodeId(node: GraphNode): string {
  return asString(node.properties.id);
}

function relationshipId(relationship: GraphRelationship): string {
  return asString(relationship.properties.id);
}

function toPath(
  nodes: GraphNode[] | null,
  relationships: GraphRelationship[] | null,
): SupportingPath {
  return {
    nodeIds: (nodes ?? []).map(nodeId).filter(Boolean),
    relationshipIds: (relationships ?? []).map(relationshipId).filter(Boolean),
  };
}

export class GraphRepository {
  private constructor(
    private readonly driver: Driver,
    private readonly database: string,
  ) {}

  static fromEnvironment(
    env: NodeJS.ProcessEnv = process.env,
  ): GraphRepository {
    const config: GraphConfig = {
      uri: env.NEO4J_URI ?? "",
      username: env.NEO4J_USERNAME ?? "",
      password: env.NEO4J_PASSWORD ?? "",
      database: env.NEO4J_DATABASE ?? "neo4j",
    };

    if (!config.uri || !config.username || !config.password) {
      throw new Error("Neo4j configuration is incomplete.");
    }

    return new GraphRepository(
      neo4j.driver(
        config.uri,
        neo4j.auth.basic(config.username, config.password),
      ),
      config.database,
    );
  }

  async verifyConnectivity(): Promise<void> {
    await this.driver.verifyConnectivity();
  }

  async close(): Promise<void> {
    await this.driver.close();
  }

  async initialize(): Promise<void> {
    const session = this.driver.session({ database: this.database });
    try {
      await session.executeWrite((transaction) =>
        transaction.run(
          "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (node:Asset) REQUIRE node.id IS UNIQUE",
        ),
      );
      await session.executeWrite((transaction) =>
        transaction.run(
          "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (node:Incident) REQUIRE node.id IS UNIQUE",
        ),
      );
      await session.executeWrite((transaction) =>
        transaction.run(
          "CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (node:Evidence) REQUIRE node.id IS UNIQUE",
        ),
      );
      await session.executeWrite((transaction) =>
        transaction.run(
          "CREATE CONSTRAINT policy_id IF NOT EXISTS FOR (node:Policy) REQUIRE node.id IS UNIQUE",
        ),
      );
      await session.executeWrite((transaction) =>
        transaction.run(
          "CREATE CONSTRAINT evaluation_id IF NOT EXISTS FOR (node:Evaluation) REQUIRE node.id IS UNIQUE",
        ),
      );
      await session.executeWrite((transaction) =>
        transaction.run(
          "CREATE CONSTRAINT receipt_id IF NOT EXISTS FOR (node:ExecutionReceipt) REQUIRE node.id IS UNIQUE",
        ),
      );
    } finally {
      await session.close();
    }
  }

  async seed(): Promise<void> {
    const session = this.driver.session({ database: this.database });
    const now = new Date().toISOString();
    try {
      await session.executeWrite((transaction) =>
        transaction.run(
          `UNWIND $assets AS asset
           MERGE (node:Asset {id: asset.id})
           SET node += asset`,
          {
            assets: [
              {
                id: "checkout-api",
                name: "Checkout API",
                assetClass: "Service",
                critical: true,
                active: true,
                createdAt: now,
              },
              {
                id: "payment-worker-a",
                name: "Payment Worker A",
                assetClass: "Service",
                critical: true,
                active: true,
                verified: false,
                credentialId: "payments-key-v1",
                createdAt: now,
              },
              {
                id: "payment-worker-b",
                name: "Payment Worker B",
                assetClass: "Service",
                critical: true,
                active: true,
                verified: false,
                credentialId: "payments-key-v1",
                createdAt: now,
              },
              {
                id: "credential-gateway",
                name: "Trusted Credential Gateway",
                assetClass: "Gateway",
                critical: true,
                active: true,
                trusted: true,
                createdAt: now,
              },
              {
                id: "ledger-service",
                name: "Ledger Service",
                assetClass: "Service",
                critical: true,
                active: true,
                createdAt: now,
              },
              {
                id: "payments-key-v1",
                name: "payments-key-v1",
                assetClass: "Credential",
                critical: true,
                status: "ACTIVE",
                createdAt: now,
              },
              {
                id: "payments-key-v2",
                name: "payments-key-v2",
                assetClass: "Credential",
                critical: true,
                status: "INACTIVE",
                createdAt: now,
              },
              {
                id: "compromised-laptop",
                name: "Compromised Laptop",
                assetClass: "Device",
                critical: false,
                active: true,
                createdAt: now,
              },
              {
                id: "attacker-process",
                name: "Independent Attacker Process",
                assetClass: "Process",
                critical: false,
                active: true,
                createdAt: now,
              },
            ],
          },
        ),
      );
      await session.executeWrite((transaction) =>
        transaction.run(
          `UNWIND $relationships AS relationship
           MATCH (from:Asset {id: relationship.from})
           MATCH (to:Asset {id: relationship.to})
           MERGE (from)-[edge:REL {id: relationship.id}]->(to)
           SET edge.type = relationship.type`,
          {
            relationships: [
              {
                id: "dep-checkout-worker-a",
                from: "checkout-api",
                to: "payment-worker-a",
                type: "DEPENDS_ON",
              },
              {
                id: "dep-checkout-worker-b",
                from: "checkout-api",
                to: "payment-worker-b",
                type: "DEPENDS_ON",
              },
              {
                id: "dep-worker-a-ledger",
                from: "payment-worker-a",
                to: "ledger-service",
                type: "DEPENDS_ON",
              },
              {
                id: "dep-worker-b-ledger",
                from: "payment-worker-b",
                to: "ledger-service",
                type: "DEPENDS_ON",
              },
              {
                id: "uses-worker-a-key-v1",
                from: "payment-worker-a",
                to: "payments-key-v1",
                type: "USES_CREDENTIAL",
              },
              {
                id: "uses-worker-b-key-v1",
                from: "payment-worker-b",
                to: "payments-key-v1",
                type: "USES_CREDENTIAL",
              },
              {
                id: "gateway-protects-key-v1",
                from: "credential-gateway",
                to: "payments-key-v1",
                type: "AUTHENTICATES_AS",
              },
              {
                id: "attacker-uses-key-v1",
                from: "attacker-process",
                to: "payments-key-v1",
                type: "USES_CREDENTIAL",
              },
              {
                id: "laptop-uses-key-v1",
                from: "compromised-laptop",
                to: "payments-key-v1",
                type: "USES_CREDENTIAL",
              },
            ],
          },
        ),
      );
      await session.executeWrite((transaction) =>
        transaction.run(
          `UNWIND $policies AS policy
           MERGE (node:Policy {id: policy.id})
           SET node += policy`,
          {
            policies: [
              {
                id: "continuity-active-consumers-v1",
                version: 1,
                summary:
                  "Credential revocation requires every critical active consumer to migrate and verify unless an emergency containment policy applies.",
              },
              {
                id: "provenance-verified-evidence-v1",
                version: 1,
                summary:
                  "Only evidence with a trusted verification relationship may support a consequential action.",
              },
            ],
          },
        ),
      );
      await session.executeWrite((transaction) =>
        transaction.run(
          `UNWIND $cases AS incident
           MERGE (node:Incident {id: incident.id})
           SET node += incident
           MERGE (context:ContextSnapshot {id: incident.contextId})
           SET context.trustedGatewayRequired = incident.trustedGatewayRequired,
               context.offDeviceReplay = incident.offDeviceReplay,
               context.environment = incident.environment
           MERGE (action:Action {id: incident.actionId})
           SET action.actionType = incident.actionType
           MERGE (outcome:Outcome {id: incident.outcomeId})
           SET outcome.status = incident.outcome,
               outcome.verified = incident.verified,
               outcome.summary = incident.summary
           MERGE (node)-[:HAS_CONTEXT {id: incident.contextRelationshipId}]->(context)
           MERGE (node)-[:PROPOSES {id: incident.proposalRelationshipId}]->(action)
           MERGE (node)-[:RESULTED_IN {id: incident.outcomeRelationshipId}]->(outcome)`,
          {
            cases: [
              {
                id: "H41",
                contextId: "context-H41",
                actionId: "action-H41",
                outcomeId: "outcome-H41",
                contextRelationshipId: "has-context-H41",
                proposalRelationshipId: "proposes-H41",
                outcomeRelationshipId: "resulted-H41",
                actionType: "revoke_credential",
                outcome: "OUTAGE",
                verified: true,
                trustedGatewayRequired: false,
                offDeviceReplay: true,
                environment: "production",
                summary:
                  "Immediate revocation of a credential with active payment consumers caused payment failures.",
              },
              {
                id: "H72",
                contextId: "context-H72",
                actionId: "action-H72",
                outcomeId: "outcome-H72",
                contextRelationshipId: "has-context-H72",
                proposalRelationshipId: "proposes-H72",
                outcomeRelationshipId: "resulted-H72",
                actionType: "revoke_credential",
                outcome: "RECOVERED",
                verified: true,
                trustedGatewayRequired: true,
                offDeviceReplay: true,
                environment: "production",
                summary:
                  "Quarantine, migration, verification, and delayed revocation preserved payment continuity.",
              },
              {
                id: "H89",
                contextId: "context-H89",
                actionId: "action-H89",
                outcomeId: "outcome-H89",
                contextRelationshipId: "has-context-H89",
                proposalRelationshipId: "proposes-H89",
                outcomeRelationshipId: "resulted-H89",
                actionType: "isolate_device",
                outcome: "INSUFFICIENT",
                verified: true,
                trustedGatewayRequired: false,
                offDeviceReplay: true,
                environment: "production",
                summary:
                  "Device isolation did not stop a copied credential used from another process.",
              },
              {
                id: "H97",
                contextId: "context-H97",
                actionId: "action-H97",
                outcomeId: "outcome-H97",
                contextRelationshipId: "has-context-H97",
                proposalRelationshipId: "proposes-H97",
                outcomeRelationshipId: "resulted-H97",
                actionType: "revoke_credential",
                outcome: "NO_IMPACT",
                verified: true,
                trustedGatewayRequired: false,
                offDeviceReplay: false,
                environment: "staging",
                summary:
                  "Immediate revocation was safe only because no critical consumers were active.",
              },
            ],
          },
        ),
      );
      await session.executeWrite((transaction) =>
        transaction.run(
          `UNWIND $evidence AS evidence
           MERGE (node:Evidence {id: evidence.id})
           SET node.contentHash = evidence.contentHash,
               node.claimedApproval = evidence.claimedApproval,
               node.ingestedAt = $now
           MERGE (source:Source {id: evidence.sourceId})
           SET source.name = evidence.sourceName,
               source.authority = evidence.authority
           MERGE (node)-[:FROM_SOURCE {id: evidence.fromSourceId}]->(source)
           FOREACH (_ IN CASE WHEN evidence.verifiedBy IS NULL THEN [] ELSE [1] END |
             MERGE (verification:Verification {id: evidence.verifiedBy})
             SET verification.scope = "demo-environment"
             MERGE (node)-[:VERIFIED_BY {id: evidence.verifiedRelationshipId}]->(verification)
           )`,
          {
            now,
            evidence: [
              {
                id: "evidence-H41",
                sourceId: "incident-registry",
                sourceName: "Security Incident Registry",
                authority: "TRUSTED",
                contentHash: "h41-verified",
                claimedApproval: false,
                fromSourceId: "from-source-H41",
                verifiedBy: "verification-H41",
                verifiedRelationshipId: "verified-H41",
              },
              {
                id: "evidence-H72",
                sourceId: "incident-registry",
                sourceName: "Security Incident Registry",
                authority: "TRUSTED",
                contentHash: "h72-verified",
                claimedApproval: false,
                fromSourceId: "from-source-H72",
                verifiedBy: "verification-H72",
                verifiedRelationshipId: "verified-H72",
              },
              {
                id: "evidence-H89",
                sourceId: "incident-registry",
                sourceName: "Security Incident Registry",
                authority: "TRUSTED",
                contentHash: "h89-verified",
                claimedApproval: false,
                fromSourceId: "from-source-H89",
                verifiedBy: "verification-H89",
                verifiedRelationshipId: "verified-H89",
              },
              {
                id: "forged-runbook",
                sourceId: "attacker-mailbox",
                sourceName: "Untrusted Runbook Mailbox",
                authority: "UNTRUSTED",
                contentHash: "forged-ledger-disable",
                claimedApproval: true,
                fromSourceId: "from-source-forged",
                verifiedBy: null,
                verifiedRelationshipId: "",
              },
            ],
          },
        ),
      );
    } finally {
      await session.close();
    }
  }

  async syncRange(snapshot: RangeSnapshot): Promise<void> {
    const session = this.driver.session({ database: this.database });
    try {
      await session.executeWrite((transaction) =>
        transaction.run(
          `MATCH (credential:Asset {id: "payments-key-v1"})
           SET credential.status = $credentialState,
               credential.scenarioVersion = $scenarioVersion
           WITH credential
           UNWIND $workers AS worker
           MATCH (node:Asset {id: worker.id})
           SET node.active = worker.active,
               node.verified = worker.verified,
               node.credentialId = worker.credentialId,
               node.scenarioVersion = $scenarioVersion
           WITH worker
           MATCH (node:Asset {assetClass: "Service", id: worker.id})-[edge:REL {type: "USES_CREDENTIAL"}]->(:Asset {assetClass: "Credential"})
           DELETE edge
           WITH worker
           MATCH (node:Asset {id: worker.id})
           MATCH (credential:Asset {id: worker.credentialId})
           MERGE (node)-[edge:REL {id: "uses-" + worker.id + "-" + worker.credentialId}]->(credential)
           SET edge.type = "USES_CREDENTIAL"
           WITH $compromisedDeviceIsolated AS isolated, $hostileSessionsInvalidated AS invalidated
           MATCH (laptop:Asset {id: "compromised-laptop"})
           SET laptop.isolated = isolated
           WITH invalidated
           MATCH (attacker:Asset {id: "attacker-process"})
           SET attacker.sessionInvalidated = invalidated`,
          {
            ...snapshot,
            workers: snapshot.workers,
          },
        ),
      );
    } finally {
      await session.close();
    }
  }

  async topology(): Promise<Topology> {
    const session = this.driver.session({ database: this.database });
    try {
      const nodesResult = await session.executeRead((transaction) =>
        transaction.run("MATCH (asset:Asset) RETURN asset ORDER BY asset.id"),
      );
      const edgesResult = await session.executeRead((transaction) =>
        transaction.run(
          `MATCH (source:Asset)-[edge:REL]->(target:Asset)
           RETURN source.id AS sourceId, target.id AS targetId, edge.id AS id, edge.type AS type
           ORDER BY edge.id`,
        ),
      );
      return {
        nodes: nodesResult.records.map((record) => {
          const asset = record.get("asset") as GraphNode;
          return {
            id: nodeId(asset),
            name: asString(asset.properties.name),
            assetClass: asString(asset.properties.assetClass),
            critical: asBoolean(asset.properties.critical),
            active: asBoolean(asset.properties.active),
            verified: asBoolean(asset.properties.verified),
            status: asString(asset.properties.status),
            credentialId: asString(asset.properties.credentialId),
          };
        }),
        edges: edgesResult.records.map((record) => ({
          id: asString(record.get("id")),
          sourceId: asString(record.get("sourceId")),
          targetId: asString(record.get("targetId")),
          type: asString(record.get("type")),
        })),
      };
    } finally {
      await session.close();
    }
  }

  async historicalCases(): Promise<HistoricalCase[]> {
    const session = this.driver.session({ database: this.database });
    try {
      const result = await session.executeRead((transaction) =>
        transaction.run(
          `MATCH path=(incident:Incident)-[:HAS_CONTEXT]->(context:ContextSnapshot)
           MATCH (incident)-[:PROPOSES]->(action:Action)
           MATCH (incident)-[:RESULTED_IN]->(outcome:Outcome)
           RETURN incident, context, action, outcome, nodes(path) AS pathNodes, relationships(path) AS pathRelationships
           ORDER BY incident.id`,
        ),
      );
      return result.records.map((record) => {
        const incident = record.get("incident") as GraphNode;
        const context = record.get("context") as GraphNode;
        const action = record.get("action") as GraphNode;
        const outcome = record.get("outcome") as GraphNode;
        return {
          id: nodeId(incident),
          actionType: asString(action.properties.actionType),
          outcome: asString(
            outcome.properties.status,
          ) as HistoricalCase["outcome"],
          verified: asBoolean(outcome.properties.verified),
          trustedGatewayRequired: asBoolean(
            context.properties.trustedGatewayRequired,
          ),
          offDeviceReplay: asBoolean(context.properties.offDeviceReplay),
          summary: asString(outcome.properties.summary),
          paths: [
            toPath(
              record.get("pathNodes") as GraphNode[],
              record.get("pathRelationships") as GraphRelationship[],
            ),
          ],
        };
      });
    } finally {
      await session.close();
    }
  }

  async affectedDependencies(credentialId: string): Promise<ActiveConsumer[]> {
    const session = this.driver.session({ database: this.database });
    try {
      const result = await session.executeRead((transaction) =>
        transaction.run(
          `MATCH (consumer:Asset)-[uses:REL {type: "USES_CREDENTIAL"}]->(credential:Asset {id: $credentialId})
           WHERE consumer.assetClass = "Service" AND consumer.active = true
           OPTIONAL MATCH path=(checkout:Asset {id: "checkout-api"})-[:REL*1..4 {type: "DEPENDS_ON"}]->(consumer)
           RETURN consumer, collect(nodes(path)) AS pathNodes, collect(relationships(path)) AS pathRelationships`,
          { credentialId },
        ),
      );
      return result.records.map((record) => {
        const consumer = record.get("consumer") as GraphNode;
        const nodeGroups = record.get("pathNodes") as GraphNode[][];
        const relationshipGroups = record.get(
          "pathRelationships",
        ) as GraphRelationship[][];
        return {
          id: nodeId(consumer),
          name: asString(consumer.properties.name),
          critical: asBoolean(consumer.properties.critical),
          active: asBoolean(consumer.properties.active),
          credentialId,
          paths: nodeGroups
            .map((nodes, index) => toPath(nodes, relationshipGroups[index]))
            .filter((path) => path.nodeIds.length > 0),
        };
      });
    } finally {
      await session.close();
    }
  }

  async matchingPrecedents(
    proposal: ActionProposal,
  ): Promise<HistoricalCase[]> {
    const session = this.driver.session({ database: this.database });
    try {
      const result = await session.executeRead((transaction) =>
        transaction.run(
          `MATCH path=(incident:Incident)-[:HAS_CONTEXT]->(context:ContextSnapshot)
           MATCH (incident)-[:PROPOSES]->(action:Action {actionType: $actionType})
           MATCH (incident)-[:RESULTED_IN]->(outcome:Outcome)
           RETURN incident, context, outcome, nodes(path) AS pathNodes, relationships(path) AS pathRelationships`,
          { actionType: proposal.actionType },
        ),
      );
      return result.records.map((record) => {
        const incident = record.get("incident") as GraphNode;
        const context = record.get("context") as GraphNode;
        const outcome = record.get("outcome") as GraphNode;
        return {
          id: nodeId(incident),
          actionType: proposal.actionType,
          outcome: asString(
            outcome.properties.status,
          ) as HistoricalCase["outcome"],
          verified: asBoolean(outcome.properties.verified),
          trustedGatewayRequired: asBoolean(
            context.properties.trustedGatewayRequired,
          ),
          offDeviceReplay: asBoolean(context.properties.offDeviceReplay),
          summary: asString(outcome.properties.summary),
          paths: [
            toPath(
              record.get("pathNodes") as GraphNode[],
              record.get("pathRelationships") as GraphRelationship[],
            ),
          ],
        };
      });
    } finally {
      await session.close();
    }
  }

  async applicablePolicies(): Promise<Policy[]> {
    const session = this.driver.session({ database: this.database });
    try {
      const result = await session.executeRead((transaction) =>
        transaction.run(
          "MATCH (policy:Policy) RETURN policy ORDER BY policy.id",
        ),
      );
      return result.records.map((record) => {
        const policy = record.get("policy") as GraphNode;
        return {
          id: nodeId(policy),
          version: Number(policy.properties.version),
          summary: asString(policy.properties.summary),
        };
      });
    } finally {
      await session.close();
    }
  }

  async evidenceLineage(evidenceIds: string[]): Promise<EvidenceLineage[]> {
    if (evidenceIds.length === 0) {
      return [];
    }
    const session = this.driver.session({ database: this.database });
    try {
      const result = await session.executeRead((transaction) =>
        transaction.run(
          `UNWIND $evidenceIds AS evidenceId
           MATCH (evidence:Evidence {id: evidenceId})-[:FROM_SOURCE]->(source:Source)
           OPTIONAL MATCH (evidence)-[:VERIFIED_BY]->(verification:Verification)
           RETURN evidence, source, verification`,
          { evidenceIds },
        ),
      );
      return result.records.map((record) => {
        const evidence = record.get("evidence") as GraphNode;
        const source = record.get("source") as GraphNode;
        const verification = record.get("verification") as GraphNode | null;
        return {
          id: nodeId(evidence),
          sourceId: nodeId(source),
          sourceName: asString(source.properties.name),
          trusted:
            asString(source.properties.authority) === "TRUSTED" &&
            verification !== null,
          verifiedBy: verification ? nodeId(verification) : null,
          contentHash: asString(evidence.properties.contentHash),
        };
      });
    } finally {
      await session.close();
    }
  }

  async recordEvaluation(
    evaluation: Evaluation,
    proposal: ActionProposal,
  ): Promise<void> {
    const session = this.driver.session({ database: this.database });
    try {
      await session.executeWrite((transaction) =>
        transaction.run(
          `MERGE (node:Evaluation {id: $evaluationId})
           SET node.proposalId = $proposalId,
               node.verdict = $verdict,
               node.reasonCodes = $reasonCodes,
               node.policyIds = $policyIds,
               node.precedentIds = $precedentIds,
               node.rejectedEvidenceIds = $rejectedEvidenceIds,
               node.scenarioVersion = $scenarioVersion,
               node.policyVersion = $policyVersion,
               node.expiresAt = $expiresAt,
               node.runId = $runId,
               node.actionType = $actionType,
               node.targetId = $targetId,
               node.createdAt = $createdAt`,
          {
            ...evaluation,
            runId: proposal.runId,
            actionType: proposal.actionType,
            targetId: proposal.targetId,
            createdAt: new Date().toISOString(),
          },
        ),
      );
    } finally {
      await session.close();
    }
  }

  async recordReceipt(receipt: ExecutionReceipt): Promise<void> {
    const session = this.driver.session({ database: this.database });
    try {
      await session.executeWrite((transaction) =>
        transaction.run(
          `MERGE (node:ExecutionReceipt {id: $receiptId})
           SET node += $receipt`,
          { receiptId: receipt.receiptId, receipt },
        ),
      );
    } finally {
      await session.close();
    }
  }

  async promoteSuccessfulRecovery(
    runId: string,
  ): Promise<{ caseId: string; summary: string }> {
    const caseId = `recovery-${runId}`;
    const summary =
      "Measured demo-environment recovery quarantined, migrated, verified, and revoked the compromised payment credential while payment probes remained healthy.";
    const session = this.driver.session({ database: this.database });
    try {
      await session.executeWrite((transaction) =>
        transaction.run(
          `MERGE (incident:Incident {id: $caseId})
           SET incident.createdAt = $createdAt, incident.originRunId = $runId, incident.learned = true
           MERGE (context:ContextSnapshot {id: "context-" + $caseId})
           SET context.trustedGatewayRequired = true, context.offDeviceReplay = true, context.environment = "demo"
           MERGE (action:Action {id: "action-" + $caseId})
           SET action.actionType = "revoke_credential"
           MERGE (outcome:Outcome {id: "outcome-" + $caseId})
           SET outcome.status = "RECOVERED", outcome.verified = true, outcome.summary = $summary, outcome.verificationScope = "demo-environment"
           MERGE (incident)-[:HAS_CONTEXT {id: "has-context-" + $caseId}]->(context)
           MERGE (incident)-[:PROPOSES {id: "proposes-" + $caseId}]->(action)
           MERGE (incident)-[:RESULTED_IN {id: "resulted-" + $caseId}]->(outcome)`,
          { caseId, runId, summary, createdAt: new Date().toISOString() },
        ),
      );
      return { caseId, summary };
    } finally {
      await session.close();
    }
  }
}
