"use client";

import {
  Background,
  Controls,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import { useCallback, useEffect, useMemo, useState } from "react";

const brokerUrl = process.env.NEXT_PUBLIC_BROKER_URL ?? "http://localhost:3001";
const runnerUrl = process.env.NEXT_PUBLIC_RUNNER_URL ?? "http://localhost:3003";

type RunOrigin = "LIVE_AGENT" | "HISTORICAL_REPLAY" | "COUNTERFACTUAL";
type GraphView = "CURRENT" | "HISTORY" | "PROVENANCE";

type RangeSnapshot = {
  scenarioVersion: number;
  policyVersion: number;
  compromisedDeviceIsolated: boolean;
  hostileSessionsInvalidated: boolean;
  credentialState: "ACTIVE" | "QUARANTINED" | "REVOKED";
  activeCredentialId: string;
  workers: Array<{
    id: string;
    credentialId: string;
    active: boolean;
    verified: boolean;
  }>;
};

type TopologyNode = {
  id: string;
  name: string;
  assetClass: string;
  critical: boolean;
  active: boolean;
  verified: boolean;
  status: string;
  credentialId: string;
};

type TopologyEdge = {
  id: string;
  sourceId: string;
  targetId: string;
  type: string;
};

type Alert = {
  id: string;
  severity: string;
  summary: string;
  targetId: string;
  consumerIds?: string[];
};

type HistoricalCase = {
  id: string;
  actionType: string;
  outcome: "RECOVERED" | "OUTAGE" | "INSUFFICIENT" | "NO_IMPACT";
  verified: boolean;
  trustedGatewayRequired: boolean;
  offDeviceReplay: boolean;
  summary: string;
  paths: Array<{ nodeIds: string[]; relationshipIds: string[] }>;
};

type Policy = {
  id: string;
  version: number;
  summary: string;
};

type EvidenceLineage = {
  id: string;
  sourceId: string;
  sourceName: string;
  trusted: boolean;
  verifiedBy: string | null;
  contentHash: string;
};

type ActionProposal = {
  proposalId: string;
  runId: string;
  actionType: string;
  targetId: string;
  args: Record<string, unknown>;
  evidenceIds: string[];
  rationaleSummary: string;
};

type Evaluation = {
  evaluationId: string;
  proposalId: string;
  verdict: "ALLOW" | "REVISE" | "DENY" | "ESCALATE";
  reasonCodes: string[];
  policyIds: string[];
  precedentIds: string[];
  rejectedEvidenceIds: string[];
  supportingPaths: Array<{ nodeIds: string[]; relationshipIds: string[] }>;
  suggestedSteps: ActionProposal[];
  scenarioVersion: number;
  policyVersion: number;
  expiresAt: string;
};

type Decision = {
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

type EventEnvelope = {
  eventId: string;
  runId: string;
  sequence: number;
  timestamp: string;
  type: string;
  origin: RunOrigin;
  payload: Record<string, unknown>;
};

type Probe = {
  probeId: string;
  probeClass: "LEGITIMATE_PAYMENT" | "ATTACKER" | "LEDGER";
  success: boolean;
  observedAt: string;
};

type Dashboard = {
  alerts: Alert[];
  snapshot: RangeSnapshot | null;
  topology: { nodes: TopologyNode[]; edges: TopologyEdge[] };
  cases: HistoricalCase[];
  policies: Policy[];
};

const initialDashboard: Dashboard = {
  alerts: [],
  snapshot: null,
  topology: { nodes: [], edges: [] },
  cases: [],
  policies: [],
};

const positions: Record<string, { x: number; y: number }> = {
  "compromised-laptop": { x: 30, y: 60 },
  "attacker-process": { x: 30, y: 250 },
  "payments-key-v1": { x: 300, y: 155 },
  "credential-gateway": { x: 300, y: 350 },
  "payment-worker-a": { x: 600, y: 70 },
  "payment-worker-b": { x: 600, y: 265 },
  "checkout-api": { x: 875, y: 70 },
  "ledger-service": { x: 875, y: 290 },
  "payments-key-v2": { x: 585, y: 455 },
};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : {};
}

function payloadEvaluation(event: EventEnvelope): Evaluation | null {
  const evaluation = asRecord(event.payload.evaluation);
  return typeof evaluation.evaluationId === "string"
    ? (evaluation as unknown as Evaluation)
    : null;
}

function evaluationIdForEvent(event: EventEnvelope): string | null {
  const evaluation = payloadEvaluation(event);
  if (evaluation) {
    return evaluation.evaluationId;
  }
  return typeof event.payload.evaluationId === "string"
    ? event.payload.evaluationId
    : null;
}

function probeForEvent(event: EventEnvelope): Probe | null {
  const probe = asRecord(event.payload.probe);
  return typeof probe.probeId === "string" ? (probe as unknown as Probe) : null;
}

async function requestJson<T>(
  baseUrl: string,
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as {
      message?: string;
    };
    throw new Error(body.message ?? `Request failed with ${response.status}.`);
  }
  return (await response.json()) as T;
}

function severityClass(severity: string): string {
  if (severity === "CRITICAL" || severity === "HIGH") {
    return "danger";
  }
  if (severity === "CONTAINED" || severity === "RESOLVED") {
    return "safe";
  }
  return "warning";
}

function verdictClass(verdict: Evaluation["verdict"]): string {
  if (verdict === "ALLOW") {
    return "safe";
  }
  if (verdict === "REVISE") {
    return "warning";
  }
  return "danger";
}

function nodeStyle(color: string, selected: boolean): React.CSSProperties {
  return {
    background: selected ? `${color}2b` : "#0d1725",
    border: `1px solid ${selected ? color : "#29405a"}`,
    borderRadius: 8,
    boxShadow: selected ? `0 0 0 1px ${color}55, 0 0 24px ${color}33` : "none",
    color: "#dce9f6",
    fontSize: 11,
    fontWeight: 650,
    padding: "9px 12px",
    width: 158,
    textAlign: "center",
  };
}

function eventSummary(event: EventEnvelope): string {
  const evaluation = payloadEvaluation(event);
  if (evaluation) {
    return `${evaluation.verdict} · ${evaluation.reasonCodes.join(", ")}`;
  }
  const proposal = asRecord(event.payload.proposal);
  if (typeof proposal.actionType === "string") {
    return `${proposal.actionType} → ${String(proposal.targetId ?? "")}`;
  }
  const probe = probeForEvent(event);
  if (probe) {
    return `${probe.probeClass.replaceAll("_", " ")} ${probe.success ? "observed success" : "observed failure"}`;
  }
  if (typeof event.payload.summary === "string") {
    return event.payload.summary;
  }
  if (Array.isArray(event.payload.reasonCodes)) {
    return (event.payload.reasonCodes as string[]).join(", ");
  }
  return event.type.replaceAll("_", " ");
}

function latestProbe(
  events: EventEnvelope[],
  probeClass: Probe["probeClass"],
): Probe | null {
  for (const event of events) {
    const probe = probeForEvent(event);
    if (probe?.probeClass === probeClass) {
      return probe;
    }
  }
  return null;
}

export function IncidentConsole() {
  const [dashboard, setDashboard] = useState<Dashboard>(initialDashboard);
  const [events, setEvents] = useState<EventEnvelope[]>([]);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [selectedEvaluationId, setSelectedEvaluationId] = useState<
    string | null
  >(null);
  const [currentRunId, setCurrentRunId] = useState<string | null>(null);
  const [graphView, setGraphView] = useState<GraphView>("CURRENT");
  const [showWhy, setShowWhy] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = useCallback(async () => {
    try {
      const [alerts, topology, cases, policies] = await Promise.all([
        requestJson<{ alerts: Alert[]; snapshot: RangeSnapshot }>(
          brokerUrl,
          "/api/alerts",
        ),
        requestJson<{
          topology: Dashboard["topology"];
          snapshot: RangeSnapshot;
        }>(brokerUrl, "/api/topology"),
        requestJson<{ cases: HistoricalCase[] }>(brokerUrl, "/api/cases"),
        requestJson<{ policies: Policy[] }>(brokerUrl, "/api/policies"),
      ]);
      setDashboard({
        alerts: alerts.alerts,
        snapshot: topology.snapshot ?? alerts.snapshot,
        topology: topology.topology,
        cases: cases.cases,
        policies: policies.policies,
      });
      setError(null);
    } catch (loadError) {
      setError(
        loadError instanceof Error
          ? loadError.message
          : "Unable to load the command state.",
      );
    }
  }, []);

  const loadDecision = useCallback(async (evaluationId: string) => {
    try {
      const next = await requestJson<Decision>(
        brokerUrl,
        `/api/decisions/${encodeURIComponent(evaluationId)}`,
      );
      setDecision(next);
      setSelectedEvaluationId(evaluationId);
    } catch (loadError) {
      setError(
        loadError instanceof Error
          ? loadError.message
          : "Unable to load the decision trace.",
      );
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
    const stream = new EventSource(`${brokerUrl}/events`);
    const onPrecedentEvent = (message: Event) => {
      try {
        const event = JSON.parse(
          (message as MessageEvent<string>).data,
        ) as EventEnvelope;
        setEvents((current) => [event, ...current].slice(0, 100));
        const evaluation = payloadEvaluation(event);
        if (evaluation) {
          void loadDecision(evaluation.evaluationId);
        } else {
          const evaluationId = evaluationIdForEvent(event);
          if (evaluationId) {
            void loadDecision(evaluationId);
          }
        }
        if (
          [
            "ACTION_EXECUTED",
            "ACTION_DENIED",
            "PROBE_RECORDED",
            "PRECEDENT_PROMOTED",
            "RANGE_RESET",
          ].includes(event.type)
        ) {
          void loadDashboard();
        }
      } catch {
        setError("Received an unreadable event from the broker.");
      }
    };
    stream.addEventListener("precedent", onPrecedentEvent);
    stream.onerror = () =>
      setError("Waiting for the broker event stream to reconnect.");
    return () => stream.close();
  }, [loadDashboard, loadDecision]);

  const startAgent = async () => {
    setBusyAction("launch");
    try {
      const run = await requestJson<{ runId: string }>(runnerUrl, "/api/runs", {
        method: "POST",
        body: JSON.stringify({
          prompt:
            "Investigate the controlled payments credential incident. Read alerts, topology, policies, historical cases, and evidence provenance before proposing any action. Contain the attacker, preserve legitimate payments when the verified controls allow it, and prove both outcomes with probes.",
          origin: "LIVE_AGENT",
        }),
      });
      setCurrentRunId(run.runId);
      setError(null);
    } catch (actionError) {
      setError(
        actionError instanceof Error
          ? actionError.message
          : "Unable to start the Qoder response.",
      );
    } finally {
      setBusyAction(null);
    }
  };

  const runDemo = async (
    action: string,
    path: string,
    origin: RunOrigin = "LIVE_AGENT",
  ) => {
    setBusyAction(action);
    try {
      const runId = currentRunId ?? crypto.randomUUID();
      const result = await requestJson<{ runId: string }>(runnerUrl, path, {
        method: "POST",
        body: JSON.stringify({ runId, origin }),
      });
      setCurrentRunId(result.runId);
      await loadDashboard();
      setError(null);
    } catch (actionError) {
      setError(
        actionError instanceof Error
          ? actionError.message
          : "Unable to run the demo control.",
      );
    } finally {
      setBusyAction(null);
    }
  };

  const selectedNodeIds = useMemo(
    () =>
      new Set(
        decision?.evaluation.supportingPaths.flatMap((path) => path.nodeIds) ??
          [],
      ),
    [decision],
  );
  const selectedEdgeIds = useMemo(
    () =>
      new Set(
        decision?.evaluation.supportingPaths.flatMap(
          (path) => path.relationshipIds,
        ) ?? [],
      ),
    [decision],
  );

  const graph = useMemo((): { nodes: Node[]; edges: Edge[] } => {
    if (graphView === "HISTORY") {
      const nodes: Node[] = dashboard.cases.map((incident, index) => ({
        id: `case-${incident.id}`,
        position: {
          x: 60 + (index % 2) * 360,
          y: 65 + Math.floor(index / 2) * 185,
        },
        data: {
          label: `${incident.id}\n${incident.outcome} · ${incident.verified ? "verified" : "unverified"}`,
        },
        style: nodeStyle(
          incident.outcome === "RECOVERED" || incident.outcome === "NO_IMPACT"
            ? "#43d59b"
            : "#ff6375",
          decision?.evaluation.precedentIds.includes(incident.id) ?? false,
        ),
      }));
      const edges: Edge[] = dashboard.cases.slice(1).map((incident, index) => ({
        id: `history-${incident.id}`,
        source: `case-${dashboard.cases[index].id}`,
        target: `case-${incident.id}`,
        label: "context + outcome",
        style: { stroke: "#42617e", strokeWidth: 1.25 },
        labelStyle: { fill: "#8ca5bc", fontSize: 10 },
      }));
      return { nodes, edges };
    }

    if (graphView === "PROVENANCE") {
      const evidence = decision?.trace.facts.evidence ?? [];
      const nodes: Node[] = [];
      const edges: Edge[] = [];
      evidence.forEach((item, index) => {
        const evidenceId = `evidence-${item.id}`;
        const sourceId = `source-${item.sourceId}`;
        nodes.push({
          id: evidenceId,
          position: { x: 80, y: 75 + index * 170 },
          data: {
            label: `${item.id}\n${item.trusted ? "trusted evidence" : "untrusted evidence"}`,
          },
          style: nodeStyle(item.trusted ? "#43d59b" : "#ff6375", true),
        });
        if (!nodes.some((node) => node.id === sourceId)) {
          nodes.push({
            id: sourceId,
            position: { x: 400, y: 75 + index * 170 },
            data: { label: `${item.sourceName}\nsource authority` },
            style: nodeStyle(item.trusted ? "#42a4ff" : "#f7af4c", false),
          });
        }
        edges.push({
          id: `lineage-${item.id}`,
          source: evidenceId,
          target: sourceId,
          label: "FROM SOURCE",
          style: {
            stroke: item.trusted ? "#43d59b" : "#ff6375",
            strokeWidth: 1.5,
          },
          labelStyle: { fill: "#a8bed0", fontSize: 10 },
        });
        if (item.verifiedBy) {
          const verificationId = `verification-${item.verifiedBy}`;
          nodes.push({
            id: verificationId,
            position: { x: 720, y: 75 + index * 170 },
            data: { label: `${item.verifiedBy}\ntrusted verification` },
            style: nodeStyle("#43d59b", false),
          });
          edges.push({
            id: `verified-${item.id}`,
            source: evidenceId,
            target: verificationId,
            label: "VERIFIED BY",
            style: { stroke: "#43d59b", strokeWidth: 1.5 },
            labelStyle: { fill: "#a8bed0", fontSize: 10 },
          });
        }
      });
      return { nodes, edges };
    }

    const nodes: Node[] = dashboard.topology.nodes.map((asset, index) => {
      const isSelected = selectedNodeIds.has(asset.id);
      const isCompromised =
        asset.id === "payments-key-v1" &&
        dashboard.snapshot?.credentialState === "ACTIVE";
      const isVerified = asset.verified || asset.id === "payments-key-v2";
      const color = isCompromised
        ? "#ff6375"
        : isVerified
          ? "#43d59b"
          : asset.critical
            ? "#f7af4c"
            : "#42a4ff";
      return {
        id: asset.id,
        position: positions[asset.id] ?? {
          x: 50 + (index % 4) * 235,
          y: 55 + Math.floor(index / 4) * 165,
        },
        data: {
          label: `${asset.name}\n${asset.assetClass}${asset.critical ? " · critical" : ""}`,
        },
        style: nodeStyle(color, isSelected || isCompromised),
      };
    });
    const edges: Edge[] = dashboard.topology.edges.map((edge) => ({
      id: edge.id,
      source: edge.sourceId,
      target: edge.targetId,
      label: edge.type.replaceAll("_", " "),
      animated: selectedEdgeIds.has(edge.id),
      style: {
        stroke: selectedEdgeIds.has(edge.id) ? "#ff6375" : "#40607f",
        strokeWidth: selectedEdgeIds.has(edge.id) ? 2.5 : 1.25,
      },
      labelStyle: { fill: "#94acc0", fontSize: 9 },
      labelBgStyle: { fill: "#0a1320", fillOpacity: 0.92 },
      labelBgPadding: [3, 2],
    }));
    return { nodes, edges };
  }, [dashboard, decision, graphView, selectedEdgeIds, selectedNodeIds]);

  const paymentProbe = latestProbe(events, "LEGITIMATE_PAYMENT");
  const attackerProbe = latestProbe(events, "ATTACKER");
  const ledgerProbe = latestProbe(events, "LEDGER");

  return (
    <main className="console-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <span className="brand-mark">P</span>
          <div>
            <p className="eyebrow">NEXUS FINANCIAL · INCIDENT COMMAND</p>
            <h1>PRECEDENT</h1>
          </div>
        </div>
        <div className="topbar-status">
          <span
            className={`status-dot ${dashboard.snapshot?.credentialState === "ACTIVE" ? "danger" : "safe"}`}
          />
          <span>
            {dashboard.snapshot?.credentialState === "ACTIVE"
              ? "COMPROMISE ACTIVE"
              : "CONTAINMENT STATE"}
          </span>
          <span className="divider" />
          <span>GRAPH v{dashboard.snapshot?.scenarioVersion ?? "—"}</span>
        </div>
      </header>

      <section className="metric-grid" aria-label="Observed range measurements">
        <Metric
          label="Legitimate payments"
          probe={paymentProbe}
          successText="OBSERVED HEALTHY"
          failureText="OBSERVED FAILURE"
        />
        <Metric
          label="Attacker requests"
          probe={attackerProbe}
          successText="OBSERVED SUCCESS"
          failureText="OBSERVED BLOCKED"
          inverse
        />
        <Metric
          label="Ledger consistency"
          probe={ledgerProbe}
          successText="OBSERVED CONSISTENT"
          failureText="OBSERVED FAILURE"
        />
        <div className="metric-card">
          <span className="metric-label">Verified memory</span>
          <strong>
            {dashboard.cases.filter((item) => item.verified).length}
          </strong>
          <span className="metric-caption">cases with a verifier record</span>
        </div>
      </section>

      {error ? <div className="connection-banner">{error}</div> : null}

      <section className="workspace">
        <aside className="timeline-panel panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">ORDERED APPLICATION EVENTS</p>
              <h2>Action stream</h2>
            </div>
            <span className="count-badge">{events.length}</span>
          </div>
          <div className="timeline-list">
            {events.length === 0 ? (
              <p className="empty-state">
                Waiting for incident and range events.
              </p>
            ) : (
              events.map((event) => {
                const evaluationId = evaluationIdForEvent(event);
                return (
                  <button
                    className={`event-row ${selectedEvaluationId === evaluationId ? "selected" : ""}`}
                    key={event.eventId}
                    onClick={() =>
                      evaluationId && void loadDecision(evaluationId)
                    }
                    type="button"
                  >
                    <span
                      className={`origin-badge ${event.origin.toLowerCase()}`}
                    >
                      {event.origin.replaceAll("_", " ")}
                    </span>
                    <strong>{event.type.replaceAll("_", " ")}</strong>
                    <span>{eventSummary(event)}</span>
                    <time>
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </time>
                  </button>
                );
              })
            )}
          </div>
        </aside>

        <section className="graph-panel panel">
          <div className="panel-heading graph-heading">
            <div>
              <p className="eyebrow">GRAPH-BACKED DECISION CONTEXT</p>
              <h2>
                {graphView === "CURRENT"
                  ? "Current infrastructure"
                  : graphView === "HISTORY"
                    ? "Verified precedent memory"
                    : "Evidence provenance"}
              </h2>
            </div>
            <div className="segmented-control" aria-label="Graph view">
              {(["CURRENT", "HISTORY", "PROVENANCE"] as GraphView[]).map(
                (view) => (
                  <button
                    className={graphView === view ? "active" : ""}
                    key={view}
                    onClick={() => setGraphView(view)}
                    type="button"
                  >
                    {view}
                  </button>
                ),
              )}
            </div>
          </div>
          <div className="graph-canvas">
            {graph.nodes.length > 0 ? (
              <ReactFlow
                edges={graph.edges}
                fitView
                fitViewOptions={{ padding: 0.2 }}
                nodes={graph.nodes}
                nodesConnectable={false}
                nodesDraggable={false}
                nodesFocusable={false}
                panOnDrag
              >
                <Background color="#233b55" gap={22} size={1} />
                <Controls showInteractive={false} />
              </ReactFlow>
            ) : (
              <div className="graph-empty">
                Load an incident decision to inspect its graph evidence.
              </div>
            )}
          </div>
          <div className="graph-legend">
            <span>
              <i className="legend-dot compromised" /> compromised or blocked
            </span>
            <span>
              <i className="legend-dot unresolved" /> unresolved critical
              dependency
            </span>
            <span>
              <i className="legend-dot verified" /> verified recovery
            </span>
            <span>
              <i className="legend-dot historical" /> historical evidence
            </span>
          </div>
        </section>

        <aside className="evidence-panel panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">PRECEDENT EVALUATOR</p>
              <h2>Evidence inspector</h2>
            </div>
            {decision ? (
              <span
                className={`verdict-badge ${verdictClass(decision.evaluation.verdict)}`}
              >
                {decision.evaluation.verdict}
              </span>
            ) : null}
          </div>
          {decision ? (
            <div className="evidence-content">
              <p className="decision-action">
                {decision.proposal.actionType.replaceAll("_", " ")}{" "}
                <span>→</span> {decision.proposal.targetId}
              </p>
              <div className="reason-list">
                {decision.evaluation.reasonCodes.map((reason) => (
                  <span key={reason}>{reason.replaceAll("_", " ")}</span>
                ))}
              </div>
              <button
                className="why-button"
                onClick={() => setShowWhy((visible) => !visible)}
                type="button"
              >
                {showWhy ? "Hide decision trace" : "Show me why"}
              </button>
              {showWhy ? (
                <div className="trace-details">
                  <TraceSection
                    title="Current dependency facts"
                    items={decision.trace.facts.dependencies.map(
                      (item) =>
                        `${item.name} · ${item.active ? "active" : "inactive"}${item.critical ? " · critical" : ""}`,
                    )}
                  />
                  <TraceSection
                    title="Applicable policies"
                    items={decision.trace.policies.map(
                      (item) => `${item.id} · ${item.summary}`,
                    )}
                  />
                  <TraceSection
                    title="Matching cases"
                    items={decision.trace.facts.precedents.map(
                      (item) =>
                        `${item.id} · ${item.outcome} · ${item.summary}`,
                    )}
                  />
                  <TraceSection
                    title="Evidence lineage"
                    items={decision.trace.facts.evidence.map(
                      (item) =>
                        `${item.id} · ${item.sourceName} · ${item.trusted ? "trusted" : "untrusted"}`,
                    )}
                  />
                  <TraceSection
                    title="Traversed paths"
                    items={decision.trace.supportingPaths.map(
                      (path) =>
                        `${path.nodeIds.join(" → ")} · ${path.relationshipIds.join(", ") || "node context"}`,
                    )}
                  />
                </div>
              ) : null}
              {decision.evaluation.suggestedSteps.length > 0 ? (
                <div className="suggested-steps">
                  <p className="section-label">Required recovery sequence</p>
                  <ol>
                    {decision.evaluation.suggestedSteps.map((step) => (
                      <li key={step.proposalId}>
                        {step.actionType.replaceAll("_", " ")}{" "}
                        <span>→ {step.targetId}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              ) : null}
              {decision.evaluation.rejectedEvidenceIds.length > 0 ? (
                <div className="rejected-evidence">
                  Untrusted evidence rejected:{" "}
                  {decision.evaluation.rejectedEvidenceIds.join(", ")}
                </div>
              ) : null}
            </div>
          ) : (
            <div className="evidence-empty">
              <p>
                Select an evaluation to inspect the policy, paths, historical
                outcomes, and evidence authority behind it.
              </p>
            </div>
          )}
        </aside>
      </section>

      <section className="control-deck panel">
        <div>
          <p className="eyebrow">DEMO CONTROL PLANE</p>
          <h2>Every consequential action remains broker-gated.</h2>
        </div>
        <div className="control-actions">
          <button
            className="primary"
            disabled={busyAction !== null}
            onClick={() => void startAgent()}
            type="button"
          >
            {busyAction === "launch"
              ? "Launching agent…"
              : "Launch attack response"}
          </button>
          <button
            disabled={busyAction !== null}
            onClick={() =>
              void runDemo(
                "replay",
                "/api/demo/historical-replay",
                "HISTORICAL_REPLAY",
              )
            }
            type="button"
          >
            {busyAction === "replay" ? "Replaying…" : "Replay H41 proposal"}
          </button>
          <button
            disabled={busyAction !== null}
            onClick={() =>
              void runDemo("inject", "/api/demo/inject-forged-runbook")
            }
            type="button"
          >
            {busyAction === "inject" ? "Injecting…" : "Inject forged runbook"}
          </button>
          <button
            disabled={busyAction !== null}
            onClick={() =>
              void runDemo("compare", "/api/demo/compare-h41", "COUNTERFACTUAL")
            }
            type="button"
          >
            {busyAction === "compare" ? "Comparing…" : "Compare response"}
          </button>
          <button
            className="quiet"
            disabled={busyAction !== null}
            onClick={() => void runDemo("reset", "/api/demo/reset")}
            type="button"
          >
            {busyAction === "reset" ? "Resetting…" : "Reset live topology"}
          </button>
        </div>
      </section>

      <section className="alert-strip" aria-label="Current incident alerts">
        {dashboard.alerts.map((alert) => (
          <div
            className={`alert-card ${severityClass(alert.severity)}`}
            key={alert.id}
          >
            <span>{alert.severity}</span>
            <p>{alert.summary}</p>
          </div>
        ))}
      </section>
    </main>
  );
}

function Metric({
  label,
  probe,
  successText,
  failureText,
  inverse = false,
}: {
  label: string;
  probe: Probe | null;
  successText: string;
  failureText: string;
  inverse?: boolean;
}) {
  const healthy = probe ? (inverse ? !probe.success : probe.success) : null;
  return (
    <div className="metric-card">
      <span className="metric-label">{label}</span>
      <strong
        className={
          healthy === null ? "" : healthy ? "metric-safe" : "metric-danger"
        }
      >
        {healthy === null ? "—" : healthy ? "PASS" : "FAIL"}
      </strong>
      <span className="metric-caption">
        {healthy === null
          ? "awaiting independent probe"
          : healthy
            ? successText
            : failureText}
      </span>
    </div>
  );
}

function TraceSection({ title, items }: { title: string; items: string[] }) {
  return (
    <section className="trace-section">
      <p className="section-label">{title}</p>
      {items.length > 0 ? (
        <ul>
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="none">No returned records.</p>
      )}
    </section>
  );
}
