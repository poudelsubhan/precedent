"use client";

import {
  Background,
  Controls,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const brokerUrl = process.env.NEXT_PUBLIC_BROKER_URL ?? "http://localhost:3001";
const runnerUrl = process.env.NEXT_PUBLIC_RUNNER_URL ?? "http://localhost:3003";

import {
  EvaluationSchema,
  EventEnvelopeSchema,
  ProbeResultSchema,
  type Evaluation,
  type EventEnvelope,
  type RunOrigin,
  type RangeSnapshot,
} from "@precedent/contracts";
import {
  requestJson,
  LatestRequest,
  type Dashboard,
  type RangeMetrics,
  type Decision,
  type GraphView,
  type Probe,
  type Alert,
  type HistoricalCase,
  type Policy,
} from "./console-api";

const initialDashboard: Dashboard = {
  alerts: [],
  snapshot: null,
  topology: { nodes: [], edges: [] },
  cases: [],
  policies: [],
};

const retainedEventIdLimit = 200;

const positions: Record<string, { x: number; y: number }> = {
  "compromised-laptop": { x: 30, y: 60 },
  "attacker-process": { x: 30, y: 250 },
  "payments-key-v1": { x: 235, y: 155 },
  "credential-gateway": { x: 235, y: 350 },
  "payment-worker-a": { x: 455, y: 70 },
  "payment-worker-b": { x: 455, y: 265 },
  "checkout-api": { x: 680, y: 70 },
  "ledger-service": { x: 680, y: 290 },
  "payments-key-v2": { x: 455, y: 455 },
};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : {};
}

function payloadEvaluation(event: EventEnvelope): Evaluation | null {
  const result = EvaluationSchema.safeParse(event.payload.evaluation);
  return result.success ? result.data : null;
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
  const result = ProbeResultSchema.safeParse(event.payload.probe);
  return result.success ? result.data : null;
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
    background: selected ? "var(--panel-raised)" : "var(--panel)",
    border: `1px solid ${selected ? color : "var(--line)"}`,
    borderRadius: 8,
    boxShadow: selected ? `0 0 0 1px ${color}` : "none",
    color: "var(--text)",
    fontSize: 15,
    fontWeight: 650,
    padding: "9px 12px",
    width: 164,
    textAlign: "center",
  };
}

function originLabel(event: EventEnvelope): string {
  const proposal = asRecord(event.payload.proposal);
  const proposalId =
    proposal.proposalId ??
    event.payload.proposalId ??
    payloadEvaluation(event)?.proposalId;
  if (
    (typeof proposalId === "string" &&
      proposalId.startsWith("forged-runbook-")) ||
    (event.type === "EVIDENCE_REJECTED" &&
      event.payload.evidenceId === "forged-runbook")
  )
    return "DEMO INJECTION";
  return event.origin.replaceAll("_", " ");
}

function eventSummary(event: EventEnvelope): string {
  const receipt = asRecord(event.payload.receipt);
  if (typeof receipt.actionType === "string")
    return `${receipt.actionType.replaceAll("_", " ")} · ${String(receipt.status)}`;
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
    const outcome = probe.success ? "success" : "failure";
    const measurement =
      event.origin === "COUNTERFACTUAL" ? "projected" : "observed";
    return `${probe.probeClass.replaceAll("_", " ")} ${measurement} ${outcome}`;
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
  const [metrics, setMetrics] = useState<RangeMetrics | null>(null);
  const [metricError, setMetricError] = useState(false);
  const [variant, setVariant] = useState("production");
  const [dashboard, setDashboard] = useState<Dashboard>(initialDashboard);
  const [events, setEvents] = useState<EventEnvelope[]>([]);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [selectedEvaluationId, setSelectedEvaluationId] = useState<
    string | null
  >(null);
  const [currentRunId, setCurrentRunId] = useState<string | null>(null);
  const [showTelemetry, setShowTelemetry] = useState(false);
  const [graphView, setGraphView] = useState<GraphView>("CURRENT");
  const [showComparison, setShowComparison] = useState(false);
  const [showWhy, setShowWhy] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [connection, setConnection] = useState("Connecting to event stream");
  const [notice, setNotice] = useState(
    "Ready. Replay H41 to inspect a blocked proposal, or launch a live response.",
  );
  const [decisionPending, setDecisionPending] = useState(false);
  const selectedDecision = useRef<string | null>(null);
  const decisionRequest = useRef(new LatestRequest());
  const dashboardRequest = useRef(new LatestRequest());
  const manualSelection = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const seenEventIds = useRef(new Set<string>());

  const loadDashboard = useCallback(async () => {
    const isCurrent = dashboardRequest.current.begin();
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
      if (!isCurrent()) return;
      setDashboard({
        alerts: alerts.alerts,
        snapshot: topology.snapshot ?? alerts.snapshot,
        topology: topology.topology,
        cases: cases.cases,
        policies: policies.policies,
      });
    } catch (loadError) {
      if (!isCurrent()) return;
      setError(
        loadError instanceof Error
          ? loadError.message
          : "Unable to load the command state.",
      );
    }
  }, []);

  const loadDecision = useCallback(async (evaluationId: string) => {
    const isCurrent = decisionRequest.current.begin();
    setDecisionPending(true);
    try {
      const next = await requestJson<Decision>(
        brokerUrl,
        `/api/decisions/${encodeURIComponent(evaluationId)}`,
      );
      if (!isCurrent()) return;
      setDecision(next);
      setSelectedEvaluationId(evaluationId);
      selectedDecision.current = evaluationId;
    } catch (loadError) {
      if (!isCurrent()) return;
      setError(
        loadError instanceof Error
          ? loadError.message
          : "Unable to load the decision trace.",
      );
    } finally {
      if (isCurrent()) setDecisionPending(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const result = await requestJson<RangeMetrics>(
          brokerUrl,
          "/api/metrics",
        );
        if (active) {
          setMetrics(result);
          setMetricError(false);
        }
      } catch {
        if (active) setMetricError(true);
      }
    };
    void refresh();
    const interval = setInterval(() => void refresh(), 2000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    void loadDashboard();
    const stream = new EventSource(`${brokerUrl}/events`);
    const onPrecedentEvent = (message: Event) => {
      try {
        const event = EventEnvelopeSchema.parse(
          JSON.parse((message as MessageEvent<string>).data),
        );
        if (seenEventIds.current.has(event.eventId)) {
          return;
        }
        seenEventIds.current.add(event.eventId);
        if (seenEventIds.current.size > retainedEventIdLimit) {
          const oldestEventId = seenEventIds.current.values().next().value;
          if (oldestEventId) {
            seenEventIds.current.delete(oldestEventId);
          }
        }
        setEvents((current) => [event, ...current].slice(0, 100));
        const evaluation = payloadEvaluation(event);
        if (event.type === "RUN_STARTED" && event.origin === "LIVE_AGENT")
          setCurrentRunId(event.runId);
        if (event.type === "RANGE_RESET") {
          setCurrentRunId(null);
          setDecision(null);
          setSelectedEvaluationId(null);
          selectedDecision.current = null;
          manualSelection.current = false;
          decisionRequest.current.cancel();
          setDecisionPending(false);
        }
        if (event.type === "ACTION_EXECUTED" && selectedDecision.current)
          void loadDecision(selectedDecision.current);
        if (evaluation && !manualSelection.current) {
          void loadDecision(evaluation.evaluationId);
        } else {
          const evaluationId = evaluationIdForEvent(event);
          if (evaluationId && !manualSelection.current) {
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
    stream.onopen = () => setConnection("Event stream connected");
    stream.onerror = () =>
      setConnection("Event stream reconnecting · displayed data may be stale");
    return () => {
      stream.close();
      decisionRequest.current.cancel();
      dashboardRequest.current.cancel();
    };
  }, [loadDashboard, loadDecision]);

  const startAgent = async () => {
    manualSelection.current = false;
    setError(null);
    setBusyAction("launch");
    setNotice("Starting a Qoder response session…");
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
      setNotice(
        "Live response started. Follow the action stream for evaluated operations.",
      );
      setError(null);
    } catch (actionError) {
      setNotice(
        "The action was not confirmed. Inspect the action stream before retrying.",
      );
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
    options: Record<string, unknown> = {},
  ) => {
    if (action === "compare") setShowComparison(true);
    setError(null);
    setBusyAction(action);
    manualSelection.current = false;
    setNotice("Running " + action + "…");
    try {
      const runId = currentRunId ?? crypto.randomUUID();
      const result = await requestJson<{ runId: string }>(runnerUrl, path, {
        method: "POST",
        body: JSON.stringify({ runId, origin, ...options }),
      });
      if (action !== "reset" && origin === "LIVE_AGENT")
        setCurrentRunId(result.runId);
      setNotice(
        action === "reset"
          ? "Live topology reset. Learned memory preserved."
          : "Demo action completed. Inspect the action stream and evidence.",
      );
      await loadDashboard();
    } catch (actionError) {
      setNotice(
        "The action was not confirmed. Inspect the action stream before retrying.",
      );
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
        id: incident.id,
        position: {
          x: 80,
          y: 120 + index * 170,
        },
        data: {
          label: `${incident.id}\n${incident.outcome} · ${incident.verified ? "verified" : "unverified"}`,
        },
        style: nodeStyle(
          incident.outcome === "RECOVERED" || incident.outcome === "NO_IMPACT"
            ? "var(--green)"
            : "var(--red)",
          decision?.evaluation.precedentIds.includes(incident.id) ?? false,
        ),
      }));
      const edges: Edge[] = [];
      dashboard.cases.forEach((incident, index) => {
        incident.paths.forEach((path) =>
          path.relationshipIds.forEach((id, step) => {
            const source = path.nodeIds[step];
            const target = path.nodeIds[step + 1];
            if (!source || !target || edges.some((edge) => edge.id === id))
              return;
            for (const [offset, nodeId] of [source, target].entries()) {
              if (!nodes.some((node) => node.id === nodeId))
                nodes.push({
                  id: nodeId,
                  position: { x: 80 + offset * 300, y: 120 + index * 170 },
                  data: { label: nodeId },
                  style: nodeStyle(
                    "var(--history)",
                    selectedNodeIds.has(nodeId),
                  ),
                });
            }
            edges.push({
              id,
              source,
              target,
              label: id,
              style: { stroke: "var(--history)" },
              labelStyle: { fill: "var(--muted)" },
            });
          }),
        );
      });
      return { nodes, edges };
    }

    if (graphView === "PROVENANCE") {
      const evidence = decision?.trace.facts.evidence ?? [];
      const nodes: Node[] = [];
      const edges: Edge[] = [];
      evidence.forEach((item, index) => {
        const evidenceId = item.id;
        const sourceId = item.sourceId;
        nodes.push({
          id: evidenceId,
          position: { x: 80, y: 75 + index * 170 },
          data: {
            label: `${item.id}\n${item.trusted ? "trusted evidence" : "untrusted evidence"}`,
          },
          style: nodeStyle(item.trusted ? "var(--green)" : "var(--red)", true),
        });
        if (!nodes.some((node) => node.id === sourceId)) {
          nodes.push({
            id: sourceId,
            position: { x: 400, y: 75 + index * 170 },
            data: { label: `${item.sourceName}\nsource authority` },
            style: nodeStyle(
              item.trusted ? "var(--blue)" : "var(--amber)",
              false,
            ),
          });
        }
        edges.push({
          id:
            item.paths?.[0]?.relationshipIds[0] ?? `legacy-lineage-${item.id}`,
          source: evidenceId,
          target: sourceId,
          label: "FROM SOURCE",
          style: {
            stroke: item.trusted ? "var(--green)" : "var(--red)",
            strokeWidth: 1.5,
          },
          labelStyle: { fill: "var(--muted)", fontSize: 10 },
        });
        if (item.verifiedBy) {
          const verificationId = item.verifiedBy;
          nodes.push({
            id: verificationId,
            position: { x: 720, y: 75 + index * 170 },
            data: { label: `${item.verifiedBy}\ntrusted verification` },
            style: nodeStyle("var(--green)", false),
          });
          edges.push({
            id:
              item.paths?.[1]?.relationshipIds[0] ??
              `legacy-verified-${item.id}`,
            source: evidenceId,
            target: verificationId,
            label: "VERIFIED BY",
            style: { stroke: "var(--green)", strokeWidth: 1.5 },
            labelStyle: { fill: "var(--muted)", fontSize: 10 },
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
      const isVerified = asset.verified;
      const color = isCompromised
        ? "var(--red)"
        : isVerified
          ? "var(--green)"
          : asset.critical
            ? "var(--amber)"
            : "var(--blue)";
      return {
        id: asset.id,
        position: positions[asset.id] ?? {
          x: 50 + (index % 4) * 235,
          y: 55 + Math.floor(index / 4) * 165,
        },
        data: {
          label: `${asset.name}\n${asset.assetClass}${isCompromised ? " · compromised" : isVerified ? " · verified" : asset.critical ? " · critical" : ""}`,
        },
        style: nodeStyle(color, isSelected || isCompromised),
      };
    });
    const edges: Edge[] = dashboard.topology.edges.map((edge) => ({
      id: edge.id,
      source: edge.sourceId,
      target: edge.targetId,
      label: edge.type.replaceAll("_", " "),
      animated: false,
      style: {
        stroke: selectedEdgeIds.has(edge.id) ? "var(--red)" : "var(--edge)",
        strokeWidth: selectedEdgeIds.has(edge.id) ? 2.5 : 1.25,
      },
      labelStyle: { fill: "var(--muted)", fontSize: 9 },
      labelBgStyle: { fill: "var(--bg)", fillOpacity: 0.92 },
      labelBgPadding: [3, 2],
    }));
    return { nodes, edges };
  }, [dashboard, decision, graphView, selectedEdgeIds, selectedNodeIds]);

  const observedEvents = useMemo(
    () =>
      events.filter(
        (event) =>
          event.origin === "LIVE_AGENT" && event.runId === currentRunId,
      ),
    [currentRunId, events],
  );
  const paymentProbe = latestProbe(observedEvents, "LEGITIMATE_PAYMENT");
  const attackerProbe = latestProbe(observedEvents, "ATTACKER");
  const ledgerProbe = latestProbe(observedEvents, "LEDGER");

  const visibleEvents = events.filter(
    (event) =>
      showTelemetry ||
      !["AGENT_TOOL_EVENT", "TOOL_PERMISSION"].includes(event.type),
  );

  return (
    <main className="console-shell" id="main-content">
      <a className="skip-link" href="#demo-controls">
        Skip to incident controls
      </a>
      <header className="topbar">
        <div className="brand-lockup">
          <span className="brand-mark">P</span>
          <div>
            <p className="eyebrow">NEXUS FINANCIAL / CONTROLLED ENVIRONMENT</p>
            <h1>
              Precedent
              <span className="brand-subtitle">Judgment before action.</span>
            </h1>
          </div>
        </div>
        <div className="topbar-status">
          <span
            className={`status-dot ${!dashboard.snapshot ? "unknown" : dashboard.snapshot.credentialState === "ACTIVE" ? "danger" : "safe"}`}
          />
          <span>
            {!dashboard.snapshot
              ? "STATE UNAVAILABLE"
              : dashboard.snapshot.credentialState === "ACTIVE"
                ? "COMPROMISE ACTIVE"
                : "CREDENTIAL " + dashboard.snapshot.credentialState}
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
            {dashboard.snapshot
              ? dashboard.cases.filter((item) => item.verified).length
              : "—"}
          </strong>
          <span className="metric-caption">
            seeded and learned verified cases
          </span>
        </div>
      </section>

      <div className="session-strip">
        <span>{connection}</span>
        <span>
          {metricError
            ? "Request counters unavailable · reconnecting"
            : metrics
              ? `${metrics.live.paymentSuccesses} payments passed / ${metrics.live.paymentFailures} failed · ${metrics.live.attackerBlocked} attacker requests blocked / ${metrics.live.attackerSuccesses} passed · ${metrics.live.reachableCriticalAssets} critical assets reachable`
              : "Loading request counters…"}
        </span>
        <span>Fictional scenario · actual HTTP requests</span>
      </div>
      {metrics?.live.windowStart && (
        <p className="command-status">
          Observed window:{" "}
          {new Date(metrics.live.windowStart).toLocaleTimeString()}–
          {metrics.live.windowEnd
            ? new Date(metrics.live.windowEnd).toLocaleTimeString()
            : "—"}
          . Counters refresh every two seconds.
        </p>
      )}
      <p className="command-status" role="status" aria-live="polite">
        {notice}
      </p>
      {error ? (
        <div className="connection-banner" role="alert">
          {error}{" "}
          <button
            onClick={() => {
              setError(null);
              void loadDashboard();
            }}
          >
            Retry connection
          </button>
        </div>
      ) : null}

      <section
        className="control-deck panel"
        id="demo-controls"
        aria-label="Incident controls"
      >
        <div>
          <p className="eyebrow">INCIDENT CONTROLS</p>
          <h2>Investigate. Intervene. Verify.</h2>
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
              void runDemo("compare", "/api/demo/compare-h41", "COUNTERFACTUAL")
            }
            type="button"
          >
            {busyAction === "compare" ? "Comparing…" : "Compare response"}
          </button>
        </div>
        <details className="secondary-controls">
          <summary>Scenario tools &amp; reset</summary>
          <div className="control-actions">
            {" "}
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
              className="quiet"
              disabled={busyAction !== null}
              onClick={() => void runDemo("reset", "/api/demo/reset")}
              type="button"
            >
              {busyAction === "reset"
                ? "Resetting…"
                : "Reset topology · keep memory"}
            </button>
          </div>
          <div className="control-actions">
            <label>
              Incident variant{" "}
              <select
                value={variant}
                onChange={(event) => setVariant(event.target.value)}
              >
                <option value="production">Production</option>
                <option value="no-gateway">Gateway unavailable</option>
                <option value="hidden-consumer">Additional consumer</option>
                <option value="failed-standby">Standby failed</option>
                <option value="staging">Staging</option>
              </select>
            </label>
            <button
              disabled={busyAction !== null}
              onClick={() =>
                void runDemo(
                  "new incident",
                  "/api/demo/new-incident",
                  "LIVE_AGENT",
                  { variant },
                )
              }
            >
              New incident · keep memory
            </button>
            <button
              disabled={busyAction !== null}
              onClick={() =>
                void runDemo("launch attack", "/api/demo/launch-attack")
              }
            >
              Launch attack
            </button>
            <button
              disabled={busyAction !== null}
              onClick={() =>
                void runDemo(
                  "full reset",
                  "/api/demo/new-incident",
                  "LIVE_AGENT",
                  { variant: "production", fullReset: true, launch: false },
                )
              }
            >
              Restore seeded fixture
            </button>
          </div>
          <p className="command-status">
            Reset restores the live topology and preserves learned precedent.
          </p>
        </details>
      </section>

      {showComparison ? (
        <section
          className="comparison-panel panel"
          aria-label="Response comparison"
        >
          <div className="panel-heading">
            <div>
              <p className="eyebrow">COUNTERFACTUAL · HTTP RESULTS</p>
              <h2>Immediate revocation vs. live response</h2>
            </div>
            <button
              className="why-button"
              onClick={() => setShowComparison(false)}
            >
              Close comparison
            </button>
          </div>
          <p className="trace-note">
            The counterfactual clones the live state when comparison starts,
            then revokes the credential in a separate range. Each result is an
            independent HTTP probe.
          </p>
          <div className="comparison-grid">
            {(["LEGITIMATE_PAYMENT", "ATTACKER", "LEDGER"] as const).map(
              (probeClass) => {
                const comparisonRun = events.find(
                  (event) => event.origin === "COUNTERFACTUAL",
                )?.runId;
                const projected = latestProbe(
                  events.filter(
                    (event) =>
                      event.origin === "COUNTERFACTUAL" &&
                      event.runId === comparisonRun,
                  ),
                  probeClass,
                );
                const observed = latestProbe(observedEvents, probeClass);
                return (
                  <div key={probeClass}>
                    <h3>{probeClass.replaceAll("_", " ")}</h3>
                    <p>
                      Counterfactual:{" "}
                      {projected
                        ? projected.success
                          ? "success"
                          : "failure"
                        : "Awaiting result"}
                    </p>
                    <p>
                      Live run:{" "}
                      {observed
                        ? observed.success
                          ? "success"
                          : "failure"
                        : "Not measured"}
                    </p>
                  </div>
                );
              },
            )}
          </div>
        </section>
      ) : null}
      <section className="workspace">
        <aside className="timeline-panel panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">ORDERED APPLICATION EVENTS</p>
              <h2>Action stream</h2>
            </div>
            <span className="count-badge">{visibleEvents.length}</span>
          </div>
          <label className="command-status">
            <input
              type="checkbox"
              checked={showTelemetry}
              onChange={(event) => setShowTelemetry(event.target.checked)}
            />{" "}
            Show SDK telemetry
          </label>
          <div className="timeline-list">
            {visibleEvents.length === 0 ? (
              <p className="empty-state">
                No events yet. Replay H41 below to see why immediate revocation
                is blocked, or launch a live response.
              </p>
            ) : (
              visibleEvents.map((event) => {
                const evaluationId = evaluationIdForEvent(event);
                return (
                  <button
                    className={`event-row ${evaluationId && selectedEvaluationId === evaluationId ? "selected" : ""}`}
                    disabled={!evaluationId}
                    aria-pressed={
                      evaluationId
                        ? selectedEvaluationId === evaluationId
                        : undefined
                    }
                    key={event.eventId}
                    onClick={() => {
                      if (evaluationId) {
                        manualSelection.current = true;
                        void loadDecision(evaluationId);
                      }
                    }}
                    type="button"
                  >
                    <span
                      className={`origin-badge ${event.origin.toLowerCase()}`}
                    >
                      {originLabel(event)}
                    </span>
                    <strong>{event.type.replaceAll("_", " ")}</strong>
                    <span>{eventSummary(event)}</span>
                    <time dateTime={event.timestamp}>
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
                    ? "Historical precedent memory"
                    : "Evidence provenance"}
              </h2>
            </div>
            <div
              className="segmented-control"
              role="group"
              aria-label="Graph view"
            >
              {(["CURRENT", "HISTORY", "PROVENANCE"] as GraphView[]).map(
                (view) => (
                  <button
                    aria-pressed={graphView === view}
                    className={graphView === view ? "active" : ""}
                    key={view}
                    onClick={() => setGraphView(view)}
                    type="button"
                  >
                    {view === "CURRENT"
                      ? "Infrastructure"
                      : view === "HISTORY"
                        ? "Memory"
                        : "Sources"}
                  </button>
                ),
              )}
            </div>
          </div>
          <div className="graph-canvas">
            {graph.nodes.length > 0 ? (
              <ReactFlow
                defaultEdgeOptions={{
                  labelBgStyle: { fill: "var(--panel)" },
                  labelStyle: { fill: "var(--muted)", fontSize: 12 },
                }}
                key={graphView}
                edges={graph.edges}
                fitView
                fitViewOptions={{ padding: 0.08 }}
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
                {graphView === "PROVENANCE" && decision
                  ? "No evidence provenance is available for this decision."
                  : "Load an incident decision to inspect its graph evidence."}
              </div>
            )}
          </div>
          <details className="graph-text">
            <summary>Read graph as text</summary>
            <ul>
              {graph.nodes.map((node) => (
                <li key={node.id}>{String(node.data.label)}</li>
              ))}
            </ul>
            <ul>
              {graph.edges.map((edge) => (
                <li key={edge.id}>
                  {edge.source} → {edge.target}: {String(edge.label)}
                </li>
              ))}
            </ul>
          </details>
          <div className="graph-legend">
            <span>
              <i className="legend-dot compromised" /> compromised or blocked
            </span>
            <span>
              <i className="legend-dot unresolved" /> critical dependency
            </span>
            <span>
              <i className="legend-dot verified" /> verified state
            </span>
          </div>
        </section>

        <aside className="evidence-panel panel" aria-busy={decisionPending}>
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
          {decisionPending ? (
            <p className="command-status" role="status">
              Loading selected decision…
            </p>
          ) : null}
          {decision ? (
            <div className="evidence-content">
              <p className="section-label">
                {decision.proposal.proposalId.startsWith("forged-runbook-")
                  ? "DEMO INJECTION"
                  : (events
                      .find(
                        (event) =>
                          evaluationIdForEvent(event) ===
                          decision.evaluation.evaluationId,
                      )
                      ?.origin.replaceAll("_", " ") ?? "Origin unavailable")}
              </p>
              <p className="receipt-summary">
                {decision.receipts.length
                  ? decision.receipts
                      .map((receipt) => receipt.status)
                      .join(" · ")
                  : "No execution receipt for this proposal"}
              </p>
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
                aria-expanded={showWhy}
                aria-controls="decision-trace"
                onClick={() => setShowWhy((visible) => !visible)}
                type="button"
              >
                {showWhy ? "Hide decision trace" : "Show me why"}
              </button>
              {showWhy ? (
                <div className="trace-details" id="decision-trace">
                  <button
                    className="why-button"
                    onClick={() => {
                      const blob = new Blob(
                        [
                          JSON.stringify(
                            {
                              exportedAt: new Date().toISOString(),
                              scope:
                                "Selected decision and retained events only; current facts are not an immutable evaluation snapshot",
                              decision,
                              events: events.filter(
                                (event) =>
                                  event.runId === decision.proposal.runId,
                              ),
                            },
                            null,
                            2,
                          ),
                        ],
                        { type: "application/json" },
                      );
                      const url = URL.createObjectURL(blob);
                      const link = document.createElement("a");
                      link.href = url;
                      link.download = `precedent-${decision.evaluation.evaluationId}.json`;
                      link.click();
                      URL.revokeObjectURL(url);
                      setNotice(
                        "Selected decision exported with retained run events.",
                      );
                    }}
                  >
                    Export selected decision
                  </button>
                  <button
                    className="why-button"
                    onClick={async () => {
                      try {
                        const response = await fetch(
                          `${brokerUrl}/api/runs/${encodeURIComponent(decision.proposal.runId)}/report`,
                        );
                        if (!response.ok)
                          throw new Error("Run report unavailable.");
                        const blob = new Blob(
                          [JSON.stringify(await response.json(), null, 2)],
                          { type: "application/json" },
                        );
                        const url = URL.createObjectURL(blob);
                        const link = document.createElement("a");
                        link.href = url;
                        link.download = `precedent-run-${decision.proposal.runId}.json`;
                        link.click();
                        URL.revokeObjectURL(url);
                        setNotice("Complete durable run report exported.");
                      } catch (error) {
                        setError(
                          error instanceof Error
                            ? error.message
                            : "Run export failed.",
                        );
                      }
                    }}
                  >
                    Export complete run report
                  </button>
                  <p className="trace-note">
                    {decision.trace.recordedAt
                      ? `Immutable decision facts recorded ${new Date(decision.trace.recordedAt).toLocaleString()}.`
                      : "Legacy trace: facts were not retained as an immutable snapshot."}
                  </p>
                  <TraceSection
                    title="Trace reference"
                    items={[
                      decision.trace.queryId,
                      `Evaluation topology v${decision.evaluation.scenarioVersion} · policy v${decision.evaluation.policyVersion}`,
                    ]}
                  />
                  <TraceSection
                    title="Dependency facts at evaluation"
                    items={decision.trace.facts.dependencies.map(
                      (item) =>
                        `${item.name} · ${item.active ? "active" : "inactive"}${item.critical ? " · critical" : ""}`,
                    )}
                  />
                  <TraceSection
                    title="Graph queries and parameters"
                    items={(decision.trace.queries ?? []).map(
                      (query) =>
                        `${query.id} · ${query.cypher} · ${JSON.stringify(query.parameters)}`,
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
  const observedSuccess = probe?.success ?? null;
  const healthy =
    observedSuccess === null
      ? null
      : inverse
        ? !observedSuccess
        : observedSuccess;
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
        {observedSuccess === null
          ? "awaiting independent probe"
          : observedSuccess
            ? successText
            : failureText}
      </span>
      {probe ? (
        <time className="metric-caption" dateTime={probe.observedAt}>
          {new Date(probe.observedAt).toLocaleTimeString()} · latest probe
        </time>
      ) : null}
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
