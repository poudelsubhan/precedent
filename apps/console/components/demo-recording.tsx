"use client";
import { useEffect, useState } from "react";
import first from "../../../docs/evidence/live-recovery.json";
import fresh from "../../../docs/evidence/fresh-session.json";
import forged from "../../../docs/evidence/forged-rejection.json";
import "./demo-recording.css";
type Entry = { timestamp: string; type: string; payload: Record<string, any> };
const names: Record<string, string> = {
  isolate_device: "Isolate the compromised laptop",
  quarantine_credential: "Restrict the stolen key",
  invalidate_session: "End the attacker’s session",
  create_credential: "Create a replacement key",
  deploy_credential: "Move a payment worker",
  verify_consumer: "Verify a payment worker",
  switch_traffic: "Switch to the verified worker",
  revoke_credential: "Cancel the stolen key",
};
function summary(e: Entry) {
  const p = e.payload;
  if (p.proposal) return names[p.proposal.actionType] ?? p.proposal.actionType;
  if (p.receipt) return names[p.receipt.actionType] ?? p.receipt.actionType;
  if (p.evaluation)
    return p.evaluation.verdict === "REVISE"
      ? "Device isolation does not stop a copied key"
      : p.evaluation.verdict === "ALLOW"
        ? "Current conditions checked"
        : "More evidence needed";
  if (p.probe)
    return p.probe.probeClass === "ATTACKER"
      ? "Attacker request blocked"
      : p.probe.probeClass === "LEDGER"
        ? "Payment records verified"
        : "Payment request succeeded";
  if (e.type === "PRECEDENT_PROMOTED")
    return "Recovery saved as a verified lesson";
  return "Qoder investigates the incident";
}
const positions: Record<string, [number, number]> = {
  attacker: [95, 115],
  old: [310, 115],
  gateway: [525, 115],
  checkout: [95, 305],
  a: [310, 260],
  b: [310, 380],
  ledger: [525, 305],
  replacement: [525, 465],
};
export function DemoRecording() {
  const [time, setTime] = useState(0),
    [playing, setPlaying] = useState(false);
  useEffect(() => {
    if (!playing) return;
    const id = setInterval(
      () =>
        setTime((t) => {
          if (t >= 160) {
            setPlaying(false);
            return 160;
          }
          return Math.min(160, t + 0.25);
        }),
      250,
    );
    return () => clearInterval(id);
  }, [playing]);
  const poison = time >= 95 && time < 115,
    learn = time >= 115;
  const data = learn ? fresh : first;
  const all = data.report.events as Entry[];
  const start = Date.parse(all[0].timestamp),
    end = Date.parse(all[all.length - 1].timestamp);
  const fraction = poison
    ? 1
    : learn
      ? Math.min(1, (time - 115) / 35)
      : Math.min(1, time / 90);
  const cutoff = start + (end - start) * fraction;
  const events = all.filter((e) => Date.parse(e.timestamp) <= cutoff);
  const shown = events.filter((e) =>
    [
      "ACTION_PROPOSED",
      "EVALUATION_CREATED",
      "ACTION_EXECUTED",
      "PROBE_RECORDED",
      "PRECEDENT_PROMOTED",
    ].includes(e.type),
  );
  const receipts = events
    .filter((e) => e.type === "ACTION_EXECUTED")
    .map((e) => e.payload.receipt);
  const done = (action: string, target?: string) =>
    receipts.some(
      (r) =>
        r?.actionType === action &&
        r.status === "SUCCEEDED" &&
        (!target || r.targetId === target),
    );
  const contained = done("quarantine_credential"),
    revoked = done("revoke_credential"),
    a = done("deploy_credential", "payment-worker-a"),
    b = done("deploy_credential", "payment-worker-b");
  const verified = events.some((e) => e.type === "PRECEDENT_PROMOTED");
  const decision = poison
    ? forged.evaluation
    : events.filter((e) => e.type === "EVALUATION_CREATED").at(-1)?.payload
        .evaluation;
  const caseName = learn ? "New verified recovery" : "H72 · Verified recovery";
  const stage = poison ? 3 : learn ? 4 : time < 25 ? 0 : time < 55 ? 1 : 2;
  const chapters = [
    "Stop the wrong response",
    "Connect the evidence",
    "Recover and verify",
    "Reject poisoned instructions",
    "Learn for the next incident",
  ];
  const caption = poison
    ? "A claim of approval is not proof of authority."
    : learn
      ? "A fresh Qoder session uses the case learned in the first recovery."
      : time < 25
        ? "A stolen key. A response that must protect customers, too."
        : time < 55
          ? "Neo4j connects current dependencies with verified experience."
          : "Qoder acts. The broker checks. Independent requests verify the result.";
  const nodes = [
    ["attacker", "Attacker", "Copied access key"],
    [
      "old",
      "Stolen key",
      revoked ? "REVOKED" : contained ? "RESTRICTED" : "COMPROMISED",
    ],
    ["gateway", "Credential gateway", "Checks every request"],
    ["checkout", "Checkout", "Customer payments"],
    ["a", "Payment worker A", a ? "Replacement key" : "Uses stolen key"],
    ["b", "Payment worker B", b ? "Replacement key" : "Uses stolen key"],
    ["ledger", "Payment records", "Independent ledger"],
    [
      "replacement",
      "Replacement key",
      done("create_credential") ? "CREATED" : "NOT YET CREATED",
    ],
  ];
  function edge(from: string, to: string, color: string, dashed = false) {
    const [x, y] = positions[from],
      [u, v] = positions[to];
    return (
      <path
        key={from + to}
        d={`M ${x} ${y} C ${x + 75} ${y}, ${u - 75} ${v}, ${u} ${v}`}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeDasharray={dashed ? "5 6" : undefined}
      />
    );
  }
  return (
    <main className="film-dashboard">
      <header className="film-header">
        <div className="film-brand">
          <span className="film-mark">P</span>
          <div>
            <b>Precedent</b>
            <small>Judgment before action</small>
          </div>
        </div>
        <div className="film-tags">
          <span>Qoder + Neo4j</span>
          <span className="film-recorded">● Recorded run</span>
          <a href="/">Live dashboard ↗</a>
        </div>
      </header>
      <div className="film-title">
        <div>
          <small>0{stage + 1} / THE INCIDENT RESPONSE</small>
          <h1>{chapters[stage]}</h1>
          <p>{caption}</p>
        </div>
        <span className={`film-state ${contained ? "safe" : ""}`}>
          {poison
            ? "UNTRUSTED SOURCE"
            : verified
              ? "RECOVERY VERIFIED"
              : contained
                ? "ATTACK CONTAINED"
                : "INCIDENT ACTIVE"}
        </span>
      </div>
      <section className="film-metrics">
        <div>
          <small>Customer payments</small>
          <strong>
            {verified
              ? "✓ Verified"
              : receipts.length
                ? "Recovery in progress"
                : "Protect continuity"}
          </strong>
          <span>
            {verified
              ? "Independent HTTP request passed"
              : "Workers depend on a shared key"}
          </span>
        </div>
        <div>
          <small>Attacker access</small>
          <strong className={contained ? "safe-text" : "danger-text"}>
            {contained ? "Blocked" : "Copied key is usable"}
          </strong>
          <span>
            {contained
              ? "Gateway restriction applied"
              : "Device isolation alone is insufficient"}
          </span>
        </div>
        <div>
          <small>Approved actions</small>
          <strong>
            {receipts.length}
            <i> / recorded recovery</i>
          </strong>
          <span>Exact-action approval and execution receipts</span>
        </div>
        <div>
          <small>Verified memory</small>
          <strong>
            {learn
              ? "New case retrieved"
              : verified
                ? "New case saved"
                : "Previous incidents"}
          </strong>
          <span>
            {learn
              ? "Used by a fresh Qoder session"
              : "Source authority checked before use"}
          </span>
        </div>
      </section>
      <section className="film-workspace">
        <aside className="film-panel film-actions">
          <div className="film-panel-title">
            <small>QODER AGENT</small>
            <h2>Action stream</h2>
          </div>
          <div className="film-action-list">
            {shown
              .slice(-7)
              .reverse()
              .map((e, i) => (
                <div
                  className={`film-action ${i === 0 ? "latest" : ""}`}
                  key={e.timestamp + i}
                >
                  <span
                    className={
                      e.payload.evaluation?.verdict === "REVISE"
                        ? "warning-text"
                        : "safe-text"
                    }
                  >
                    {e.type === "ACTION_EXECUTED"
                      ? "✓ EXECUTED"
                      : e.type === "ACTION_PROPOSED"
                        ? "→ PROPOSED"
                        : (e.payload.evaluation?.verdict ??
                          (e.type === "PROBE_RECORDED"
                            ? "✓ VERIFIED"
                            : "LEARNED"))}
                  </span>
                  <p>{summary(e)}</p>
                  <small>
                    {new Date(e.timestamp).toLocaleTimeString("en-US", {
                      hour12: false,
                    })}{" "}
                    · original event
                  </small>
                </div>
              ))}
            {!shown.length && (
              <div className="film-action">
                <span>INVESTIGATING</span>
                <p>Qoder reads alerts, dependencies, policies and evidence.</p>
                <small>Actual SDK session</small>
              </div>
            )}
          </div>
        </aside>
        <section className="film-panel film-graph">
          <div className="film-panel-title">
            <small>
              {poison
                ? "SOURCE PROVENANCE"
                : learn
                  ? "CURRENT SYSTEM + VERIFIED MEMORY"
                  : "LIVE SYSTEM DEPENDENCIES"}
            </small>
            <h2>
              {poison
                ? "Who supplied this instruction?"
                : "Payments infrastructure"}
            </h2>
          </div>
          {poison ? (
            <div className="film-poison">
              <div className="film-source danger">
                <span>UNTRUSTED SOURCE</span>
                <h3>Attacker-controlled mailbox</h3>
                <p>“Security approved disabling the ledger.”</p>
              </div>
              <div className="film-chain">↓ Claimed approval</div>
              <div className="film-source">
                <span>VERIFICATION CHECK</span>
                <h3>No trusted verification</h3>
                <p>Document text cannot create authority.</p>
              </div>
              <div className="film-chain danger-text">⊘ Action denied</div>
              <div className="film-protected">✓ Payment records protected</div>
            </div>
          ) : (
            <svg
              className="film-network"
              viewBox="0 0 620 525"
              aria-label="Payment services and their credential dependencies"
            >
              {edge(
                "attacker",
                "old",
                contained ? "#6f7889" : "#ff8a98",
                contained,
              )}
              {edge("old", "gateway", revoked ? "#454b59" : "#efbd6d", revoked)}
              {edge("checkout", "a", "#90acff")}
              {edge("checkout", "b", "#90acff")}
              {edge("a", "ledger", a ? "#6ed6a5" : "#90acff")}
              {edge("b", "ledger", b ? "#6ed6a5" : "#90acff")}
              {edge("a", a ? "replacement" : "old", a ? "#6ed6a5" : "#efbd6d")}
              {edge("b", b ? "replacement" : "old", b ? "#6ed6a5" : "#efbd6d")}
              {nodes.map(([id, label, status]) => {
                const [x, y] = positions[id];
                const color =
                  id === "attacker" || id === "old"
                    ? contained
                      ? "#6f7889"
                      : "#ff8a98"
                    : id === "replacement" ||
                        (id === "a" && a) ||
                        (id === "b" && b)
                      ? "#6ed6a5"
                      : "#90acff";
                return (
                  <g key={id}>
                    <rect
                      x={x - 78}
                      y={y - 34}
                      width="156"
                      height="68"
                      rx="10"
                      fill="#20242e"
                      stroke={color}
                    />
                    <circle cx={x - 61} cy={y - 12} r="3" fill={color} />
                    <text
                      x={x - 49}
                      y={y - 8}
                      fill="#f1f3f8"
                      fontSize="12"
                      fontWeight="600"
                    >
                      {label}
                    </text>
                    <text
                      x={x}
                      y={y + 15}
                      textAnchor="middle"
                      fill={color}
                      fontSize="10"
                    >
                      {status}
                    </text>
                  </g>
                );
              })}
            </svg>
          )}
          <div className="film-graph-footer">
            {poison
              ? "Authority comes from a trusted verification path."
              : learn
                ? "Experience is reused only when today’s conditions match."
                : "Graph links represent payment dependencies in the recorded range."}
          </div>
        </section>
        <aside className="film-panel film-evidence">
          <div className="film-panel-title">
            <small>PRECEDENT</small>
            <h2>Evidence & decision</h2>
          </div>
          <div className="film-evidence-body">
            <div
              className={`film-verdict ${poison ? "denied" : decision?.verdict === "REVISE" ? "revised" : ""}`}
            >
              {poison ? "DENY" : (decision?.verdict ?? "INVESTIGATE")}
            </div>
            <h3>
              {poison
                ? "Claimed approval rejected"
                : decision?.verdict === "REVISE"
                  ? "Isolation is not enough"
                  : verified
                    ? "Outcome independently verified"
                    : "Check before each action"}
            </h3>
            <p>
              {poison
                ? "The source has no trusted verification. No permission to disable payment records."
                : decision?.verdict === "REVISE"
                  ? "The attacker has a copy of the key. Isolating the original laptop leaves that copy usable."
                  : "The proposal is checked against current dependencies, policy and trusted evidence."}
            </p>
            <div className="film-evidence-item">
              <small>
                {poison
                  ? "SOURCE"
                  : learn
                    ? "LEARNED CASE"
                    : "VERIFIED EXPERIENCE"}
              </small>
              <b>{poison ? "Attacker mailbox" : caseName}</b>
              <p>
                {poison
                  ? "Claimed approval ≠ verified approval"
                  : learn
                    ? "Recovered in the previous session. Retrieved and cited by this agent."
                    : "Restrict the key → migrate workers → verify → revoke"}
              </p>
            </div>
            <div className="film-evidence-item">
              <small>ENFORCEMENT</small>
              <b>
                {poison
                  ? "No action authorized"
                  : "One exact approval per action"}
              </b>
              <p>Separate broker · state checks · durable receipts</p>
            </div>
            {verified && (
              <div className="film-proof">
                ✓ Payment passed
                <br />✓ Attacker blocked
                <br />✓ Ledger consistent
              </div>
            )}
          </div>
        </aside>
      </section>
      <footer className="film-controls">
        <button onClick={() => setPlaying((p) => !p)}>
          {playing ? "Pause" : "Play recording"}
        </button>
        <button
          onClick={() => {
            setTime(0);
            setPlaying(false);
          }}
        >
          Restart
        </button>
        <button
          aria-label="Advance recording two seconds"
          onClick={() => setTime((t) => Math.min(160, t + 2))}
        >
          Next
        </button>
        <input
          aria-label="Recording time"
          type="range"
          min="0"
          max="160"
          step="0.25"
          value={time}
          onChange={(e) => {
            setPlaying(false);
            setTime(Number(e.target.value));
          }}
        />
        <span>
          {Math.floor(time / 60)}:
          {String(Math.floor(time % 60)).padStart(2, "0")} / 2:40
        </span>
        <small>
          Fictional range · actual recorded execution · timing compressed
        </small>
      </footer>
    </main>
  );
}
