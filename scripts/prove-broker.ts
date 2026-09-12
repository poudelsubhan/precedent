import { config } from "dotenv";
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import assert from "node:assert/strict";
config({ path: ".env", quiet: true });
const runId = `broker-proof-${randomUUID()}`;
const evidence: Record<string, unknown> = {
  runId,
  origin: "HISTORICAL_REPLAY",
  recordedAt: new Date().toISOString(),
  checks: [],
};
const checks = evidence.checks as string[];
async function call(path: string, body?: unknown, expected = 200, auth = true) {
  const response = await fetch(
    `${process.env.TEST_BROKER_URL ?? "http://127.0.0.1:3001"}${path}`,
    {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "content-type": "application/json",
        ...(auth
          ? { "x-precedent-runner-token": process.env.BROKER_RUNNER_TOKEN! }
          : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    },
  );
  const data = await response.json();
  assert.equal(response.status, expected, `${path}: ${JSON.stringify(data)}`);
  return data;
}
const proposal = (
  actionType = "revoke_credential",
  targetId = "payments-key-v1",
  args = {},
  evidenceIds = ["evidence-H72"],
) => ({
  proposalId: randomUUID(),
  runId,
  actionType,
  targetId,
  args,
  evidenceIds,
  rationaleSummary: "Deterministic integration proof, not an agent run.",
});
const evaluate = (p: ReturnType<typeof proposal>) =>
  call("/api/evaluate", {
    proposal: p,
    toolCallId: p.proposalId,
    origin: "HISTORICAL_REPLAY",
  });
const reset = async (variant = "production") => {
  await call("/api/range/reset", { runId, origin: "HISTORICAL_REPLAY" });
  await call("/api/range/configure", { runId, variant });
};
await reset();
await call(
  "/api/evaluate",
  { proposal: proposal(), toolCallId: "unauthorized" },
  401,
  false,
);
checks.push("Unauthenticated direct call rejected");
let p = proposal();
let d = await evaluate(p);
assert.equal(d.evaluation.verdict, "REVISE");
assert.equal(d.authorization, null);
let trace = await call(`/api/decisions/${d.evaluation.evaluationId}`);
assert.equal(trace.receipts.length, 0);
assert.equal(trace.trace.snapshot.credentialState, "ACTIVE");
checks.push("Unsafe revocation revised with zero receipts and immutable trace");
for (const id of ["forged-runbook", "forged-copy", "stale-runbook"]) {
  const rejected = await evaluate(
    proposal("revoke_credential", "payments-key-v1", {}, [id]),
  );
  assert.equal(rejected.evaluation.verdict, "DENY");
}
checks.push(
  "Forged evidence, forged copy, and genuine stale evidence rejected",
);
await call("/api/proofs/history", {
  caseId: "H72",
  verified: false,
  outcome: "OUTAGE",
});
d = await evaluate(proposal());
assert.equal(d.evaluation.verdict, "ESCALATE");
await call("/api/proofs/history", {
  caseId: "H72",
  verified: true,
  outcome: "RECOVERED",
});
checks.push("Changing historical outcome changes recovery eligibility");
for (const variant of [
  "no-gateway",
  "failed-standby",
  "hidden-consumer",
  "staging",
]) {
  await reset(variant);
  d = await evaluate(proposal());
  if (variant === "staging") assert.equal(d.evaluation.verdict, "ALLOW");
  else if (variant === "hidden-consumer") {
    assert.equal(d.evaluation.verdict, "REVISE");
    assert.ok(
      d.evaluation.suggestedSteps.some(
        (s: any) => s.targetId === "payment-worker-hidden",
      ),
    );
  } else assert.equal(d.evaluation.verdict, "ESCALATE");
}
checks.push(
  "Gateway, failed standby, hidden consumer and staging variants change decisions",
);
await reset();
p = proposal("quarantine_credential");
d = await evaluate(p);
assert.equal(d.evaluation.verdict, "ALLOW");
const request = {
  authorizationId: d.authorization.authorizationId,
  proposal: p,
  toolCallId: p.proposalId,
  origin: "HISTORICAL_REPLAY",
};
await call(
  "/api/execute",
  { ...request, proposal: { ...p, args: { changed: true } } },
  403,
);
const first = await call("/api/execute", request);
const repeat = await call("/api/execute", request);
assert.equal(first.receipt.receiptId, repeat.receipt.receiptId);
assert.equal(
  (await call(`/api/decisions/${d.evaluation.evaluationId}`)).receipts.length,
  1,
);
assert.deepEqual(
  (await call(`/api/decisions/${trace.evaluation.evaluationId}`)).trace,
  trace.trace,
);
checks.push(
  "Changed arguments rejected; duplicate execution has one receipt; old trace unchanged",
);
await reset();
p = proposal("quarantine_credential");
d = await evaluate(p);
await call("/api/range/configure", { runId, variant: "attack" });
await call(
  "/api/execute",
  {
    authorizationId: d.authorization.authorizationId,
    proposal: p,
    toolCallId: p.proposalId,
  },
  409,
);
checks.push("Topology version changes invalidate authorization");
await reset();
evidence.checks = checks;
writeFileSync(
  "docs/evidence/broker-proof.json",
  JSON.stringify(evidence, null, 2) + "\n",
);
console.log(JSON.stringify({ status: "PASS", checks }, null, 2));
