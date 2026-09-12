import { readFileSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import assert from "node:assert/strict";
const env = Object.fromEntries(
  readFileSync(process.env.RANGE_ENV_FILE ?? ".env.range", "utf8")
    .split("\n")
    .filter((line) => line.includes("="))
    .map((line) => {
      const i = line.indexOf("=");
      return [line.slice(0, i), line.slice(i + 1)];
    }),
);
const base = process.env.TEST_RANGE_URL ?? "http://127.0.0.1:3102";
const runId = `range-proof-${randomUUID()}`;
const request = async (
  path: string,
  body?: unknown,
  token = env.RANGE_BROKER_TOKEN,
) => {
  const response = await fetch(base + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "content-type": "application/json",
      "x-range-broker-token": token!,
      "idempotency-key": randomUUID(),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(JSON.stringify(result));
  return result;
};
const proposal = (actionType: string, targetId: string, args = {}) => ({
  proposalId: randomUUID(),
  runId,
  actionType,
  targetId,
  args,
  evidenceIds: ["evidence-H72"],
  rationaleSummary: "Isolated service proof",
});
const mutate = (type: string, target: string, args = {}) =>
  request("/admin/mutate", { proposal: proposal(type, target, args) });
const results: Record<string, unknown> = {
  runId,
  recordedAt: new Date().toISOString(),
};
await request("/admin/reset", {});
assert.equal((await request("/probe/payment", { runId })).success, true);
assert.equal((await request("/probe/attacker", { runId })).success, true);
await mutate("isolate_device", "compromised-laptop");
assert.equal((await request("/probe/attacker", { runId })).success, true);
results.deviceIsolationDoesNotStopCopy = true;
const initial = await request("/snapshot");
await request("/counterfactual/admin/restore", { snapshot: initial });
await request("/counterfactual/admin/mutate", {
  proposal: proposal("revoke_credential", "payments-key-v1"),
});
assert.equal(
  (await request("/counterfactual/probe/payment", { runId })).success,
  false,
);
assert.equal((await request("/probe/payment", { runId })).success, true);
results.counterfactualOutageAndIsolation = true;
await mutate("quarantine_credential", "payments-key-v1");
assert.equal((await request("/probe/attacker", { runId })).success, false);
assert.equal((await request("/probe/payment", { runId })).success, true);
await mutate("invalidate_session", "hostile-session");
await mutate("create_credential", "payments-key-v2");
for (const id of ["payment-worker-b", "payment-worker-a"]) {
  await mutate("deploy_credential", id, {
    consumerId: id,
    credentialId: "payments-key-v2",
  });
  await mutate("verify_consumer", id, { consumerId: id });
  if (id.endsWith("-b")) await mutate("switch_traffic", id, { workerId: id });
  assert.equal((await request("/probe/payment", { runId })).success, true);
}
await mutate("revoke_credential", "payments-key-v1");
results.finalPayment = await request("/probe/payment", { runId });
results.finalAttacker = await request("/probe/attacker", { runId });
results.ledger = await request("/probe/ledger", { runId });
assert.equal((results.finalPayment as { success: boolean }).success, true);
assert.equal((results.finalAttacker as { success: boolean }).success, false);
assert.equal((results.ledger as { success: boolean }).success, true);
results.metrics = await request("/metrics");
await assert.rejects(
  request(
    "/admin/mutate",
    { proposal: proposal("disable_service", "ledger-service") },
    "invalid-token",
  ),
);
results.directAdministrationDenied = true;
writeFileSync(
  "docs/evidence/range-proof.json",
  JSON.stringify(results, null, 2) + "\n",
);
console.log(
  "PASS: real HTTP payments, copied attacker, isolation, quarantine, migration, ledger, counterfactual and admin denial.",
);
