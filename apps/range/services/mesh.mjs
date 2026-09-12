import http from "node:http";
import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";
import { mkdirSync, appendFileSync, readFileSync, existsSync } from "node:fs";

const role = process.env.SERVICE_ROLE;
const port = Number(process.env.SERVICE_PORT || 4100);
const controller = process.env.CONTROLLER_URL || "http://127.0.0.1:3002";
const scope = process.env.RANGE_SCOPE || "live";
const readToken = process.env.RANGE_READ_TOKEN;
const workerSecrets = JSON.parse(process.env.WORKLOAD_SECRETS || "{}");
const gateway = process.env.GATEWAY_URL || "http://127.0.0.1:4101";
const ledger = process.env.LEDGER_URL || "http://127.0.0.1:4102";
const checkout = process.env.CHECKOUT_URL || "http://127.0.0.1:4100";
const ledgerToken = process.env.LEDGER_TOKEN;
const workers = JSON.parse(process.env.WORKER_URLS || "{}");
const secret = process.env.WORKLOAD_SECRET;
const workerId = process.env.WORKER_ID;
const json = async (url, body, headers = {}) => {
  const response = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(3000),
  });
  return {
    ok: response.ok,
    status: response.status,
    body: await response.json(),
  };
};
const state = async () =>
  (
    await json(`${controller}/internal/state/${scope}`, undefined, {
      "x-range-read-token": readToken,
    })
  ).body;
const sign = (key, data) =>
  createHmac("sha256", key).update(JSON.stringify(data)).digest("hex");
const equal = (a, b) =>
  typeof a === "string" &&
  typeof b === "string" &&
  a.length === b.length &&
  timingSafeEqual(Buffer.from(a), Buffer.from(b));
const nonces = new Map();
const commits = new Set();
const dataDir = process.env.DATA_DIR || "/tmp/precedent-range";
mkdirSync(dataDir, { recursive: true });
const ledgerFile = `${dataDir}/${scope}-ledger.jsonl`;
if (role === "ledger" && existsSync(ledgerFile))
  for (const line of readFileSync(ledgerFile, "utf8")
    .split("\n")
    .filter(Boolean))
    commits.add(JSON.parse(line).transactionId);
const handle = async (path, body, headers) => {
  if (path === "/health") return [200, { role, scope }];
  if (role === "ledger") {
    if (!equal(headers["x-ledger-token"], ledgerToken))
      return [401, { error: "Ledger writer not authenticated" }];
    if (path === "/entries") return [200, { transactionIds: [...commits] }];
    if (path === "/commit" && typeof body.transactionId === "string") {
      const duplicate = commits.has(body.transactionId);
      if (!duplicate) {
        appendFileSync(
          ledgerFile,
          JSON.stringify({
            transactionId: body.transactionId,
            committedAt: new Date().toISOString(),
          }) + "\n",
        );
        commits.add(body.transactionId);
      }
      return [
        200,
        { transactionId: body.transactionId, committed: true, duplicate },
      ];
    }
  }
  if (role === "gateway") {
    if (path === "/audit") {
      if (!equal(headers["x-range-read-token"], readToken))
        return [401, { error: "Audit not authenticated" }];
      const result = await json(`${ledger}/entries`, undefined, {
        "x-ledger-token": ledgerToken,
      });
      return [result.status, result.body];
    }
    if (path === "/authorize") {
      const current = await state();
      const envelope = body.envelope;
      let authenticated = false;
      if (
        envelope &&
        workerSecrets[envelope.workerId] &&
        Math.abs(Date.now() - envelope.timestamp) < 10000 &&
        typeof envelope.nonce === "string"
      ) {
        for (const [nonce, expires] of nonces)
          if (expires < Date.now()) nonces.delete(nonce);
        authenticated =
          !nonces.has(envelope.nonce) &&
          equal(
            body.signature,
            sign(workerSecrets[envelope.workerId], envelope),
          );
        if (authenticated) nonces.set(envelope.nonce, Date.now() + 10000);
      }
      const credentialId = authenticated
        ? envelope.credentialId
        : body.credentialId;
      const worker =
        authenticated &&
        current.workers.find(
          (item) => item.id === envelope.workerId && item.active,
        );
      const workerAllowed = Boolean(
        worker &&
          worker.credentialId === credentialId &&
          !current.failedWorkerIds.includes(worker.id),
      );
      const usable =
        credentialId === "payments-key-v1"
          ? current.credentialState !== "REVOKED" &&
            (current.credentialState !== "QUARANTINED" ||
              (current.trustedGateway && workerAllowed))
          : credentialId === "payments-key-v2" &&
            current.activeCredentialId === credentialId &&
            workerAllowed;
      if (!usable) return [403, { authorized: false }];
      if (!authenticated) {
        if (!current.attackActive) return [403, { authorized: false }];
        if (
          body.accessMode === "device-session" &&
          (current.compromisedDeviceIsolated ||
            current.hostileSessionsInvalidated)
        )
          return [403, { authorized: false }];
        return [
          200,
          {
            authorized: true,
            accessMode: body.accessMode,
            reachableAssets: ["ledger-service", "checkout-api"],
          },
        ];
      }
      if (!workerAllowed || !current.ledgerEnabled)
        return [503, { error: "Payment path unavailable" }];
      const result = await json(
        `${ledger}/commit`,
        { transactionId: envelope.transactionId },
        { "x-ledger-token": ledgerToken },
      );
      return [result.status, result.body];
    }
  }
  if (role === "worker" && path === "/pay") {
    const current = await state();
    const worker = current.workers.find((item) => item.id === workerId);
    if (!worker?.active || current.failedWorkerIds.includes(workerId))
      return [503, { error: "Worker unavailable" }];
    const envelope = {
      workerId,
      credentialId: worker.credentialId,
      transactionId: body.transactionId,
      nonce: randomUUID(),
      timestamp: Date.now(),
    };
    const result = await json(`${gateway}/authorize`, {
      envelope,
      signature: sign(secret, envelope),
    });
    return [result.status, { ...result.body, workerId }];
  }
  if (role === "checkout" && path === "/pay") {
    const current = await state();
    const selected = body.probeWorkerId || current.trafficWorkerId;
    if (!workers[selected]) return [503, { error: "No worker route" }];
    const result = await json(`${workers[selected]}/pay`, {
      transactionId: body.transactionId,
    });
    return [result.status, result.body];
  }
  if ((role === "attacker" || role === "load") && path === "/probe") {
    const transactionId = body.transactionId || randomUUID();
    const result =
      role === "load"
        ? await json(`${checkout}/pay`, {
            transactionId,
            probeWorkerId: body.probeWorkerId,
          })
        : await json(`${gateway}/authorize`, {
            credentialId: "payments-key-v1",
            accessMode: body.accessMode || "off-device",
          });
    return [
      200,
      {
        success: result.ok,
        httpStatus: result.status,
        transactionId,
        response: result.body,
        observedAt: new Date().toISOString(),
      },
    ];
  }
  return [404, { error: "Unknown operation" }];
};
const server = http.createServer(async (req, res) => {
  try {
    let raw = "";
    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > 65536) throw new Error("Request too large");
    }
    const [status, result] = await handle(
      req.url,
      raw ? JSON.parse(raw) : {},
      req.headers,
    );
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(result));
  } catch {
    res.writeHead(503, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Service unavailable" }));
  }
});
server.listen(port, process.env.SERVICE_HOST || "127.0.0.1");
if (role === "load" || role === "attacker") {
  let running = false;
  setInterval(async () => {
    if (running) return;
    running = true;
    try {
      const [, observation] = await handle("/probe", {}, {});
      await json(
        `${controller}/internal/observations/${scope}`,
        {
          ...observation,
          probeClass: role === "load" ? "LEGITIMATE_PAYMENT" : "ATTACKER",
        },
        { "x-observation-token": process.env.OBSERVATION_TOKEN },
      );
    } catch {
    } finally {
      running = false;
    }
  }, 500).unref();
}
