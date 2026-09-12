import { fileURLToPath } from "node:url";
import { config } from "dotenv";
import Fastify from "fastify";
import {
  ActionProposalSchema,
  RangeSnapshotSchema,
  type ActionProposal,
} from "@precedent/contracts";
import { ServiceMesh } from "./mesh.js";
import { RangeController } from "./index.js";

config({ path: fileURLToPath(new URL("../../../.env", import.meta.url)) });

const brokerToken = process.env.RANGE_BROKER_TOKEN;
if (!brokerToken) {
  throw new Error("RANGE_BROKER_TOKEN must be configured.");
}

const range = new RangeController(
  fileURLToPath(
    new URL("../../../data/range/live-state.json", import.meta.url),
  ),
);
const counterfactualRange = new RangeController(
  fileURLToPath(
    new URL("../../../data/range/counterfactual-state.json", import.meta.url),
  ),
);
const server = Fastify({ logger: true });
const mesh = new ServiceMesh();
const observations: Record<string, Array<Record<string, unknown>>> = {
  live: [],
  counterfactual: [],
};
server.get("/internal/state/:scope", async (request, reply) => {
  if (request.headers["x-range-read-token"] !== mesh.readToken)
    return reply.status(401).send({ error: "Unauthorized state read" });
  return (request.params as { scope: string }).scope === "live"
    ? range.snapshot()
    : counterfactualRange.snapshot();
});
server.post("/internal/observations/:scope", async (request, reply) => {
  if (request.headers["x-observation-token"] !== mesh.observationToken)
    return reply.status(401).send({ error: "Unauthorized observation" });
  const scope = (request.params as { scope: string }).scope;
  if (!observations[scope]) return reply.status(400).send();
  observations[scope]!.push(request.body as Record<string, unknown>);
  observations[scope] = observations[scope]!.slice(-2000);
  return { accepted: true };
});

const authenticateBroker = async (request: {
  headers: Record<string, string | string[] | undefined>;
}) => {
  if (request.headers["x-range-broker-token"] !== brokerToken) {
    throw Object.assign(
      new Error("Range administration is restricted to the broker."),
      {
        statusCode: 401,
      },
    );
  }
};

const bodyProposal = (body: unknown): ActionProposal =>
  ActionProposalSchema.parse((body as { proposal?: unknown }).proposal);

server.get("/health", async () => ({ status: "ok" }));

server.get("/snapshot", { preHandler: authenticateBroker }, async () =>
  range.snapshot(),
);
server.get(
  "/counterfactual/snapshot",
  { preHandler: authenticateBroker },
  async () => counterfactualRange.snapshot(),
);

server.post(
  "/probe/payment",
  { preHandler: authenticateBroker },
  async (request) => {
    const body = request.body as { runId?: string; transactionId?: string };
    if (!body.runId) {
      throw Object.assign(new Error("runId is required."), { statusCode: 400 });
    }
    return mesh.probe(body.runId, "LEGITIMATE_PAYMENT");
  },
);

server.post(
  "/probe/attacker",
  { preHandler: authenticateBroker },
  async (request) => {
    const body = request.body as { runId?: string };
    if (!body.runId) {
      throw Object.assign(new Error("runId is required."), { statusCode: 400 });
    }
    return mesh.probe(body.runId, "ATTACKER");
  },
);

server.post(
  "/probe/ledger",
  { preHandler: authenticateBroker },
  async (request) => {
    const body = request.body as { runId?: string };
    if (!body.runId) {
      throw Object.assign(new Error("runId is required."), { statusCode: 400 });
    }
    const probe = await mesh.probe(body.runId, "LEDGER");
    const committed = new Set(probe.details.transactionIds as string[]);
    const payments = observations.live!.filter(
      (item) =>
        item.probeClass === "LEGITIMATE_PAYMENT" && item.success === true,
    );
    const missing = payments.filter(
      (item) => !committed.has(item.transactionId as string),
    );
    probe.success = missing.length === 0 && range.snapshot().ledgerEnabled;
    probe.details = {
      ...probe.details,
      checkedPayments: payments.length,
      missingTransactions: missing.length,
    };
    return probe;
  },
);

server.post(
  "/admin/mutate",
  { preHandler: authenticateBroker },
  async (request) => {
    const proposal = bodyProposal(request.body);
    const idempotencyKey = request.headers["idempotency-key"];
    if (typeof idempotencyKey !== "string" || idempotencyKey.length === 0) {
      throw Object.assign(new Error("idempotency-key is required."), {
        statusCode: 400,
      });
    }
    if (proposal.actionType === "verify_consumer") {
      const probe = await mesh.probe(
        proposal.runId,
        "LEGITIMATE_PAYMENT",
        "live",
        String(proposal.args.consumerId),
      );
      if (!probe.success)
        throw new Error("Independent consumer payment probe failed.");
    }
    return range.mutate(proposal, idempotencyKey);
  },
);

server.post("/admin/reset", { preHandler: authenticateBroker }, async () =>
  range.reset(),
);

server.post(
  "/counterfactual/admin/mutate",
  { preHandler: authenticateBroker },
  async (request) => {
    const idempotencyKey = request.headers["idempotency-key"];
    if (typeof idempotencyKey !== "string" || idempotencyKey.length === 0) {
      throw Object.assign(new Error("idempotency-key is required."), {
        statusCode: 400,
      });
    }
    return counterfactualRange.counterfactualMutate(
      bodyProposal(request.body),
      idempotencyKey,
    );
  },
);
server.post(
  "/counterfactual/admin/reset",
  { preHandler: authenticateBroker },
  async () => counterfactualRange.reset(),
);
server.post(
  "/counterfactual/probe/payment",
  { preHandler: authenticateBroker },
  async (request) => {
    const body = request.body as { runId?: string };
    if (!body.runId) {
      throw Object.assign(new Error("runId is required."), { statusCode: 400 });
    }
    return mesh.probe(body.runId, "LEGITIMATE_PAYMENT", "counterfactual");
  },
);
server.post(
  "/counterfactual/probe/attacker",
  { preHandler: authenticateBroker },
  async (request) => {
    const body = request.body as { runId?: string };
    if (!body.runId) {
      throw Object.assign(new Error("runId is required."), { statusCode: 400 });
    }
    return mesh.probe(body.runId, "ATTACKER", "counterfactual");
  },
);
server.post(
  "/counterfactual/probe/ledger",
  { preHandler: authenticateBroker },
  async (request) => {
    const body = request.body as { runId?: string };
    if (!body.runId) {
      throw Object.assign(new Error("runId is required."), { statusCode: 400 });
    }
    return mesh.probe(body.runId, "LEDGER", "counterfactual");
  },
);

server.setErrorHandler((error, _request, reply) => {
  const message =
    error instanceof Error ? error.message : "Range request failed.";
  reply.status((error as { statusCode?: number }).statusCode ?? 500).send({
    message,
  });
});

server.post(
  "/admin/configure",
  { preHandler: authenticateBroker },
  async (request) =>
    range.configure(String((request.body as { variant: string }).variant)),
);
server.post(
  "/counterfactual/admin/restore",
  { preHandler: authenticateBroker },
  async (request) =>
    counterfactualRange.restore(
      RangeSnapshotSchema.parse(
        (request.body as { snapshot: unknown }).snapshot,
      ),
    ),
);
server.get("/metrics", { preHandler: authenticateBroker }, async () => {
  const output: Record<string, unknown> = {};
  for (const scope of ["live", "counterfactual"]) {
    const entries = observations[scope]!;
    const payment = entries.filter(
      (item) => item.probeClass === "LEGITIMATE_PAYMENT",
    );
    const attacker = entries.filter((item) => item.probeClass === "ATTACKER");
    output[scope] = {
      windowStart: entries[0]?.observedAt ?? null,
      windowEnd: entries.at(-1)?.observedAt ?? null,
      paymentSuccesses: payment.filter((item) => item.success).length,
      paymentFailures: payment.filter((item) => !item.success).length,
      attackerSuccesses: attacker.filter((item) => item.success).length,
      attackerBlocked: attacker.filter((item) => !item.success).length,
      reachableCriticalAssets: attacker.at(-1)?.success ? 2 : 0,
    };
  }
  return output;
});
const port = Number(process.env.RANGE_PORT ?? 3002);
await server.listen({ host: process.env.RANGE_HOST ?? "127.0.0.1", port });
await mesh.start();
