import { fileURLToPath } from "node:url";
import { config } from "dotenv";
import Fastify from "fastify";
import {
  ActionProposalSchema,
  type ActionProposal,
} from "@precedent/contracts";
import { RangeController } from "./index.js";

config({ path: fileURLToPath(new URL("../../../.env", import.meta.url)) });

const brokerToken = process.env.RANGE_BROKER_TOKEN;
if (!brokerToken) {
  throw new Error("RANGE_BROKER_TOKEN must be configured.");
}

const range = new RangeController();
const counterfactualRange = new RangeController();
const server = Fastify({ logger: true });

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
    return range.paymentProbe(body.runId, body.transactionId);
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
    return range.attackerProbe(body.runId);
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
    return range.ledgerProbe(body.runId);
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
    return counterfactualRange.paymentProbe(body.runId);
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
    return counterfactualRange.attackerProbe(body.runId);
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
    return counterfactualRange.ledgerProbe(body.runId);
  },
);

server.setErrorHandler((error, _request, reply) => {
  const message =
    error instanceof Error ? error.message : "Range request failed.";
  reply.status((error as { statusCode?: number }).statusCode ?? 500).send({
    message,
  });
});

const port = Number(process.env.RANGE_PORT ?? 3002);
await server.listen({ host: "127.0.0.1", port });
