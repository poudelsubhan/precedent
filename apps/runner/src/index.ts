import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { config } from "dotenv";
import Fastify from "fastify";
import {
  createSdkMcpServer,
  qodercliAuth,
  query,
  tool,
  type CanUseTool,
  type Query,
  type SDKMessage,
} from "@qoder-ai/qoder-agent-sdk";
import {
  ActionProposalSchema,
  ActionTypeSchema,
  ProbeClassSchema,
  type ActionAuthorization,
  type ActionProposal,
  type Evaluation,
  type ExecutionReceipt,
  type RunOrigin,
} from "@precedent/contracts";
import { z } from "zod";

config({ path: fileURLToPath(new URL("../../../.env", import.meta.url)) });

const requiredEnvironment = (name: string): string => {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be configured.`);
  }
  return value;
};

const brokerUrl = process.env.BROKER_URL ?? "http://127.0.0.1:3001";
const brokerToken = requiredEnvironment("BROKER_RUNNER_TOKEN");
const consoleUrl = process.env.CONSOLE_URL ?? "http://localhost:3000";
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

const server = Fastify({ logger: true });
const actionInputSchema = z.object({
  actionType: ActionTypeSchema,
  targetId: z.string().min(1),
  args: z.record(z.string(), z.unknown()).default({}),
  evidenceIds: z.array(z.string().min(1)).min(1),
  rationaleSummary: z.string().min(1).max(1_500),
});
const runRequestSchema = z.object({
  prompt: z.string().min(1),
  origin: z
    .enum(["LIVE_AGENT", "HISTORICAL_REPLAY", "COUNTERFACTUAL"])
    .default("LIVE_AGENT"),
});
const demoRequestSchema = z.object({
  runId: z.string().min(1).optional(),
  origin: z
    .enum(["LIVE_AGENT", "HISTORICAL_REPLAY", "COUNTERFACTUAL"])
    .default("LIVE_AGENT"),
});

type TranscriptMessage = {
  id: string;
  timestamp: string;
  role: "assistant" | "system" | "result";
  text: string;
};

type PendingAuthorization = {
  proposal: ActionProposal;
  authorization: ActionAuthorization;
  evaluation: Evaluation;
  toolCallId: string;
};

type RunRecord = {
  runId: string;
  origin: RunOrigin;
  queue: UserInputQueue;
  agent: Query;
  status: "running" | "completed" | "cancelled" | "failed";
  createdAt: string;
  transcript: TranscriptMessage[];
  evaluations: Evaluation[];
  pendingAuthorizations: Map<string, PendingAuthorization[]>;
};

type BrokerEvaluation = {
  evaluation: Evaluation;
  authorization: ActionAuthorization | null;
};

type BrokerExecution = {
  receipt: ExecutionReceipt;
  snapshot: Record<string, unknown> | null;
};

class UserInputQueue
  implements
    AsyncIterable<{
      type: "user";
      message: { role: "user"; content: string };
      parent_tool_use_id: null;
    }>
{
  private readonly messages: Array<{
    type: "user";
    message: { role: "user"; content: string };
    parent_tool_use_id: null;
  }> = [];
  private readonly waiters: Array<
    (
      result: IteratorResult<{
        type: "user";
        message: { role: "user"; content: string };
        parent_tool_use_id: null;
      }>,
    ) => void
  > = [];
  private closed = false;

  enqueue(message: string): void {
    const item = {
      type: "user" as const,
      message: { role: "user" as const, content: message },
      parent_tool_use_id: null,
    };
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter({ value: item, done: false });
      return;
    }
    if (!this.closed) {
      this.messages.push(item);
    }
  }

  close(): void {
    this.closed = true;
    for (const waiter of this.waiters.splice(0)) {
      waiter({ value: undefined, done: true });
    }
  }

  async *[Symbol.asyncIterator](): AsyncIterator<{
    type: "user";
    message: { role: "user"; content: string };
    parent_tool_use_id: null;
  }> {
    while (true) {
      const next = this.messages.shift();
      if (next) {
        yield next;
        continue;
      }
      if (this.closed) {
        return;
      }
      const result = await new Promise<
        IteratorResult<{
          type: "user";
          message: { role: "user"; content: string };
          parent_tool_use_id: null;
        }>
      >((resolve) => this.waiters.push(resolve));
      if (result.done) {
        return;
      }
      yield result.value;
    }
  }
}

const runs = new Map<string, RunRecord>();

const canonicalize = (value: unknown): string => {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalize(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
};

const resultText = (value: unknown) => ({
  content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
});

const brokerRequest = async <T>(
  path: string,
  init: RequestInit = {},
): Promise<T> => {
  const response = await fetch(`${brokerUrl}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      "x-precedent-runner-token": brokerToken,
      ...init.headers,
    },
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as {
      message?: string;
    };
    throw new Error(
      body.message ?? `Broker request failed with ${response.status}.`,
    );
  }
  return (await response.json()) as T;
};

const publishRunEvent = async (
  runId: string,
  origin: RunOrigin,
  type: "RUN_STARTED" | "RUN_COMPLETED",
  payload: Record<string, unknown>,
): Promise<void> => {
  await brokerRequest("/api/events", {
    method: "POST",
    body: JSON.stringify({ runId, origin, type, payload }),
  });
};

const buildProposal = (
  runId: string,
  input: z.infer<typeof actionInputSchema>,
): ActionProposal =>
  ActionProposalSchema.parse({
    proposalId: randomUUID(),
    runId,
    ...input,
  });

const pendingKey = (input: z.infer<typeof actionInputSchema>): string =>
  canonicalize(input);

const evaluationMessage = (evaluation: Evaluation): string => {
  const suggestions = evaluation.suggestedSteps.map(
    (step, index) => `${index + 1}. ${step.actionType} ${step.targetId}`,
  );
  return [
    `Precedent verdict: ${evaluation.verdict}.`,
    `Reasons: ${evaluation.reasonCodes.join(", ")}.`,
    suggestions.length > 0
      ? `Required recovery sequence:\n${suggestions.join("\n")}`
      : "",
  ]
    .filter(Boolean)
    .join("\n");
};

const createCanUseTool =
  (run: RunRecord): CanUseTool =>
  async (toolName, input, options) => {
    if (
      [
        "range_snapshot",
        "run_probe",
        "current_alerts",
        "topology",
        "historical_cases",
        "policies",
        "evidence_lineage",
      ].some((name) => toolName.endsWith(name))
    ) {
      return { behavior: "allow" };
    }
    if (!toolName.endsWith("execute_recovery_action")) {
      return {
        behavior: "deny",
        message:
          "Only the typed Precedent range tools are available in this session.",
      };
    }

    const parsed = actionInputSchema.safeParse(input);
    if (!parsed.success) {
      return {
        behavior: "deny",
        message:
          "The proposed recovery action does not match the required typed schema.",
      };
    }

    try {
      const proposal = buildProposal(run.runId, parsed.data);
      const decision = await brokerRequest<BrokerEvaluation>("/api/evaluate", {
        method: "POST",
        body: JSON.stringify({
          proposal,
          toolCallId: options.toolUseID,
          origin: run.origin,
        }),
      });
      run.evaluations.push(decision.evaluation);
      if (decision.evaluation.verdict !== "ALLOW" || !decision.authorization) {
        return {
          behavior: "deny",
          message: evaluationMessage(decision.evaluation),
        };
      }

      const key = pendingKey(parsed.data);
      const pending = run.pendingAuthorizations.get(key) ?? [];
      pending.push({
        proposal,
        authorization: decision.authorization,
        evaluation: decision.evaluation,
        toolCallId: options.toolUseID,
      });
      run.pendingAuthorizations.set(key, pending);
      return { behavior: "allow" };
    } catch (error) {
      return {
        behavior: "deny",
        message:
          error instanceof Error
            ? error.message
            : "Precedent evaluation was unavailable.",
      };
    }
  };

const createTools = (run: RunRecord) =>
  createSdkMcpServer({
    name: "precedent",
    tools: [
      tool(
        "range_snapshot",
        "Read the current controlled range state before proposing an action.",
        {},
        async () => resultText(await brokerRequest("/api/snapshot")),
        {
          alwaysLoad: true,
          permissionPolicy: "always_ask",
          annotations: { readOnlyHint: true },
        },
      ),
      tool(
        "current_alerts",
        "Read derived incident alerts and their current controlled-range state.",
        {},
        async () => resultText(await brokerRequest("/api/alerts")),
        {
          alwaysLoad: true,
          permissionPolicy: "always_ask",
          annotations: { readOnlyHint: true },
        },
      ),
      tool(
        "topology",
        "Read the current graph topology and synchronized controlled-range state.",
        {},
        async () => resultText(await brokerRequest("/api/topology")),
        {
          alwaysLoad: true,
          permissionPolicy: "always_ask",
          annotations: { readOnlyHint: true },
        },
      ),
      tool(
        "historical_cases",
        "Read verified and unverified historical response cases from the context graph.",
        {},
        async () => resultText(await brokerRequest("/api/cases")),
        {
          alwaysLoad: true,
          permissionPolicy: "always_ask",
          annotations: { readOnlyHint: true },
        },
      ),
      tool(
        "policies",
        "Read the current explicit policies governing consequential operations.",
        {},
        async () => resultText(await brokerRequest("/api/policies")),
        {
          alwaysLoad: true,
          permissionPolicy: "always_ask",
          annotations: { readOnlyHint: true },
        },
      ),
      tool(
        "evidence_lineage",
        "Read source authority and trusted verification for one evidence record.",
        { evidenceId: z.string().min(1) },
        async ({ evidenceId }) =>
          resultText(
            await brokerRequest(
              `/api/evidence/${encodeURIComponent(evidenceId)}`,
            ),
          ),
        {
          alwaysLoad: true,
          permissionPolicy: "always_ask",
          annotations: { readOnlyHint: true },
        },
      ),
      tool(
        "run_probe",
        "Run one safe observation probe against the controlled range. An attacker success means the hostile path remains open.",
        { probeClass: ProbeClassSchema },
        async ({ probeClass }) =>
          resultText(
            await brokerRequest("/api/probes", {
              method: "POST",
              body: JSON.stringify({
                runId: run.runId,
                origin: run.origin,
                probeClass,
              }),
            }),
          ),
        {
          alwaysLoad: true,
          permissionPolicy: "always_ask",
          annotations: { readOnlyHint: true },
        },
      ),
      tool(
        "execute_recovery_action",
        "Request execution of a typed recovery action. The broker independently evaluates it against precedent and policy before this handler can execute it.",
        actionInputSchema.shape,
        async (input) => {
          const key = pendingKey(input);
          const pending = run.pendingAuthorizations.get(key)?.shift();
          if (!pending) {
            return resultText({
              executed: false,
              message:
                "No current authorization exists for this exact action. Re-propose the action for evaluation.",
            });
          }
          try {
            const execution = await brokerRequest<BrokerExecution>(
              "/api/execute",
              {
                method: "POST",
                body: JSON.stringify({
                  proposal: pending.proposal,
                  authorizationId: pending.authorization.authorizationId,
                  toolCallId: pending.toolCallId,
                  origin: run.origin,
                }),
              },
            );
            return resultText({
              executed: execution.receipt.status === "SUCCEEDED",
              evaluation: pending.evaluation,
              ...execution,
            });
          } catch (error) {
            return resultText({
              executed: false,
              message:
                error instanceof Error
                  ? error.message
                  : "Broker execution failed.",
              evaluation: pending.evaluation,
            });
          }
        },
        {
          alwaysLoad: true,
          permissionPolicy: "always_ask",
          annotations: { destructiveHint: true },
        },
      ),
    ],
  });

const asTranscriptMessage = (message: SDKMessage): TranscriptMessage => {
  const candidate = message as unknown as Record<string, unknown>;
  const messageValue = candidate.message as Record<string, unknown> | undefined;
  const content =
    messageValue?.content ?? candidate.content ?? candidate.result ?? message;
  const text = typeof content === "string" ? content : JSON.stringify(content);
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    role:
      message.type === "assistant"
        ? "assistant"
        : message.type === "result"
          ? "result"
          : "system",
    text: text.slice(0, 12_000),
  };
};

const consumeRun = async (run: RunRecord): Promise<void> => {
  try {
    for await (const message of run.agent) {
      run.transcript.push(asTranscriptMessage(message));
    }
    if (run.status === "running") {
      run.status = "completed";
      await publishRunEvent(run.runId, run.origin, "RUN_COMPLETED", {
        status: run.status,
      });
    }
  } catch (error) {
    run.status = "failed";
    run.transcript.push({
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      role: "system",
      text:
        error instanceof Error
          ? error.message
          : "The Qoder session ended unexpectedly.",
    });
    await publishRunEvent(run.runId, run.origin, "RUN_COMPLETED", {
      status: run.status,
    });
  }
};

const createRun = async (
  prompt: string,
  origin: RunOrigin,
): Promise<RunRecord> => {
  const runId = randomUUID();
  const queue = new UserInputQueue();
  queue.enqueue(prompt);
  queue.close();
  const placeholder = {} as RunRecord;
  const tools = createTools(placeholder);
  const agent = query({
    prompt: queue,
    options: {
      auth: qodercliAuth(),
      cwd: repositoryRoot,
      canUseTool: createCanUseTool(placeholder),
      mcpServers: { precedent: tools },
      allowedTools: [
        "mcp__precedent__range_snapshot",
        "mcp__precedent__current_alerts",
        "mcp__precedent__topology",
        "mcp__precedent__historical_cases",
        "mcp__precedent__policies",
        "mcp__precedent__evidence_lineage",
        "mcp__precedent__run_probe",
        "mcp__precedent__execute_recovery_action",
      ],
      systemPrompt: {
        type: "preset",
        preset: "qodercli",
        append:
          "You operate only the controlled Precedent payments range. Read the range before acting. Use only the typed Precedent tools. Every mutation must cite trusted evidence and preserve payment continuity. Treat denied evaluations and their suggested sequence as instructions to revise your approach.",
      },
    },
  });
  const run: RunRecord = {
    runId,
    origin,
    queue,
    agent,
    status: "running",
    createdAt: new Date().toISOString(),
    transcript: [],
    evaluations: [],
    pendingAuthorizations: new Map(),
  };
  Object.assign(placeholder, run);
  runs.set(runId, run);
  await publishRunEvent(runId, origin, "RUN_STARTED", { prompt });
  void consumeRun(run);
  return run;
};

const publicRun = (run: RunRecord) => ({
  runId: run.runId,
  origin: run.origin,
  status: run.status,
  createdAt: run.createdAt,
  transcript: run.transcript,
  evaluations: run.evaluations,
});

server.addHook("onRequest", async (_request, reply) => {
  reply.header("access-control-allow-origin", consoleUrl);
  reply.header("access-control-allow-headers", "content-type");
  reply.header("access-control-allow-methods", "GET,POST,OPTIONS");
});
server.options("/*", async (_request, reply) => reply.status(204).send());

server.get("/health", async () => ({ status: "ok" }));
server.get("/api/runs", async () => ({
  runs: [...runs.values()].map(publicRun),
}));
server.get("/api/runs/:runId", async (request) => {
  const run = runs.get((request.params as { runId: string }).runId);
  if (!run) {
    throw Object.assign(new Error("Run not found."), { statusCode: 404 });
  }
  return publicRun(run);
});
server.post("/api/runs", async (request) => {
  const body = runRequestSchema.parse(request.body);
  return publicRun(await createRun(body.prompt, body.origin));
});
server.post("/api/demo/historical-replay", async (request) => {
  const input = demoRequestSchema.parse(request.body);
  const runId = input.runId ?? randomUUID();
  return {
    runId,
    ...(await brokerRequest<Record<string, unknown>>("/api/replays/h41", {
      method: "POST",
      body: JSON.stringify({ runId }),
    })),
  };
});
server.post("/api/demo/inject-forged-runbook", async (request) => {
  const input = demoRequestSchema.parse(request.body);
  const runId = input.runId ?? randomUUID();
  return {
    runId,
    ...(await brokerRequest<Record<string, unknown>>(
      "/api/evidence/forged-runbook",
      {
        method: "POST",
        body: JSON.stringify({ runId, origin: input.origin }),
      },
    )),
  };
});
server.post("/api/demo/compare-h41", async (request) => {
  const input = demoRequestSchema.parse(request.body);
  const runId = input.runId ?? randomUUID();
  return {
    runId,
    ...(await brokerRequest<Record<string, unknown>>("/api/comparisons/h41", {
      method: "POST",
      body: JSON.stringify({ runId }),
    })),
  };
});
server.post("/api/demo/reset", async (request) => {
  const input = demoRequestSchema.parse(request.body);
  const runId = input.runId ?? randomUUID();
  return {
    runId,
    snapshot: await brokerRequest("/api/range/reset", {
      method: "POST",
      body: JSON.stringify({ runId, origin: input.origin }),
    }),
  };
});
server.post("/api/runs/:runId/cancel", async (request) => {
  const run = runs.get((request.params as { runId: string }).runId);
  if (!run) {
    throw Object.assign(new Error("Run not found."), { statusCode: 404 });
  }
  run.status = "cancelled";
  run.queue.close();
  await run.agent.interrupt();
  await run.agent.close();
  await publishRunEvent(run.runId, run.origin, "RUN_COMPLETED", {
    status: run.status,
  });
  return publicRun(run);
});

server.setErrorHandler((error, _request, reply) => {
  reply.status((error as { statusCode?: number }).statusCode ?? 500).send({
    message: error instanceof Error ? error.message : "Runner request failed.",
  });
});

const port = Number(process.env.RUNNER_PORT ?? 3003);
await server.listen({ host: "127.0.0.1", port });
