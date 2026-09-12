# Precedent

**Precedent checks an AI agent’s next action against what the system depends on and what happened before.**

Precedent helps an AI responder avoid fixing one problem by creating another. It brings together current dependencies, company policies, past incidents, and evidence sources before an action can run.

For example, an attacker copies a payments credential at the fictional Nexus Financial. Revoking it immediately would also break payments because the payment workers still use it. Precedent blocks that proposal and shows the dependencies and past cases behind the decision.

The intended recovery is to restrict the compromised credential, move the workers to a replacement, check that payments still work, and then revoke the old credential. Each action needs its own approval. A forged runbook cannot approve shutting down the ledger just by saying a security leader signed it.

The local demonstration runs real HTTP payment and attacker requests against a controlled payments range. A recorded Qoder run completed recovery, passed independent checks, and created a verified case. A fresh agent session then cited that new case and recovered another incident. The [evidence report](docs/evidence/live-recovery.json) contains the original decisions, receipts, and probe results.

> Check the context. Explain the decision. Verify the outcome.

[Silent 2:40 recorded demo](docs/media/recorded-demo.mp4) · [Your narration script](docs/demo-script.md) · [Build evidence](docs/build-audit.md) · [Design decisions](docs/design-principles.md)

## How it works

| Step        | What Precedent does                                                                    |
| ----------- | -------------------------------------------------------------------------------------- |
| Investigate | Qoder reads the incident, system dependencies, policies, and past cases.               |
| Check       | Precedent evaluates a proposed action and the evidence it cites.                       |
| Intervene   | It allows the action, blocks it, suggests a revision, or asks for missing information. |
| Execute     | A separate broker checks the approval before changing the demo environment.            |
| Verify      | Independent requests check payments, attacker access, and the ledger.                  |
| Remember    | Verified payment, attacker, and ledger results turn a recovery into a trusted case.    |

## Architecture

```mermaid
flowchart TD
    Incident[Incident and evidence] --> Qoder[Qoder response agent]
    Qoder --> Proposal[Proposed action]
    Proposal --> Gate[Precedent checks the action]
    Memory[Neo4j: dependencies, policies, history, sources] <--> Gate
    Gate -->|Blocked with reasons| Qoder
    Gate -->|Exact action approval| Broker[Execution broker]
    Broker --> Range[Isolated HTTP payments range]
    Range --> Probes[Check the outcome]
    Probes --> Learning[Recovery promotion]
    Learning --> Memory
    Gate --> Console[Precedent console]
    Broker --> Console
    Probes --> Console
```

The agent proposes actions. The broker controls execution. The console shows decisions and receipts; it does not create approvals.

Approvals are tied to the action, arguments, caller, run, state version, and expiry. The broker records an execution intent before a mutation. An uncertain result is marked unknown instead of being reported as successful.

## What we checked

- **Blocked revocation:** the H41 historical proposal receives `REVISE` while payment workers still use the old credential.
- **Evidence rejection:** the evaluator rejects untrusted evidence before allowing the requested action.
- **Copied credentials:** the range tests show that isolating the originating laptop does not stop off-device use of a copied credential.
- **Recovery guards:** tests cover migration, traffic switching, revocation, and duplicate mutation handling in the HTTP range.
- **Console behavior:** the interface separates live agent events, historical replay, and counterfactual results. It exposes decision paths, execution receipts, probe times, and a selected-decision export.
- **Frontend checks:** tests cover stale response protection, request cancellation, and invalid response data. Type checking and the production build are separate checks.

The [acceptance evidence](docs/evidence/broker-proof.json) also covers altered arguments, duplicate execution, stale approvals, changed history, missing gateways, failed standby workers, additional consumers, and staging. Decision reports retain the facts and graph queries used at evaluation. See the [audit](docs/build-audit.md) for measured acceptance and submission status.

The historical cases H41, H72, H89, and H97 are fictional fixtures. They are created in `packages/graph/src/index.ts`. The range does not reproduce AWS IAM or operate a real payment network.

## How Qoder and Neo4j fit the project

| Technology             | Its role                                                                                                                                                             |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Qoder                  | Runs the response agent, discovers typed MCP tools, and receives permission decisions before execution. The SDK is pinned to `@qoder-ai/qoder-agent-sdk` **1.0.39**. |
| Neo4j                  | Stores dependencies, policies, source relationships, historical cases, evaluations, approvals, and execution records.                                                |
| Next.js and React Flow | Present the action stream, infrastructure graph, and evidence inspector.                                                                                             |
| TypeScript and Zod     | Define shared data contracts and check incoming data.                                                                                                                |

The runtime uses the local Qoder CLI session through `qodercliAuth()`. The recorded runtime evidence includes actual SDK permission callbacks, a revised proposal with no execution receipt, and approved actions with receipts. Qoder development review was waived by the project owner; runtime evidence is labeled separately.

## Run locally

Requires Node.js 24+, npm 11+, a reachable Neo4j database, and an authenticated Qoder CLI session for live agent responses.

```sh
npm ci
cp .env.example .env
```

In `.env`, set the Neo4j connection details. Set `BROKER_RUNNER_TOKEN` and `RANGE_BROKER_TOKEN` to different random secrets. Keep this file out of version control. The example file lists the service addresses.

Authenticate your installed Qoder CLI, then start the workspace:

```sh
qodercli login
npm run dev
```

Open [localhost:3000](http://localhost:3000).

| Service | Local address    | What it runs                     |
| ------- | ---------------- | -------------------------------- |
| Console | `localhost:3000` | The incident interface           |
| Broker  | `127.0.0.1:3001` | Evaluation and execution checks  |
| Range   | `127.0.0.1:3002` | The controlled HTTP range        |
| Runner  | `127.0.0.1:3003` | Qoder sessions and demo controls |

### Run the container range

The native development command starts separate Node processes. Docker provides the isolated range: checkout, two workers, gateway, ledger, legitimate load, and two attacker processes, plus an independent counterfactual copy.

```sh
node scripts/configure-range.mjs
docker compose --env-file .env.range -f compose.range.yaml up -d --build
npx tsx scripts/prove-range.ts
node scripts/run-broker-proof.mjs
```

The controller listens on `127.0.0.1:3102`. Service traffic stays on Docker's internal network. To connect the normal broker to this range, set `RANGE_URL=http://127.0.0.1:3102` and use the range token generated in `.env.range`. Keep both environment files private. The broker proof temporarily uses the configured fictional Neo4j fixtures; run it while no agent incident is active.

## Try the demo

1. **Replay H41 proposal.** Inspect a blocked credential revocation with a visible historical replay label. Select **Show me why** to read its evidence and paths.
2. **Compare response.** Clone the current live state into a separate counterfactual range and measure what immediate revocation does there. Run this before recovery for the outage comparison.
3. **Launch attack response.** Start a real Qoder session and follow its proposed actions. The current scenario already begins with a compromised credential; this button starts the response.

Under **Scenario tools & reset**, inject the forged runbook, start a fresh incident while keeping memory, or restore the seeded fixture. Gateway, additional-consumer, failed-standby, and staging variants exercise different decisions. In the expanded decision trace, **Export selected decision** downloads that decision and the retained events for its run. **Export complete run report** includes all persisted events, decisions, receipts, measured outcomes, and learned case IDs.

If Qoder chooses a safe response immediately, show that honestly. Use the labeled H41 replay to demonstrate the blocked proposal instead of attributing it to the live agent.

## Verify the build

```sh
npm test
npm run typecheck
npm run build
npm run format
```

[Build audit and remaining acceptance work](docs/build-audit.md) · [Precedent design decisions](docs/design-principles.md)

## Keywords

AI agents · autonomous agents · agentic AI · AI safety · agent security · autonomous response · incident response · cyber defense · cybersecurity · decision support · institutional judgment · institutional memory · agent memory · verified memory · memory poisoning · prompt injection · evidence provenance · source authority · source verification · context graphs · knowledge graphs · graph retrieval · dependency analysis · blast radius · policy enforcement · action authorization · execution broker · audit trails · decision traces · tool permissions · MCP tools · credential compromise · credential rotation · payment continuity · staged recovery · outcome verification · counterfactual comparison · historical replay · idempotency · durable execution intents · fail-closed authorization · observability · Qoder · Qoder Agent SDK · Neo4j · Cypher · TypeScript · Zod · Node.js · Fastify · Next.js · React · React Flow · server-sent events · Vitest
