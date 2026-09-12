# Precedent

Precedent is a graph-backed incident-response console for a controlled payments-credential compromise. It combines verified precedent, policy constraints, evidence provenance, and live range observations before a consequential action can execute.

## Components

- **Console** (`localhost:3000`): operational graph, ordered event stream, decision evidence, and demo controls.
- **Runner** (`127.0.0.1:3003`): persistent Qoder Agent SDK session with constrained read and execution tools.
- **Broker** (`127.0.0.1:3001`): graph evaluation, single-use authorization, event publication, and recovery promotion.
- **Range** (`127.0.0.1:3002`): controlled payments scenario with isolated live and counterfactual state.
- **Neo4j**: verified historical cases, policy records, evidence lineage, topology, evaluations, and receipts.

## Setup

Requirements: Node.js 24+, npm 11+, and a reachable Neo4j database.

```sh
npm ci
cp .env.example .env
```

Configure the Neo4j connection in `.env`. To use the live runner, authenticate the local Qoder CLI session before starting the stack.

```sh
qodercli login
npm run dev
```

Open `http://localhost:3000`.

## Demo flow

1. **Replay H41 proposal** rejects immediate credential revocation as `REVISE`, citing active consumers and the required staged recovery sequence.
2. **Inject forged runbook** rejects untrusted evidence and denies disabling the ledger.
3. **Compare response** runs immediate revocation only in the isolated counterfactual range, showing payment failure while blocking the attacker.
4. **Launch attack response** starts the Qoder-backed response session when the local CLI is authenticated.
5. **Reset live topology** restores the live controlled range without deleting learned precedent.

## Safety guarantees

- The range accepts administrative mutations only from the broker.
- The broker accepts consequential requests only from the runner.
- Every execution needs an allowed evaluation and a single-use, expiring authorization bound to the exact action arguments and current range and policy versions.
- Untrusted or unverifiable evidence fails closed.
- Counterfactual actions are isolated from the live range.
- A recovery becomes learned precedent only after payment, attacker, and ledger probes independently verify the outcome.

## Verification

```sh
npm run format
npm run typecheck
npm test
```
