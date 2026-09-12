import {
  existsSync,
  readFileSync,
  writeFileSync,
  renameSync,
  mkdirSync,
} from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import type {
  ActionProposal,
  MutationOutcome,
  ProbeResult,
  RangeSnapshot,
} from "@precedent/contracts";

type Worker = {
  id: string;
  credentialId: string;
  active: boolean;
  verified: boolean;
};

type RangeState = {
  scenarioVersion: number;
  policyVersion: number;
  compromisedDeviceIsolated: boolean;
  hostileSessionsInvalidated: boolean;
  credentialState: "ACTIVE" | "QUARANTINED" | "REVOKED";
  activeCredentialId: string;
  workers: Worker[];
  trafficWorkerId: string;
  ledgerEnabled: boolean;
  transactionIds: Set<string>;
  trustedGateway: boolean;
  attackActive: boolean;
  environment: "production" | "staging";
  failedWorkerIds: string[];
};

const originalState = (scenarioVersion = 1): RangeState => ({
  scenarioVersion,
  policyVersion: 1,
  compromisedDeviceIsolated: false,
  hostileSessionsInvalidated: false,
  credentialState: "ACTIVE",
  activeCredentialId: "payments-key-v1",
  workers: [
    {
      id: "payment-worker-a",
      credentialId: "payments-key-v1",
      active: true,
      verified: false,
    },
    {
      id: "payment-worker-b",
      credentialId: "payments-key-v1",
      active: true,
      verified: false,
    },
  ],
  trafficWorkerId: "payment-worker-a",
  ledgerEnabled: true,
  transactionIds: new Set(),
  trustedGateway: true,
  attackActive: true,
  environment: "production",
  failedWorkerIds: [],
});

type IdempotentMutation = {
  fingerprint: string;
  outcome: MutationOutcome;
};

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

export class RangeController {
  private state = originalState();
  private readonly mutations = new Map<string, IdempotentMutation>();

  constructor(private readonly storagePath?: string) {
    if (storagePath && existsSync(storagePath)) {
      const saved = JSON.parse(readFileSync(storagePath, "utf8"));
      this.state = {
        ...saved.state,
        transactionIds: new Set(saved.state.transactionIds),
      };
      for (const [key, value] of saved.mutations)
        this.mutations.set(key, value);
    }
  }
  private persist(): void {
    if (!this.storagePath) return;
    mkdirSync(dirname(this.storagePath), { recursive: true });
    writeFileSync(
      this.storagePath + ".tmp",
      JSON.stringify({
        state: {
          ...this.state,
          transactionIds: [...this.state.transactionIds],
        },
        mutations: [...this.mutations],
      }),
      { mode: 0o600 },
    );
    renameSync(this.storagePath + ".tmp", this.storagePath);
  }

  snapshot(): RangeSnapshot {
    return {
      scenarioVersion: this.state.scenarioVersion,
      policyVersion: this.state.policyVersion,
      compromisedDeviceIsolated: this.state.compromisedDeviceIsolated,
      hostileSessionsInvalidated: this.state.hostileSessionsInvalidated,
      credentialState: this.state.credentialState,
      activeCredentialId: this.state.activeCredentialId,
      trustedGateway: this.state.trustedGateway,
      attackActive: this.state.attackActive,
      environment: this.state.environment,
      trafficWorkerId: this.state.trafficWorkerId,
      ledgerEnabled: this.state.ledgerEnabled,
      failedWorkerIds: [...this.state.failedWorkerIds],
      observedAt: new Date().toISOString(),
      workers: this.state.workers.map((worker) => ({ ...worker })),
    };
  }

  reset(): RangeSnapshot {
    this.state = originalState(this.state.scenarioVersion + 1);
    this.persist();
    return this.snapshot();
  }

  restore(snapshot: RangeSnapshot): RangeSnapshot {
    this.state = {
      ...originalState(),
      ...structuredClone(snapshot),
      transactionIds: new Set(),
    };
    this.persist();
    return this.snapshot();
  }

  configure(variant: string): RangeSnapshot {
    if (variant === "no-gateway") this.state.trustedGateway = false;
    else if (variant === "failed-standby")
      this.state.failedWorkerIds = ["payment-worker-b"];
    else if (variant === "hidden-consumer")
      this.state.workers.push({
        id: "payment-worker-hidden",
        credentialId: "payments-key-v1",
        active: true,
        verified: false,
      });
    else if (variant === "staging") {
      this.state.environment = "staging";
      this.state.workers.forEach((worker) => (worker.active = false));
    } else if (variant === "healthy") this.state.attackActive = false;
    else if (variant === "attack") this.state.attackActive = true;
    else if (variant !== "production")
      throw new Error("Unknown scenario variant.");
    this.state.scenarioVersion++;
    this.persist();
    return this.snapshot();
  }

  paymentProbe(runId: string, transactionId?: string): ProbeResult {
    const observedTransactionId = transactionId ?? randomUUID();
    const worker = this.state.workers.find(
      (candidate) =>
        candidate.id === this.state.trafficWorkerId && candidate.active,
    );
    const credentialUsable =
      worker !== undefined &&
      (this.state.credentialState !== "REVOKED" ||
        worker.credentialId !== "payments-key-v1");
    const success = Boolean(
      worker && credentialUsable && this.state.ledgerEnabled,
    );

    if (success) {
      this.state.transactionIds.add(observedTransactionId);
    }

    return {
      probeId: randomUUID(),
      runId,
      probeClass: "LEGITIMATE_PAYMENT",
      success,
      observedAt: new Date().toISOString(),
      details: {
        transactionId: observedTransactionId,
        workerId: worker?.id ?? null,
        credentialId: worker?.credentialId ?? null,
        ledgerCommitted: success,
      },
    };
  }

  attackerProbe(runId: string): ProbeResult {
    const success =
      this.state.attackActive && this.state.credentialState === "ACTIVE";
    return {
      probeId: randomUUID(),
      runId,
      probeClass: "ATTACKER",
      success,
      observedAt: new Date().toISOString(),
      details: {
        credentialId: "payments-key-v1",
        copiedCredential: true,
        sourceDeviceIsolated: this.state.compromisedDeviceIsolated,
        hostileSessionsInvalidated: this.state.hostileSessionsInvalidated,
      },
    };
  }

  ledgerProbe(runId: string): ProbeResult {
    return {
      probeId: randomUUID(),
      runId,
      probeClass: "LEDGER",
      success: this.state.ledgerEnabled,
      observedAt: new Date().toISOString(),
      details: {
        committedTransactions: this.state.transactionIds.size,
      },
    };
  }

  mutate(proposal: ActionProposal, idempotencyKey: string): MutationOutcome {
    return this.withIdempotency(proposal, idempotencyKey, () =>
      this.applyMutation(proposal),
    );
  }

  counterfactualMutate(
    proposal: ActionProposal,
    idempotencyKey: string,
  ): MutationOutcome {
    return this.withIdempotency(proposal, idempotencyKey, () => {
      if (
        proposal.actionType !== "revoke_credential" ||
        proposal.targetId !== "payments-key-v1"
      ) {
        throw new Error(
          "The comparison range only models immediate old-credential revocation.",
        );
      }
      this.state.credentialState = "REVOKED";
      return this.changed({
        credentialId: proposal.targetId,
        state: "REVOKED",
        projected: true,
        bypassedContinuityGuard: true,
      });
    });
  }

  private applyMutation(proposal: ActionProposal): MutationOutcome {
    switch (proposal.actionType) {
      case "isolate_device":
        this.requireTarget(proposal, "compromised-laptop");
        this.state.compromisedDeviceIsolated = true;
        return this.changed({ device: "compromised-laptop", isolated: true });
      case "invalidate_session":
        this.requireTarget(proposal, "hostile-session");
        this.state.hostileSessionsInvalidated = true;
        return this.changed({ session: "hostile-session", invalidated: true });
      case "quarantine_credential":
        this.requireTarget(proposal, "payments-key-v1");
        this.requireCredentialState("ACTIVE");
        if (!this.state.trustedGateway)
          throw new Error("Trusted quarantine gateway unavailable.");
        this.state.credentialState = "QUARANTINED";
        return this.changed({
          credentialId: proposal.targetId,
          state: "QUARANTINED",
        });
      case "create_credential":
        this.requireTarget(proposal, "payments-key-v2");
        if (this.state.activeCredentialId === "payments-key-v2") {
          throw new Error("Replacement credential already exists.");
        }
        this.state.activeCredentialId = "payments-key-v2";
        return this.changed({ credentialId: proposal.targetId, created: true });
      case "deploy_credential":
        return this.deployCredential(proposal);
      case "verify_consumer":
        return this.verifyConsumer(proposal);
      case "switch_traffic":
        return this.switchTraffic(proposal);
      case "revoke_credential":
        return this.revokeCredential(proposal);
      case "disable_service":
        this.requireTarget(proposal, "ledger-service");
        this.state.ledgerEnabled = false;
        return this.changed({ serviceId: proposal.targetId, enabled: false });
    }
  }

  mutationResult(
    proposal: ActionProposal,
    key: string,
  ): MutationOutcome | null {
    const saved = this.mutations.get(key);
    if (!saved) return null;
    if (saved.fingerprint !== canonicalize(proposal))
      throw new Error("Mutation fingerprint mismatch.");
    return saved.outcome;
  }

  private withIdempotency(
    proposal: ActionProposal,
    idempotencyKey: string,
    mutate: () => MutationOutcome,
  ): MutationOutcome {
    if (idempotencyKey.length === 0) {
      throw new Error("idempotency-key is required.");
    }
    const fingerprint = canonicalize(proposal);
    const existing = this.mutations.get(idempotencyKey);
    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        throw new Error(
          "The idempotency key was reused for a different mutation.",
        );
      }
      return existing.outcome;
    }
    const outcome = mutate();
    this.mutations.set(idempotencyKey, { fingerprint, outcome });
    this.persist();
    return outcome;
  }

  private deployCredential(proposal: ActionProposal): MutationOutcome {
    const consumerId = this.argumentString(proposal, "consumerId");
    const credentialId = this.argumentString(proposal, "credentialId");
    if (
      credentialId !== "payments-key-v2" ||
      this.state.activeCredentialId !== credentialId
    ) {
      throw new Error("Replacement credential has not been created.");
    }
    const worker = this.worker(consumerId);
    worker.credentialId = credentialId;
    worker.verified = false;
    return this.changed({ consumerId, credentialId, deployed: true });
  }

  private verifyConsumer(proposal: ActionProposal): MutationOutcome {
    const consumerId = this.argumentString(proposal, "consumerId");
    const worker = this.worker(consumerId);
    if (worker.credentialId !== "payments-key-v2") {
      throw new Error("Consumer is not using the replacement credential.");
    }
    if (this.state.failedWorkerIds.includes(consumerId))
      throw new Error("Consumer probe failed.");
    worker.verified = true;
    return this.changed({ consumerId, verified: true });
  }

  private switchTraffic(proposal: ActionProposal): MutationOutcome {
    const workerId = this.argumentString(proposal, "workerId");
    const worker = this.worker(workerId);
    if (!worker.verified || worker.credentialId !== "payments-key-v2") {
      throw new Error(
        "Traffic can only switch to a verified replacement consumer.",
      );
    }
    this.state.trafficWorkerId = workerId;
    return this.changed({ workerId, activeTraffic: true });
  }

  private revokeCredential(proposal: ActionProposal): MutationOutcome {
    this.requireTarget(proposal, "payments-key-v1");
    if (
      this.state.workers.some(
        (worker) => worker.active && worker.credentialId === "payments-key-v1",
      )
    ) {
      throw new Error(
        "An active payment consumer still depends on the old credential.",
      );
    }
    this.state.credentialState = "REVOKED";
    return this.changed({ credentialId: proposal.targetId, state: "REVOKED" });
  }

  private changed(details: Record<string, unknown>): MutationOutcome {
    this.state.scenarioVersion += 1;
    return {
      stateChanged: true,
      scenarioVersion: this.state.scenarioVersion,
      details,
    };
  }

  private requireTarget(
    proposal: ActionProposal,
    expectedTarget: string,
  ): void {
    if (proposal.targetId !== expectedTarget) {
      throw new Error(`Action target must be ${expectedTarget}.`);
    }
  }

  private requireCredentialState(
    expectedState: RangeState["credentialState"],
  ): void {
    if (this.state.credentialState !== expectedState) {
      throw new Error(`Credential must be ${expectedState}.`);
    }
  }

  private argumentString(proposal: ActionProposal, name: string): string {
    const value = proposal.args[name];
    if (typeof value !== "string" || value.length === 0) {
      throw new Error(`Action requires a ${name} argument.`);
    }
    return value;
  }

  private worker(id: string): Worker {
    const worker = this.state.workers.find((candidate) => candidate.id === id);
    if (!worker) {
      throw new Error(`Unknown payment consumer: ${id}.`);
    }
    return worker;
  }
}

export type RangeClient = {
  snapshot(): Promise<RangeSnapshot>;
  mutationResult(
    proposal: ActionProposal,
    key: string,
  ): Promise<MutationOutcome | null>;
  mutate(
    proposal: ActionProposal,
    idempotencyKey: string,
  ): Promise<MutationOutcome>;
  paymentProbe(runId: string): Promise<ProbeResult>;
  attackerProbe(runId: string): Promise<ProbeResult>;
  ledgerProbe(runId: string): Promise<ProbeResult>;
  reset(): Promise<RangeSnapshot>;
  configure(variant: string): Promise<RangeSnapshot>;
  metrics(): Promise<Record<string, unknown>>;
  cloneCounterfactual(snapshot: RangeSnapshot): Promise<RangeSnapshot>;
  counterfactualSnapshot(): Promise<RangeSnapshot>;
  counterfactualMutate(
    proposal: ActionProposal,
    idempotencyKey: string,
  ): Promise<MutationOutcome>;
  counterfactualPaymentProbe(runId: string): Promise<ProbeResult>;
  counterfactualAttackerProbe(runId: string): Promise<ProbeResult>;
  counterfactualLedgerProbe(runId: string): Promise<ProbeResult>;
  resetCounterfactual(): Promise<RangeSnapshot>;
};

export function createRangeClient(
  baseUrl: string,
  brokerToken: string,
): RangeClient {
  const request = async <T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> => {
    const response = await fetch(`${baseUrl}${path}`, {
      ...init,
      signal: AbortSignal.timeout(15000),
      headers: {
        "x-range-broker-token": brokerToken,
        ...(init.body === undefined
          ? {}
          : { "content-type": "application/json" }),
        ...init.headers,
      },
    });
    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as {
        message?: string;
      };
      throw new Error(
        body.message ?? `Range request failed with ${response.status}.`,
      );
    }
    return (await response.json()) as T;
  };

  return {
    snapshot: () => request<RangeSnapshot>("/snapshot"),
    mutationResult: (proposal, key) =>
      request<MutationOutcome | null>("/admin/mutation-result", {
        method: "POST",
        body: JSON.stringify({ proposal, key }),
      }),
    configure: (variant) =>
      request<RangeSnapshot>("/admin/configure", {
        method: "POST",
        body: JSON.stringify({ variant }),
      }),
    metrics: () => request<Record<string, unknown>>("/metrics"),
    cloneCounterfactual: (snapshot) =>
      request<RangeSnapshot>("/counterfactual/admin/restore", {
        method: "POST",
        body: JSON.stringify({ snapshot }),
      }),
    mutate: (proposal, idempotencyKey) =>
      request<MutationOutcome>("/admin/mutate", {
        method: "POST",
        headers: { "idempotency-key": idempotencyKey },
        body: JSON.stringify({ proposal }),
      }),
    paymentProbe: (runId) =>
      request<ProbeResult>("/probe/payment", {
        method: "POST",
        body: JSON.stringify({ runId }),
      }),
    attackerProbe: (runId) =>
      request<ProbeResult>("/probe/attacker", {
        method: "POST",
        body: JSON.stringify({ runId }),
      }),
    ledgerProbe: (runId) =>
      request<ProbeResult>("/probe/ledger", {
        method: "POST",
        body: JSON.stringify({ runId }),
      }),
    reset: () => request<RangeSnapshot>("/admin/reset", { method: "POST" }),
    counterfactualSnapshot: () =>
      request<RangeSnapshot>("/counterfactual/snapshot"),
    counterfactualMutate: (proposal, idempotencyKey) =>
      request<MutationOutcome>("/counterfactual/admin/mutate", {
        method: "POST",
        headers: { "idempotency-key": idempotencyKey },
        body: JSON.stringify({ proposal }),
      }),
    counterfactualPaymentProbe: (runId) =>
      request<ProbeResult>("/counterfactual/probe/payment", {
        method: "POST",
        body: JSON.stringify({ runId }),
      }),
    counterfactualAttackerProbe: (runId) =>
      request<ProbeResult>("/counterfactual/probe/attacker", {
        method: "POST",
        body: JSON.stringify({ runId }),
      }),
    counterfactualLedgerProbe: (runId) =>
      request<ProbeResult>("/counterfactual/probe/ledger", {
        method: "POST",
        body: JSON.stringify({ runId }),
      }),
    resetCounterfactual: () =>
      request<RangeSnapshot>("/counterfactual/admin/reset", { method: "POST" }),
  };
}
