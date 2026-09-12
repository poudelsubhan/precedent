import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import type { ProbeResult } from "@precedent/contracts";

export class ServiceMesh {
  readonly readToken =
    process.env.RANGE_READ_TOKEN ?? randomBytes(32).toString("hex");
  readonly observationToken =
    process.env.OBSERVATION_TOKEN ?? randomBytes(32).toString("hex");
  private children: ChildProcess[] = [];
  private base = Number(process.env.MESH_BASE_PORT ?? 4100);
  private urls(scope: string) {
    const base = this.base + (scope === "live" ? 0 : 20);
    return {
      checkout: `http://127.0.0.1:${base}`,
      gateway: `http://127.0.0.1:${base + 1}`,
      load: `http://127.0.0.1:${base + 6}`,
      attacker: `http://127.0.0.1:${base + 7}`,
    };
  }
  async start(): Promise<void> {
    if (process.env.MESH_EXTERNAL === "1") return;
    for (const scope of ["live", "counterfactual"]) {
      const base = this.base + (scope === "live" ? 0 : 20);
      const secrets = Object.fromEntries(
        ["a", "b", "hidden"].map((suffix) => [
          `payment-worker-${suffix}`,
          randomBytes(32).toString("hex"),
        ]),
      );
      const workerUrls = Object.fromEntries(
        ["a", "b", "hidden"].map((suffix, i) => [
          `payment-worker-${suffix}`,
          `http://127.0.0.1:${base + 3 + i}`,
        ]),
      );
      const ledgerToken = randomBytes(32).toString("hex");
      const roles = [
        "checkout",
        "gateway",
        "ledger",
        "worker",
        "worker",
        "worker",
        "load",
        "attacker",
      ];
      roles.forEach((role, index) => {
        const id = Object.keys(secrets)[index - 3];
        const env: NodeJS.ProcessEnv = {
          PATH: process.env.PATH,
          SERVICE_ROLE: role,
          SERVICE_PORT: String(base + index),
          RANGE_SCOPE: scope,
          CONTROLLER_URL: `http://127.0.0.1:${process.env.RANGE_PORT ?? 3002}`,
          CHECKOUT_URL: this.urls(scope).checkout,
          GATEWAY_URL: this.urls(scope).gateway,
          LEDGER_URL: `http://127.0.0.1:${base + 2}`,
          DATA_DIR: fileURLToPath(
            new URL("../../../data/range", import.meta.url),
          ),
          ...(role === "gateway" || role === "ledger"
            ? { LEDGER_TOKEN: ledgerToken }
            : {}),
          ...(["checkout", "gateway", "worker"].includes(role)
            ? { RANGE_READ_TOKEN: this.readToken }
            : {}),
          ...(role === "gateway"
            ? { WORKLOAD_SECRETS: JSON.stringify(secrets) }
            : {}),
          ...(role === "checkout"
            ? { WORKER_URLS: JSON.stringify(workerUrls) }
            : {}),
          ...(role === "worker"
            ? { WORKER_ID: id, WORKLOAD_SECRET: secrets[id!] }
            : {}),
          ...(["load", "attacker"].includes(role)
            ? { OBSERVATION_TOKEN: this.observationToken }
            : {}),
        };
        this.children.push(
          spawn(
            process.execPath,
            [fileURLToPath(new URL("../services/mesh.mjs", import.meta.url))],
            { env, stdio: "ignore" },
          ),
        );
      });
    }
    process.once("exit", () => this.close());
    process.once("SIGTERM", () => {
      this.close();
      process.exit(0);
    });
    process.once("SIGINT", () => {
      this.close();
      process.exit(0);
    });
  }
  close() {
    this.children.forEach((child) => child.kill());
  }
  private externalUrl(scope: string, role: "load" | "attacker" | "gateway") {
    return process.env.MESH_EXTERNAL === "1"
      ? `http://${scope}-${role}:4100`
      : this.urls(scope)[role];
  }
  async probe(
    runId: string,
    probeClass: ProbeResult["probeClass"],
    scope = "live",
    probeWorkerId?: string,
    accessMode = "off-device",
  ): Promise<ProbeResult> {
    const role =
      probeClass === "LEGITIMATE_PAYMENT"
        ? "load"
        : probeClass === "ATTACKER"
          ? "attacker"
          : "gateway";
    const response = await fetch(
      `${this.externalUrl(scope, role)}/${probeClass === "LEDGER" ? "audit" : "probe"}`,
      {
        method: probeClass === "LEDGER" ? "GET" : "POST",
        headers: {
          "content-type": "application/json",
          "x-range-read-token": this.readToken,
        },
        ...(probeClass === "LEDGER"
          ? {}
          : {
              body: JSON.stringify({
                probeWorkerId,
                accessMode,
                transactionId: randomUUID(),
              }),
            }),
        signal: AbortSignal.timeout(5000),
      },
    );
    if (!response.ok) throw new Error("Independent range service unavailable.");
    const result = (await response.json()) as {
      success?: boolean;
      transactionIds?: string[];
      [key: string]: unknown;
    };
    return {
      probeId: randomUUID(),
      runId,
      probeClass,
      success:
        probeClass === "LEDGER"
          ? Array.isArray(result.transactionIds)
          : result.success === true,
      observedAt: new Date().toISOString(),
      details: { ...result, measurement: "HTTP_REQUEST", scope },
    };
  }
}
