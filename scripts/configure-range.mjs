import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
const file = ".env.range";
if (existsSync(file)) {
  console.log("Existing isolated range secrets preserved.");
  process.exit(0);
}
const names = [
  "RANGE_BROKER_TOKEN",
  "RANGE_READ_TOKEN",
  "OBSERVATION_TOKEN",
  "LEDGER_TOKEN",
  "WORKER_A_SECRET",
  "WORKER_B_SECRET",
  "WORKER_HIDDEN_SECRET",
];
writeFileSync(
  file,
  names.map((name) => `${name}=${randomBytes(32).toString("hex")}`).join("\n") +
    "\n",
  { mode: 0o600 },
);
console.log("Created isolated range secrets in .env.range.");
