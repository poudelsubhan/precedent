import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { parse } from "dotenv";
const rangeEnv = parse(readFileSync(".env.range"));
const env = {
  ...process.env,
  BROKER_RUNNER_TOKEN: randomBytes(32).toString("hex"),
  RANGE_BROKER_TOKEN: rangeEnv.RANGE_BROKER_TOKEN,
  RANGE_URL: "http://127.0.0.1:3102",
  BROKER_PORT: "3101",
  TEST_BROKER_URL: "http://127.0.0.1:3101",
};
const broker = spawn("npx", ["tsx", "apps/broker/src/index.ts"], {
  env,
  stdio: ["ignore", "ignore", "inherit"],
});
try {
  let ready = false;
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(env.TEST_BROKER_URL + "/health");
      if (r.ok) {
        ready = true;
        break;
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  if (!ready) throw new Error("Test broker startup timed out");
  await new Promise((resolve, reject) => {
    const test = spawn("npx", ["tsx", "scripts/prove-broker.ts"], {
      env,
      stdio: "inherit",
    });
    test.on("exit", (code) =>
      code === 0 ? resolve() : reject(new Error("Proof failed")),
    );
  });
} finally {
  broker.kill("SIGTERM");
}
