import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { createAgent } from "./agent.ts";
import { createAgentHandler } from "./app.ts";
import { createKeyring } from "./kek.ts";
import { log } from "./log.ts";
import { loadState } from "./state.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const url = process.env.DAST_URL;
if (!url) {
  log("error", "DAST_URL is required: the address of DAST, such as http://dast:8080");
  process.exit(1);
}
const keyFile = process.env.DAST_AGENT_SECRETS_KEY_FILE ?? "/run/secrets/openasy-agent-kek";
let kek: Buffer;
try {
  const text = readFileSync(keyFile, "utf8").trim();
  kek = /^[0-9a-f]{64}$/i.test(text) ? Buffer.from(text, "hex") : Buffer.from(text, "base64");
  if (kek.length !== 32) throw new Error("not 32 bytes");
} catch (err) {
  // The agent's secret asks dast for scans: it does not start without the key that encrypts it (ADR 0021).
  log("error", "no key-encryption key: mount 32 random bytes (openssl rand -hex 32)", { file: keyFile, error: String(err) });
  process.exit(1);
}
const keyring = createKeyring(kek);
const statePath = process.env.DAST_AGENT_STATE ?? "/data/agent.state";
const pollSeconds = Number(process.env.POLL_SECONDS ?? 10);
const agent = createAgent({
  url,
  version,
  state: loadState(statePath, keyring),
  statePath,
  keyring,
  enrollToken: process.env.DAST_ENROLL_TOKEN || undefined,
  scan: {
    workDir: process.env.WORK_DIR ?? tmpdir(),
    zap: process.env.ZAP_BIN ?? "/zap/zap.sh",
    nuclei: process.env.NUCLEI_BIN ?? "/usr/local/bin/nuclei",
    templates: process.env.NUCLEI_TEMPLATES ?? "/opt/nuclei-templates",
    zapMemoryMb: Number(process.env.ZAP_MEMORY_MB ?? 1536),
    timeoutMs: Number(process.env.SCAN_TIMEOUT_MINUTES ?? 120) * 60_000,
  },
});

const port = Number(process.env.PORT ?? 9100);
const server = createServer(createAgentHandler(version, agent.status));
server.listen(port, () => log("info", "dast-agent started", { version, port, dast: url, enrolled: agent.status.enrolled }));

let busy = false;
const tick = () => {
  if (busy) return;
  busy = true;
  agent
    .round()
    .catch((err: unknown) => {
      log("error", "round failed", { error: String(err) });
      return false;
    })
    // A queue with work in it is emptied without waiting for the next tick.
    .then((more) => {
      busy = false;
      if (more) setImmediate(tick);
    });
};
tick();
const timer = setInterval(tick, pollSeconds * 1000);

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  clearInterval(timer);
  setTimeout(() => process.exit(1), 10_000).unref();
  server.close(() => process.exit(0));
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
