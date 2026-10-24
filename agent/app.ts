import type { IncomingMessage, ServerResponse } from "node:http";
import type { Status } from "./agent.ts";

function send(res: ServerResponse, status: number, body: string, type = "application/json") {
  res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body), "x-content-type-options": "nosniff" });
  res.end(body);
}

/** Health and metrics for the agent (ADR 0017). The agent has no API of its own. */
export function createAgentHandler(version: string, s: Status) {
  return (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    if (path === "/healthz") return send(res, 200, JSON.stringify({ status: "ok" }));
    if (path === "/readyz") {
      const problems = [!s.enrolled && "not enrolled", !s.dastOk && `DAST unreachable${s.lastError ? `: ${s.lastError}` : ""}`].filter(Boolean);
      return send(res, problems.length ? 503 : 200, JSON.stringify(problems.length ? { status: "degraded", problems } : { status: "ready" }));
    }
    if (path === "/metrics") {
      const lines = [
        "# HELP openasy_build_info Build information.",
        "# TYPE openasy_build_info gauge",
        `openasy_build_info{product="dast-agent",version="${version}"} 1`,
        "# HELP openasy_dast_agent_scans_total Scans run.",
        "# TYPE openasy_dast_agent_scans_total counter",
        `openasy_dast_agent_scans_total ${s.scans}`,
        "# HELP openasy_dast_agent_scan_failures_total Scans that failed (an engine failed or ran out of time).",
        "# TYPE openasy_dast_agent_scan_failures_total counter",
        `openasy_dast_agent_scan_failures_total ${s.scanFailures}`,
        "# HELP openasy_dast_agent_running Scans running now.",
        "# TYPE openasy_dast_agent_running gauge",
        `openasy_dast_agent_running ${s.running}`,
        "# HELP openasy_dast_agent_last_contact_timestamp_seconds Last successful call to DAST; 0 before the first.",
        "# TYPE openasy_dast_agent_last_contact_timestamp_seconds gauge",
        `openasy_dast_agent_last_contact_timestamp_seconds ${s.lastContactAt ? Math.floor(Date.parse(s.lastContactAt) / 1000) : 0}`,
      ];
      return send(res, 200, lines.join("\n") + "\n", "text/plain; version=0.0.4");
    }
    send(res, 404, JSON.stringify({ status: "not found" }));
  };
}
