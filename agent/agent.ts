// The loop: ask dast for a job, run it, send what each engine found. dast being down never stops the agent; it says
// so in /readyz and keeps asking (ADR 0037, the pattern of infra-agent).
import { enroll, sendDone, sendFailure, sendProof, sendSarif, work, type DastError } from "./client.ts";
import { checkJob, readProof, runNuclei, runZap, type EngineReport, type Job, type ScanOptions } from "./jobs.ts";
import type { Keyring } from "./kek.ts";
import { log } from "./log.ts";
import { saveState, type AgentState } from "./state.ts";

export interface AgentOptions {
  url: string;
  version: string;
  state: AgentState;
  statePath: string;
  keyring: Keyring;
  enrollToken?: string;
  scan: ScanOptions;
  /** Tests replace the engines. */
  engines?: { zap: (job: Job, o: ScanOptions) => Promise<EngineReport>; nuclei: (job: Job, o: ScanOptions) => Promise<EngineReport> };
}

export interface Status {
  enrolled: boolean;
  dastOk: boolean;
  lastError: string | null;
  lastContactAt: string | null;
  scans: number;
  scanFailures: number;
  running: number;
}

export function createAgent(o: AgentOptions) {
  const status: Status = { enrolled: !!o.state.secret, dastOk: false, lastError: null, lastContactAt: null, scans: 0, scanFailures: 0, running: 0 };
  const engines = o.engines ?? { zap: runZap, nuclei: runNuclei };
  const failed = (err: unknown) => {
    status.dastOk = false;
    status.lastError = (err as Error).message;
    log("warn", "dast call failed", { status: (err as DastError).status, error: status.lastError });
  };

  async function ensureEnrolled(): Promise<boolean> {
    if (o.state.secret) return true;
    if (!o.enrollToken) {
      status.lastError = "Not enrolled: add this agent in DAST under Agents, and start it with DAST_ENROLL_TOKEN";
      return false;
    }
    try {
      const r = await enroll(o.url, o.enrollToken, o.version);
      o.state.agentId = r.id;
      o.state.secret = r.secret;
      saveState(o.statePath, o.keyring, o.state);
      status.enrolled = true;
      log("info", "enrolled", { agentId: r.id, name: r.name });
      return true;
    } catch (err) {
      failed(err);
      return false;
    }
  }

  /** Runs one job and tells dast how it went; a refused job is reported as failed, never run. */
  async function runJob(raw: unknown) {
    const secret = o.state.secret!;
    let job: Job;
    try {
      job = checkJob(raw);
    } catch (err) {
      const id = String((raw as { id?: unknown } | null)?.id ?? "");
      if (id) await sendFailure(o.url, secret, id, `The agent refused the job: ${(err as Error).message}`).catch(failed);
      return;
    }
    const started = Date.now();
    const fields = { job: job.id, target: job.target.name, kind: job.kind, profile: job.profile };
    if (job.kind === "verify") {
      try {
        await sendProof(o.url, secret, job.id, await readProof(job));
        log("info", "proof read", fields);
      } catch (err) {
        await sendFailure(o.url, secret, job.id, `Could not read the proof: ${(err as Error).message}`).catch(failed);
      }
      return;
    }
    // ZAP for every profile, Nuclei for those that may send attacks. One engine failing does not lose the other's report.
    const errors: string[] = [];
    for (const name of job.profile === "passive" ? (["zap"] as const) : (["zap", "nuclei"] as const)) {
      try {
        const r = await engines[name](job, o.scan);
        await sendSarif(o.url, secret, job.id, r.engine, r.sarif);
        log("info", "engine finished", { ...fields, engine: name, results: r.results });
      } catch (err) {
        errors.push((err as Error).message);
        log("warn", "engine failed", { ...fields, engine: name, error: (err as Error).message });
      }
    }
    status.scans++;
    log("info", "scan finished", { ...fields, seconds: Math.round((Date.now() - started) / 1000), errors: errors.length });
    if (errors.length) {
      status.scanFailures++;
      await sendFailure(o.url, secret, job.id, errors.join("; ").slice(0, 1000)).catch(failed);
    } else await sendDone(o.url, secret, job.id).catch(failed);
  }

  /** One round: ask for work and run it. Returns whether there was a job. */
  async function round(): Promise<boolean> {
    if (!(await ensureEnrolled())) return false;
    let jobs: unknown[];
    try {
      jobs = (await work(o.url, o.state.secret!, o.version)).jobs;
      status.dastOk = true;
      status.lastError = null;
      status.lastContactAt = new Date().toISOString();
    } catch (err) {
      failed(err);
      return false;
    }
    for (const job of jobs) {
      status.running++;
      try {
        await runJob(job);
      } finally {
        status.running--;
      }
    }
    return jobs.length > 0;
  }

  return { round, status };
}
