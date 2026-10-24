// What dast may ask, and how the agent does it (ADR 0037). dast is not trusted with more than it needs: every job is
// checked before anything runs, the scanners get an address and a profile and nothing else, ZAP stays inside the
// target's address, Nuclei follows no redirects and calls no outside service, and nothing a scan wrote outlives it.
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

export type Profile = "passive" | "standard" | "full";

export interface Job {
  id: string;
  kind: "scan" | "verify";
  target: { name: string; url: string; production: boolean };
  profile: Profile | null;
  proofUrl?: string;
}

export interface EngineReport {
  engine: "zap" | "nuclei";
  sarif: Buffer;
  results: number;
}

export interface ScanOptions {
  workDir: string;
  zap: string;
  nuclei: string;
  templates: string;
  /** ZAP's Java heap, in MB. */
  zapMemoryMb: number;
  timeoutMs: number;
}

const ID = /^[A-Za-z0-9-]{1,64}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PROFILES: Profile[] = ["passive", "standard", "full"];

function address(v: unknown, what: string): URL {
  if (typeof v !== "string" || v.length > 2048) throw new Error(`${what} is not an address`);
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new Error(`${what} is not an address`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error(`${what} is not an http or https address`);
  if (u.username || u.password) throw new Error(`${what} has credentials in it`);
  return u;
}

/** Throws when dast sent something the agent will not do. */
export function checkJob(raw: unknown): Job {
  const j = raw as Partial<Job> | null;
  if (!j || typeof j !== "object" || typeof j.id !== "string" || !ID.test(j.id)) throw new Error("a job needs an id");
  if (j.kind !== "scan" && j.kind !== "verify") throw new Error("kind is scan or verify");
  const t = j.target as Job["target"] | undefined;
  if (!t || typeof t.name !== "string" || !NAME.test(t.name) || typeof t.production !== "boolean") throw new Error("the target needs a name");
  const url = address(t.url, "the target");
  if (url.search || url.hash) throw new Error("the target is an origin and a path");
  if (j.kind === "scan") {
    if (!PROFILES.includes(j.profile as Profile)) throw new Error(`profile is one of ${PROFILES.join(", ")}`);
    return { id: j.id, kind: "scan", target: { name: t.name, url: url.href.replace(/\/$/, ""), production: t.production }, profile: j.profile! };
  }
  const proof = address(j.proofUrl, "the proof address");
  // The proof is read from the target's own origin and nowhere else.
  if (proof.origin !== url.origin) throw new Error("the proof address is not on the target's origin");
  return {
    id: j.id,
    kind: "verify",
    target: { name: t.name, url: url.href.replace(/\/$/, ""), production: t.production },
    profile: null,
    proofUrl: proof.href,
  };
}

/** Reads the proof, without following redirects: a target that sends the agent elsewhere proves nothing. */
export async function readProof(job: Job): Promise<string> {
  const res = await fetch(job.proofUrl!, { redirect: "manual", signal: AbortSignal.timeout(10_000), headers: { accept: "text/plain" } });
  if (res.status !== 200) throw new Error(`${job.proofUrl} answered ${res.status}`);
  return (await res.text()).slice(0, 256);
}

/** Runs a program without a shell, in its own process group so a time limit stops its children (ZAP's browser too). */
function run(
  cmd: string,
  args: string[],
  o: { env: NodeJS.ProcessEnv; timeoutMs: number; what: string; cwd?: string },
): Promise<{ code: number | null; log: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { env: o.env, cwd: o.cwd, stdio: ["ignore", "pipe", "pipe"], detached: true });
    let log = "";
    const keep = (d: Buffer) => (log = (log + d.toString("utf8")).slice(-4000));
    child.stdout.on("data", keep);
    child.stderr.on("data", keep);
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        process.kill(-child.pid!, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }, o.timeoutMs);
    child.on("error", (err) => (clearTimeout(timer), reject(new Error(`${o.what} could not start: ${err.message}`))));
    child.on("close", (code) => {
      clearTimeout(timer);
      if (timedOut) reject(new Error(`${o.what} took longer than ${Math.round(o.timeoutMs / 60_000)} minutes`));
      else resolve({ code, log });
    });
  });
}

const lastLines = (s: string) => s.trim().split("\n").filter(Boolean).slice(-3).join(" ");
const results = (sarif: Buffer) =>
  ((JSON.parse(sarif.toString("utf8")) as { runs?: Array<{ results?: unknown[] }> }).runs ?? []).reduce((n, r) => n + (r.results?.length ?? 0), 0);

/** How long and how hard each profile tests, in ZAP's terms. */
const ZAP_PROFILE: Record<Profile, { spiderMinutes: number; ajax: boolean; strength: "low" | "medium" | null; activeMinutes: number }> = {
  passive: { spiderMinutes: 5, ajax: false, strength: null, activeMinutes: 0 },
  standard: { spiderMinutes: 10, ajax: false, strength: "low", activeMinutes: 30 },
  full: { spiderMinutes: 20, ajax: true, strength: "medium", activeMinutes: 90 },
};

/**
 * ZAP's automation plan for a scan: crawl the target, let the passive rules read what came back, attack it for the
 * standard and full profiles, and write SARIF. JSON is valid YAML, so the plan is written as JSON.
 */
export function zapPlan(job: Job, reportDir: string) {
  const p = ZAP_PROFILE[job.profile!];
  const url = job.target.url;
  const context = "target";
  return {
    env: {
      contexts: [
        {
          name: context,
          urls: [`${url}/`],
          // The target's address and what is under it, never the rest of the host: \Q...\E quotes the address.
          includePaths: [`\\Q${url}\\E([/?#].*)?`],
        },
      ],
      parameters: { failOnError: true, failOnWarning: false, progressToStdout: true },
    },
    jobs: [
      { type: "spider", parameters: { context, maxDuration: p.spiderMinutes, maxDepth: 8 } },
      ...(p.ajax ? [{ type: "spiderAjax", parameters: { context, maxDuration: 10, browserId: "firefox-headless" } }] : []),
      { type: "passiveScan-wait", parameters: { maxDuration: 15 } },
      ...(p.strength
        ? [
            {
              type: "activeScan",
              parameters: { context, maxScanDurationInMins: p.activeMinutes, maxRuleDurationInMins: p.strength === "low" ? 3 : 10 },
              policyDefinition: { defaultStrength: p.strength, defaultThreshold: "medium" },
            },
          ]
        : []),
      { type: "report", parameters: { template: "sarif-json", reportDir, reportFile: "zap" } },
    ],
  };
}

async function sarifIn(dir: string): Promise<Buffer | undefined> {
  if (!existsSync(dir)) return undefined;
  const f = (await readdir(dir)).find((x) => x.endsWith(".json") || x.endsWith(".sarif"));
  return f ? readFile(join(dir, f)) : undefined;
}

/** ZAP in command line mode, with a home of its own that is deleted afterwards. */
export async function runZap(job: Job, o: ScanOptions): Promise<EngineReport> {
  const home = await mkdtemp(join(o.workDir, "zap-"));
  try {
    const zapDir = join(home, ".ZAP");
    const reportDir = join(home, "report");
    await mkdir(zapDir, { recursive: true });
    await mkdir(reportDir);
    // zap.sh reads the Java heap from the home's .ZAP folder.
    await writeFile(join(zapDir, ".ZAP_JVM.properties"), `-Xmx${o.zapMemoryMb}m\n`);
    const plan = join(home, "plan.yaml");
    await writeFile(plan, JSON.stringify(zapPlan(job, reportDir), null, 2));
    const r = await run(o.zap, ["-cmd", "-silent", "-dir", zapDir, "-autorun", plan], {
      env: { PATH: process.env.PATH, HOME: home, TMPDIR: home, JAVA_TOOL_OPTIONS: `-Djava.io.tmpdir=${home}` },
      timeoutMs: o.timeoutMs,
      what: "ZAP",
      cwd: home,
    });
    const sarif = await sarifIn(reportDir);
    // A plan with errors may still write a report; without one, the scan did not happen.
    if (!sarif) throw new Error(`ZAP wrote no report (exit ${r.code}): ${lastLines(r.log)}`);
    return { engine: "zap", sarif, results: results(sarif) };
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

/** Template tags Nuclei leaves out per profile: nothing that floods or breaks a service, ever. */
const NUCLEI_EXCLUDE: Record<"standard" | "full", string> = {
  standard: "dos,fuzz,intrusive,bruteforce,brute-force,default-login,sqli,rce",
  full: "dos",
};

export function nucleiArgs(job: Job, o: Pick<ScanOptions, "templates">, out: string): string[] {
  return [
    "-target",
    job.target.url,
    "-templates",
    o.templates,
    "-type",
    "http,ssl",
    "-severity",
    "low,medium,high,critical",
    "-exclude-tags",
    NUCLEI_EXCLUDE[job.profile as "standard" | "full"],
    "-sarif-export",
    out,
    "-rate-limit",
    "50",
    "-concurrency",
    "10",
    "-timeout",
    "10",
    "-retries",
    "1",
    // No calls to projectdiscovery's servers: no update checks, no interactsh, no cloud upload.
    "-disable-update-check",
    "-no-interactsh",
    "-silent",
    "-no-color",
  ];
}

/** Nuclei over the target's address, for the standard and full profiles. */
export async function runNuclei(job: Job, o: ScanOptions): Promise<EngineReport> {
  const home = await mkdtemp(join(o.workDir, "nuclei-"));
  try {
    const out = join(home, "nuclei.sarif");
    const r = await run(o.nuclei, nucleiArgs(job, o, out), { env: { PATH: process.env.PATH, HOME: home }, timeoutMs: o.timeoutMs, what: "Nuclei", cwd: home });
    if (r.code !== 0) throw new Error(`Nuclei failed (exit ${r.code}): ${lastLines(r.log)}`);
    // Nuclei writes no file when it found nothing; that is an empty report, which fixes what it found before.
    const sarif = existsSync(out)
      ? await readFile(out)
      : Buffer.from(JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "Nuclei" } }, results: [] }] }));
    return { engine: "nuclei", sarif, results: results(sarif) };
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}
