import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAgent } from "./agent.ts";
import { checkJob, nucleiArgs, runNuclei, runZap, zapPlan, type ScanOptions } from "./jobs.ts";
import { createKeyring } from "./kek.ts";
import { loadState } from "./state.ts";

const tmp = (p: string) => mkdtempSync(join(tmpdir(), `dast-agent-${p}-`));
const job = (over: Record<string, unknown> = {}) => ({
  id: "0b8c2d1e-0000-4000-8000-000000000001",
  kind: "scan",
  target: { name: "shop", url: "https://shop.example.com", production: false },
  profile: "standard",
  ...over,
});
const SARIF = (tool: string, n: number) =>
  JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: tool } }, results: Array.from({ length: n }, (_, i) => ({ ruleId: `r${i}` })) }] });

function program(dir: string, name: string, body: string) {
  const file = join(dir, name);
  writeFileSync(file, `#!/usr/bin/env node\nconst fs = require("fs"), path = require("path");\n${body}\n`);
  chmodSync(file, 0o755);
  return file;
}

/** ZAP and Nuclei for tests: they record how they were run and write a SARIF report as the real ones do. */
function fakeEngines() {
  const dir = tmp("bin");
  const zap = program(
    dir,
    "zap.sh",
    `const a = process.argv.slice(2), plan = JSON.parse(fs.readFileSync(a[a.indexOf("-autorun") + 1], "utf8"));
fs.writeFileSync(${JSON.stringify(join(dir, "zap.json"))}, JSON.stringify({ args: a, plan, home: process.env.HOME, header: [process.env.ZAP_AUTH_HEADER, process.env.ZAP_AUTH_HEADER_VALUE, process.env.ZAP_AUTH_HEADER_SITE], planMode: (fs.statSync(a[a.indexOf("-autorun") + 1]).mode & 0o777).toString(8), jvm: fs.readFileSync(path.join(a[a.indexOf("-dir") + 1], ".ZAP_JVM.properties"), "utf8") }));
const report = plan.jobs.find((j) => j.type === "report").parameters;
fs.writeFileSync(path.join(report.reportDir, report.reportFile + ".json"), ${JSON.stringify(SARIF("ZAP", 2))});`,
  );
  const nuclei = program(
    dir,
    "nuclei",
    `const a = process.argv.slice(2);
fs.writeFileSync(${JSON.stringify(join(dir, "nuclei.json"))}, JSON.stringify({ args: a, home: process.env.HOME, secrets: a.includes("-secret-file") ? fs.readFileSync(a[a.indexOf("-secret-file") + 1], "utf8") : null }));
if (fs.existsSync(${JSON.stringify(join(dir, "nuclei-fails"))})) { console.error("[FTL] Could not run nuclei: no templates"); process.exit(1) }
if (!fs.existsSync(${JSON.stringify(join(dir, "nuclei-finds-nothing"))})) fs.writeFileSync(a[a.indexOf("-sarif-export") + 1], ${JSON.stringify(SARIF("Nuclei", 1))});`,
  );
  const read = (name: string) => JSON.parse(readFileSync(join(dir, `${name}.json`), "utf8"));
  return { dir, zap, nuclei, read };
}

let fake: ReturnType<typeof fakeEngines>;
let options: ScanOptions;
beforeAll(() => {
  fake = fakeEngines();
  options = { workDir: tmp("work"), zap: fake.zap, nuclei: fake.nuclei, templates: "/opt/nuclei-templates", zapMemoryMb: 1024, timeoutMs: 60_000 };
});

describe("jobs from dast", () => {
  it.each([
    ["an address that is not http", { target: { name: "shop", url: "ftp://shop.example.com", production: false } }],
    ["an address with credentials", { target: { name: "shop", url: "https://a:b@shop.example.com", production: false } }],
    ["an address with a query", { target: { name: "shop", url: "https://shop.example.com/?x=1", production: false } }],
    ["a profile it does not know", { profile: "insane" }],
    ["a proof on another origin", { kind: "verify", profile: null, proofUrl: "https://evil.example.com/.well-known/openasy-dast" }],
  ])("refuses %s", (_, over) => {
    expect(() => checkJob(job(over))).toThrow();
  });

  it("crawls and only watches for a passive scan, and attacks harder for a full one, inside the target's address", () => {
    const passive = zapPlan(checkJob(job({ profile: "passive" })), "/r");
    expect(passive.jobs.map((j) => j.type)).toEqual(["spider", "passiveScan-wait", "report"]);
    expect(passive.env.contexts[0]!.includePaths).toEqual(["\\Qhttps://shop.example.com\\E([/?#].*)?"]);
    const full = zapPlan(checkJob(job({ profile: "full" })), "/r");
    expect(full.jobs.map((j) => j.type)).toEqual(["spider", "spiderAjax", "passiveScan-wait", "activeScan", "report"]);
    expect(full.jobs.find((j) => j.type === "activeScan")).toMatchObject({ policyDefinition: { defaultStrength: "medium" } });
    expect(zapPlan(checkJob(job()), "/r").jobs.find((j) => j.type === "activeScan")).toMatchObject({ policyDefinition: { defaultStrength: "low" } });
  });

  it("runs Nuclei without its outside services, and never its templates that flood a service", () => {
    const standard = nucleiArgs(checkJob(job()), options, "/o.sarif");
    expect(standard).toEqual(expect.arrayContaining(["-disable-update-check", "-no-interactsh", "-target", "https://shop.example.com"]));
    expect(standard[standard.indexOf("-exclude-tags") + 1]).toContain("intrusive");
    const full = nucleiArgs(checkJob(job({ profile: "full" })), options, "/o.sarif");
    expect(full[full.indexOf("-exclude-tags") + 1]).toBe("dos");
  });
});

describe("logins", () => {
  const form = {
    kind: "form",
    loginUrl: "https://shop.example.com/login",
    usernameField: "email",
    passwordField: "password",
    username: "scan@example.com",
    password: "hunter22",
    loggedInRegex: "Sign out",
  };
  const header = { kind: "header", headerName: "Authorization", value: "Bearer t0ken" };

  it.each([
    ["a form login sent to another origin", { ...form, loginUrl: "https://evil.example.com/login" }],
    ["a header value on two lines", { ...header, value: "a\r\nX-Evil: 1" }],
    ["a field name a form would not have", { ...form, usernameField: "a&b=c" }],
  ])("refuses %s", (_, auth) => {
    expect(() => checkJob(job({ auth }))).toThrow();
  });

  it("signs ZAP in with a form login, as one user, away from sign-out links", () => {
    const plan = zapPlan(checkJob(job({ profile: "full", auth: form })), "/r");
    expect(plan.env.contexts[0]).toMatchObject({
      authentication: {
        method: "form",
        parameters: { loginPageUrl: form.loginUrl, loginRequestBody: "email={%username%}&password={%password%}" },
        verification: { method: "response", loggedInRegex: "Sign out" },
      },
      users: [{ name: "scan", credentials: { username: "scan@example.com", password: "hunter22" } }],
      excludePaths: [expect.stringContaining("sign-?out")],
    });
    for (const j of plan.jobs.filter((j) => ["spider", "spiderAjax", "activeScan"].includes(j.type))) expect(j.parameters).toMatchObject({ user: "scan" });
  });

  it("gives a header login to ZAP through its environment and to Nuclei in a secrets file for the target's host", async () => {
    await runZap(checkJob(job({ auth: header })), options);
    expect(fake.read("zap").header).toEqual(["Authorization", "Bearer t0ken", "shop.example.com"]);
    await runZap(checkJob(job({ auth: form })), options);
    expect(fake.read("zap")).toMatchObject({ header: [null, null, null], planMode: "600" });
    await runNuclei(checkJob(job({ auth: header })), options);
    expect(JSON.parse(fake.read("nuclei").secrets)).toEqual({
      static: [{ type: "header", domains: ["shop.example.com"], headers: [{ key: "Authorization", value: "Bearer t0ken" }] }],
    });
    // Nuclei cannot fill in a form: it runs signed out.
    await runNuclei(checkJob(job({ auth: form })), options);
    expect(fake.read("nuclei").secrets).toBeNull();
    expect(readdirSync(options.workDir)).toEqual([]);
  });
});

describe("the engines", () => {
  it("runs ZAP with a home and a heap of its own, keeps its report and deletes the rest", async () => {
    const r = await runZap(checkJob(job()), options);
    expect(r).toMatchObject({ engine: "zap", results: 2 });
    const call = fake.read("zap");
    expect(call.args.slice(0, 2)).toEqual(["-cmd", "-silent"]);
    expect(call.jvm).toBe("-Xmx1024m\n");
    expect(existsSync(call.home)).toBe(false);
    expect(readdirSync(options.workDir)).toEqual([]);
  });

  it("takes no file from Nuclei as an empty report, and a failure as a failure", async () => {
    expect(await runNuclei(checkJob(job()), options)).toMatchObject({ engine: "nuclei", results: 1 });
    writeFileSync(join(fake.dir, "nuclei-finds-nothing"), "");
    expect(await runNuclei(checkJob(job()), options)).toMatchObject({ results: 0 });
    writeFileSync(join(fake.dir, "nuclei-fails"), "");
    await expect(runNuclei(checkJob(job()), options)).rejects.toThrow(/Nuclei failed \(exit 1\): \[FTL\] Could not run nuclei/);
    for (const f of ["nuclei-fails", "nuclei-finds-nothing"]) rmSync(join(fake.dir, f));
  });
});

describe("the agent with dast", () => {
  const calls: Array<{ path: string; body: Buffer }> = [];
  let jobs: unknown[] = [];
  const server = createServer(async (req: IncomingMessage, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = req.headers["content-encoding"] === "gzip" ? gunzipSync(Buffer.concat(chunks)) : Buffer.concat(chunks);
    calls.push({ path: req.url!, body });
    const send = (status: number, value?: unknown) =>
      res.writeHead(status, { "content-type": "application/json" }).end(value === undefined ? "" : JSON.stringify(value));
    if (req.url === "/api/v1/agent/enroll") return send(200, { id: "a1", name: "dc1", secret: "oda_secret" });
    if (req.headers.authorization !== "Bearer oda_secret") return send(401, {});
    if (req.url === "/api/v1/agent/work") return send(200, { jobs: jobs.splice(0) });
    if (req.url!.includes("/sarif")) return send(201, {});
    send(204);
  });
  // A target that serves its proof, and one that sends the agent elsewhere.
  const site = createServer((req, res) =>
    req.url === "/.well-known/openasy-dast"
      ? res.writeHead(200).end("openasy-dast-proof")
      : res.writeHead(302, { location: "https://evil.example.com/" }).end(),
  );
  let base: string;
  let siteUrl: string;
  beforeAll(async () => {
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    await new Promise<void>((r) => site.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    siteUrl = `http://127.0.0.1:${(site.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await new Promise((r) => server.close(r));
    await new Promise((r) => site.close(r));
  });

  it("runs ZAP alone for a passive scan, both engines otherwise, and sends each report even when the other fails", async () => {
    const keyring = createKeyring(Buffer.alloc(32, 7));
    const statePath = join(tmp("state"), "agent.state");
    const agent = createAgent({ url: base, version: "0.5.0", state: loadState(statePath, keyring), statePath, keyring, enrollToken: "ode_x", scan: options });
    const paths = () => calls.map((c) => c.path.replace(/jobs\/[^/]+\//, "jobs/:id/"));

    jobs = [job({ profile: "passive" })];
    expect(await agent.round()).toBe(true);
    expect(paths()).toEqual(["/api/v1/agent/enroll", "/api/v1/agent/work", "/api/v1/agent/jobs/:id/sarif?engine=zap", "/api/v1/agent/jobs/:id/done"]);
    expect(readFileSync(statePath, "utf8")).not.toContain("oda_secret");

    calls.length = 0;
    writeFileSync(join(fake.dir, "nuclei-fails"), "");
    jobs = [job()];
    await agent.round();
    expect(paths()).toEqual(["/api/v1/agent/work", "/api/v1/agent/jobs/:id/sarif?engine=zap", "/api/v1/agent/jobs/:id/failed"]);
    expect(JSON.parse(calls.at(-1)!.body.toString()).error).toMatch(/Nuclei failed/);
    expect(agent.status).toMatchObject({ scans: 2, scanFailures: 1 });
  });

  it("reads a proof from the target itself, and refuses a target that redirects", async () => {
    const keyring = createKeyring(Buffer.alloc(32, 7));
    const statePath = join(tmp("state"), "agent.state");
    const agent = createAgent({ url: base, version: "0.5.0", state: loadState(statePath, keyring), statePath, keyring, enrollToken: "ode_x", scan: options });
    const target = { name: "intranet", url: siteUrl, production: false };
    calls.length = 0;
    jobs = [
      job({ kind: "verify", profile: null, target, proofUrl: `${siteUrl}/.well-known/openasy-dast` }),
      job({ id: "j2", kind: "verify", profile: null, target, proofUrl: `${siteUrl}/elsewhere` }),
    ];
    await agent.round();
    const proof = calls.find((c) => c.path.endsWith("/proof"))!;
    expect(JSON.parse(proof.body.toString())).toEqual({ content: "openasy-dast-proof" });
    const failed = calls.find((c) => c.path.endsWith("/failed"))!;
    expect(failed.path).toBe("/api/v1/agent/jobs/j2/failed");
    expect(JSON.parse(failed.body.toString()).error).toMatch(/answered 302/);
  });
});
