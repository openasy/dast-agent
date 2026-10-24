// Everything the agent sends goes to the dast API, and only that way (ADR 0037): the agent accepts no requests from
// dast. It asks for work and sends results.
import { gzipSync } from "node:zlib";

export class DastError extends Error {
  readonly status: number | undefined;
  readonly code: string | undefined;
  constructor(status: number | undefined, code: string | undefined, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function call(url: string, path: string, init: { secret?: string; body: Buffer | unknown; timeoutMs?: number }): Promise<Response> {
  const raw = Buffer.isBuffer(init.body) ? init.body : Buffer.from(JSON.stringify(init.body));
  let res: Response;
  try {
    res = await fetch(new URL(path, url), {
      method: "POST",
      headers: { ...(init.secret && { authorization: `Bearer ${init.secret}` }), "content-type": "application/json", "content-encoding": "gzip" },
      body: gzipSync(raw),
      signal: AbortSignal.timeout(init.timeoutMs ?? 15_000),
    });
  } catch (err) {
    throw new DastError(undefined, "unreachable", `dast at ${url} is unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) {
    const p = (await res.json().catch(() => ({}))) as { code?: string; detail?: string; title?: string };
    throw new DastError(res.status, p.code, p.detail ?? p.title ?? `${res.status}`);
  }
  return res;
}

export const enroll = async (url: string, token: string, version: string) =>
  (await (await call(url, "/api/v1/agent/enroll", { body: { token, version } })).json()) as { id: string; name: string; secret: string };
export const work = async (url: string, secret: string, version: string) =>
  (await (await call(url, "/api/v1/agent/work", { secret, body: { version } })).json()) as { jobs: unknown[] };
export const sendSarif = async (url: string, secret: string, jobId: string, engine: string, sarif: Buffer) =>
  void (await call(url, `/api/v1/agent/jobs/${encodeURIComponent(jobId)}/sarif?engine=${engine}`, { secret, body: sarif, timeoutMs: 120_000 }));
export const sendDone = async (url: string, secret: string, jobId: string) =>
  void (await call(url, `/api/v1/agent/jobs/${encodeURIComponent(jobId)}/done`, { secret, body: {} }));
export const sendFailure = async (url: string, secret: string, jobId: string, error: string) =>
  void (await call(url, `/api/v1/agent/jobs/${encodeURIComponent(jobId)}/failed`, { secret, body: { error } }));
export const sendProof = async (url: string, secret: string, jobId: string, content: string) =>
  void (await call(url, `/api/v1/agent/jobs/${encodeURIComponent(jobId)}/proof`, { secret, body: { content } }));
