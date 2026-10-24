// What the agent keeps on its own volume (ADR 0021): the secret it got when it enrolled, sealed with its own
// key-encryption key, so a copy of the volume alone cannot ask dast for work.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Keyring } from "./kek.ts";

export interface AgentState {
  agentId?: string;
  secret?: string;
}

export function loadState(path: string, keyring: Keyring): AgentState {
  let sealed: string | undefined;
  try {
    sealed = readFileSync(path, "utf8").trim();
  } catch {
    sealed = undefined;
  }
  return sealed ? (JSON.parse(keyring.open(sealed).toString("utf8")) as AgentState) : {};
}

export function saveState(path: string, keyring: Keyring, state: AgentState) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, keyring.seal(JSON.stringify(state)), { mode: 0o600 });
  renameSync(tmp, path);
}
