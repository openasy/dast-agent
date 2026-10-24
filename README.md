# dast-agent

[![CI](https://github.com/openasy/dast-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/dast-agent/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The agent of [OpenAsy DAST](https://github.com/openasy/dast). It runs [ZAP](https://www.zaproxy.org/) and
[Nuclei](https://github.com/projectdiscovery/nuclei) where your applications are, against targets in dast, and sends
each engine's findings back as SARIF (ADR 0037). dast holds no scanner.

- **Only targets proven to be yours are attacked.** dast decides what a target allows and says so in each job: a
  target nobody has verified gets a passive scan, which crawls and watches but sends no attacks. A full scan of a
  production target needs an admin.
- **It stays inside the target.** ZAP's context is the target's address and what is under it, Nuclei follows no
  redirects, and a proof is read from the target's own origin without redirects.
- **Nothing calls home.** ZAP runs with `-silent`, and Nuclei with no update checks, no interactsh and no cloud upload.
  The templates are the ones built into the image.
- **It connects out, never in.** It enrols once with a one-time token and then uses its own secret, kept in
  `/data/agent.state` and sealed with its own key-encryption key. When dast is down it keeps asking and says so in
  `/readyz`.
- **It verifies targets dast cannot reach.** For a target on a private address, dast queues a verify job; the agent
  reads the proof in its network and sends back what it read.

## Scans

| Profile | ZAP | Nuclei |
| --- | --- | --- |
| `passive` | Crawls for 5 minutes and runs the passive rules: no attacks | not run |
| `standard` | Crawls for 10 minutes, then the active rules at low strength, 30 minutes at most | HTTP and TLS templates of low severity and up, without intrusive, fuzzing, brute force or denial of service templates |
| `full` | Crawls for 20 minutes, also with a headless browser, then the active rules at medium strength, 90 minutes at most | Every HTTP and TLS template of low severity and up, except denial of service |

Each engine's report is kept per profile in dast, such as `zap-standard`, so a passive scan never marks what an active
one found as fixed.

## Run

Add the agent in DAST under Agents. It shows a one-time enrolment token and this command:

```bash
openssl rand -hex 32 > openasy-agent-kek   # keep it with your backups
docker run -d --name dast-agent --restart unless-stopped --read-only --tmpfs /tmp:size=1g \
  --cap-drop ALL --security-opt no-new-privileges --memory 3g \
  -v dast-agent-data:/data -v "$PWD/openasy-agent-kek:/run/secrets/openasy-agent-kek:ro" \
  -e DAST_URL=https://dast.example.com -e DAST_ENROLL_TOKEN=ode_... \
  ghcr.io/openasy/dast-agent:0.5.0
```

The image is about 2 GB: ZAP, Java and a headless browser. A scan uses up to `ZAP_MEMORY_MB` for ZAP's heap plus about
1 GB more. The agent must be the same version as dast (ADR 0019).

| Variable | Default | |
| --- | --- | --- |
| `DAST_URL` | | Where dast is, such as `http://dast:8080` or its https:// address |
| `DAST_ENROLL_TOKEN` | | One-time, for the first start only |
| `DAST_AGENT_SECRETS_KEY_FILE` | `/run/secrets/openasy-agent-kek` | 32-byte key that seals the agent's secret |
| `DAST_AGENT_STATE` | `/data/agent.state` | The sealed state, on its volume |
| `POLL_SECONDS` | `10` | How often it asks for work when the queue is empty |
| `ZAP_MEMORY_MB` | `1536` | ZAP's Java heap |
| `SCAN_TIMEOUT_MINUTES` | `120` | Time limit for each engine of one scan |
| `PORT` | `9100` | `/healthz`, `/readyz` and `/metrics` |

## Versions

ZAP 2.17.0 (its image, pinned by digest), Nuclei 3.11.1 (checked against its published checksum) and the Nuclei
templates of their v10.5.0 release, pinned by commit (ADR 0027). The image is signed and has SLSA provenance in the
public transparency log like every OpenAsy image; its SBOM is too large for that log, so the SBOM attestation carries a
signed timestamp instead and is verified with `cosign verify-attestation --type spdxjson --insecure-ignore-tlog
--use-signed-timestamps`, as the release notes show. Dependabot proposes new versions; CI scans a small
site with each before it ships.

## Develop

```bash
npm install
npm test   # jobs, ZAP's plan, Nuclei's options and the loop, against stand-ins for both engines
```

CI also builds the image and runs the real ZAP and Nuclei, through the agent's own code, against a small site.

## Licence

AGPL-3.0 (ADR 0008). ZAP is Apache-2.0 and Nuclei and its templates are MIT.
