# syntax=docker/dockerfile:1

# Nuclei is a pinned release, checked against its published checksum when the image is built (ADR 0027, 0037).
FROM scratch AS nuclei-zip-amd64
ADD --checksum=sha256:ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6 \
  https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip /nuclei.zip
FROM scratch AS nuclei-zip-arm64
ADD --checksum=sha256:8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07 \
  https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_arm64.zip /nuclei.zip
FROM nuclei-zip-${TARGETARCH} AS nuclei-zip

FROM debian:trixie-slim AS nuclei
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*
COPY --from=nuclei-zip /nuclei.zip /nuclei.zip
RUN unzip /nuclei.zip nuclei -d /out

FROM node:26.12.0-trixie-slim AS node

# ZAP's own image, pinned by digest: ZAP, Java and the headless browser its AJAX spider drives. Node runs the agent's
# TypeScript sources directly; it has no runtime dependencies.
FROM ghcr.io/zaproxy/zaproxy:2.17.0@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238
USER root
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei
# Nuclei's templates at the commit of their v10.5.0 release, so a scan does not change under an install.
ADD https://github.com/projectdiscovery/nuclei-templates.git#f8b8b8dcd70d93826c3767e1829ef8243af9f03b /opt/nuclei-templates
RUN mkdir -p /data && chown zap:zap /data
WORKDIR /app
COPY package.json ./
COPY agent ./agent
# The agent's secret lives sealed in /data. ZAP and Nuclei get a home of their own in /tmp (tmpfs) for each scan.
ENV NODE_ENV=production PORT=9100 DAST_AGENT_STATE=/data/agent.state WORK_DIR=/tmp \
  ZAP_BIN=/zap/zap.sh NUCLEI_BIN=/usr/local/bin/nuclei NUCLEI_TEMPLATES=/opt/nuclei-templates
VOLUME /data
EXPOSE 9100
USER zap
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:9100/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
ENTRYPOINT []
CMD ["node", "agent/main.ts"]
