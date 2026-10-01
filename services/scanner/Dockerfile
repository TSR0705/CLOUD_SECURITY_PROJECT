# ==============================================================================
# Secure Upload Gateway (SUG) — Scanner Worker Service
# Includes Node.js runtime and pinned YARA-X 1.20.0 CLI (`yr`)
# ==============================================================================

FROM node:24-bookworm-slim AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV YARA_VERSION=1.20.0
ENV YARA_SHA256=cabb8df46492fff59c51261302c71ed9cb2cef393d3f0ca560801a34a8e24cbe
ENV YARA_RULES_PATH=/app/packages/scanner/rules

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tar \
    qpdf \
    && rm -rf /var/lib/apt/lists/*

# Download and verify official YARA-X 1.20.0 release binary
RUN curl -fsSL "https://github.com/VirusTotal/yara-x/releases/download/v${YARA_VERSION}/yara-x-v${YARA_VERSION}-x86_64-unknown-linux-gnu.tar.gz" -o /tmp/yara-x.tar.gz \
    && echo "${YARA_SHA256}  /tmp/yara-x.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/yara-x.tar.gz -C /usr/local/bin yr \
    && chmod +x /usr/local/bin/yr \
    && rm -f /tmp/yara-x.tar.gz \
    && yr --version

WORKDIR /app

# Enable pnpm
RUN corepack enable && corepack prepare pnpm@12.5.1 --activate

# Copy monorepo configuration and lockfile
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/storage/package.json ./packages/storage/
COPY packages/security-engine/package.json ./packages/security-engine/
COPY packages/scanner/package.json ./packages/scanner/
COPY services/scanner/package.json ./services/scanner/

# Install workspace dependencies
RUN pnpm install --frozen-lockfile

# Copy source trees, scripts, and rules
COPY scripts/ ./scripts/
COPY packages/shared/ ./packages/shared/
COPY packages/storage/ ./packages/storage/
COPY packages/security-engine/ ./packages/security-engine/
COPY packages/scanner/ ./packages/scanner/
COPY services/scanner/ ./services/scanner/

# Build TypeScript packages
RUN pnpm --filter @sug/shared build \
    && pnpm --filter @sug/storage build \
    && pnpm --filter @sug/security-engine build \
    && pnpm --filter @sug/scanner build \
    && pnpm --filter @sug/service-scanner build

# Validate rules at container build time
RUN node scripts/validate-yara-rules.mjs packages/scanner/rules

USER node

CMD ["node", "services/scanner/dist/index.js"]
