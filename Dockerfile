# syntax=docker/dockerfile:1.4
# =============================================================================
# Ubuntu image for running AI coding workflows with Cline + common dev tools.
#
# Includes: git, npm (Node.js LTS), the Cline CLI, and common dev utilities.
#
# API keys are accepted from the current environment:
#   * At BUILD time via --build-arg  (baked into the image — see security note)
#   * At RUN time  via `-e` / --env-file  (recommended)
# =============================================================================

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Node.js major version (LTS) to install. Override with --build-arg NODE_MAJOR=22
ARG NODE_MAJOR=24

# ---------------------------------------------------------------------------
# API keys (build-time). Values supplied via `--build-arg` are captured into a
# file and exported by the entrypoint at run time — but only when the variable
# is not already provided via `docker run -e` / `--env-file`. Runtime values
# always win. This avoids baking empty-string env vars into the image, which
# would otherwise break the Cline CLI at startup ("baseURL must be non-empty").
#
# ⚠️ Note: keys passed via --build-arg still appear in `docker history`.
# Prefer runtime injection for anything shared or pushed.
# ---------------------------------------------------------------------------
ARG ANTHROPIC_API_KEY=""
ARG ANTHROPIC_BASE_URL=""
ARG OPENAI_API_KEY=""
ARG OPENAI_BASE_URL=""
ARG OPENROUTER_API_KEY=""
ARG DEEPSEEK_API_KEY=""
ARG GEMINI_API_KEY=""
ARG GOOGLE_GENERATIVE_AI_API_KEY=""
ARG MISTRAL_API_KEY=""
ARG AWS_ACCESS_KEY_ID=""
ARG AWS_SECRET_ACCESS_KEY=""
ARG AWS_SESSION_TOKEN=""

# ---------------------------------------------------------------------------
# System dependencies + Node.js (npm) + Cline CLI
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        git \
        build-essential \
        python3 \
        python3-pip \
        python3-venv \
        openssh-client \
        unzip \
        zip \
        jq \
        ripgrep \
        wget \
        vim \
        nano \
        less \
        tree \
        htop \
        procps \
        && curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
        && apt-get install -y --no-install-recommends nodejs \
        && npm install -g cline \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

# Verify installations
RUN set -eux; \
    node --version; \
    npm --version; \
    git --version; \
    command -v cline; \
    cline --version || true

# Capture build-time API keys (non-empty only) for the entrypoint to export.
RUN mkdir -p /etc/cline && umask 077 && : > /etc/cline/build-keys.env && \
    for v in \
        ANTHROPIC_API_KEY ANTHROPIC_BASE_URL \
        OPENAI_API_KEY OPENAI_BASE_URL \
        OPENROUTER_API_KEY DEEPSEEK_API_KEY \
        GEMINI_API_KEY GOOGLE_GENERATIVE_AI_API_KEY \
        MISTRAL_API_KEY AWS_ACCESS_KEY_ID \
        AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; do \
        eval "val=\${$v:-}"; \
        if [ -n "$val" ]; then printf '%s=%s\n' "$v" "$val" >> /etc/cline/build-keys.env; fi; \
    done

# Entrypoint exports baked-in keys without overriding runtime values.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Bake the user's memory/rules file into the image as GLOBAL rules so Cline
# loads it at the start of every session, in every project. Copied to both
# global rules locations: ~/.cline/rules/ (native) and ~/Documents/Cline/Rules/
# (cross-tool; still found when ~/.cline is overlaid by the cline-data volume).
RUN mkdir -p /root/.cline/rules /root/Documents/Cline/Rules
COPY .clinerules/cline.md /root/.cline/rules/cline.md
COPY .clinerules/cline.md /root/Documents/Cline/Rules/cline.md

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
