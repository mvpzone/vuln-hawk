# vuln-hawk — ADK web app + sibling-container PoC sandbox.
#
# The agent uses the host's Docker daemon (via /var/run/docker.sock mount)
# to spawn target + sender containers at runtime. This image carries only
# the agent itself plus the bundled targets/ trees used as build contexts.

FROM python:3.13-slim AS base

# Install Docker CLI (talks to the host daemon via the mounted socket)
# + minimal git for any runtime git ops + curl for the uv installer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        docker.io \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv — fast Python package manager (matches project's pyproject.toml + uv.lock)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.local/bin/uv /usr/local/bin/uv

WORKDIR /app

# Layer caching: copy lockfile + pyproject first, install, then copy app code.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy app code + bundled scan targets (target_manager builds these via docker.sock at runtime)
COPY vuln_agent/ ./vuln_agent/
COPY sandbox/ ./sandbox/
COPY targets/ ./targets/
COPY eval/ ./eval/

# Install the project itself (resolves the `vuln-discovery-agent` entry point)
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000

# adk web — listens on 0.0.0.0:8000; ADK discovers vuln_agent via cwd lookup.
# Run as root: required for docker.sock access to host daemon (sibling-container pattern).
CMD ["adk", "web", "--host=0.0.0.0", "--port=8000"]
