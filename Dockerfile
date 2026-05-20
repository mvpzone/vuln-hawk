# vuln-hawk — ADK web app + sibling-container PoC sandbox.
#
# The agent uses the host's Docker daemon (via /var/run/docker.sock mount)
# to spawn target + sender containers at runtime. This image carries only
# the agent itself plus the bundled targets/ trees used as build contexts.

FROM python:3.13-slim AS base

# Install Docker CE CLI from Docker's upstream Debian apt repo. Matches
# the VM host's `docker-ce` install for client/server version
# consistency. The container only needs the CLI; the daemon lives on
# the host and we mount its socket. No `docker-ce` or `containerd.io`
# inside the container.
#
# Follows Docker's official Debian install guide using deb822 .sources
# format + .asc keyring (current canonical pattern):
#   https://docs.docker.com/engine/install/debian/
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
         -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && DEBIAN_CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME") \
    && printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.asc\n' \
         "$DEBIAN_CODENAME" "$(dpkg --print-architecture)" \
         > /etc/apt/sources.list.d/docker.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        docker-ce-cli \
        docker-buildx-plugin \
        docker-compose-plugin \
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
