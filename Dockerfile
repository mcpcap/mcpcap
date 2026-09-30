# syntax=docker/dockerfile:1
FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.19 /uv /uvx /bin/

ARG MCPPCAP_VERSION=0.0.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="mcpcap" \
      org.opencontainers.image.description="A modular Python MCP server for analyzing PCAP files" \
      org.opencontainers.image.source="https://github.com/mcpcap/mcpcap" \
      org.opencontainers.image.version="${MCPPCAP_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    SETUPTOOLS_SCM_PRETEND_VERSION=${MCPPCAP_VERSION} \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN groupadd --system mcpcap \
    && useradd --system --gid mcpcap --create-home --home-dir /home/mcpcap mcpcap \
    && mkdir -p /pcaps /tmp \
    && chown -R mcpcap:mcpcap /pcaps /tmp /home/mcpcap

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src

# An optional combined CA bundle supports builds behind a trusted HTTPS proxy.
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; \
    uv sync --locked --no-dev --group build --no-install-project \
    && uv sync --locked --no-dev --group build --no-editable --no-build-isolation

USER mcpcap

WORKDIR /home/mcpcap

EXPOSE 8080

ENTRYPOINT ["mcpcap"]
