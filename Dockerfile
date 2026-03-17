FROM python:3.11-slim

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
    SETUPTOOLS_SCM_PRETEND_VERSION=${MCPPCAP_VERSION}

WORKDIR /app

RUN groupadd --system mcpcap \
    && useradd --system --gid mcpcap --create-home --home-dir /home/mcpcap mcpcap \
    && mkdir -p /pcaps /tmp \
    && chown -R mcpcap:mcpcap /pcaps /tmp /home/mcpcap

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --no-cache-dir uv \
    && uv pip install --system .

USER mcpcap

WORKDIR /home/mcpcap

EXPOSE 8080

ENTRYPOINT ["mcpcap"]
