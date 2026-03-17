# Installation

mcpcap requires Python 3.10 or greater.

## Using pip (Recommended)

Install mcpcap from PyPI:

```bash
pip install mcpcap
```

This will install mcpcap and all its dependencies.

## Using uv

If you're using [uv](https://github.com/astral-sh/uv):

```bash
uv add mcpcap
```

## Using uvx (One-time usage)

To run mcpcap without installing it permanently:

```bash
uvx mcpcap
```

Then connect with an MCP client and pass a PCAP path or URL to the analysis tool you want to call.

For HTTP-based MCP clients, start mcpcap with:

```bash
mcpcap --transport http --host 127.0.0.1 --port 8080
```

## Using Docker

Build the runtime image from the repository root:

```bash
docker build -t mcpcap .
```

Start mcpcap in HTTP mode with a mounted capture directory:

```bash
docker run --rm \
  -p 8080:8080 \
  -v "/path/to/captures:/pcaps:ro" \
  mcpcap --transport http --host 0.0.0.0 --port 8080
```

For stdio-based MCP clients that can spawn containers directly:

```bash
docker run --rm -i \
  -v "/path/to/captures:/pcaps:ro" \
  mcpcap
```

Use the mounted container path when calling tools:

```text
analyze_dns_packets("/pcaps/dns.pcap")
```

Local file analysis only works for paths visible inside the container, so mount the directory that contains your PCAP files. Remote `http://` and `https://` captures do not require a volume mount.

## Using Docker Compose

The repository also includes a Compose file for the standard HTTP deployment:

```bash
docker compose up
```

This pulls `ghcr.io/mcpcap/mcpcap:latest`, starts mcpcap on `http://127.0.0.1:8080/mcp`, and mounts `./examples` as `/pcaps` inside the container.

Update [docker-compose.yml](/Users/daniel/.codex/worktrees/4c5f/mcpcap/docker-compose.yml) if you want to mount a different local capture directory.

For local development with a build from the checked-out repository:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

## Development Installation

If you want to contribute to mcpcap or modify it:

```bash
# Clone the repository
git clone https://github.com/mcpcap/mcpcap.git
cd mcpcap

# Install in development mode with all dependencies
pip install -e ".[dev,docs,test]"

# Install the repository's Git hooks
pre-commit install
```

If you prefer `uv` for development:

```bash
uv sync --extra dev --extra docs --extra test
pre-commit install
```

## Verify Installation

Verify that mcpcap is installed correctly:

```bash
mcpcap --help
```

You should see the help message showing available command-line options.

## Dependencies

mcpcap depends on:

- **fastmcp**: MCP server framework
- **scapy**: Packet parsing and analysis
- **requests**: HTTP client for remote PCAP access
- **Python 3.10+**: Modern Python features and type hints

All dependencies are automatically installed when you install mcpcap.

## Troubleshooting

### Permission Issues

mcpcap analyzes existing capture files. It does not capture live traffic itself, so elevated packet-capture privileges are not normally required.

### Import Errors

If you encounter import errors, make sure you're using the correct Python version:

```bash
python --version  # Should be 3.10 or higher
```

### Virtual Environment

It's recommended to use a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install mcpcap
```
