# MCP Client Integration

mcpcap runs as a stateless MCP server. You start the server once, then call tools with a `pcap_file` argument that points to either a local capture or a remote HTTP URL.

## What mcpcap exposes

CLI startup supports module selection, packet limits, and MCP transport choice:

```bash
mcpcap [--modules MODULES] [--max-packets N] [--transport {stdio,http}] [--host HOST] [--port PORT]
```

Available modules:

- `dns`
- `dhcp`
- `icmp`
- `tcp`
- `sip`
- `capinfos`

## Claude Desktop

Add mcpcap to Claude Desktop with the normal stdio configuration:

```json
{
  "mcpServers": {
    "mcpcap": {
      "command": "mcpcap",
      "args": []
    }
  }
}
```

If you want to reduce the exposed tool set, configure modules explicitly:

```json
{
  "mcpServers": {
    "mcpcap-tcp": {
      "command": "mcpcap",
      "args": ["--modules", "tcp,capinfos", "--max-packets", "1000"]
    }
  }
}
```

If your client can launch Docker instead of a local binary, the same stdio setup can run through the container image:

```json
{
  "mcpServers": {
    "mcpcap-docker": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v",
        "/Users/me/captures:/pcaps:ro",
        "ghcr.io/mcpcap/mcpcap:latest"
      ]
    }
  }
}
```

In that setup, tool calls must use container-visible paths such as `/pcaps/dns.pcap`.

## HTTP MCP Clients

For clients that connect to a network endpoint instead of spawning a local stdio process, start mcpcap in HTTP mode:

```bash
mcpcap --transport http --host 127.0.0.1 --port 8080
```

Then point the client at:

```text
http://127.0.0.1:8080/mcp
```

If you want the endpoint reachable from other machines on your network, bind a different host:

```bash
mcpcap --transport http --host 0.0.0.0 --port 8080
```

The equivalent Docker command is:

```bash
docker run --rm \
  -p 8080:8080 \
  -v "/path/to/captures:/pcaps:ro" \
  ghcr.io/mcpcap/mcpcap:latest \
  --transport http --host 0.0.0.0 --port 8080
```

The repository's Compose file starts the same HTTP endpoint locally:

```bash
docker compose up
```

It pulls `ghcr.io/mcpcap/mcpcap:latest`, mounts `./examples` into the container as `/pcaps`, and serves the same endpoint locally. Tool calls should use paths such as `/pcaps/dns.pcap`.

For local development against the checked-out source:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

## MCP Inspector

For direct tool testing:

```bash
npm install -g @modelcontextprotocol/inspector
npx @modelcontextprotocol/inspector mcpcap
```

## Custom Python Client

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def analyze_dns() -> None:
    server_params = StdioServerParameters(command="mcpcap", args=[])

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "analyze_dns_packets",
                arguments={"pcap_file": "./examples/dns.pcap"},
            )
            print(result.content)


asyncio.run(analyze_dns())
```

## Tool model

There is no `list_pcap_files` tool and no startup-time PCAP selection. Each tool call includes the capture to analyze.

### DNS

- `analyze_dns_packets(pcap_file)`

### DHCP

- `analyze_dhcp_packets(pcap_file)`

### ICMP

- `analyze_icmp_packets(pcap_file)`

### TCP

- `analyze_tcp_connections(pcap_file, server_ip=None, server_port=None, detailed=False)`
- `analyze_tcp_anomalies(pcap_file, server_ip=None, server_port=None)`
- `analyze_tcp_retransmissions(pcap_file, server_ip=None, threshold=0.02)`
- `analyze_traffic_flow(pcap_file, server_ip, server_port=None)`

### SIP

- `analyze_sip_packets(pcap_file)`

### CapInfos

- `analyze_capinfos(pcap_file)`

## Prompt support

Available prompts are registered by module:

- DNS: `security_analysis`, `network_troubleshooting`, `forensic_investigation`
- DHCP: `dhcp_network_analysis`, `dhcp_security_analysis`, `dhcp_forensic_investigation`
- ICMP: `icmp_network_diagnostics`, `icmp_security_analysis`, `icmp_forensic_investigation`
- TCP: `tcp_connection_troubleshooting`, `tcp_security_analysis`
- SIP: `sip_security_analysis`, `sip_troubleshooting_analysis`, `sip_forensic_investigation`

## Input expectations

- Local files can be absolute or relative paths as long as the server process can read them.
- When running in Docker, local host paths are not visible automatically; mount them and use the in-container path instead.
- Remote files must be `http://` or `https://` URLs.
- Supported extensions are `.pcap`, `.pcapng`, and `.cap`.
- MCP file uploads are not consumed directly; pass a saved file path or URL instead.

## Usage examples

```text
analyze_dns_packets("./examples/dns.pcap")
analyze_dhcp_packets("./examples/dhcp.pcap")
analyze_icmp_packets("/absolute/path/to/icmp.pcap")
analyze_tcp_connections("/absolute/path/to/tcp-session.pcap", server_port=443)
analyze_sip_packets("/absolute/path/to/voip-signaling.pcap")
analyze_capinfos("https://example.com/capture.pcap")
```

Docker-mounted example:

```text
analyze_dns_packets("/pcaps/dns.pcap")
```

## Troubleshooting

**Tool missing**
- Check the server was started with the module that owns that tool.
- Restart the MCP client after changing config.

**File not found**
- Pass a path visible from the machine running `mcpcap`.
- In Docker, make sure the host directory is mounted into the container and use the mounted path.
- Use a valid `.pcap`, `.pcapng`, or `.cap` filename.

**No protocol packets found**
- The tool returns successfully even when the target protocol is absent.
- Confirm the capture contains the traffic you expect before assuming a parser issue.
