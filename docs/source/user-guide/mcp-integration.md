# MCP Client Integration

mcpcap runs as a stateless MCP server. You start the server once, then call tools with a `pcap_file` argument that points to either a local capture or a remote HTTP URL.

## What mcpcap exposes

CLI startup is limited to module loading and packet limits:

```bash
mcpcap [--modules MODULES] [--max-packets N]
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

## Troubleshooting

**Tool missing**
- Check the server was started with the module that owns that tool.
- Restart the MCP client after changing config.

**File not found**
- Pass a path visible from the machine running `mcpcap`.
- Use a valid `.pcap`, `.pcapng`, or `.cap` filename.

**No protocol packets found**
- The tool returns successfully even when the target protocol is absent.
- Confirm the capture contains the traffic you expect before assuming a parser issue.
