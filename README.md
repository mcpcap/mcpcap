# mcpcap

<!-- mcp-name: ai.mcpcap/mcpcap -->

![mcpcap logo](https://raw.githubusercontent.com/mcpcap/mcpcap/main/readme-assets/mcpcap-logo.png)

<a href="https://glama.ai/mcp/servers/@danohn/mcpcap">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@danohn/mcpcap/badge" alt="mcpcap MCP server" />
</a>

A modular Python MCP (Model Context Protocol) Server for analyzing PCAP files. mcpcap enables LLMs to read and analyze network packet captures with protocol-specific analysis tools that accept local file paths or remote URLs as parameters (no file uploads - provide the path or URL to your PCAP file).

## Overview

mcpcap uses a modular architecture to analyze different network protocols found in PCAP files. Each module provides specialized analysis tools that can be called independently with any PCAP file, making it perfect for integration with Claude Desktop and other MCP clients.

### Key Features

- **Stateless MCP Tools**: Each analysis accepts PCAP file paths or URLs as parameters (no file uploads)
- **Modular Architecture**: DNS, DHCP, ICMP, and CapInfos modules with easy extensibility for new protocols  
- **Local & Remote PCAP Support**: Analyze files from local storage or HTTP URLs
- **Scapy Integration**: Leverages scapy's comprehensive packet parsing capabilities
- **Specialized Analysis Prompts**: Security, networking, and forensic analysis guidance
- **JSON Responses**: Structured data format optimized for LLM consumption

## Installation

mcpcap requires Python 3.10 or greater.

### Using pip

```bash
pip install mcpcap
```

### Using uv

```bash
uv add mcpcap
```

### Using uvx (for one-time usage)

```bash
uvx mcpcap
```

## Quick Start

### 1. Start the MCP Server

Start mcpcap as a stateless MCP server:

```bash
# Default: Start with DNS, DHCP, and ICMP modules
mcpcap

# Start with specific modules only
mcpcap --modules dns

# With packet analysis limits
mcpcap --max-packets 1000
```

### 2. Connect Your MCP Client

Configure your MCP client (like Claude Desktop) to connect to the mcpcap server:

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

### 3. Analyze PCAP Files

Use the analysis tools with any PCAP file by providing the file path or URL (not file uploads):

**DNS Analysis:**
```
analyze_dns_packets("/path/to/dns.pcap")
analyze_dns_packets("https://example.com/remote.pcap")
```

**DHCP Analysis:**
```
analyze_dhcp_packets("/path/to/dhcp.pcap")
analyze_dhcp_packets("https://example.com/dhcp-capture.pcap")
```

**ICMP Analysis:**
```
analyze_icmp_packets("/path/to/icmp.pcap")
analyze_icmp_packets("https://example.com/ping-capture.pcap")
```

**CapInfos Analysis:**
```
analyze_capinfos("/path/to/any.pcap")
analyze_capinfos("https://example.com/capture.pcap")
```

## Available Tools

### DNS Analysis Tools

- **`analyze_dns_packets(pcap_file)`**: Complete DNS traffic analysis
  - Extract DNS queries and responses
  - Identify queried domains and subdomains
  - Analyze query types (A, AAAA, MX, CNAME, etc.)
  - Track query frequency and patterns
  - Detect potential security issues

### DHCP Analysis Tools

- **`analyze_dhcp_packets(pcap_file)`**: Complete DHCP traffic analysis
  - Track DHCP transactions (DISCOVER, OFFER, REQUEST, ACK)
  - Identify DHCP clients and servers
  - Monitor IP address assignments and lease information
  - Analyze DHCP options and configurations
  - Detect DHCP anomalies and security issues

### ICMP Analysis Tools

- **`analyze_icmp_packets(pcap_file)`**: Complete ICMP traffic analysis
  - Analyze ping requests and replies with response times
  - Identify network connectivity and reachability issues
  - Track TTL values and routing paths (traceroute data)
  - Detect ICMP error messages (unreachable, time exceeded)
  - Monitor for potential ICMP-based attacks or reconnaissance

### CapInfos Analysis Tools

- **`analyze_capinfos(pcap_file)`**: PCAP file metadata and statistics
  - File information (size, name, link layer encapsulation)
  - Packet statistics (count, data size, average packet size)
  - Temporal analysis (duration, timestamps, packet rates)
  - Data throughput metrics (bytes/second, bits/second)
  - Similar to Wireshark's capinfos(1) utility

## Analysis Prompts

mcpcap provides specialized analysis prompts to guide LLM analysis:

### DNS Prompts
- **`security_analysis`** - Focus on threat detection, DGA domains, DNS tunneling
- **`network_troubleshooting`** - Identify DNS performance and configuration issues
- **`forensic_investigation`** - Timeline reconstruction and evidence collection

### DHCP Prompts  
- **`dhcp_network_analysis`** - Network administration and IP management
- **`dhcp_security_analysis`** - Security threats and rogue DHCP detection
- **`dhcp_forensic_investigation`** - Forensic analysis of DHCP transactions

### ICMP Prompts
- **`icmp_network_diagnostics`** - Network connectivity and path analysis
- **`icmp_security_analysis`** - ICMP-based attacks and reconnaissance detection
- **`icmp_forensic_investigation`** - Timeline reconstruction and network mapping

## Configuration Options

### Module Selection

```bash
# Load specific modules
mcpcap --modules dns              # DNS analysis only
mcpcap --modules dhcp             # DHCP analysis only
mcpcap --modules icmp             # ICMP analysis only  
mcpcap --modules dns,dhcp,icmp,capinfos    # All modules (default)
```

### Analysis Limits

```bash
# Limit packet analysis for large files
mcpcap --max-packets 1000
```

### Complete Configuration Example

```bash
mcpcap --modules dns,dhcp,icmp,capinfos --max-packets 500
```

## CLI Reference

```bash
mcpcap [--modules MODULES] [--max-packets N]
```

**Options:**
- `--modules MODULES`: Comma-separated modules to load (default: `dns,dhcp,icmp,capinfos`)
  - Available modules: `dns`, `dhcp`, `icmp`, `capinfos`
- `--max-packets N`: Maximum packets to analyze per file (default: unlimited)

**Examples:**
```bash
# Start with all modules
mcpcap

# DNS analysis only
mcpcap --modules dns

# With packet limits for large files
mcpcap --max-packets 1000
```

## Examples

Example PCAP files are included in the `examples/` directory:

- `dns.pcap` - DNS traffic for testing DNS analysis
- `dhcp.pcap` - DHCP 4-way handshake capture
- `icmp.pcap` - ICMP ping and traceroute traffic

### Using with MCP Inspector

```bash
npm install -g @modelcontextprotocol/inspector
npx @modelcontextprotocol/inspector mcpcap
```

Then test the tools:
```javascript
// In the MCP Inspector web interface
analyze_dns_packets("./examples/dns.pcap")
analyze_dhcp_packets("./examples/dhcp.pcap")
analyze_icmp_packets("./examples/icmp.pcap")
analyze_capinfos("./examples/dns.pcap")
```

## Architecture

mcpcap's modular design supports easy extension:

### Core Components
1. **BaseModule**: Shared file handling, validation, and remote download
2. **Protocol Modules**: DNS, DHCP, and ICMP analysis implementations  
3. **MCP Interface**: Tool registration and prompt management
4. **FastMCP Framework**: MCP server implementation

### Tool Flow
```
MCP Client Request → analyze_*_packets(pcap_file)
                  → BaseModule.analyze_packets()
                  → Module._analyze_protocol_file()
                  → Structured JSON Response
```

### Adding New Modules

Create new protocol modules by:

1. Inheriting from `BaseModule`
2. Implementing `_analyze_protocol_file(pcap_file)`
3. Registering analysis tools with the MCP server
4. Adding specialized analysis prompts

Future modules might include:
- HTTP/HTTPS traffic analysis
- TCP connection tracking  
- BGP routing analysis
- SSL/TLS certificate analysis
- Network forensics tools

## Remote File Support

Both analysis tools accept remote PCAP files via HTTP/HTTPS URLs:

```bash
# Examples of remote analysis
analyze_dns_packets("https://wiki.wireshark.org/uploads/dns.cap")
analyze_dhcp_packets("https://example.com/network-capture.pcap")
analyze_icmp_packets("https://example.com/ping-test.pcap")
analyze_capinfos("https://example.com/network-metadata.pcap")
```

**Features:**
- Automatic temporary download and cleanup
- Support for `.pcap`, `.pcapng`, and `.cap` files
- HTTP/HTTPS protocols supported

## Security Considerations

When analyzing PCAP files:
- Files may contain sensitive network information
- Remote downloads are performed over HTTPS when possible
- Temporary files are cleaned up automatically
- Consider the source and trustworthiness of remote files

## Contributing

Contributions welcome! Areas for contribution:

- **New Protocol Modules**: Add support for HTTP, BGP, TCP, etc.
- **Enhanced Analysis**: Improve existing DNS/DHCP analysis
- **Security Features**: Add more threat detection capabilities
- **Performance**: Optimize analysis for large PCAP files

## License

MIT

## Requirements

- Python 3.10+
- scapy (packet parsing and analysis)
- requests (remote file access)
- fastmcp (MCP server framework)

## Documentation

- **GitHub**: [github.com/mcpcap/mcpcap](https://github.com/mcpcap/mcpcap)
- **Documentation**: [docs.mcpcap.ai](https://docs.mcpcap.ai) 
- **Website**: [mcpcap.ai](https://mcpcap.ai)

## Support

For questions, issues, or feature requests, please open an issue on GitHub.