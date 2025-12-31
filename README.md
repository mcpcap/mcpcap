# mcpcap

<!-- mcp-name: ai.mcpcap/mcpcap -->

![mcpcap logo](https://raw.githubusercontent.com/mcpcap/mcpcap/main/readme-assets/mcpcap-logo.png)

A modular Python MCP (Model Context Protocol) Server for analyzing PCAP files. mcpcap enables LLMs to read and analyze network packet captures with protocol-specific analysis tools that accept local file paths or remote URLs as parameters (no file uploads - provide the path or URL to your PCAP file).

## Overview

mcpcap uses a modular architecture to analyze different network protocols found in PCAP files. Each module provides specialized analysis tools that can be called independently with any PCAP file, making it perfect for integration with Claude Desktop and other MCP clients.

### Key Features

- **Stateless MCP Tools**: Each analysis accepts PCAP file paths or URLs as parameters (no file uploads)
- **Modular Architecture**: DNS, DHCP, ICMP, TCP, Payload, and CapInfos modules with easy extensibility for new protocols  
- **Advanced TCP Analysis**: Connection tracking, anomaly detection, retransmission analysis, and traffic flow inspection
- **Payload Analysis**: Automatic protocol detection (MySQL, PostgreSQL, Redis), SQL query extraction, encryption detection
- **Database Protocol Support**: Extract SQL queries and commands from MySQL, PostgreSQL, and Redis traffic
- **Encryption Detection**: Identify TLS/SSL encryption with intelligent recommendations for analysis
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
# Default: Start with DNS, DHCP, ICMP, TCP, Payload, and CapInfos modules
mcpcap

# Start with specific modules only
mcpcap --modules dns,tcp,payload

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

**TCP Connection Analysis:**
```
analyze_tcp_connections("/path/to/capture.pcap")
analyze_tcp_connections("/path/to/capture.pcap", server_ip="192.168.1.1", server_port=80)
```

**TCP Anomaly Detection:**
```
analyze_tcp_anomalies("/path/to/capture.pcap", server_ip="10.0.0.1")
```

**TCP Retransmission Analysis:**
```
analyze_tcp_retransmissions("/path/to/capture.pcap")
```

**Traffic Flow Analysis:**
```
analyze_traffic_flow("/path/to/capture.pcap", server_ip="192.168.1.100")
```

**CapInfos Analysis:**
```
analyze_capinfos("/path/to/any.pcap")
analyze_capinfos("https://example.com/capture.pcap")
```

**Payload Analysis:**
```
analyze_payload("/path/to/capture.pcap")
extract_database_queries("/path/to/mysql.pcap", protocol="mysql")
detect_protocols("/path/to/capture.pcap")
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

### TCP Analysis Tools

- **`analyze_tcp_connections(pcap_file, server_ip=None, server_port=None, detailed=False)`**: TCP connection state analysis
  - Track TCP three-way handshake (SYN, SYN-ACK, ACK)
  - Analyze connection lifecycle and termination (FIN, RST)
  - Identify successful vs failed connections
  - Filter by server IP and/or port
  - Detect connection issues and abnormal closures

- **`analyze_tcp_anomalies(pcap_file, server_ip=None, server_port=None)`**: Intelligent TCP anomaly detection
  - Automatically detect common network problems
  - Identify client vs server-initiated RST patterns (firewall blocks)
  - Detect high retransmission rates (network quality issues)
  - Diagnose handshake failures
  - Root cause analysis with confidence scoring
  - Actionable recommendations

- **`analyze_tcp_retransmissions(pcap_file, server_ip=None, threshold=0.02)`**: TCP retransmission analysis
  - Measure overall and per-connection retransmission rates
  - Identify connections with quality issues
  - Compare against configurable thresholds
  - Detect network congestion and packet loss

- **`analyze_traffic_flow(pcap_file, server_ip, server_port=None)`**: Bidirectional traffic flow analysis
  - Analyze client-to-server vs server-to-client traffic
  - Identify traffic asymmetry
  - Determine RST packet sources
  - Interpret connection patterns and behaviors

### CapInfos Analysis Tools

- **`analyze_capinfos(pcap_file)`**: PCAP file metadata and statistics
  - File information (size, name, link layer encapsulation)
  - Packet statistics (count, data size, average packet size)
  - Temporal analysis (duration, timestamps, packet rates)
  - Data throughput metrics (bytes/second, bits/second)
  - Similar to Wireshark's capinfos(1) utility

### Payload Analysis Tools

- **`analyze_payload(pcap_file, port=None, protocol="auto")`**: Complete application-layer analysis
  - Automatic protocol detection (MySQL, PostgreSQL, Redis, MongoDB, HTTP, TLS)
  - Extract all TCP/UDP payloads with hex and ASCII representation
  - Detect encryption status and TLS versions
  - Parse database protocols and extract queries/commands
  - Generate intelligent recommendations for encrypted traffic
  
- **`extract_database_queries(pcap_file, protocol="auto", port=None)`**: Specialized SQL/command extraction
  - Extract SQL queries from MySQL, PostgreSQL traffic
  - Parse Redis commands (GET, SET, HGET, etc.)
  - Identify query types (SELECT, INSERT, UPDATE, DELETE)
  - Filter by protocol and port
  - Works only with unencrypted traffic (provides guidance for encrypted)

- **`detect_protocols(pcap_file, port=None)`**: Quick protocol identification
  - Identify application protocols with confidence scores
  - Detect TLS/SSL encryption
  - No full payload parsing (faster than analyze_payload)
  - Useful for understanding traffic composition

**Supported Protocols:**
- MySQL (port 3306) - Server handshake, COM_QUERY, OK/ERR responses
- PostgreSQL (port 5432) - Startup messages, Simple Query, Prepared Statements
- Redis (port 6379) - RESP protocol, commands and responses
- MongoDB (port 27017) - Wire protocol detection
- HTTP/HTTPS (ports 80, 8080, 443) - Request/response line detection
- TLS/SSL - Version detection (1.0, 1.1, 1.2, 1.3)

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

### TCP Prompts
- **`tcp_connection_troubleshooting`** - Connection issues, handshake analysis, termination patterns
- **`tcp_security_analysis`** - Attack detection, firewall analysis, anomaly identification

### Payload Prompts
- **`payload_database_analysis`** - Extract and analyze SQL queries from database traffic
- **`payload_security_analysis`** - Detect suspicious commands, SQL injection patterns
- **`payload_encryption_analysis`** - Identify encryption, provide decryption guidance

## Configuration Options

### Module Selection

```bash
# Load specific modules
mcpcap --modules dns              # DNS analysis only
mcpcap --modules tcp              # TCP analysis only
mcpcap --modules payload          # Payload analysis only
mcpcap --modules dhcp             # DHCP analysis only
mcpcap --modules icmp             # ICMP analysis only  
mcpcap --modules dns,tcp,payload  # Multiple modules
mcpcap --modules dns,dhcp,icmp,tcp,capinfos,payload    # All modules (default)
```

### Analysis Limits

```bash
# Limit packet analysis for large files
mcpcap --max-packets 1000
```

### Complete Configuration Example

```bash
mcpcap --modules dns,dhcp,icmp,tcp,capinfos,payload --max-packets 500
```

## CLI Reference

```bash
mcpcap [--modules MODULES] [--max-packets N]
```

**Options:**
- `--modules MODULES`: Comma-separated modules to load (default: `dns,dhcp,icmp,tcp,capinfos,payload`)
  - Available modules: `dns`, `dhcp`, `icmp`, `tcp`, `capinfos`, `payload`
- `--max-packets N`: Maximum packets to analyze per file (default: unlimited)

**Examples:**
```bash
# Start with all modules
mcpcap

# DNS and TCP analysis only
mcpcap --modules dns,tcp

# TCP analysis for troubleshooting connections
mcpcap --modules tcp

# Payload analysis for database traffic
mcpcap --modules payload

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
2. **Protocol Modules**: DNS, DHCP, ICMP, TCP, and Payload analysis implementations  
3. **MCP Interface**: Tool registration and prompt management
4. **FastMCP Framework**: MCP server implementation
5. **Protocol Detectors**: Automatic protocol identification engine
6. **Database Parsers**: MySQL, PostgreSQL, Redis protocol parsers

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

Future enhancements might include:
- MongoDB wire protocol full implementation
- HTTP/HTTPS request/response complete extraction
- Enhanced SQL injection detection
- Sensitive data detection (passwords, tokens)
- Statistical analysis (query frequency, slow queries)
- UDP connection analysis
- BGP routing analysis
- SSL/TLS certificate analysis
- Network forensics tools
- Port scan detection

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

- **New Protocol Modules**: Add support for HTTP, BGP, SMTP, etc.
- **Enhanced Database Parsers**: MongoDB, Cassandra, ElasticSearch protocols
- **Enhanced Analysis**: Improve existing protocol analysis
- **Security Features**: Add more threat detection capabilities (SQL injection, data exfiltration)
- **Performance**: Optimize analysis for large PCAP files
- **Stream Reassembly**: Handle fragmented TCP packets

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