# mcpcap Examples

This directory contains bundled example PCAP files for testing mcpcap's analysis tools.

## Example Files

- **`dns.pcap`** - DNS traffic capture containing queries and responses for testing DNS analysis
- **`dhcp.pcap`** - DHCP traffic showing complete 4-way handshake (DISCOVER → OFFER → REQUEST → ACK)

## Quick Start

### 1. Start the mcpcap MCP server

```bash
# Start with all modules (default)
mcpcap

# Or start with specific modules only
mcpcap --modules dns
mcpcap --modules dhcp
```

### 2. Use the analysis tools

With the MCP server running, use these analysis tools:

**DNS Analysis:**
```
analyze_dns_packets("./examples/dns.pcap")
analyze_dns_packets("/absolute/path/to/examples/dns.pcap")
```

**DHCP Analysis:**
```
analyze_dhcp_packets("./examples/dhcp.pcap")
analyze_dhcp_packets("/absolute/path/to/examples/dhcp.pcap")
```

**CapInfos Analysis:**
```
analyze_capinfos("./examples/dns.pcap")
```

## Testing with MCP Inspector

The MCP Inspector provides an easy way to test mcpcap tools:

### 1. Install MCP Inspector
```bash
npm install -g @modelcontextprotocol/inspector
```

### 2. Start Inspector with mcpcap
```bash
npx @modelcontextprotocol/inspector mcpcap
```

### 3. Test the Tools
In the web interface, try these tool calls:

**DNS Analysis:**
```javascript
analyze_dns_packets("./examples/dns.pcap")
```

**DHCP Analysis:**
```javascript
analyze_dhcp_packets("./examples/dhcp.pcap")
```

**CapInfos Analysis:**
```javascript
analyze_capinfos("./examples/dns.pcap")
```

**With Packet Limits:**
```javascript
// Start mcpcap with limits first: mcpcap --max-packets 10
analyze_dns_packets("./examples/dns.pcap")
```

## Analysis Prompts

mcpcap provides specialized prompts to guide your analysis. Use these in your MCP client:

### DNS Analysis Prompts

- **`security_analysis`** - Focus on security threats:
  - Suspicious domain patterns (DGA domains)
  - DNS tunneling detection
  - C2 communication patterns
  - Known malicious domains

- **`network_troubleshooting`** - Network performance focus:
  - DNS response times and latency
  - Failed queries and timeouts  
  - DNS server issues
  - Configuration problems

- **`forensic_investigation`** - Legal/forensic analysis:
  - Timeline reconstruction
  - Evidence preservation
  - Attribution and tracking
  - Detailed documentation

### DHCP Analysis Prompts

- **`dhcp_network_analysis`** - Network administration:
  - IP address management
  - DHCP lease analysis
  - Network topology mapping
  - Configuration optimization

- **`dhcp_security_analysis`** - Security threats:
  - Rogue DHCP server detection
  - DHCP attack identification
  - Client behavior anomalies
  - Security policy violations

- **`dhcp_forensic_investigation`** - Forensic analysis:
  - Device tracking via MAC addresses
  - Network presence timeline
  - Evidence collection
  - Incident reconstruction

## Expected Output Examples

### DNS Analysis Results
When analyzing DNS packets, you'll receive structured JSON including:

```json
{
  "file": "./examples/dns.pcap",
  "analysis_timestamp": "2024-01-01T12:00:00.000000",
  "total_packets_in_file": 50,
  "dns_packets_found": 25,
  "dns_packets_analyzed": 25,
  "statistics": {
    "queries": 12,
    "responses": 13,
    "unique_domains_queried": 8,
    "unique_domains": ["example.com", "google.com", "...]
  },
  "packets": [
    {
      "packet_number": 1,
      "timestamp": "2024-01-01T12:00:00.123456",
      "source_ip": "192.168.1.100",
      "destination_ip": "8.8.8.8",
      "protocol": "UDP",
      "flags": {
        "is_response": false,
        "authoritative": false,
        "truncated": false
      },
      "questions": [
        {
          "name": "example.com",
          "type": 1,
          "class": 1
        }
      ]
    }
  ]
}
```

### DHCP Analysis Results
When analyzing DHCP packets, you'll receive structured JSON including:

```json
{
  "file": "./examples/dhcp.pcap",
  "total_packets": 20,
  "dhcp_packets_found": 4,
  "dhcp_packets_analyzed": 4,
  "statistics": {
    "unique_clients_count": 1,
    "unique_servers_count": 1,
    "message_type_counts": {
      "DISCOVER": 1,
      "OFFER": 1,
      "REQUEST": 1,
      "ACK": 1
    },
    "transaction_count": 1
  },
  "packets": [
    {
      "packet_number": 1,
      "timestamp": 1234567890.0,
      "op": "Request",
      "message_type": "DISCOVER",
      "transaction_id": "0x12345678",
      "client_mac": "00:11:22:33:44:55",
      "options": {
        "parameter_request_list": [1, 3, 6, 15]
      }
    }
  ]
}
```

## Notes

- Bundled captures currently include `dns.pcap` and `dhcp.pcap`.
- ICMP and TCP examples in the docs use generic file paths because those sample captures are not bundled.

## Remote File Testing

You can also test with remote PCAP files:

```javascript
// Test with remote files
analyze_dns_packets("https://wiki.wireshark.org/uploads/dns.cap")
analyze_dhcp_packets("https://example.com/network-capture.pcap")
```

## Creating Custom Examples

To add your own example files:

### 1. Add PCAP Files
Place PCAP files (`.pcap`, `.pcapng`, or `.cap`) in this directory.

### 2. Test the Analysis
```bash
# Start mcpcap
mcpcap

# Test your file
analyze_dns_packets("./examples/your-file.pcap")
```

### 3. Document Your Example
Add descriptions to this README explaining what traffic is captured in your file.

## Troubleshooting

### File Not Found Errors
- Use absolute paths: `/full/path/to/examples/dns.pcap`
- Check current working directory where mcpcap was started
- Verify file permissions

### No Packets Found
- Confirm the PCAP contains the expected protocol traffic
- Try with `--max-packets 10` to limit analysis for testing
- Check that the appropriate module is loaded (`--modules dns,dhcp`)

### Analysis Errors
- Verify PCAP file integrity with Wireshark
- Check file extensions (`.pcap`, `.pcapng`, `.cap` supported)
- Review mcpcap server logs for detailed error messages
