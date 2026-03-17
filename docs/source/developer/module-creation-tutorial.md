# Module Creation Tutorial

This tutorial will walk you through creating a complete HTTP analysis module for mcpcap. By the end, you'll understand the module architecture and be able to create your own protocol analyzers.

## Overview

We'll create an HTTP module that can:
- Parse HTTP requests and responses from PCAP files
- Extract URLs, methods, status codes, and headers
- Generate security-focused analysis
- Provide statistics on HTTP traffic

## Prerequisites

Before starting, ensure you have:
- mcpcap development environment set up (see [CONTRIBUTING.md](https://github.com/mcpcap/mcpcap/blob/main/CONTRIBUTING.md))
- Basic understanding of HTTP protocol
- Familiarity with Python and Scapy

## Step 1: Create the Module File

Create a new file `src/mcpcap/modules/http.py`:

```python
"""HTTP analysis module."""

from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP
from scapy.all import TCP, rdpcap

from .base import BaseModule


class HTTPModule(BaseModule):
    """Module for analyzing HTTP packets in PCAP files."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "HTTP"

    def analyze_http_packets(self, pcap_file: str) -> dict[str, Any]:
        """
        Analyze HTTP packets from a PCAP file and return comprehensive analysis results.

        Args:
            pcap_file: Path to local PCAP file or HTTP URL to remote PCAP file

        Returns:
            A structured dictionary containing HTTP packet analysis results
        """
        return self.analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform the actual HTTP packet analysis on a local PCAP file."""
        try:
            packets = rdpcap(pcap_file)

            # Filter for TCP packets on HTTP ports (80, 443, 8080, etc.)
            http_packets = []
            for pkt in packets:
                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    if (tcp_layer.dport in [80, 443, 8080, 8443] or
                        tcp_layer.sport in [80, 443, 8080, 8443]):
                        # Check if packet contains HTTP data
                        if hasattr(pkt[TCP], 'load') and pkt[TCP].load:
                            payload = pkt[TCP].load
                            if self._is_http_packet(payload):
                                http_packets.append(pkt)

            if not http_packets:
                return {
                    "file": pcap_file,
                    "total_packets": len(packets),
                    "http_packets_found": 0,
                    "message": "No HTTP packets found in this capture",
                }

            # Apply max_packets limit if specified
            packets_to_analyze = http_packets
            limited = False
            if self.config.max_packets and len(http_packets) > self.config.max_packets:
                packets_to_analyze = http_packets[:self.config.max_packets]
                limited = True

            packet_details = []
            for i, pkt in enumerate(packets_to_analyze, 1):
                packet_info = self._analyze_http_packet(pkt, i)
                if packet_info:  # Only add valid HTTP packets
                    packet_details.append(packet_info)

            # Generate statistics
            stats = self._generate_statistics(packet_details)

            result = {
                "file": pcap_file,
                "analysis_timestamp": datetime.now().isoformat(),
                "total_packets": len(packets),
                "http_packets_found": len(http_packets),
                "http_packets_analyzed": len(packet_details),
                "statistics": stats,
                "packets": packet_details,
            }

            if limited:
                result["note"] = (
                    f"Analysis limited to first {self.config.max_packets} HTTP packets due to --max-packets setting"
                )

            return result

        except Exception as e:
            return {
                "error": f"Error reading PCAP file '{pcap_file}': {str(e)}",
                "file": pcap_file,
            }

    def _is_http_packet(self, payload: bytes) -> bool:
        """Check if TCP payload contains HTTP data."""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            # Check for HTTP request methods
            http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']
            if any(payload_str.startswith(method) for method in http_methods):
                return True
            # Check for HTTP response
            if payload_str.startswith('HTTP/'):
                return True
            return False
        except:
            return False

    def _analyze_http_packet(self, pkt: Any, packet_number: int) -> dict[str, Any] | None:
        """Analyze a single HTTP packet."""
        try:
            tcp_layer = pkt[TCP]
            payload = tcp_layer.load.decode('utf-8', errors='ignore')

            packet_info = {
                "packet_number": packet_number,
                "timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat(),
                "source_ip": pkt[0][1].src,
                "destination_ip": pkt[0][1].dst,
                "source_port": tcp_layer.sport,
                "destination_port": tcp_layer.dport,
            }

            # Parse HTTP request
            if any(payload.startswith(method) for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']):
                request_info = self._parse_http_request(payload)
                packet_info.update({
                    "type": "request",
                    **request_info
                })

            # Parse HTTP response
            elif payload.startswith('HTTP/'):
                response_info = self._parse_http_response(payload)
                packet_info.update({
                    "type": "response",
                    **response_info
                })
            else:
                return None  # Not a valid HTTP packet

            return packet_info

        except Exception as e:
            return {
                "packet_number": packet_number,
                "timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat(),
                "error": f"Failed to parse HTTP packet: {str(e)}",
                "type": "parsing_error"
            }

    def _parse_http_request(self, payload: str) -> dict[str, Any]:
        """Parse HTTP request payload."""
        lines = payload.split('\\n')
        request_line = lines[0].strip()

        try:
            method, url, version = request_line.split(' ', 2)

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line and line.strip():
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                elif line.strip() == '':
                    break

            # Extract additional info
            parsed_url = urlparse(url)

            return {
                "method": method,
                "url": url,
                "path": parsed_url.path,
                "query": parsed_url.query,
                "version": version,
                "headers": headers,
                "host": headers.get('host', 'unknown'),
                "user_agent": headers.get('user-agent', 'unknown'),
                "content_type": headers.get('content-type', 'unknown'),
                "content_length": headers.get('content-length', '0'),
            }
        except ValueError:
            return {
                "method": "unknown",
                "url": "unknown",
                "version": "unknown",
                "headers": {},
                "parsing_error": "Invalid request line format"
            }

    def _parse_http_response(self, payload: str) -> dict[str, Any]:
        """Parse HTTP response payload."""
        lines = payload.split('\\n')
        status_line = lines[0].strip()

        try:
            parts = status_line.split(' ', 2)
            version = parts[0]
            status_code = int(parts[1])
            status_text = parts[2] if len(parts) > 2 else 'Unknown'

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line and line.strip():
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                elif line.strip() == '':
                    break

            return {
                "version": version,
                "status_code": status_code,
                "status_text": status_text,
                "headers": headers,
                "content_type": headers.get('content-type', 'unknown'),
                "content_length": headers.get('content-length', '0'),
                "server": headers.get('server', 'unknown'),
                "cache_control": headers.get('cache-control', 'unknown'),
            }
        except (ValueError, IndexError):
            return {
                "version": "unknown",
                "status_code": 0,
                "status_text": "unknown",
                "headers": {},
                "parsing_error": "Invalid response line format"
            }

    def _generate_statistics(self, packets: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate statistics from analyzed HTTP packets."""
        request_count = sum(1 for p in packets if p.get("type") == "request")
        response_count = sum(1 for p in packets if p.get("type") == "response")

        # Collect methods
        methods = {}
        for p in packets:
            if p.get("type") == "request" and "method" in p:
                method = p["method"]
                methods[method] = methods.get(method, 0) + 1

        # Collect status codes
        status_codes = {}
        for p in packets:
            if p.get("type") == "response" and "status_code" in p:
                code = p["status_code"]
                status_codes[code] = status_codes.get(code, 0) + 1

        # Collect unique hosts
        unique_hosts = set()
        for p in packets:
            if p.get("type") == "request" and "host" in p and p["host"] != "unknown":
                unique_hosts.add(p["host"])

        # Collect unique user agents
        unique_user_agents = set()
        for p in packets:
            if p.get("type") == "request" and "user_agent" in p and p["user_agent"] != "unknown":
                unique_user_agents.add(p["user_agent"])

        return {
            "total_requests": request_count,
            "total_responses": response_count,
            "http_methods": methods,
            "status_codes": status_codes,
            "unique_hosts_count": len(unique_hosts),
            "unique_hosts": list(unique_hosts),
            "unique_user_agents_count": len(unique_user_agents),
            "unique_user_agents": list(unique_user_agents)[:10],  # Limit to first 10
        }

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Set up HTTP-specific analysis prompts for the MCP server."""

        @mcp.prompt
        def http_security_analysis():
            """Prompt for analyzing HTTP traffic from a security perspective"""
            return """You are a cybersecurity analyst examining HTTP traffic. Focus your analysis on:

1. **Threat Detection:**
   - Look for suspicious URLs or paths (directory traversal, SQL injection attempts)
   - Identify potentially malicious user agents or automated scanning tools
   - Check for unusual HTTP methods or non-standard requests
   - Monitor for data exfiltration patterns in POST requests

2. **Authentication and Session Analysis:**
   - Examine authentication mechanisms and credential transmission
   - Look for session tokens in URLs or headers
   - Check for insecure authentication patterns
   - Identify potential session hijacking indicators

3. **Content and Data Analysis:**
   - Review sensitive data transmission (credentials, PII, API keys)
   - Check for unencrypted data over HTTP (should be HTTPS)
   - Look for unusual content types or encoding
   - Monitor file upload/download activities

4. **Attack Pattern Recognition:**
   - Web application attacks (XSS, CSRF, injection attacks)
   - Brute force authentication attempts
   - Web scraping or automated reconnaissance
   - Command and control communication patterns

Provide specific examples and recommend follow-up investigations for any suspicious findings."""

        @mcp.prompt
        def http_web_analysis():
            """Prompt for analyzing HTTP traffic from a web development perspective"""
            return """You are a web developer analyzing HTTP traffic for optimization and debugging. Focus on:

1. **Performance Analysis:**
   - Identify slow loading resources and bottlenecks
   - Check for proper caching headers and strategies
   - Look for unnecessary redirects or inefficient request patterns
   - Analyze content compression and optimization

2. **API Usage Patterns:**
   - Review REST API calls and response structures
   - Check for proper HTTP method usage
   - Identify API rate limiting or error responses
   - Monitor for deprecated API endpoints

3. **User Experience Insights:**
   - Track user navigation patterns through URLs
   - Identify popular content and resources
   - Check for broken links or 404 errors
   - Monitor mobile vs desktop traffic patterns

4. **Technical Health:**
   - Review HTTP status code distributions
   - Check for proper error handling
   - Identify server or application errors (5xx codes)
   - Monitor for proper HTTP header usage

Provide actionable recommendations for performance improvements and better user experience."""

        @mcp.prompt
        def http_forensic_investigation():
            """Prompt for forensic analysis of HTTP traffic"""
            return """You are conducting a digital forensics investigation involving HTTP traffic. Approach systematically:

1. **Timeline Reconstruction:**
   - Create chronological sequence of HTTP requests and responses
   - Map user activities and session flows
   - Correlate HTTP activity with incident timeframes
   - Track user journey through web applications

2. **Evidence Collection:**
   - Document suspicious HTTP requests and responses
   - Preserve authentication and session information
   - Record file transfers and data exchanges
   - Note any encrypted or encoded content

3. **Attribution and Tracking:**
   - Link HTTP activity to source IP addresses and users
   - Track session persistence across time periods
   - Identify user agents and client fingerprints
   - Map relationships between different HTTP sessions

4. **Impact Assessment:**
   - Determine scope of data accessed or exfiltrated
   - Assess potential compromise through HTTP channels
   - Identify systems and applications accessed
   - Evaluate ongoing security risks

Present findings with timestamps, evidence preservation notes, and clear documentation suitable for legal proceedings."""
```

## Step 2: Register the Module

Now we need to register our HTTP module with the MCP server. Edit `src/mcpcap/core/server.py`:

```text
# Add import at the top
from ..modules.http import HTTPModule

# In the __init__ method, add HTTP module loading:
if "http" in self.config.modules:
    self.modules["http"] = HTTPModule(config)

# In the _register_tools method, add HTTP tool registration:
elif module_name == "http":
    self.mcp.tool(module.analyze_http_packets)
```

## Step 3: Update CLI Configuration

Edit `src/mcpcap/cli.py` to include HTTP in the default modules:

```python
# Update the modules argument default value
parser.add_argument(
    "--modules",
    default="dns,dhcp,http",  # Add http here
    help="Comma-separated list of modules to load (dns,dhcp,http)",
)
```

## Step 4: Create Tests

Create comprehensive tests in `tests/test_modules/test_http.py`:

```python
"""Tests for HTTP module."""

from unittest.mock import Mock, patch
import pytest

from mcpcap.modules.http import HTTPModule
from mcpcap.core.config import Config


class TestHTTPModule:
    """Test HTTP module functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        config = Config(modules=["http"], max_packets=None)
        self.http_module = HTTPModule(config)

    def test_protocol_name(self):
        """Test protocol name property."""
        assert self.http_module.protocol_name == "HTTP"

    def test_is_http_packet_request(self):
        """Test HTTP request detection."""
        request_payload = b"GET /index.html HTTP/1.1\\r\\n"
        assert self.http_module._is_http_packet(request_payload) is True

    def test_is_http_packet_response(self):
        """Test HTTP response detection."""
        response_payload = b"HTTP/1.1 200 OK\\r\\n"
        assert self.http_module._is_http_packet(response_payload) is True

    def test_is_http_packet_invalid(self):
        """Test non-HTTP packet detection."""
        invalid_payload = b"Not an HTTP packet"
        assert self.http_module._is_http_packet(invalid_payload) is False

    def test_parse_http_request(self):
        """Test HTTP request parsing."""
        request_payload = """GET /api/users?id=123 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Content-Type: application/json"""

        result = self.http_module._parse_http_request(request_payload)

        assert result["method"] == "GET"
        assert result["url"] == "/api/users?id=123"
        assert result["path"] == "/api/users"
        assert result["query"] == "id=123"
        assert result["host"] == "example.com"
        assert result["user_agent"] == "Mozilla/5.0"

    def test_parse_http_response(self):
        """Test HTTP response parsing."""
        response_payload = """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1234
Server: nginx/1.18.0"""

        result = self.http_module._parse_http_response(response_payload)

        assert result["status_code"] == 200
        assert result["status_text"] == "OK"
        assert result["content_type"] == "text/html"
        assert result["content_length"] == "1234"
        assert result["server"] == "nginx/1.18.0"

    @patch("mcpcap.modules.http.rdpcap")
    def test_analyze_http_packets_no_packets(self, mock_rdpcap):
        """Test analysis with no HTTP packets."""
        # Mock empty packet capture
        mock_rdpcap.return_value = []

        result = self.http_module.analyze_http_packets("test.pcap")

        assert result["http_packets_found"] == 0
        assert "No HTTP packets found" in result["message"]

    @patch("mcpcap.modules.http.rdpcap")
    def test_analyze_http_packets_with_packets(self, mock_rdpcap):
        """Test analysis with HTTP packets."""
        # Create mock HTTP packet
        mock_packet = Mock()
        mock_packet.time = 1234567890
        mock_packet.haslayer.return_value = True

        # Mock TCP layer
        mock_tcp = Mock()
        mock_tcp.dport = 80
        mock_tcp.sport = 45678
        mock_tcp.load = b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
        mock_packet.__getitem__.return_value = mock_tcp

        # Mock IP layer
        mock_ip = Mock()
        mock_ip.src = "192.168.1.100"
        mock_ip.dst = "93.184.216.34"
        mock_packet.__getitem__.side_effect = lambda x: mock_ip if x == 1 else mock_tcp

        mock_rdpcap.return_value = [mock_packet]

        result = self.http_module.analyze_http_packets("test.pcap")

        assert result["http_packets_found"] >= 0
        assert "statistics" in result

    def test_generate_statistics(self):
        """Test statistics generation."""
        packets = [
            {
                "type": "request",
                "method": "GET",
                "host": "example.com",
                "user_agent": "Mozilla/5.0"
            },
            {
                "type": "response",
                "status_code": 200
            },
            {
                "type": "request",
                "method": "POST",
                "host": "api.example.com",
                "user_agent": "curl/7.68.0"
            }
        ]

        stats = self.http_module._generate_statistics(packets)

        assert stats["total_requests"] == 2
        assert stats["total_responses"] == 1
        assert stats["http_methods"]["GET"] == 1
        assert stats["http_methods"]["POST"] == 1
        assert stats["status_codes"][200] == 1
        assert stats["unique_hosts_count"] == 2
        assert "example.com" in stats["unique_hosts"]
        assert "api.example.com" in stats["unique_hosts"]
```

## Step 5: Test Your Module

Run the tests to ensure everything works:

```bash
# Run HTTP module tests
pytest tests/test_modules/test_http.py -v

# Run all tests
pytest

# Check test coverage
pytest --cov=src/mcpcap/modules/http --cov-report=html
```

## Step 6: Test Integration

Now test your module with the actual server:

```bash
# Start the server with HTTP module
mcpcap --modules http

# In another terminal, test with MCP Inspector
npx @modelcontextprotocol/inspector mcpcap
```

In the MCP Inspector, you should now see the `analyze_http_packets` tool available.

## Step 7: Create Sample Data

Create a sample HTTP PCAP file for testing. You can generate one using:

```bash
# Capture HTTP traffic
tcpdump -i any port 80 -w examples/http.pcap

# Or use an existing sample
curl -s https://raw.githubusercontent.com/mcpcap/mcpcap/main/examples/dns.pcap -o examples/http.pcap
```

## Step 8: Update Documentation

Add examples to the user guides showing how to use your HTTP module:

```markdown
### HTTP Analysis

Use the `analyze_http_packets` tool to analyze HTTP traffic:

**Local files:**
```javascript
analyze_http_packets("./examples/http.pcap")
```

**Example response:**
```json
{
  "file": "./examples/http.pcap",
  "total_packets": 100,
  "http_packets_found": 25,
  "statistics": {
    "total_requests": 12,
    "total_responses": 13,
    "http_methods": {
      "GET": 10,
      "POST": 2
    },
    "status_codes": {
      "200": 10,
      "404": 2,
      "500": 1
    },
    "unique_hosts": ["example.com", "api.example.com"]
  }
}
```
```

## Best Practices

### Error Handling

Always handle parsing errors gracefully:

```python
try:
    # Parse packet data
    result = self._parse_packet(packet)
except Exception as e:
    return {
        "error": f"Failed to parse packet: {str(e)}",
        "packet_number": packet_num
    }
```

### Performance Considerations

- Use efficient packet filtering
- Implement max_packets limits
- Handle large payloads carefully
- Cache expensive computations

### Security Considerations

- Sanitize extracted data before logging
- Be careful with user-provided file paths
- Handle malformed packets without crashing
- Don't expose sensitive data in error messages

## Advanced Features

### Custom Statistics

Add protocol-specific statistics:

```python
def _generate_statistics(self, packets):
    stats = super()._generate_statistics(packets)

    # Add HTTP-specific stats
    stats.update({
        "ssl_requests": self._count_ssl_requests(packets),
        "api_calls": self._count_api_calls(packets),
        "error_rate": self._calculate_error_rate(packets)
    })

    return stats
```

### Multiple Analysis Modes

Support different analysis focuses:

```python
def analyze_http_security(self, pcap_file: str) -> dict[str, Any]:
    """Analyze HTTP traffic with security focus."""
    result = self.analyze_packets(pcap_file)

    # Add security-specific analysis
    result["security_analysis"] = self._perform_security_analysis(result["packets"])

    return result
```

## Troubleshooting

### Common Issues

1. **Module not loading:** Check import statements and registration
2. **Tests failing:** Ensure mocks match actual scapy packet structure
3. **Parsing errors:** Handle malformed HTTP packets gracefully
4. **Performance issues:** Implement efficient filtering and limits

### Debugging Tips

- Use logging instead of print statements
- Test with real PCAP files
- Check scapy packet structure with `packet.show()`
- Use MCP Inspector for interactive testing

## Next Steps

- Add more advanced HTTP features (WebSocket, HTTP/2)
- Implement content analysis and filtering
- Add integration with threat intelligence feeds
- Create specialized analysis prompts for different use cases

Congratulations! You've successfully created a complete HTTP analysis module for mcpcap. The same patterns can be applied to create modules for any network protocol.
