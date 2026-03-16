"""SIP analysis module."""

from collections import Counter
from datetime import datetime
from typing import Any

from fastmcp import FastMCP
from scapy.all import IP, TCP, UDP, IPv6, Raw, rdpcap

from .base import BaseModule

SIP_METHODS = {
    "ACK",
    "BYE",
    "CANCEL",
    "INFO",
    "INVITE",
    "MESSAGE",
    "NOTIFY",
    "OPTIONS",
    "PRACK",
    "PUBLISH",
    "REFER",
    "REGISTER",
    "SUBSCRIBE",
    "UPDATE",
}
SIP_PORTS = {5060, 5061}


class SIPModule(BaseModule):
    """Module for analyzing SIP packets in PCAP files."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "SIP"

    def analyze_sip_packets(self, pcap_file: str) -> dict[str, Any]:
        """
        Analyze SIP packets from a PCAP file and return structured signaling details.

        FILE UPLOAD LIMITATION: This MCP tool cannot process files uploaded through
        Claude's web interface. Files must be accessible via URL or local file path.

        SUPPORTED INPUT FORMATS:
        - Remote files: "https://example.com/capture.pcap"
        - Local files: "/absolute/path/to/capture.pcap"

        UNSUPPORTED:
        - Files uploaded through Claude's file upload feature
        - Base64 file content
        - Relative file paths

        Args:
            pcap_file: HTTP URL or absolute local file path to PCAP file

        Returns:
            A structured dictionary containing SIP packet analysis results
        """
        return self.analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform the actual SIP packet analysis on a local PCAP file."""
        try:
            packets = rdpcap(pcap_file)
            sip_packets = [pkt for pkt in packets if self._is_sip_packet(pkt)]

            if not sip_packets:
                return {
                    "file": pcap_file,
                    "total_packets_in_file": len(packets),
                    "sip_packets_found": 0,
                    "message": "No SIP packets found in this capture",
                }

            packets_to_analyze = sip_packets
            limited = False
            if self.config.max_packets and len(sip_packets) > self.config.max_packets:
                packets_to_analyze = sip_packets[: self.config.max_packets]
                limited = True

            packet_details = [
                self._analyze_sip_packet(pkt, packet_number)
                for packet_number, pkt in enumerate(packets_to_analyze, 1)
            ]
            stats = self._generate_statistics(packet_details)

            result = {
                "file": pcap_file,
                "analysis_timestamp": datetime.now().isoformat(),
                "total_packets_in_file": len(packets),
                "sip_packets_found": len(sip_packets),
                "sip_packets_analyzed": len(packet_details),
                "statistics": stats,
                "packets": packet_details,
            }

            if limited:
                result["note"] = (
                    f"Analysis limited to first {self.config.max_packets} SIP packets due to --max-packets setting"
                )

            return result

        except Exception as e:
            return {
                "error": f"Error reading PCAP file '{pcap_file}': {str(e)}",
                "file": pcap_file,
            }

    def _is_sip_packet(self, pkt: Any) -> bool:
        """Check whether a packet contains SIP payload data."""
        if not pkt.haslayer(Raw):
            return False

        if not pkt.haslayer(UDP) and not pkt.haslayer(TCP):
            return False

        payload = bytes(pkt[Raw].load)
        if not payload:
            return False

        return self._is_sip_payload(payload)

    def _is_sip_payload(self, payload: bytes) -> bool:
        """Check whether payload bytes look like a SIP message."""
        try:
            first_line = (
                payload.decode("utf-8", errors="ignore").splitlines()[0].strip()
            )
        except IndexError:
            return False

        if first_line.startswith("SIP/2.0 "):
            return True

        method = first_line.split(" ", 1)[0].upper()
        return method in SIP_METHODS

    def _analyze_sip_packet(self, pkt: Any, packet_number: int) -> dict[str, Any]:
        """Analyze a single SIP packet."""
        payload = bytes(pkt[Raw].load).decode("utf-8", errors="replace")
        start_line, headers, body = self._parse_sip_message(payload)
        src_ip, dst_ip = self._extract_ips(pkt)
        transport, src_port, dst_port = self._extract_transport(pkt)
        message_type, parsed_message = self._parse_start_line(start_line)

        via_header = headers.get("via", "")
        content_length = self._safe_int(headers.get("content-length"))
        known_port_match = src_port in SIP_PORTS or dst_port in SIP_PORTS

        packet_info = {
            "packet_number": packet_number,
            "timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "transport": transport,
            "message_type": message_type,
            "start_line": start_line,
            "call_id": headers.get("call-id", ""),
            "cseq": headers.get("cseq", ""),
            "from": headers.get("from", ""),
            "to": headers.get("to", ""),
            "contact": headers.get("contact", ""),
            "user_agent": headers.get("user-agent", ""),
            "server": headers.get("server", ""),
            "via": via_header,
            "content_type": headers.get("content-type", ""),
            "content_length": content_length,
            "body_length": len(body.encode("utf-8")),
            "known_sip_port": known_port_match,
            "headers": headers,
            "summary": pkt.summary(),
        }
        packet_info.update(parsed_message)
        return packet_info

    def _parse_sip_message(self, payload: str) -> tuple[str, dict[str, str], str]:
        """Parse a SIP message into start line, headers, and body."""
        normalized = payload.replace("\r\n", "\n").replace("\r", "\n")
        header_part, _, body = normalized.partition("\n\n")
        header_lines = [line for line in header_part.split("\n") if line.strip()]
        start_line = header_lines[0].strip() if header_lines else ""

        headers: dict[str, str] = {}
        current_header: str | None = None
        for line in header_lines[1:]:
            if line.startswith((" ", "\t")) and current_header:
                headers[current_header] = f"{headers[current_header]} {line.strip()}"
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            normalized_key = key.strip().lower()
            headers[normalized_key] = value.strip()
            current_header = normalized_key

        return start_line, headers, body

    def _parse_start_line(self, start_line: str) -> tuple[str, dict[str, Any]]:
        """Parse the SIP start line into either request or response data."""
        if start_line.startswith("SIP/2.0 "):
            parts = start_line.split(" ", 2)
            status_code = self._safe_int(parts[1]) if len(parts) > 1 else None
            return "response", {
                "status_code": status_code,
                "reason_phrase": parts[2] if len(parts) > 2 else "",
            }

        parts = start_line.split(" ", 2)
        method = parts[0].upper() if parts else ""
        return "request", {
            "method": method,
            "request_uri": parts[1] if len(parts) > 1 else "",
            "sip_version": parts[2] if len(parts) > 2 else "",
        }

    def _extract_ips(self, pkt: Any) -> tuple[str, str]:
        """Extract source and destination IP addresses."""
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
        return "unknown", "unknown"

    def _extract_transport(self, pkt: Any) -> tuple[str, int | None, int | None]:
        """Extract transport protocol and ports."""
        if pkt.haslayer(UDP):
            return "UDP", pkt[UDP].sport, pkt[UDP].dport
        if pkt.haslayer(TCP):
            return "TCP", pkt[TCP].sport, pkt[TCP].dport
        return "unknown", None, None

    def _safe_int(self, value: str | None) -> int | None:
        """Convert a header value to int when possible."""
        if value is None:
            return None
        try:
            return int(value.strip().split(" ", 1)[0])
        except (TypeError, ValueError, AttributeError):
            return None

    def _generate_statistics(self, packets: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate SIP-specific statistics from analyzed packets."""
        requests = [packet for packet in packets if packet["message_type"] == "request"]
        responses = [
            packet for packet in packets if packet["message_type"] == "response"
        ]

        method_counts = Counter(packet.get("method", "") for packet in requests)
        response_classes = Counter()
        for packet in responses:
            status_code = packet.get("status_code")
            if isinstance(status_code, int):
                response_classes[f"{status_code // 100}xx"] += 1

        call_ids = {packet["call_id"] for packet in packets if packet.get("call_id")}
        transports = Counter(packet["transport"] for packet in packets)
        user_agents = sorted(
            {packet["user_agent"] for packet in packets if packet.get("user_agent")}
        )

        return {
            "requests": len(requests),
            "responses": len(responses),
            "methods": dict(sorted(method_counts.items())),
            "response_classes": dict(sorted(response_classes.items())),
            "unique_call_ids": len(call_ids),
            "call_ids": sorted(call_ids),
            "transports": dict(sorted(transports.items())),
            "user_agents": user_agents,
        }

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Set up SIP-specific prompts for the MCP server."""

        @mcp.prompt
        def sip_security_analysis():
            """Prompt for reviewing SIP traffic from a security perspective."""
            return """You are analyzing SIP signaling traffic for security issues. Focus on:

1. Authentication failures, brute-force registration attempts, or credential misuse.
2. Unusual call setup patterns, suspicious destinations, or unexpected SIP methods.
3. Indicators of toll fraud, rogue endpoints, or malformed signaling.
4. Exposure of internal addressing, software banners, or topology information.
5. Concrete packet-level evidence and any missing context needed for confidence."""

        @mcp.prompt
        def sip_troubleshooting_analysis():
            """Prompt for troubleshooting SIP signaling behavior."""
            return """You are troubleshooting SIP signaling. Focus on:

1. Call setup progression across INVITE, provisional responses, final responses, ACK, BYE, and CANCEL.
2. Registration success or failure, including CSeq progression and response codes.
3. Transport or addressing mismatches visible in Via, Contact, From, and To headers.
4. Error response patterns such as 4xx, 5xx, or 6xx classes and the point where signaling fails.
5. Concise next-step hypotheses grounded only in the capture contents."""

        @mcp.prompt
        def sip_forensic_investigation():
            """Prompt for reconstructing SIP activity for forensic work."""
            return """You are reconstructing SIP activity for a forensic investigation. Focus on:

1. Building a timeline of registrations, call attempts, responses, and terminations.
2. Correlating traffic by Call-ID, CSeq, source/destination IP, and transport.
3. Identifying the apparent user agents, servers, and contacted SIP URIs.
4. Highlighting failed calls, repeated attempts, and notable response codes.
5. Preserving uncertainty explicitly when fields are missing or ambiguous."""
