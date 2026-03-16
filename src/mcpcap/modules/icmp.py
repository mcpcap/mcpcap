"""ICMP analysis module."""

from datetime import datetime
from typing import Any

from fastmcp import FastMCP
from scapy.all import ICMP, IP, IPv6, rdpcap

from .base import BaseModule


class ICMPModule(BaseModule):
    """Module for analyzing ICMP packets in PCAP files."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "ICMP"

    def analyze_icmp_packets(self, pcap_file: str) -> dict[str, Any]:
        """
        Analyze ICMP packets from a PCAP file and return comprehensive analysis results.

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
            A structured dictionary containing ICMP packet analysis results
        """
        return self.analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform the actual ICMP packet analysis on a local PCAP file."""
        try:
            packets = rdpcap(pcap_file)
            icmp_packets = [pkt for pkt in packets if pkt.haslayer(ICMP)]

            if not icmp_packets:
                return {
                    "file": pcap_file,
                    "total_packets": len(packets),
                    "icmp_packets_found": 0,
                    "message": "No ICMP packets found in this capture",
                }

            # Apply max_packets limit if specified
            packets_to_analyze = icmp_packets
            limited = False
            if self.config.max_packets and len(icmp_packets) > self.config.max_packets:
                packets_to_analyze = icmp_packets[: self.config.max_packets]
                limited = True

            packet_details = []
            for i, pkt in enumerate(packets_to_analyze, 1):
                packet_info = self._analyze_icmp_packet(pkt, i)
                packet_details.append(packet_info)

            # Generate statistics
            stats = self._generate_statistics(packet_details)

            result = {
                "file": pcap_file,
                "analysis_timestamp": datetime.now().isoformat(),
                "total_packets": len(packets),
                "icmp_packets_found": len(icmp_packets),
                "icmp_packets_analyzed": len(packet_details),
                "statistics": stats,
                "packets": packet_details,
            }

            if limited:
                result["note"] = (
                    f"Analysis limited to first {self.config.max_packets} ICMP packets due to --max-packets setting"
                )

            return result

        except Exception as e:
            return {
                "error": f"Error reading PCAP file '{pcap_file}': {str(e)}",
                "file": pcap_file,
            }

    def _analyze_icmp_packet(self, packet, packet_num: int) -> dict[str, Any]:
        """Analyze a single ICMP packet and extract relevant information."""
        info = {
            "packet_number": packet_num,
            "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
        }

        # Basic IP information
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            info.update(
                {
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "ip_version": 4,
                    "ttl": ip_layer.ttl,
                    "packet_size": len(packet),
                }
            )
        elif packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            info.update(
                {
                    "src_ip": ipv6_layer.src,
                    "dst_ip": ipv6_layer.dst,
                    "ip_version": 6,
                    "hop_limit": ipv6_layer.hlim,
                    "packet_size": len(packet),
                }
            )

        # ICMP information
        if packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]

            # Map ICMP types to human-readable names
            icmp_types = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                4: "Source Quench",
                5: "Redirect",
                8: "Echo Request",
                11: "Time Exceeded",
                12: "Parameter Problem",
                13: "Timestamp Request",
                14: "Timestamp Reply",
                15: "Information Request",
                16: "Information Reply",
            }

            # Map destination unreachable codes
            dest_unreach_codes = {
                0: "Network Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable",
                3: "Port Unreachable",
                4: "Fragmentation Required",
                5: "Source Route Failed",
            }

            # Map time exceeded codes
            time_exceeded_codes = {
                0: "TTL Exceeded in Transit",
                1: "Fragment Reassembly Time Exceeded",
            }

            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code

            info.update(
                {
                    "icmp_type": icmp_type,
                    "icmp_code": icmp_code,
                    "icmp_type_name": icmp_types.get(
                        icmp_type, f"Unknown Type ({icmp_type})"
                    ),
                    "icmp_id": getattr(icmp_layer, "id", None),
                    "icmp_seq": getattr(icmp_layer, "seq", None),
                    "checksum": icmp_layer.chksum,
                }
            )

            # Add code descriptions for specific types
            if icmp_type == 3:  # Destination Unreachable
                info["icmp_code_name"] = dest_unreach_codes.get(
                    icmp_code, f"Unknown Code ({icmp_code})"
                )
            elif icmp_type == 11:  # Time Exceeded
                info["icmp_code_name"] = time_exceeded_codes.get(
                    icmp_code, f"Unknown Code ({icmp_code})"
                )
            else:
                info["icmp_code_name"] = f"Code {icmp_code}"

        return info

    def _generate_statistics(self, packets: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate statistics from analyzed ICMP packets."""
        stats = {
            "icmp_types": {},
            "unique_sources": set(),
            "unique_destinations": set(),
            "echo_pairs": {},
            "unreachable_destinations": set(),
        }

        for pkt in packets:
            # Count ICMP types
            if "icmp_type_name" in pkt:
                type_name = pkt["icmp_type_name"]
                stats["icmp_types"][type_name] = (
                    stats["icmp_types"].get(type_name, 0) + 1
                )

            # Track unique IPs
            if "src_ip" in pkt:
                stats["unique_sources"].add(pkt["src_ip"])
            if "dst_ip" in pkt:
                stats["unique_destinations"].add(pkt["dst_ip"])

            # Track echo request/reply pairs
            if pkt.get("icmp_type") in [0, 8] and pkt.get("icmp_id") is not None:
                echo_id = pkt["icmp_id"]
                if echo_id not in stats["echo_pairs"]:
                    stats["echo_pairs"][echo_id] = {"requests": 0, "replies": 0}

                if pkt["icmp_type"] == 8:  # Echo Request
                    stats["echo_pairs"][echo_id]["requests"] += 1
                elif pkt["icmp_type"] == 0:  # Echo Reply
                    stats["echo_pairs"][echo_id]["replies"] += 1

            # Track unreachable destinations
            if pkt.get("icmp_type") == 3:  # Destination Unreachable
                if "dst_ip" in pkt:
                    stats["unreachable_destinations"].add(pkt["dst_ip"])

        # Convert sets to lists for JSON serialization
        return {
            "icmp_type_counts": stats["icmp_types"],
            "unique_sources_count": len(stats["unique_sources"]),
            "unique_destinations_count": len(stats["unique_destinations"]),
            "unique_sources": list(stats["unique_sources"]),
            "unique_destinations": list(stats["unique_destinations"]),
            "echo_sessions": len(stats["echo_pairs"]),
            "echo_pairs": stats["echo_pairs"],
            "unreachable_destinations_count": len(stats["unreachable_destinations"]),
            "unreachable_destinations": list(stats["unreachable_destinations"]),
        }

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Set up ICMP-specific analysis prompts for the MCP server."""

        @mcp.prompt
        def icmp_network_diagnostics():
            """Prompt for analyzing ICMP traffic from a network diagnostics perspective"""
            return """You are a network engineer analyzing ICMP traffic for network diagnostics. Focus on:

1. **Connectivity Testing:**
   - Analyze ping (echo request/reply) patterns and success rates
   - Identify network reachability issues from failed pings
   - Check ping response times and latency patterns
   - Look for asymmetric routing issues

2. **Network Path Analysis:**
   - Examine TTL values and time exceeded messages for traceroute data
   - Identify network hops and routing paths
   - Look for routing loops or suboptimal paths
   - Check for fragmentation issues

3. **Error Diagnostics:**
   - Analyze destination unreachable messages and their causes
   - Identify network, host, protocol, or port unreachability
   - Look for fragmentation required messages
   - Check source quench messages for congestion

4. **Network Health Assessment:**
   - Monitor ICMP message frequencies and patterns
   - Identify potential network congestion indicators
   - Look for unusual ICMP traffic that might indicate problems
   - Assess overall network responsiveness

Provide specific recommendations for network troubleshooting and optimization."""

        @mcp.prompt
        def icmp_security_analysis():
            """Prompt for analyzing ICMP traffic from a security perspective"""
            return """You are a security analyst examining ICMP traffic for threats and anomalies. Focus on:

1. **Reconnaissance Detection:**
   - Identify ping sweeps and network scanning activities
   - Look for systematic probing of network ranges
   - Check for unusual ping patterns that might indicate reconnaissance
   - Monitor for traceroute-based network mapping

2. **Covert Channel Analysis:**
   - Examine ICMP payloads for potential data exfiltration
   - Look for unusual ICMP packet sizes or timing patterns
   - Check for non-standard ICMP types or codes
   - Identify potential ICMP tunneling activities

3. **DoS Attack Detection:**
   - Monitor for ICMP flood attacks (ping floods)
   - Look for smurf attack patterns (broadcast ping amplification)
   - Check for fragmentation attacks using ICMP
   - Identify potential death of death or similar attacks

4. **Policy Compliance:**
   - Verify ICMP traffic matches network security policies
   - Check for unauthorized ICMP types (if policy restricts certain types)
   - Monitor for ICMP traffic from unexpected sources
   - Identify potential firewall bypass attempts

Provide threat assessment and recommended security controls."""

        @mcp.prompt
        def icmp_forensic_investigation():
            """Prompt for forensic analysis of ICMP traffic"""
            return """You are conducting a digital forensics investigation involving ICMP traffic. Approach systematically:

1. **Timeline Reconstruction:**
   - Create chronological sequence of ICMP events
   - Map ping activities to potential user or system actions
   - Correlate ICMP traffic with incident timeframes
   - Track network connectivity patterns over time

2. **Attribution and Tracking:**
   - Trace ICMP traffic to source systems and networks
   - Identify systems involved in ping exchanges
   - Map network topology from traceroute data
   - Document unique identifiers in ICMP packets

3. **Evidence Collection:**
   - Preserve all ICMP packet details with precise timestamps
   - Document network paths and hop information
   - Record error messages and their contexts
   - Note any unusual or suspicious ICMP characteristics

4. **Impact Assessment:**
   - Determine scope of network reconnaissance or scanning
   - Assess potential information leakage through ICMP
   - Identify systems that may have been probed
   - Evaluate ongoing security implications

Present findings with precise timestamps, evidence preservation notes, and clear documentation suitable for legal proceedings."""
