"""DHCP analysis module."""

from typing import Any

from fastmcp import FastMCP
from scapy.all import BOOTP, DHCP, IP, UDP, rdpcap

from .base import BaseModule


class DHCPModule(BaseModule):
    """Module for analyzing DHCP packets in PCAP files."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "DHCP"

    def analyze_dhcp_packets(self, pcap_file: str) -> dict[str, Any]:
        """
        Analyze DHCP packets from a PCAP file and return comprehensive analysis results.

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
            A structured dictionary containing DHCP packet analysis results
        """
        return self.analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform the actual DHCP packet analysis on a local PCAP file."""
        try:
            packets = rdpcap(pcap_file)
            dhcp_packets = [pkt for pkt in packets if pkt.haslayer(BOOTP)]

            if not dhcp_packets:
                return {
                    "file": pcap_file,
                    "total_packets": len(packets),
                    "dhcp_packets_found": 0,
                    "message": "No DHCP packets found in this capture",
                }

            # Apply max_packets limit if specified
            packets_to_analyze = dhcp_packets
            limited = False
            if self.config.max_packets and len(dhcp_packets) > self.config.max_packets:
                packets_to_analyze = dhcp_packets[: self.config.max_packets]
                limited = True

            packet_details = []
            for i, pkt in enumerate(packets_to_analyze, 1):
                packet_info = self._analyze_dhcp_packet(pkt, i)
                packet_details.append(packet_info)

            # Generate statistics
            stats = self._generate_statistics(packet_details)

            result = {
                "file": pcap_file,
                "total_packets": len(packets),
                "dhcp_packets_found": len(dhcp_packets),
                "dhcp_packets_analyzed": len(packet_details),
                "statistics": stats,
                "packets": packet_details,
            }

            # Add information about packet limiting
            if limited:
                result["note"] = (
                    f"Analysis limited to first {self.config.max_packets} DHCP packets due to --max-packets setting"
                )

            return result

        except Exception as e:
            return {
                "error": f"Error reading PCAP file '{pcap_file}': {str(e)}",
                "file": pcap_file,
            }

    def _analyze_dhcp_packet(self, packet, packet_num: int) -> dict[str, Any]:
        """Analyze a single DHCP packet and extract relevant information."""
        info = {
            "packet_number": packet_num,
            "timestamp": packet.time,
        }

        # Basic IP information
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            info.update(
                {
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                }
            )

        # UDP information
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            info.update(
                {
                    "src_port": udp_layer.sport,
                    "dst_port": udp_layer.dport,
                }
            )

        # BOOTP/DHCP information
        if packet.haslayer(BOOTP):
            bootp_layer = packet[BOOTP]
            info.update(
                {
                    "op": "Request" if bootp_layer.op == 1 else "Reply",
                    "transaction_id": f"0x{bootp_layer.xid:08x}",
                    "client_ip": str(bootp_layer.ciaddr),
                    "your_ip": str(bootp_layer.yiaddr),
                    "server_ip": str(bootp_layer.siaddr),
                    "relay_ip": str(bootp_layer.giaddr),
                    "client_mac": bootp_layer.chaddr[:6].hex(":"),
                }
            )

        # DHCP options analysis
        if packet.haslayer(DHCP):
            dhcp_layer = packet[DHCP]
            dhcp_info = self._parse_dhcp_options(dhcp_layer.options)
            info.update(dhcp_info)

        return info

    def _parse_dhcp_options(self, options) -> dict[str, Any]:
        """Parse DHCP options and return structured information."""
        dhcp_info = {"options": {}}

        # DHCP message type mappings
        message_types = {
            1: "DISCOVER",
            2: "OFFER",
            3: "REQUEST",
            4: "DECLINE",
            5: "ACK",
            6: "NAK",
            7: "RELEASE",
            8: "INFORM",
        }

        for opt in options:
            if isinstance(opt, tuple) and len(opt) == 2:
                key, value = opt

                if key == "message-type":
                    dhcp_info["message_type"] = message_types.get(
                        value, f"Unknown({value})"
                    )
                    dhcp_info["message_type_code"] = value
                elif key == "lease_time":
                    dhcp_info["lease_time"] = value
                    dhcp_info["options"]["lease_time"] = f"{value} seconds"
                elif key == "renewal_time":
                    dhcp_info["renewal_time"] = value
                    dhcp_info["options"]["renewal_time"] = f"{value} seconds"
                elif key == "rebinding_time":
                    dhcp_info["rebinding_time"] = value
                    dhcp_info["options"]["rebinding_time"] = f"{value} seconds"
                elif key == "server_id":
                    dhcp_info["server_id"] = str(value)
                elif key == "subnet_mask":
                    dhcp_info["options"]["subnet_mask"] = str(value)
                elif key == "router":
                    dhcp_info["options"]["router"] = str(value)
                elif key == "name_server":
                    dhcp_info["options"]["dns_servers"] = str(value)
                elif key == "requested_addr":
                    dhcp_info["requested_ip"] = str(value)
                elif key == "client_id":
                    if isinstance(value, bytes):
                        dhcp_info["client_id"] = value.hex(":")
                    else:
                        dhcp_info["client_id"] = str(value)
                elif key == "param_req_list":
                    dhcp_info["options"]["parameter_request_list"] = list(value)
                else:
                    # Store other options as strings
                    dhcp_info["options"][key] = str(value)

        return dhcp_info

    def _generate_statistics(self, packets: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate statistics from analyzed DHCP packets."""
        stats = {
            "unique_clients": set(),
            "unique_servers": set(),
            "message_types": {},
            "transactions": {},
        }

        for pkt in packets:
            # Count unique clients and servers
            if "client_mac" in pkt:
                stats["unique_clients"].add(pkt["client_mac"])
            if "server_id" in pkt:
                stats["unique_servers"].add(pkt["server_id"])

            # Count message types
            if "message_type" in pkt:
                msg_type = pkt["message_type"]
                stats["message_types"][msg_type] = (
                    stats["message_types"].get(msg_type, 0) + 1
                )

            # Track transactions
            if "transaction_id" in pkt:
                tx_id = pkt["transaction_id"]
                if tx_id not in stats["transactions"]:
                    stats["transactions"][tx_id] = []
                stats["transactions"][tx_id].append(
                    {
                        "packet_number": pkt["packet_number"],
                        "message_type": pkt.get("message_type", "Unknown"),
                        "timestamp": pkt["timestamp"],
                    }
                )

        # Convert sets to counts for JSON serialization
        return {
            "unique_clients_count": len(stats["unique_clients"]),
            "unique_servers_count": len(stats["unique_servers"]),
            "unique_clients": list(stats["unique_clients"]),
            "unique_servers": list(stats["unique_servers"]),
            "message_type_counts": stats["message_types"],
            "transaction_count": len(stats["transactions"]),
            "transactions": stats["transactions"],
        }

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Set up DHCP-specific analysis prompts for the MCP server.

        Args:
            mcp: FastMCP server instance
        """

        @mcp.prompt
        def dhcp_network_analysis():
            """Prompt for analyzing DHCP traffic from a network perspective"""
            return """You are a network administrator analyzing DHCP traffic. Focus your analysis on:

1. **IP Address Management:**
   - Track DHCP lease assignments and renewals
   - Identify IP address pool usage and availability
   - Look for lease conflicts or duplicate IP assignments
   - Monitor lease duration patterns and optimization

2. **Client Behavior Analysis:**
   - Identify DHCP client types and operating systems
   - Track client renewal patterns and timing
   - Look for unusual client behavior (rapid requests, failures)
   - Monitor mobile devices vs. static clients

3. **Server Performance:**
   - Analyze DHCP server response times
   - Look for server failures or timeouts
   - Check for multiple DHCP servers (potential conflicts)
   - Monitor server load and capacity planning

4. **Network Troubleshooting:**
   - Identify DHCP DISCOVER floods or storms
   - Look for relay agent issues
   - Check for scope exhaustion problems
   - Find misconfigurations in options delivery

Provide specific recommendations for network optimization and problem resolution."""

        @mcp.prompt
        def dhcp_security_analysis():
            """Prompt for analyzing DHCP traffic from a security perspective"""
            return """You are a security analyst examining DHCP traffic for threats. Focus on:

1. **Rogue DHCP Detection:**
   - Identify unauthorized DHCP servers on the network
   - Look for conflicting server responses or options
   - Check for suspicious server_id values
   - Monitor for DHCP server impersonation attempts

2. **DHCP Attacks:**
   - Detect DHCP starvation attacks (rapid lease consumption)
   - Look for DHCP spoofing or man-in-the-middle attempts
   - Identify abnormal request patterns or frequencies
   - Check for MAC address spoofing in client requests

3. **Client Anomalies:**
   - Find clients with suspicious hostnames or identifiers
   - Look for rapid MAC address changes from single sources
   - Detect clients requesting unusual or dangerous options
   - Monitor for clients bypassing expected DHCP flow

4. **Data Exfiltration Risks:**
   - Check for unusual data in DHCP option fields
   - Look for DNS server redirection attempts
   - Monitor for suspicious router or gateway assignments
   - Identify potential DNS tunneling via DHCP options

Provide threat assessment and recommended security controls."""

        @mcp.prompt
        def dhcp_forensic_investigation():
            """Prompt for forensic analysis of DHCP traffic"""
            return """You are conducting a digital forensics investigation involving DHCP traffic. Approach systematically:

1. **Timeline Reconstruction:**
   - Create chronological sequence of DHCP transactions
   - Map client activity periods and network presence
   - Correlate DHCP assignments with incident timeframes
   - Track device mobility through IP address changes

2. **Device Attribution:**
   - Link MAC addresses to specific devices or users
   - Track device behavior patterns across time
   - Identify device types through DHCP fingerprinting
   - Document lease history for evidence correlation

3. **Network Mapping:**
   - Reconstruct network topology from DHCP data
   - Identify network segments and VLAN assignments
   - Map DHCP server infrastructure and relationships
   - Document network configuration at incident time

4. **Evidence Collection:**
   - Extract client identifiers and hostnames
   - Document IP address assignments for legal proceedings
   - Preserve transaction timing for event correlation
   - Collect option data that may contain forensic artifacts

Present findings with precise timestamps, evidence preservation notes, and clear documentation suitable for legal proceedings."""
