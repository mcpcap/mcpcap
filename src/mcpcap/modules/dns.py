"""DNS analysis module."""

from datetime import datetime
from typing import Any

from fastmcp import FastMCP
from scapy.all import DNS, IP, TCP, UDP, IPv6, rdpcap

from .base import BaseModule


class DNSModule(BaseModule):
    """Module for analyzing DNS packets in PCAP files."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "DNS"

    def analyze_dns_packets(self, pcap_file: str) -> dict[str, Any]:
        """
        Analyze DNS packets from a PCAP file and return comprehensive analysis results.

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
            A structured dictionary containing DNS packet analysis results
        """
        return self.analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform the actual DNS packet analysis on a local PCAP file."""
        try:
            packets = rdpcap(pcap_file)
            dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS)]

            if not dns_packets:
                return {
                    "file": pcap_file,
                    "total_packets": len(packets),
                    "dns_packets_found": 0,
                    "message": "No DNS packets found in this capture",
                }

            # Apply max_packets limit if specified
            packets_to_analyze = dns_packets
            limited = False
            if self.config.max_packets and len(dns_packets) > self.config.max_packets:
                packets_to_analyze = dns_packets[: self.config.max_packets]
                limited = True

            packet_details = []
            for i, pkt in enumerate(packets_to_analyze, 1):
                packet_info = self._analyze_dns_packet(pkt, i)
                packet_details.append(packet_info)

            # Generate statistics
            stats = self._generate_statistics(packet_details)

            result = {
                "file": pcap_file,
                "analysis_timestamp": datetime.now().isoformat(),
                "total_packets_in_file": len(packets),
                "dns_packets_found": len(dns_packets),
                "dns_packets_analyzed": len(packet_details),
                "statistics": stats,
                "packets": packet_details,
            }

            # Add information about packet limiting
            if limited:
                result["note"] = (
                    f"Analysis limited to first {self.config.max_packets} DNS packets due to --max-packets setting"
                )

            return result

        except Exception as e:
            return {
                "error": f"Error reading PCAP file '{pcap_file}': {str(e)}",
                "file": pcap_file,
            }

    def _analyze_dns_packet(self, pkt: Any, packet_number: int) -> dict[str, Any]:
        """Analyze a single DNS packet.

        Args:
            pkt: Scapy packet object
            packet_number: Packet sequence number

        Returns:
            Dictionary containing packet analysis
        """
        dns_layer = pkt[DNS]

        # Extract IP information
        src_ip = dst_ip = "unknown"
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        # Extract protocol (UDP/TCP)
        protocol = "unknown"
        if pkt.haslayer(UDP):
            protocol = "UDP"
        elif pkt.haslayer(TCP):
            protocol = "TCP"

        # Extract DNS questions
        questions = []
        if dns_layer.qd:
            for q in dns_layer.qd:
                try:
                    name = (
                        q.qname.decode().rstrip(".")
                        if hasattr(q.qname, "decode")
                        else str(q.qname).rstrip(".")
                    )
                    questions.append(
                        {
                            "name": name,
                            "type": getattr(q, "qtype", 0),
                            "class": getattr(q, "qclass", 0),
                        }
                    )
                except (AttributeError, UnicodeDecodeError) as e:
                    # Skip malformed questions but log the issue
                    questions.append(
                        {
                            "name": f"<parsing_error: {str(e)}>",
                            "type": getattr(q, "qtype", 0),
                            "class": getattr(q, "qclass", 0),
                        }
                    )

        # Extract DNS answers
        answers = []
        if dns_layer.an:
            for a in dns_layer.an:
                try:
                    # Safely extract the resource record name
                    if hasattr(a, "rrname"):
                        if hasattr(a.rrname, "decode"):
                            name = a.rrname.decode().rstrip(".")
                        else:
                            name = str(a.rrname).rstrip(".")
                    else:
                        name = "<unknown>"

                    answer_data = {
                        "name": name,
                        "type": getattr(a, "type", 0),
                        "class": getattr(a, "rclass", 0),
                        "ttl": getattr(a, "ttl", 0),
                    }

                    # Handle different answer types
                    if hasattr(a, "rdata"):
                        try:
                            if a.type == 1:  # A record
                                answer_data["address"] = str(a.rdata)
                            elif a.type == 28:  # AAAA record
                                answer_data["address"] = str(a.rdata)
                            elif a.type == 5:  # CNAME
                                answer_data["cname"] = str(a.rdata).rstrip(".")
                            elif a.type == 15:  # MX
                                answer_data["mx"] = str(a.rdata)
                            else:
                                answer_data["data"] = str(a.rdata)
                        except Exception as rdata_error:
                            answer_data["data"] = (
                                f"<rdata_parsing_error: {str(rdata_error)}>"
                            )

                    answers.append(answer_data)

                except (AttributeError, UnicodeDecodeError) as e:
                    # Skip malformed answers but include error info
                    answers.append(
                        {
                            "name": f"<parsing_error: {str(e)}>",
                            "type": getattr(a, "type", 0),
                            "class": getattr(a, "rclass", 0),
                            "ttl": getattr(a, "ttl", 0),
                            "data": "<malformed_record>",
                        }
                    )

        return {
            "packet_number": packet_number,
            "timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "dns_id": dns_layer.id,
            "flags": {
                "is_response": bool(dns_layer.qr),
                "authoritative": bool(dns_layer.aa),
                "truncated": bool(dns_layer.tc),
                "recursion_desired": bool(dns_layer.rd),
                "recursion_available": bool(dns_layer.ra),
            },
            "questions": questions,
            "answers": answers,
            "summary": pkt.summary(),
        }

    def _generate_statistics(self, packet_details: list) -> dict[str, Any]:
        """Generate statistics from analyzed packets.

        Args:
            packet_details: List of analyzed packet dictionaries

        Returns:
            Dictionary containing statistics
        """
        query_count = sum(1 for p in packet_details if not p["flags"]["is_response"])
        response_count = sum(1 for p in packet_details if p["flags"]["is_response"])
        unique_domains = set()
        for p in packet_details:
            for q in p["questions"]:
                unique_domains.add(q["name"])

        return {
            "queries": query_count,
            "responses": response_count,
            "unique_domains_queried": len(unique_domains),
            "unique_domains": list(unique_domains),
        }

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Set up DNS-specific analysis prompts for the MCP server.

        Args:
            mcp: FastMCP server instance
        """

        @mcp.prompt
        def security_analysis():
            """Prompt for analyzing DNS traffic from a security perspective"""
            return """You are a cybersecurity analyst examining DNS traffic. Focus your analysis on:

1. **Threat Detection:**
   - Look for suspicious domain patterns (DGA, long random strings)
   - Identify potential DNS tunneling (unusually long queries, high TXT record volume)
   - Spot potential C2 communication patterns
   - Check for queries to known malicious domains

2. **Behavioral Analysis:**
   - Identify unusual query frequencies or patterns
   - Look for reconnaissance activities (PTR lookups, zone transfers)
   - Check for DNS cache poisoning attempts
   - Monitor for subdomain enumeration

3. **Infrastructure Assessment:**
   - Identify DNS servers being used
   - Check for DNS over non-standard ports
   - Look for failed queries (NXDOMAIN) patterns
   - Assess query distribution across time

Provide specific examples and recommend follow-up investigations for any suspicious findings."""

        @mcp.prompt
        def network_troubleshooting():
            """Prompt for troubleshooting DNS-related network issues"""
            return """You are a network engineer troubleshooting DNS issues. Focus on:

1. **Performance Issues:**
   - Identify slow DNS responses (high latency)
   - Look for timeouts and retransmissions
   - Check for load balancing issues
   - Analyze response times across different servers

2. **Connectivity Problems:**
   - Find failed DNS queries and their causes
   - Identify unreachable DNS servers
   - Look for network path issues
   - Check for DNS server failures

3. **Configuration Issues:**
   - Verify proper DNS server assignments
   - Check for mismatched recursion settings
   - Look for incorrect domain configurations
   - Identify forwarding problems

4. **Capacity Planning:**
   - Analyze query volumes and patterns
   - Identify peak usage times
   - Look for resource exhaustion indicators
   - Assess server response capabilities

Provide actionable recommendations for resolving identified issues."""

        @mcp.prompt
        def forensic_investigation():
            """Prompt for forensic analysis of DNS traffic"""
            return """You are conducting a digital forensics investigation involving DNS traffic. Approach this systematically:

1. **Timeline Reconstruction:**
   - Create a chronological sequence of DNS events
   - Correlate DNS queries with potential incident timeframes
   - Identify patterns in query timing and frequency
   - Map DNS activity to user/system behavior

2. **Evidence Collection:**
   - Document all suspicious or anomalous DNS queries
   - Preserve query-response pairs for analysis
   - Record DNS server interactions and responses
   - Note any encrypted or tunneled DNS traffic

3. **Attribution and Tracking:**
   - Trace DNS queries to source systems/users
   - Identify external domains contacted
   - Map communication patterns and relationships
   - Document potential data exfiltration via DNS

4. **Impact Assessment:**
   - Determine scope of DNS-related compromise
   - Assess potential data exposure through DNS
   - Identify systems that may be affected
   - Evaluate ongoing security risks

Present findings with timestamps, evidence preservation notes, and clear documentation suitable for legal proceedings."""
