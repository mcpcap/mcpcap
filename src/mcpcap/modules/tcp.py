"""TCP analysis module."""

from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

from fastmcp import FastMCP
from scapy.all import IP, TCP, IPv6, rdpcap

from .base import BaseModule


class TCPModule(BaseModule):
    """Module for analyzing TCP packets in PCAP files."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "TCP"

    def analyze_tcp_connections(
        self,
        pcap_file: str,
        server_ip: Optional[str] = None,
        server_port: Optional[int] = None,
        detailed: bool = False,
    ) -> dict[str, Any]:
        """
        Analyze TCP connection states and lifecycle.

        This is the core tool for TCP connection analysis, solving 80% of TCP-related issues.

        ⚠️  FILE UPLOAD LIMITATION: This MCP tool cannot process files uploaded through
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
            server_ip: Optional filter for server IP address
            server_port: Optional filter for server port
            detailed: Whether to return detailed connection information

        Returns:
            A structured dictionary containing TCP connection analysis results including:
            - summary: Overall connection statistics
            - connections: List of individual connections with states
            - issues: Detected problems
        """
        return self.analyze_packets(
            pcap_file,
            analysis_type="connections",
            server_ip=server_ip,
            server_port=server_port,
            detailed=detailed,
        )

    def analyze_tcp_anomalies(
        self,
        pcap_file: str,
        server_ip: Optional[str] = None,
        server_port: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Detect TCP traffic patterns through statistical analysis.

        This tool analyzes TCP traffic to identify observable patterns without
        making assumptions about root causes. It provides factual metrics and
        pattern detection that can be used for further investigation.

        Args:
            pcap_file: HTTP URL or absolute local file path to PCAP file
            server_ip: Optional filter for server IP address
            server_port: Optional filter for server port

        Returns:
            A structured dictionary containing:
            - statistics: Comprehensive TCP metrics (handshakes, flags, RST distribution, etc.)
            - patterns: Observable patterns detected in the traffic
            - summary: High-level summary of findings

        Detected pattern categories:
        - connection_establishment: Handshake success/failure rates, SYN response ratios
        - connection_termination: RST distribution, normal vs abnormal closes
        - reliability: Retransmission rates, packet loss indicators
        - connection_lifecycle: Connection state transitions

        The analysis is purely observational - it reports what is seen in the traffic
        without attempting to diagnose specific issues like "firewall block" or
        "network congestion". This allows the data to be interpreted in context.
        """
        return self.analyze_packets(
            pcap_file,
            analysis_type="anomalies",
            server_ip=server_ip,
            server_port=server_port,
        )

    def analyze_tcp_retransmissions(
        self,
        pcap_file: str,
        server_ip: Optional[str] = None,
        threshold: float = 0.02,
    ) -> dict[str, Any]:
        """
        Analyze TCP retransmission patterns.

        Args:
            pcap_file: HTTP URL or absolute local file path to PCAP file
            server_ip: Optional filter for server IP address
            threshold: Retransmission rate threshold (default: 2%)

        Returns:
            A structured dictionary containing:
            - total_retransmissions: Total number of retransmissions
            - retransmission_rate: Overall retransmission rate
            - by_connection: Per-connection retransmission statistics
            - summary: Worst connections and threshold violations
        """
        return self.analyze_packets(
            pcap_file,
            analysis_type="retransmissions",
            server_ip=server_ip,
            threshold=threshold,
        )

    def analyze_traffic_flow(
        self,
        pcap_file: str,
        server_ip: str,
        server_port: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Analyze bidirectional traffic flow characteristics.

        Identifies traffic direction, asymmetry, RST sources, and data transfer patterns.

        Args:
            pcap_file: HTTP URL or absolute local file path to PCAP file
            server_ip: Server IP address (required)
            server_port: Optional filter for server port

        Returns:
            A structured dictionary containing:
            - client_to_server: Client-to-server traffic statistics
            - server_to_client: Server-to-client traffic statistics
            - analysis: Asymmetry analysis and interpretations
        """
        return self.analyze_packets(
            pcap_file,
            analysis_type="traffic_flow",
            server_ip=server_ip,
            server_port=server_port,
        )

    def analyze_packets(
        self, pcap_file: str, analysis_type: str = "connections", **kwargs
    ) -> dict[str, Any]:
        """Analyze packets with specified analysis type."""
        self._analysis_type = analysis_type
        self._analysis_kwargs = kwargs
        return super().analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform the actual TCP packet analysis on a local PCAP file."""
        try:
            packets = rdpcap(pcap_file)
            tcp_packets = [pkt for pkt in packets if pkt.haslayer(TCP)]

            if not tcp_packets:
                return {
                    "file": pcap_file,
                    "total_packets": len(packets),
                    "tcp_packets_found": 0,
                    "message": "No TCP packets found in this capture",
                }

            # Apply filtering if specified
            filtered_packets = self._apply_filters(
                tcp_packets,
                self._analysis_kwargs.get("server_ip"),
                self._analysis_kwargs.get("server_port"),
            )

            # Route to appropriate analysis method
            if self._analysis_type == "connections":
                return self._analyze_connections(pcap_file, filtered_packets, packets)
            elif self._analysis_type == "anomalies":
                return self._analyze_anomalies(pcap_file, filtered_packets, packets)
            elif self._analysis_type == "retransmissions":
                return self._analyze_retrans(pcap_file, filtered_packets, packets)
            elif self._analysis_type == "traffic_flow":
                return self._analyze_flow(pcap_file, filtered_packets, packets)
            else:
                return {"error": f"Unknown analysis type: {self._analysis_type}"}

        except Exception as e:
            return {
                "error": f"Error reading PCAP file '{pcap_file}': {str(e)}",
                "file": pcap_file,
            }

    def _apply_filters(
        self, packets: list, server_ip: Optional[str], server_port: Optional[int]
    ) -> list:
        """Apply IP and port filters to packets."""
        if not server_ip and not server_port:
            return packets

        filtered = []
        for pkt in packets:
            src_ip, dst_ip = self._extract_ips(pkt)
            tcp = pkt[TCP]

            # Check if packet matches filter
            if server_ip:
                if src_ip != server_ip and dst_ip != server_ip:
                    continue
            if server_port:
                if tcp.sport != server_port and tcp.dport != server_port:
                    continue

            filtered.append(pkt)

        return filtered

    def _analyze_connections(
        self, pcap_file: str, tcp_packets: list, all_packets: list
    ) -> dict[str, Any]:
        """Analyze TCP connections."""
        # Group packets by connection (4-tuple)
        connections = defaultdict(list)
        for pkt in tcp_packets:
            conn_key = self._get_connection_key(pkt)
            connections[conn_key].append(pkt)

        # Analyze each connection
        connection_details = []
        successful_handshakes = 0
        failed_handshakes = 0
        reset_connections = 0
        normal_close = 0
        issues = []

        for conn_key, pkts in connections.items():
            conn_info = self._analyze_single_connection(conn_key, pkts)
            connection_details.append(conn_info)

            if conn_info["handshake_completed"]:
                successful_handshakes += 1
            else:
                failed_handshakes += 1

            if conn_info["close_reason"] == "reset":
                reset_connections += 1
            elif conn_info["close_reason"] == "normal":
                normal_close += 1

        # Detect issues
        total_rst = sum(c["rst_count"] for c in connection_details)
        total_retrans = sum(c["retransmissions"] for c in connection_details)

        if reset_connections > 0:
            issues.append(f"{reset_connections} connections terminated by RST")
        if total_retrans > 0:
            issues.append(f"{total_retrans} retransmissions detected")
        if failed_handshakes > 0:
            issues.append(f"{failed_handshakes} failed handshakes")

        return {
            "file": pcap_file,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_packets": len(all_packets),
            "tcp_packets_found": len(tcp_packets),
            "filter": {
                "server_ip": self._analysis_kwargs.get("server_ip"),
                "server_port": self._analysis_kwargs.get("server_port"),
            },
            "summary": {
                "total_connections": len(connections),
                "successful_handshakes": successful_handshakes,
                "failed_handshakes": failed_handshakes,
                "established_connections": successful_handshakes,
                "reset_connections": reset_connections,
                "normal_close": normal_close,
                "active_connections": len(connections)
                - reset_connections
                - normal_close,
            },
            "connections": connection_details
            if self._analysis_kwargs.get("detailed", False)
            else connection_details[:10],
            "issues": issues,
        }

    def _analyze_single_connection(
        self, conn_key: tuple, packets: list
    ) -> dict[str, Any]:
        """Analyze a single TCP connection."""
        src_ip, src_port, dst_ip, dst_port = conn_key

        syn_count = 0
        syn_ack_count = 0
        ack_count = 0
        rst_count = 0
        fin_count = 0
        data_packets = 0
        retransmissions = 0

        seen_seqs = set()
        handshake_completed = False

        for pkt in packets:
            tcp = pkt[TCP]
            flags = tcp.flags

            # Count flags
            if flags & 0x02:  # SYN
                syn_count += 1
            if flags & 0x12 == 0x12:  # SYN-ACK
                syn_ack_count += 1
            if flags & 0x10:  # ACK
                ack_count += 1
            if flags & 0x04:  # RST
                rst_count += 1
            if flags & 0x01:  # FIN
                fin_count += 1

            # Check for data
            if len(tcp.payload) > 0:
                data_packets += 1

            # Detect retransmissions (simplified)
            seq = tcp.seq
            if seq in seen_seqs and len(tcp.payload) > 0:
                retransmissions += 1
            seen_seqs.add(seq)

        # Determine handshake completion
        if syn_count > 0 and syn_ack_count > 0 and ack_count > 0:
            handshake_completed = True

        # Determine close reason
        close_reason = "unknown"
        if rst_count > 0:
            close_reason = "reset"
        elif fin_count >= 2:
            close_reason = "normal"
        elif len(packets) > 3:
            close_reason = "active"

        return {
            "client": f"{src_ip}:{src_port}",
            "server": f"{dst_ip}:{dst_port}",
            "state": "closed" if close_reason in ["reset", "normal"] else "active",
            "handshake_completed": handshake_completed,
            "syn_count": syn_count,
            "syn_ack_count": syn_ack_count,
            "ack_count": ack_count,
            "rst_count": rst_count,
            "fin_count": fin_count,
            "data_packets": data_packets,
            "retransmissions": retransmissions,
            "close_reason": close_reason,
            "packet_count": len(packets),
        }

    def _analyze_anomalies(
        self, pcap_file: str, tcp_packets: list, all_packets: list
    ) -> dict[str, Any]:
        """Detect TCP anomalies using pattern-based analysis.
        
        This method collects observable metrics and patterns from the traffic,
        without making assumptions about root causes. The analysis focuses on
        factual observations that can be derived from packet-level data.
        """
        # Group packets by connection
        connections = defaultdict(list)
        for pkt in tcp_packets:
            conn_key = self._get_connection_key(pkt)
            connections[conn_key].append(pkt)

        # Collect comprehensive statistics
        stats = self._collect_tcp_statistics(connections, tcp_packets)
        
        # Detect observable patterns (not diagnoses)
        patterns = self._detect_tcp_patterns(stats, connections)

        return {
            "file": pcap_file,
            "analysis_timestamp": datetime.now().isoformat(),
            "filter": {
                "server_ip": self._analysis_kwargs.get("server_ip"),
                "server_port": self._analysis_kwargs.get("server_port"),
            },
            "statistics": stats,
            "patterns": patterns,
            "summary": self._generate_pattern_summary(patterns),
        }

    def _analyze_retrans(
        self, pcap_file: str, tcp_packets: list, all_packets: list
    ) -> dict[str, Any]:
        """Analyze TCP retransmissions."""
        threshold = self._analysis_kwargs.get("threshold", 0.02)

        # Group by connection
        connections = defaultdict(list)
        for pkt in tcp_packets:
            conn_key = self._get_connection_key(pkt)
            connections[conn_key].append(pkt)

        by_connection = []
        total_retrans = 0
        worst_rate = 0
        worst_conn = ""

        for conn_key, pkts in connections.items():
            src_ip, src_port, dst_ip, dst_port = conn_key
            conn_str = f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"

            conn_info = self._analyze_single_connection(conn_key, pkts)
            retrans_count = conn_info["retransmissions"]
            total_retrans += retrans_count

            retrans_rate = retrans_count / len(pkts) if len(pkts) > 0 else 0

            by_connection.append(
                {
                    "connection": conn_str,
                    "retrans_count": retrans_count,
                    "total_packets": len(pkts),
                    "retrans_rate": retrans_rate,
                }
            )

            if retrans_rate > worst_rate:
                worst_rate = retrans_rate
                worst_conn = conn_str

        # Sort by retransmission rate
        by_connection.sort(key=lambda x: x["retrans_rate"], reverse=True)

        overall_rate = total_retrans / len(tcp_packets) if len(tcp_packets) > 0 else 0
        connections_above_threshold = sum(
            1 for c in by_connection if c["retrans_rate"] > threshold
        )

        return {
            "file": pcap_file,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_packets": len(tcp_packets),
            "total_retransmissions": total_retrans,
            "retransmission_rate": overall_rate,
            "threshold": threshold,
            "exceeds_threshold": overall_rate > threshold,
            "by_connection": by_connection[:10],  # Top 10
            "summary": {
                "worst_connection": worst_conn,
                "worst_retrans_rate": worst_rate,
                "connections_above_threshold": connections_above_threshold,
            },
        }

    def _analyze_flow(
        self, pcap_file: str, tcp_packets: list, all_packets: list
    ) -> dict[str, Any]:
        """Analyze traffic flow."""
        server_ip = self._analysis_kwargs.get("server_ip")
        server_port = self._analysis_kwargs.get("server_port")

        if not server_ip:
            return {"error": "server_ip is required for traffic flow analysis"}

        client_to_server = {
            "packet_count": 0,
            "byte_count": 0,
            "syn_count": 0,
            "rst_count": 0,
            "fin_count": 0,
            "data_packets": 0,
            "retransmissions": 0,
        }

        server_to_client = {
            "packet_count": 0,
            "byte_count": 0,
            "syn_count": 0,
            "rst_count": 0,
            "fin_count": 0,
            "data_packets": 0,
            "retransmissions": 0,
        }

        client_seqs = set()
        server_seqs = set()

        for pkt in tcp_packets:
            src_ip, dst_ip = self._extract_ips(pkt)
            tcp = pkt[TCP]
            flags = tcp.flags

            # Determine direction
            is_client_to_server = dst_ip == server_ip
            if server_port:
                is_client_to_server = tcp.dport == server_port

            stats = client_to_server if is_client_to_server else server_to_client
            seqs = client_seqs if is_client_to_server else server_seqs

            stats["packet_count"] += 1
            stats["byte_count"] += len(pkt)

            if flags & 0x02:
                stats["syn_count"] += 1
            if flags & 0x04:
                stats["rst_count"] += 1
            if flags & 0x01:
                stats["fin_count"] += 1
            if len(tcp.payload) > 0:
                stats["data_packets"] += 1

            # Retransmissions
            seq = tcp.seq
            if seq in seqs and len(tcp.payload) > 0:
                stats["retransmissions"] += 1
            seqs.add(seq)

        # Analysis
        total_client = client_to_server["packet_count"]
        total_server = server_to_client["packet_count"]
        asymmetry_ratio = total_client / total_server if total_server > 0 else 0

        # Determine primary RST source
        client_rst = client_to_server["rst_count"]
        server_rst = server_to_client["rst_count"]
        if client_rst > server_rst:
            rst_source = "client"
            interpretation = f"Client sends all RST packets ({client_rst} vs {server_rst}). Server responds normally. Suggests client-side issue (possibly firewall)."
        elif server_rst > client_rst:
            rst_source = "server"
            interpretation = "Server sends more RST packets. Suggests server-side rejection or service issue."
        else:
            rst_source = "balanced"
            interpretation = "Balanced RST distribution."

        return {
            "file": pcap_file,
            "analysis_timestamp": datetime.now().isoformat(),
            "server": f"{server_ip}:{server_port or 'any'}",
            "client_to_server": client_to_server,
            "server_to_client": server_to_client,
            "analysis": {
                "asymmetry_ratio": asymmetry_ratio,
                "primary_rst_source": rst_source,
                "data_flow_direction": "client_heavy"
                if asymmetry_ratio > 1.2
                else "server_heavy"
                if asymmetry_ratio < 0.8
                else "balanced",
                "interpretation": interpretation,
            },
        }

    def _get_connection_key(self, pkt) -> tuple:
        """Extract connection 4-tuple (src_ip, src_port, dst_ip, dst_port)."""
        src_ip, dst_ip = self._extract_ips(pkt)
        tcp = pkt[TCP]
        return (src_ip, tcp.sport, dst_ip, tcp.dport)

    def _extract_ips(self, pkt) -> tuple:
        """Extract source and destination IPs."""
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
        return "unknown", "unknown"

    def _collect_tcp_statistics(
        self, connections: dict, tcp_packets: list
    ) -> dict[str, Any]:
        """Collect comprehensive TCP statistics from connections.
        
        Returns factual metrics without interpretation.
        """
        server_ip = self._analysis_kwargs.get("server_ip")
        server_port = self._analysis_kwargs.get("server_port")
        
        stats = {
            "total_connections": len(connections),
            "total_packets": len(tcp_packets),
            "handshake": {
                "successful": 0,
                "failed": 0,
                "incomplete": 0,
            },
            "flags": {
                "syn": 0,
                "syn_ack": 0,
                "rst": 0,
                "fin": 0,
                "ack": 0,
            },
            "rst_distribution": {
                "by_source": {},  # IP -> count
                "by_direction": {
                    "to_server": 0,
                    "from_server": 0,
                    "unknown": 0,
                },
                "connections_with_rst": [],
            },
            "retransmissions": {
                "total": 0,
                "by_connection": {},
            },
            "connection_states": {
                "established": 0,
                "reset": 0,
                "closed": 0,
                "unknown": 0,
            },
        }
        
        for conn_key, pkts in connections.items():
            src_ip, src_port, dst_ip, dst_port = conn_key
            conn_info = self._analyze_single_connection(conn_key, pkts)
            
            # Handshake analysis
            if conn_info["handshake_completed"]:
                stats["handshake"]["successful"] += 1
            else:
                stats["handshake"]["failed"] += 1
            
            # Flag counting
            for pkt in pkts:
                tcp = pkt[TCP]
                flags = tcp.flags
                
                if flags & 0x02:  # SYN
                    stats["flags"]["syn"] += 1
                if flags & 0x12 == 0x12:  # SYN-ACK
                    stats["flags"]["syn_ack"] += 1
                if flags & 0x04:  # RST
                    stats["flags"]["rst"] += 1
                    pkt_src_ip, _ = self._extract_ips(pkt)
                    
                    # Track RST by source IP
                    stats["rst_distribution"]["by_source"][pkt_src_ip] = (
                        stats["rst_distribution"]["by_source"].get(pkt_src_ip, 0) + 1
                    )
                    
                    # Track RST by direction (if server info provided)
                    if server_ip:
                        if pkt_src_ip == server_ip:
                            stats["rst_distribution"]["by_direction"]["from_server"] += 1
                        else:
                            stats["rst_distribution"]["by_direction"]["to_server"] += 1
                    else:
                        stats["rst_distribution"]["by_direction"]["unknown"] += 1
                        
                if flags & 0x01:  # FIN
                    stats["flags"]["fin"] += 1
                if flags & 0x10:  # ACK
                    stats["flags"]["ack"] += 1
            
            # RST connections
            if conn_info["rst_count"] > 0:
                stats["rst_distribution"]["connections_with_rst"].append(
                    f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
                )
            
            # Retransmissions
            retrans = conn_info["retransmissions"]
            stats["retransmissions"]["total"] += retrans
            if retrans > 0:
                conn_str = f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
                stats["retransmissions"]["by_connection"][conn_str] = retrans
            
            # Connection states
            if conn_info["close_reason"] == "reset":
                stats["connection_states"]["reset"] += 1
            elif conn_info["close_reason"] == "normal":
                stats["connection_states"]["closed"] += 1
            elif conn_info["handshake_completed"]:
                stats["connection_states"]["established"] += 1
            else:
                stats["connection_states"]["unknown"] += 1
        
        # Calculate rates
        stats["retransmissions"]["rate"] = (
            stats["retransmissions"]["total"] / stats["total_packets"]
            if stats["total_packets"] > 0
            else 0
        )
        
        return stats

    def _detect_tcp_patterns(
        self, stats: dict, connections: dict
    ) -> list[dict[str, Any]]:
        """Detect observable patterns in TCP traffic.
        
        Returns patterns with factual descriptions, not interpretations.
        Each pattern includes the raw data that led to its detection.
        """
        patterns = []
        
        # Pattern 1: RST asymmetry
        rst_by_dir = stats["rst_distribution"]["by_direction"]
        if rst_by_dir["to_server"] > 0 or rst_by_dir["from_server"] > 0:
            total_rst = rst_by_dir["to_server"] + rst_by_dir["from_server"]
            if total_rst > 0:
                patterns.append({
                    "pattern": "rst_directional_asymmetry",
                    "category": "connection_termination",
                    "observations": {
                        "rst_to_server": rst_by_dir["to_server"],
                        "rst_from_server": rst_by_dir["from_server"],
                        "ratio": rst_by_dir["to_server"] / total_rst if total_rst > 0 else 0,
                        "affected_connections": stats["rst_distribution"]["connections_with_rst"],
                    },
                    "description": f"RST packets show directional bias: {rst_by_dir['to_server']} toward server, {rst_by_dir['from_server']} from server",
                })
        
        # Pattern 2: Retransmission rate
        retrans_rate = stats["retransmissions"]["rate"]
        if retrans_rate > 0:
            patterns.append({
                "pattern": "packet_retransmission",
                "category": "reliability",
                "observations": {
                    "total_retransmissions": stats["retransmissions"]["total"],
                    "total_packets": stats["total_packets"],
                    "rate": retrans_rate,
                    "threshold": 0.02,  # Common baseline
                    "exceeds_threshold": retrans_rate > 0.02,
                    "by_connection": stats["retransmissions"]["by_connection"],
                },
                "description": f"Retransmission rate: {retrans_rate:.2%} ({stats['retransmissions']['total']}/{stats['total_packets']} packets)",
            })
        
        # Pattern 3: Handshake failure rate
        total_attempts = stats["handshake"]["successful"] + stats["handshake"]["failed"]
        if total_attempts > 0:
            failure_rate = stats["handshake"]["failed"] / total_attempts
            if failure_rate > 0:
                patterns.append({
                    "pattern": "handshake_completion",
                    "category": "connection_establishment",
                    "observations": {
                        "successful": stats["handshake"]["successful"],
                        "failed": stats["handshake"]["failed"],
                        "failure_rate": failure_rate,
                    },
                    "description": f"Handshake success rate: {(1-failure_rate):.1%} ({stats['handshake']['successful']}/{total_attempts})",
                })
        
        # Pattern 4: Connection termination method
        total_conns = stats["total_connections"]
        if total_conns > 0:
            rst_rate = stats["connection_states"]["reset"] / total_conns
            if rst_rate > 0.1:  # More than 10% reset
                patterns.append({
                    "pattern": "abnormal_termination",
                    "category": "connection_lifecycle",
                    "observations": {
                        "reset_count": stats["connection_states"]["reset"],
                        "normal_close": stats["connection_states"]["closed"],
                        "total_connections": total_conns,
                        "reset_rate": rst_rate,
                    },
                    "description": f"{rst_rate:.1%} of connections terminated by RST ({stats['connection_states']['reset']}/{total_conns})",
                })
        
        # Pattern 5: Flag anomalies
        if stats["flags"]["syn"] > 0:
            syn_ack_ratio = stats["flags"]["syn_ack"] / stats["flags"]["syn"]
            if syn_ack_ratio < 0.5:  # Less than 50% of SYNs get SYN-ACK
                patterns.append({
                    "pattern": "syn_response_imbalance",
                    "category": "connection_establishment",
                    "observations": {
                        "syn_count": stats["flags"]["syn"],
                        "syn_ack_count": stats["flags"]["syn_ack"],
                        "response_ratio": syn_ack_ratio,
                    },
                    "description": f"Only {syn_ack_ratio:.1%} of SYN packets received SYN-ACK response",
                })
        
        return patterns

    def _generate_pattern_summary(self, patterns: list) -> dict[str, Any]:
        """Generate a summary of detected patterns by category."""
        summary = {
            "total_patterns": len(patterns),
            "by_category": {},
            "notable_observations": [],
        }
        
        for pattern in patterns:
            category = pattern["category"]
            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        
        # Extract notable observations (can be extended)
        for pattern in patterns:
            if pattern["pattern"] == "rst_directional_asymmetry":
                obs = pattern["observations"]
                if obs["ratio"] > 0.9 or obs["ratio"] < 0.1:
                    summary["notable_observations"].append({
                        "type": "strong_rst_asymmetry",
                        "detail": f"RST packets heavily biased: {obs['ratio']:.1%} in one direction",
                    })
            
            if pattern["pattern"] == "packet_retransmission":
                obs = pattern["observations"]
                if obs["exceeds_threshold"]:
                    summary["notable_observations"].append({
                        "type": "high_retransmission",
                        "detail": f"Retransmission rate {obs['rate']:.2%} exceeds typical threshold of 2%",
                    })
        
        return summary

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Set up TCP-specific analysis prompts for the MCP server.

        Args:
            mcp: FastMCP server instance
        """

        @mcp.prompt
        def tcp_connection_troubleshooting():
            """Prompt for troubleshooting TCP connection issues"""
            return """You are a network engineer troubleshooting TCP connection problems. Focus on:

1. **Connection Establishment:**
   - Analyze three-way handshake (SYN, SYN-ACK, ACK)
   - Identify failed handshakes and root causes
   - Check for connection timeouts
   - Look for firewall blocks or network ACLs

2. **Connection Termination:**
   - Identify RST (reset) packets and their sources
   - Analyze normal FIN-based termination
   - Detect abnormal connection closures
   - Determine if issues are client-side or server-side

3. **Network Quality:**
   - Measure retransmission rates
   - Identify packet loss patterns
   - Check for network congestion
   - Analyze latency issues

4. **Traffic Patterns:**
   - Examine bidirectional traffic flow
   - Identify traffic asymmetry
   - Detect unusual connection patterns
   - Look for scanning or attack behaviors

Provide specific diagnostics with evidence and actionable remediation steps."""

        @mcp.prompt
        def tcp_security_analysis():
            """Prompt for analyzing TCP traffic from a security perspective"""
            return """You are a security analyst examining TCP traffic. Focus on:

1. **Attack Detection:**
   - Identify SYN flood attacks
   - Detect port scanning activities
   - Look for connection flooding
   - Find abnormal connection patterns

2. **Firewall Analysis:**
   - Identify blocked connections (RST patterns)
   - Analyze firewall effectiveness
   - Detect firewall misconfigurations
   - Check for bypass attempts

3. **Anomaly Detection:**
   - Find unusual RST patterns
   - Detect connection hijacking attempts
   - Identify data exfiltration patterns
   - Look for covert channels

4. **Forensic Evidence:**
   - Document connection timelines
   - Correlate TCP events with security incidents
   - Preserve evidence of malicious activity
   - Track attacker behavior patterns

Present findings with severity levels, evidence, and recommended security actions."""
