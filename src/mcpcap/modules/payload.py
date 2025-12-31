"""Payload analysis module for extracting and analyzing application layer data."""

from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

from scapy.all import IP, TCP, UDP, IPv6, rdpcap

from .base import BaseModule


class PayloadModule(BaseModule):
    """Module for analyzing TCP/UDP payloads and extracting application layer data."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "Payload"

    def analyze_payload(
        self,
        pcap_file: str,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        extract_text: bool = True,
        detect_encryption: bool = True,
    ) -> dict[str, Any]:
        """
        Analyze TCP/UDP payloads and extract application layer data.

        This is a universal payload analysis tool that:
        1. Extracts all TCP/UDP payloads
        2. Automatically detects application layer protocols
        3. Detects encryption status (TLS/SSL)
        4. Extracts plaintext data (SQL, commands, queries)

        Args:
            pcap_file: HTTP URL or absolute local file path to PCAP file
            port: Optional port filter (None = all ports)
            protocol: Protocol hint ("mysql", "postgres", "redis", "auto", or None)
            extract_text: Whether to extract readable text
            detect_encryption: Whether to detect encryption

        Returns:
            A structured dictionary containing:
            - summary: Overall statistics
            - connections: List of connections with payloads
            - extracted_data: Extracted queries, commands, text
            - recommendations: Smart suggestions
        """
        return self.analyze_packets(
            pcap_file,
            port=port,
            protocol=protocol,
            extract_text=extract_text,
            detect_encryption=detect_encryption,
        )

    def extract_database_queries(
        self,
        pcap_file: str,
        port: Optional[int] = None,
        protocol: Optional[str] = "auto",
    ) -> dict[str, Any]:
        """
        Extract database queries (SQL statements, Redis commands, etc.) from PCAP.

        Specialized tool for database traffic analysis.

        Args:
            pcap_file: HTTP URL or absolute local file path to PCAP file
            port: Optional port filter (default: auto-detect from common ports)
            protocol: Database protocol ("mysql", "postgres", "redis", "auto")

        Returns:
            Dictionary containing extracted queries and statistics
        """
        return self.analyze_packets(
            pcap_file,
            port=port,
            protocol=protocol,
            extract_text=True,
            detect_encryption=True,
            queries_only=True,
        )

    def detect_protocols(
        self,
        pcap_file: str,
        port: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Detect application layer protocols in PCAP traffic.

        Quick analysis to identify what protocols are present.

        Args:
            pcap_file: HTTP URL or absolute local file path to PCAP file
            port: Optional port filter

        Returns:
            Dictionary containing detected protocols and confidence scores
        """
        return self.analyze_packets(
            pcap_file,
            port=port,
            protocol="auto",
            extract_text=False,
            detect_encryption=True,
            detection_only=True,
        )

    def _analyze_protocol_file(self, pcap_file: str, **kwargs) -> dict[str, Any]:
        """
        Analyze a local PCAP file for payload data.

        Args:
            pcap_file: Path to local PCAP file
            **kwargs: Additional analysis options

        Returns:
            Analysis results dictionary
        """
        from .protocol_detector import ProtocolDetector
        from .text_extractor import TextExtractor

        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            return {
                "error": f"Failed to read PCAP file: {str(e)}",
                "file": pcap_file,
            }

        # Initialize helpers
        detector = ProtocolDetector()
        text_extractor = TextExtractor()

        # Extract options
        port_filter = kwargs.get("port")
        protocol_hint = kwargs.get("protocol", "auto")
        extract_text = kwargs.get("extract_text", True)
        detect_encryption = kwargs.get("detect_encryption", True)
        queries_only = kwargs.get("queries_only", False)
        detection_only = kwargs.get("detection_only", False)

        # Statistics
        stats = {
            "total_packets": len(packets),
            "packets_with_payload": 0,
            "total_payload_bytes": 0,
            "encrypted_packets": 0,
            "plaintext_packets": 0,
        }

        # Track connections
        connections = defaultdict(lambda: {
            "packets": [],
            "payloads": [],
            "protocol_detected": None,
            "confidence": 0.0,
            "encryption": {
                "is_encrypted": False,
                "type": None,
                "starts_at_packet": None,
            },
        })

        # First pass: extract payloads
        for i, pkt in enumerate(packets):
            packet_num = i + 1

            # Get IP layer
            ip_layer = None
            if IP in pkt:
                ip_layer = pkt[IP]
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
            else:
                continue

            # Get transport layer (TCP or UDP)
            transport = None
            if TCP in pkt:
                transport = pkt[TCP]
                transport_type = "tcp"
            elif UDP in pkt:
                transport = pkt[UDP]
                transport_type = "udp"
            else:
                continue

            # Check port filter
            if port_filter and transport.sport != port_filter and transport.dport != port_filter:
                continue

            # Extract payload
            payload = bytes(transport.payload) if transport.payload else b""
            if not payload:
                continue

            stats["packets_with_payload"] += 1
            stats["total_payload_bytes"] += len(payload)

            # Identify connection (5-tuple)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = transport.sport
            dst_port = transport.dport

            # Normalize connection direction (client->server)
            if src_port < dst_port:
                conn_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                direction = "client->server"
            else:
                conn_key = f"{dst_ip}:{dst_port} -> {src_ip}:{src_port}"
                direction = "server->client"

            conn = connections[conn_key]

            # Detect protocol on first payload
            if conn["protocol_detected"] is None:
                detection = detector.detect_protocol(
                    payload,
                    port=dst_port if direction == "client->server" else src_port,
                    direction=direction,
                )
                conn["protocol_detected"] = detection["protocol"]
                conn["confidence"] = detection["confidence"]

                if detection.get("is_encrypted"):
                    conn["encryption"]["is_encrypted"] = True
                    conn["encryption"]["type"] = detection.get("tls_version", "TLS")
                    conn["encryption"]["starts_at_packet"] = packet_num

            # Check if this packet is encrypted
            is_encrypted = False
            if detect_encryption:
                # Check TLS signature
                if len(payload) >= 3 and payload[0] in [0x16, 0x17, 0x14, 0x15]:
                    tls_version = (payload[1] << 8) | payload[2]
                    if tls_version in [0x0301, 0x0302, 0x0303, 0x0304]:
                        is_encrypted = True
                        stats["encrypted_packets"] += 1
                        if not conn["encryption"]["is_encrypted"]:
                            conn["encryption"]["is_encrypted"] = True
                            conn["encryption"]["starts_at_packet"] = packet_num
                            # Detect TLS version
                            tls_versions = {
                                0x0301: "TLS 1.0",
                                0x0302: "TLS 1.1",
                                0x0303: "TLS 1.2",
                                0x0304: "TLS 1.3",
                            }
                            conn["encryption"]["type"] = tls_versions.get(tls_version, "TLS")

            if not is_encrypted:
                stats["plaintext_packets"] += 1

            # Store payload info
            payload_info = {
                "packet_num": packet_num,
                "direction": direction,
                "size": len(payload),
                "is_encrypted": is_encrypted,
                "timestamp": float(pkt.time) if hasattr(pkt, 'time') else None,
            }

            # Extract hex (first 64 bytes)
            payload_info["hex"] = payload[:64].hex()

            # Try to extract ASCII
            try:
                ascii_data = payload[:100].decode('utf-8', errors='ignore')
                if ascii_data:
                    payload_info["ascii"] = ascii_data
            except:
                pass

            # Extract text if requested and not encrypted
            if extract_text and not is_encrypted:
                texts = text_extractor.extract_text(payload)
                if texts:
                    payload_info["texts"] = texts

            # Parse protocol-specific data if not encrypted
            if not is_encrypted and conn["protocol_detected"] not in ["unknown", "tls"]:
                parsed = self._parse_protocol_payload(
                    payload,
                    conn["protocol_detected"],
                    direction,
                )
                if parsed:
                    payload_info["analysis"] = parsed

            conn["payloads"].append(payload_info)

        # Build result
        result = {
            "file": pcap_file,
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": stats,
        }

        # Convert connections to list
        connections_list = []
        for conn_key, conn_data in connections.items():
            parts = conn_key.split(" -> ")
            conn_info = {
                "client": parts[0],
                "server": parts[1],
                "port": int(parts[1].split(':')[1]),
                "protocol_detected": conn_data["protocol_detected"],
                "confidence": conn_data["confidence"],
                "encryption": conn_data["encryption"],
                "payloads": conn_data["payloads"],
                "payload_count": len(conn_data["payloads"]),
            }

            # Extract queries/commands if requested
            if queries_only or not detection_only:
                extracted = self._extract_queries_from_connection(conn_data)
                if extracted:
                    conn_info["extracted_data"] = extracted

            connections_list.append(conn_info)

        result["connections"] = connections_list

        # Generate recommendations
        if not detection_only:
            from .recommendation import RecommendationEngine
            rec_engine = RecommendationEngine()
            result["recommendations"] = rec_engine.generate_recommendations(result)

        return result

    def _parse_protocol_payload(
        self,
        payload: bytes,
        protocol: str,
        direction: str,
    ) -> Optional[dict]:
        """Parse payload according to detected protocol."""
        try:
            if protocol == "mysql":
                from .database.mysql_parser import MySQLParser
                parser = MySQLParser()
                return parser.parse_packet(payload, {"direction": direction})
            elif protocol == "postgresql":
                from .database.postgres_parser import PostgresParser
                parser = PostgresParser()
                return parser.parse_packet(payload, {"direction": direction})
            elif protocol == "redis":
                from .database.redis_parser import RedisParser
                parser = RedisParser()
                return parser.parse_packet(payload, {"direction": direction})
        except Exception as e:
            return {"error": f"Parse error: {str(e)}"}

        return None

    def _extract_queries_from_connection(self, conn_data: dict) -> Optional[dict]:
        """Extract queries/commands from connection payloads."""
        queries = []
        responses = []

        for payload_info in conn_data["payloads"]:
            if payload_info.get("is_encrypted"):
                continue

            analysis = payload_info.get("analysis")
            if not analysis:
                continue

            # Extract queries
            if analysis.get("type") == "query":
                queries.append({
                    "packet_num": payload_info["packet_num"],
                    "query_type": analysis.get("query_type", "UNKNOWN"),
                    "query": analysis.get("sql") or analysis.get("command") or analysis.get("full_command"),
                    "is_encrypted": False,
                })

            # Extract responses
            elif analysis.get("type") in ["response", "ok", "error"]:
                responses.append({
                    "packet_num": payload_info["packet_num"],
                    "result_type": analysis.get("status", analysis.get("type")),
                    "error_msg": analysis.get("error"),
                })

        if queries or responses:
            return {
                "queries": queries,
                "responses": responses,
                "query_count": len(queries),
            }

        return None

    def setup_prompts(self, mcp) -> None:
        """Set up Payload-specific analysis prompts for the MCP server.

        Args:
            mcp: FastMCP server instance
        """

        @mcp.prompt
        def payload_database_analysis():
            """Prompt for analyzing database traffic and SQL queries"""
            return """You are a database administrator analyzing database traffic. Focus on:

1. **SQL Query Analysis:**
   - Extract and review SQL queries (SELECT, INSERT, UPDATE, DELETE)
   - Identify slow or inefficient queries
   - Look for query patterns and access patterns
   - Check for proper query optimization

2. **Database Security:**
   - Detect potential SQL injection attempts
   - Look for suspicious query patterns
   - Identify unauthorized access attempts
   - Check for data exfiltration patterns

3. **Protocol Detection:**
   - Identify database protocols (MySQL, PostgreSQL, Redis)
   - Detect database versions from handshake
   - Understand client-server communication patterns

4. **Performance Insights:**
   - Analyze query frequency and patterns
   - Identify connection pooling behavior
   - Look for connection leaks or excessive connections
   - Check for transaction patterns

When analyzing, provide actionable insights and recommendations."""

        @mcp.prompt
        def payload_security_analysis():
            """Prompt for security analysis of application layer payloads"""
            return """You are a security analyst examining application layer traffic. Focus on:

1. **Attack Detection:**
   - Identify SQL injection patterns in queries
   - Look for command injection attempts
   - Detect NoSQL injection in Redis/MongoDB
   - Find authentication bypass attempts

2. **Data Leakage:**
   - Identify sensitive data in plaintext
   - Look for password transmission
   - Detect PII (personally identifiable information)
   - Check for credential leaks

3. **Protocol Abuse:**
   - Detect protocol violations
   - Look for malformed packets
   - Identify unusual command sequences
   - Find protocol-level attacks

4. **Encryption Analysis:**
   - Identify unencrypted sensitive traffic
   - Check TLS/SSL versions and vulnerabilities
   - Recommend encryption where missing

Always provide risk assessment and mitigation recommendations."""

        @mcp.prompt
        def payload_encryption_analysis():
            """Prompt for analyzing encryption status and providing decryption guidance"""
            return """You are a network security specialist analyzing traffic encryption. Focus on:

1. **Encryption Detection:**
   - Identify TLS/SSL encrypted traffic
   - Detect encryption versions (TLS 1.0, 1.1, 1.2, 1.3)
   - Find mixed plaintext/encrypted connections
   - Recognize encryption handshake patterns

2. **Decryption Guidance:**
   - Provide steps to capture TLS keys (SSLKEYLOGFILE)
   - Recommend Wireshark decryption setup
   - Suggest proxy-based decryption methods
   - Explain certificate pinning bypass techniques

3. **Security Assessment:**
   - Identify weak encryption (TLS 1.0/1.1)
   - Recommend strong cipher suites
   - Check for certificate issues
   - Assess overall encryption posture

4. **Analysis Strategy:**
   - Suggest alternative analysis methods for encrypted traffic
   - Recommend metadata analysis techniques
   - Propose behavioral analysis approaches
   - Guide on legal/compliance considerations

Provide practical, actionable recommendations for both analysis and security improvement."""
