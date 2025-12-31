"""Recommendation engine for providing smart suggestions based on analysis results."""

from typing import Any


class RecommendationEngine:
    """Generate intelligent recommendations based on payload analysis results."""

    def generate_recommendations(self, analysis_result: dict[str, Any]) -> list[str]:
        """
        Generate recommendations based on analysis results.

        Args:
            analysis_result: Analysis result from PayloadModule

        Returns:
            List of recommendation strings
        """
        recommendations = []
        seen = set()  # Track recommendations to avoid duplicates

        connections = analysis_result.get("connections", [])

        for conn in connections:
            protocol = conn.get("protocol_detected", "unknown")
            port = conn.get("port")
            encryption = conn.get("encryption", {})
            is_encrypted = encryption.get("is_encrypted", False)
            extracted_data = conn.get("extracted_data", {})

            # Encrypted traffic recommendations
            if is_encrypted:
                recs = self._get_decryption_recommendations(protocol, port)
                for rec in recs:
                    if rec not in seen:
                        recommendations.append(rec)
                        seen.add(rec)

            # Protocol detected but no data extracted
            elif protocol not in ["unknown", "text"] and not extracted_data:
                rec = (
                    f"Port {port} detected {protocol} protocol (confidence: {conn.get('confidence', 0):.2f}), "
                    f"but traffic is encrypted or parsing failed"
                )
                if rec not in seen:
                    recommendations.append(rec)
                    seen.add(rec)

            # Successfully extracted data
            elif extracted_data and extracted_data.get("queries"):
                query_count = len(extracted_data["queries"])
                rec = f"Successfully extracted {query_count} queries from {protocol} traffic"
                if rec not in seen:
                    recommendations.append(rec)
                    seen.add(rec)

        # General recommendations if nothing specific found
        if not recommendations:
            summary = analysis_result.get("summary", {})
            if summary.get("encrypted_packets", 0) > 0:
                recommendations.append(
                    "Detected encrypted traffic, unable to extract application layer data. "
                    "Consider disabling TLS/SSL or using application layer logs."
                )

        return recommendations

    def _get_decryption_recommendations(self, protocol: str, port: int) -> list[str]:
        """
        Get decryption/alternative analysis recommendations for encrypted traffic.

        Args:
            protocol: Detected protocol
            port: Port number

        Returns:
            List of recommendations
        """
        # MySQL recommendations
        if protocol == "mysql" or port == 3306:
            return [
                "⚠️  MySQL traffic is encrypted, cannot directly parse SQL statements",
                "",
                "📋 Solution 1: Disable SSL connection",
                "  - Server: SET GLOBAL require_secure_transport=OFF",
                "  - Client: Use --ssl-mode=DISABLED when connecting",
                "",
                "📋 Solution 2: Enable MySQL logging",
                "  - General Log: SET GLOBAL general_log=ON; SET GLOBAL log_output='TABLE';",
                "  - View logs: SELECT * FROM mysql.general_log ORDER BY event_time DESC LIMIT 100;",
                "",
                "📋 Solution 3: Use Performance Schema",
                "  - View statement history: SELECT * FROM performance_schema.events_statements_history;",
                "",
                "📋 Solution 4: Deploy audit plugins",
                "  - Percona Audit Plugin",
                "  - MySQL Enterprise Audit",
            ]

        # PostgreSQL recommendations
        elif protocol == "postgresql" or port == 5432:
            return [
                "⚠️  PostgreSQL traffic is encrypted",
                "",
                "📋 Solution 1: Disable SSL",
                "  - Modify pg_hba.conf: Change sslmode to 'trust' or 'md5'",
                "  - Client: psql 'sslmode=disable'",
                "",
                "📋 Solution 2: Enable query logging",
                "  - postgresql.conf: log_statement = 'all'",
                "  - View logs: tail -f /var/log/postgresql/postgresql-*.log",
                "",
                "📋 Solution 3: Use pg_stat_statements",
                "  - CREATE EXTENSION pg_stat_statements;",
                "  - SELECT * FROM pg_stat_statements ORDER BY calls DESC;",
            ]

        # Redis recommendations
        elif protocol == "redis" or port == 6379:
            return [
                "⚠️  Redis traffic is encrypted (Redis 6.0+ TLS or stunnel)",
                "",
                "📋 Solution 1: Disable TLS",
                "  - redis.conf: Remove TLS-related configuration",
                "  - If using stunnel: Stop stunnel service",
                "",
                "📋 Solution 2: Use MONITOR command (Warning: High performance impact)",
                "  - redis-cli MONITOR",
                "",
                "📋 Solution 3: Enable slow query log",
                "  - CONFIG SET slowlog-log-slower-than 10000",
                "  - SLOWLOG GET 100",
            ]

        # MongoDB recommendations
        elif protocol == "mongodb" or port == 27017:
            return [
                "⚠️  MongoDB traffic is encrypted",
                "",
                "📋 Solution 1: Disable TLS",
                "  - mongod.conf: Remove net.tls configuration",
                "",
                "📋 Solution 2: Enable Database Profiler",
                "  - db.setProfilingLevel(2); // Log all operations",
                "  - db.system.profile.find().pretty();",
                "",
                "📋 Solution 3: View slow query log",
                "  - mongod.conf: operationProfiling.slowOpThresholdMs: 100",
            ]

        # HTTP/HTTPS
        elif protocol == "http" or port in [80, 443, 8080]:
            return [
                "⚠️  HTTP(S) traffic is encrypted",
                "",
                "📋 Solution 1: Use SSLKEYLOGFILE (Browser)",
                "  - export SSLKEYLOGFILE=/path/to/keylog.txt",
                "  - Wireshark can use this file to decrypt TLS",
                "",
                "📋 Solution 2: Proxy server logging",
                "  - Use tools like mitmproxy",
                "",
                "📋 Solution 3: Application layer logs",
                "  - Nginx: Detailed log_format",
                "  - Apache: LogLevel debug",
            ]

        # Generic encrypted traffic
        else:
            return [
                f"⚠️  Traffic on port {port} is encrypted",
                "",
                "📋 General recommendations:",
                "  1. Disable TLS/SSL configuration on server side",
                "  2. Enable application layer logging",
                "  3. Use built-in audit/monitoring features",
                "  4. If analysis is necessary, consider using SSLKEYLOGFILE",
            ]

    def get_analysis_summary(self, analysis_result: dict[str, Any]) -> str:
        """
        Generate a human-readable summary of analysis results.

        Args:
            analysis_result: Analysis result from PayloadModule

        Returns:
            Summary string
        """
        summary = analysis_result.get("summary", {})
        connections = analysis_result.get("connections", [])

        lines = []
        lines.append("=" * 60)
        lines.append("Payload Analysis Summary")
        lines.append("=" * 60)

        # Statistics
        lines.append(f"\n📊 Statistics:")
        lines.append(f"  - Total packets: {summary.get('total_packets', 0)}")
        lines.append(f"  - Packets with payload: {summary.get('packets_with_payload', 0)}")
        lines.append(f"  - Plaintext packets: {summary.get('plaintext_packets', 0)}")
        lines.append(f"  - Encrypted packets: {summary.get('encrypted_packets', 0)}")
        lines.append(f"  - Total payload size: {summary.get('total_payload_bytes', 0)} bytes")

        # Connections
        lines.append(f"\n🔗 Connection Info:")
        for i, conn in enumerate(connections, 1):
            protocol = conn.get('protocol_detected', 'unknown')
            confidence = conn.get('confidence', 0)
            is_encrypted = conn.get('encryption', {}).get('is_encrypted', False)

            lines.append(f"  {i}. {conn.get('client')} → {conn.get('server')}")
            lines.append(f"     Protocol: {protocol} (confidence: {confidence:.2f})")

            if is_encrypted:
                tls_version = conn.get('encryption', {}).get('type', 'TLS')
                lines.append(f"     Encrypted: Yes ({tls_version})")
            else:
                lines.append(f"     Encrypted: No")

            # Extracted data
            extracted = conn.get('extracted_data', {})
            if extracted:
                query_count = len(extracted.get('queries', []))
                if query_count > 0:
                    lines.append(f"     Extracted queries: {query_count}")

        return "\n".join(lines)
