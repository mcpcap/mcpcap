"""Protocol detection engine for automatic application layer protocol identification."""

import re
import struct
from typing import Optional


class ProtocolDetector:
    """Automatic application layer protocol detector."""

    # Protocol signature database
    PROTOCOL_SIGNATURES = {
        "mysql": {
            "ports": [3306],
            "server_handshake_check": True,
            "min_size": 40,
            "max_size": 200,
        },
        "postgresql": {
            "ports": [5432],
            "startup_packet_check": True,
        },
        "redis": {
            "ports": [6379],
            "resp_protocol_check": True,
        },
        "mongodb": {
            "ports": [27017],
            "wire_protocol_check": True,
        },
        "http": {
            "ports": [80, 8080, 8000, 8888, 9000],
            "text_protocol_check": True,
        },
    }

    def detect_protocol(
        self,
        payload: bytes,
        port: int,
        direction: str = "unknown",
    ) -> dict:
        """
        Detect application layer protocol from payload.

        Args:
            payload: Payload bytes
            port: Port number
            direction: "client->server" or "server->client"

        Returns:
            {
                "protocol": "mysql" | "postgresql" | ... | "unknown",
                "confidence": 0.0-1.0,
                "is_encrypted": bool,
                "tls_version": str (if encrypted)
            }
        """
        if len(payload) == 0:
            return {
                "protocol": "unknown",
                "confidence": 0.0,
                "is_encrypted": False,
            }

        # First check: TLS/SSL encryption
        tls_result = self._check_tls_signature(payload)
        if tls_result["is_tls"]:
            return {
                "protocol": "tls",
                "confidence": 1.0,
                "is_encrypted": True,
                "tls_version": tls_result["version"],
            }

        # Second check: Protocol-specific signatures
        results = []

        # MySQL detection
        mysql_confidence = self._check_mysql(payload, port, direction)
        if mysql_confidence > 0:
            results.append(("mysql", mysql_confidence))

        # PostgreSQL detection
        postgres_confidence = self._check_postgresql(payload, port, direction)
        if postgres_confidence > 0:
            results.append(("postgresql", postgres_confidence))

        # Redis detection
        redis_confidence = self._check_redis(payload, port, direction)
        if redis_confidence > 0:
            results.append(("redis", redis_confidence))

        # MongoDB detection
        mongodb_confidence = self._check_mongodb(payload, port, direction)
        if mongodb_confidence > 0:
            results.append(("mongodb", mongodb_confidence))

        # HTTP detection
        http_confidence = self._check_http(payload, port)
        if http_confidence > 0:
            results.append(("http", http_confidence))

        # Return best match
        if results:
            protocol, confidence = max(results, key=lambda x: x[1])
            return {
                "protocol": protocol,
                "confidence": confidence,
                "is_encrypted": False,
            }

        # Fallback: check if it's readable text
        if self._is_readable_text(payload):
            return {
                "protocol": "text",
                "confidence": 0.5,
                "is_encrypted": False,
            }

        return {
            "protocol": "unknown",
            "confidence": 0.0,
            "is_encrypted": False,
        }

    def _check_tls_signature(self, payload: bytes) -> dict:
        """Check if payload is TLS/SSL encrypted."""
        if len(payload) < 3:
            return {"is_tls": False}

        # TLS record type (first byte)
        record_type = payload[0]
        if record_type not in [0x16, 0x17, 0x14, 0x15, 0x18]:
            return {"is_tls": False}

        # TLS version (bytes 1-2)
        tls_version_value = (payload[1] << 8) | payload[2]

        tls_versions = {
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3",
        }

        if tls_version_value in tls_versions:
            return {
                "is_tls": True,
                "version": tls_versions[tls_version_value],
                "record_type": record_type,
            }

        return {"is_tls": False}

    def _check_mysql(self, payload: bytes, port: int, direction: str) -> float:
        """Check if payload is MySQL protocol."""
        confidence = 0.0

        # Port match
        if port == 3306:
            confidence += 0.4

        # MySQL packet format: [3 bytes length][1 byte sequence][data]
        if len(payload) < 5:
            return 0.0

        try:
            pkt_len = payload[0] | (payload[1] << 8) | (payload[2] << 16)
            seq_num = payload[3]

            # Reasonable packet length (must match or be within packet size)
            if pkt_len > 0 and pkt_len <= len(payload) - 4 and pkt_len < 16777215:
                confidence += 0.1

            # Server handshake packet detection (strongest signal)
            if seq_num == 0 and len(payload) >= 10:
                protocol_version = payload[4]

                # MySQL protocol version 10
                if protocol_version == 0x0A:
                    confidence += 0.4

                    # Check for version string (e.g., "8.0.43", "5.7.32")
                    if len(payload) > 15:
                        # Look for null-terminated version string
                        version_end = payload.find(b'\x00', 5)
                        if 5 < version_end < 50:
                            version_str = payload[5:version_end]
                            # Check if it looks like a version string
                            if re.match(rb'\d+\.\d+\.\d+', version_str):
                                # This is a very strong indicator
                                return 0.95

            # COM_QUERY detection (client->server, command byte 0x03)
            elif direction == "client->server" and len(payload) > 5:
                if payload[4] == 0x03:  # COM_QUERY
                    # Check if rest looks like SQL
                    sql_bytes = payload[5:min(len(payload), 100)]
                    if self._looks_like_sql(sql_bytes):
                        confidence += 0.5

        except:
            pass

        return min(confidence, 1.0)

    def _check_postgresql(self, payload: bytes, port: int, direction: str) -> float:
        """Check if payload is PostgreSQL protocol."""
        confidence = 0.0

        # Port match
        if port == 5432:
            confidence += 0.3

        if len(payload) < 8:
            return 0.0

        try:
            # PostgreSQL startup message or SSLRequest
            if direction == "client->server":
                # Message length (first 4 bytes, big-endian)
                msg_len = struct.unpack('>I', payload[0:4])[0]

                if msg_len == len(payload) or msg_len == len(payload) + 4:
                    confidence += 0.2

                    # Protocol version number (bytes 4-7)
                    protocol_version = struct.unpack('>I', payload[4:8])[0]

                    # SSLRequest: 80877103 (decimal) = 0x04D2162F
                    if protocol_version == 80877103:
                        confidence += 0.5

                    # Startup message: version 3.0 = 196608 (0x00030000)
                    elif protocol_version == 196608:
                        confidence += 0.3

                        # Look for "user" parameter
                        if b'user\x00' in payload:
                            confidence += 0.2

            # Query message (client->server, type 'Q')
            elif len(payload) >= 5:
                msg_type = chr(payload[0]) if 32 <= payload[0] < 127 else None
                if msg_type == 'Q':
                    msg_len = struct.unpack('>I', payload[1:5])[0]
                    if 5 <= msg_len <= 10000:
                        # Check if query looks like SQL
                        query_bytes = payload[5:min(len(payload), 100)]
                        if self._looks_like_sql(query_bytes):
                            confidence += 0.5

        except:
            pass

        return min(confidence, 1.0)

    def _check_redis(self, payload: bytes, port: int, direction: str) -> float:
        """Check if payload is Redis RESP protocol."""
        confidence = 0.0

        # Port match
        if port == 6379:
            confidence += 0.3

        if len(payload) == 0:
            return 0.0

        try:
            first_char = chr(payload[0])

            # RESP protocol markers
            if first_char in ['*', '+', '-', ':', '$']:
                confidence += 0.3

                # Array (command): *<count>\r\n$<len>\r\n<data>\r\n...
                if first_char == '*' and b'\r\n' in payload:
                    confidence += 0.2

                    # Parse array count
                    parts = payload.split(b'\r\n', 1)
                    if len(parts) >= 2:
                        try:
                            count = int(parts[0][1:])
                            if 1 <= count <= 100:
                                confidence += 0.1

                                # Check for common Redis commands
                                if any(cmd in payload.upper() for cmd in [
                                    b'GET', b'SET', b'HGET', b'HSET',
                                    b'LPUSH', b'RPUSH', b'DEL', b'KEYS',
                                    b'AUTH', b'PING', b'SELECT'
                                ]):
                                    confidence += 0.2
                        except:
                            pass

                # Simple string response: +OK\r\n
                elif first_char == '+':
                    if payload.startswith(b'+OK\r\n') or payload.startswith(b'+PONG\r\n'):
                        confidence += 0.3

                # Error: -ERR
                elif first_char == '-' and payload.startswith(b'-ERR'):
                    confidence += 0.3

        except:
            pass

        return min(confidence, 1.0)

    def _check_mongodb(self, payload: bytes, port: int, direction: str) -> float:
        """Check if payload is MongoDB wire protocol."""
        confidence = 0.0

        # Port match
        if port == 27017:
            confidence += 0.3

        if len(payload) < 16:
            return 0.0

        try:
            # MongoDB message header: [length][requestID][responseTo][opCode]
            msg_len = struct.unpack('<i', payload[0:4])[0]
            request_id = struct.unpack('<i', payload[4:8])[0]
            response_to = struct.unpack('<i', payload[8:12])[0]
            op_code = struct.unpack('<i', payload[12:16])[0]

            # Reasonable message length
            if 16 <= msg_len <= 48000000:  # MongoDB max message size
                confidence += 0.2

            # Known opCodes
            known_opcodes = [1, 1000, 2001, 2002, 2004, 2005, 2006, 2007, 2010, 2013]
            if op_code in known_opcodes:
                confidence += 0.4

        except:
            pass

        return min(confidence, 1.0)

    def _check_http(self, payload: bytes, port: int) -> float:
        """Check if payload is HTTP protocol."""
        confidence = 0.0

        # Port match
        if port in [80, 8080, 8000, 8888, 9000]:
            confidence += 0.2

        if len(payload) < 10:
            return 0.0

        try:
            # Try to decode as ASCII
            text = payload[:200].decode('ascii', errors='ignore')

            # HTTP request line
            if re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) .+ HTTP/\d\.\d', text):
                confidence += 0.7

            # HTTP response line
            elif re.match(r'^HTTP/\d\.\d \d{3}', text):
                confidence += 0.7

            # HTTP headers
            if any(header in text for header in ['Content-Length:', 'Content-Type:', 'User-Agent:', 'Host:']):
                confidence += 0.1

        except:
            pass

        return min(confidence, 1.0)

    def _looks_like_sql(self, data: bytes) -> bool:
        """Check if data looks like SQL statement."""
        try:
            text = data.decode('utf-8', errors='ignore').upper()

            # SQL keywords
            sql_keywords = [
                'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP',
                'ALTER', 'FROM', 'WHERE', 'JOIN', 'TABLE', 'DATABASE',
                'SHOW', 'SET', 'USE', 'GRANT', 'REVOKE'
            ]

            keyword_count = sum(1 for kw in sql_keywords if kw in text)
            return keyword_count >= 1

        except:
            return False

    def _is_readable_text(self, payload: bytes, threshold: float = 0.7) -> bool:
        """Check if payload is readable text."""
        if len(payload) == 0:
            return False

        # Check first 200 bytes
        sample = payload[:200]

        printable_count = sum(
            1 for b in sample
            if 32 <= b < 127 or b in [9, 10, 13]  # ASCII printable + tab/lf/cr
        )

        ratio = printable_count / len(sample)
        return ratio >= threshold
