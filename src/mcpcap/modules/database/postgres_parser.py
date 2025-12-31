"""PostgreSQL protocol parser."""

import struct
from typing import Optional


class PostgresParser:
    """Parser for PostgreSQL protocol packets."""

    def parse_packet(self, payload: bytes, context: dict) -> Optional[dict]:
        """
        Parse PostgreSQL protocol packet.

        PostgreSQL message format:
        - Startup/SSLRequest: [4 bytes length][4 bytes version][parameters...]
        - Regular message: [1 byte type][4 bytes length][message body]

        Args:
            payload: Raw packet payload
            context: Parsing context (direction, etc.)

        Returns:
            Parsed packet information or None
        """
        if len(payload) < 5:
            return None

        try:
            direction = context.get("direction", "unknown")

            # Check if this is a startup message (no type byte, starts with length)
            if direction == "client->server":
                # Try parsing as startup message first
                msg_len = struct.unpack('>I', payload[0:4])[0]

                # If length matches or is close, might be startup
                if abs(msg_len - len(payload)) <= 4:
                    protocol_version = struct.unpack('>I', payload[4:8])[0]

                    # SSLRequest: 80877103
                    if protocol_version == 80877103:
                        return {
                            "type": "ssl_request",
                            "length": msg_len,
                        }

                    # Startup message: version 3.0 = 196608
                    elif protocol_version == 196608:
                        return self._parse_startup_message(payload)

            # Regular message with type byte
            msg_type = chr(payload[0]) if 32 <= payload[0] < 127 else None

            if msg_type:
                msg_len = struct.unpack('>I', payload[1:5])[0]
                msg_body = payload[5:5+msg_len-4] if len(payload) >= 5+msg_len-4 else b''

                # Query message (client->server)
                if msg_type == 'Q':
                    return self._parse_query_message(msg_body)

                # Parse message (client->server, prepared statement)
                elif msg_type == 'P':
                    return self._parse_prepare_message(msg_body)

                # Execute message (client->server)
                elif msg_type == 'E':
                    return {"type": "command", "command": "Execute"}

                # Row Description (server->client)
                elif msg_type == 'T':
                    return {"type": "response", "status": "row_description"}

                # Data Row (server->client)
                elif msg_type == 'D':
                    return {"type": "response", "status": "data_row"}

                # Command Complete (server->client)
                elif msg_type == 'C':
                    return self._parse_command_complete(msg_body)

                # Error Response (server->client)
                elif msg_type == 'E':
                    return self._parse_error_response(msg_body)

                # Ready For Query (server->client)
                elif msg_type == 'Z':
                    return {"type": "response", "status": "ready_for_query"}

                # Authentication messages (server->client)
                elif msg_type == 'R':
                    return self._parse_auth_response(msg_body)

                # Other messages
                else:
                    return {
                        "type": "message",
                        "message_type": msg_type,
                        "length": msg_len,
                    }

            return None

        except Exception as e:
            return {"type": "parse_error", "error": str(e)}

    def _parse_startup_message(self, payload: bytes) -> dict:
        """Parse PostgreSQL startup message."""
        try:
            msg_len = struct.unpack('>I', payload[0:4])[0]
            protocol_version = struct.unpack('>I', payload[4:8])[0]

            # Parse parameters (null-terminated key-value pairs)
            offset = 8
            parameters = {}

            while offset < len(payload) - 1:
                # Find null terminator for key
                key_end = payload.find(b'\x00', offset)
                if key_end == -1:
                    break

                key = payload[offset:key_end].decode('utf-8', errors='ignore')
                offset = key_end + 1

                # Find null terminator for value
                value_end = payload.find(b'\x00', offset)
                if value_end == -1:
                    break

                value = payload[offset:value_end].decode('utf-8', errors='ignore')
                offset = value_end + 1

                if key:
                    parameters[key] = value

            return {
                "type": "startup",
                "protocol_version": f"{protocol_version >> 16}.{protocol_version & 0xFFFF}",
                "user": parameters.get("user"),
                "database": parameters.get("database"),
                "parameters": parameters,
            }

        except Exception as e:
            return {"type": "startup", "parse_error": str(e)}

    def _parse_query_message(self, msg_body: bytes) -> dict:
        """Parse Simple Query message."""
        try:
            # Query is null-terminated string
            query = msg_body.rstrip(b'\x00').decode('utf-8', errors='ignore')

            return {
                "type": "query",
                "protocol": "simple",
                "sql": query,
                "query_type": self._identify_query_type(query),
            }

        except Exception as e:
            return {"type": "query", "parse_error": str(e)}

    def _parse_prepare_message(self, msg_body: bytes) -> dict:
        """Parse Parse message (prepared statement)."""
        try:
            # Statement name (null-terminated)
            name_end = msg_body.find(b'\x00')
            if name_end == -1:
                return {"type": "command", "command": "Parse"}

            stmt_name = msg_body[:name_end].decode('utf-8', errors='ignore')
            offset = name_end + 1

            # Query string (null-terminated)
            query_end = msg_body.find(b'\x00', offset)
            if query_end == -1:
                return {"type": "command", "command": "Parse", "statement": stmt_name}

            query = msg_body[offset:query_end].decode('utf-8', errors='ignore')

            return {
                "type": "query",
                "protocol": "prepared",
                "statement": stmt_name,
                "sql": query,
                "query_type": self._identify_query_type(query),
            }

        except Exception as e:
            return {"type": "command", "command": "Parse", "parse_error": str(e)}

    def _parse_command_complete(self, msg_body: bytes) -> dict:
        """Parse Command Complete message."""
        try:
            # Command tag (null-terminated string)
            tag = msg_body.rstrip(b'\x00').decode('utf-8', errors='ignore')

            # Extract affected rows if present
            parts = tag.split()
            affected_rows = None

            if len(parts) >= 2 and parts[-1].isdigit():
                affected_rows = int(parts[-1])

            return {
                "type": "response",
                "status": "complete",
                "command_tag": tag,
                "affected_rows": affected_rows,
            }

        except Exception as e:
            return {"type": "response", "status": "complete", "parse_error": str(e)}

    def _parse_error_response(self, msg_body: bytes) -> dict:
        """Parse Error Response message."""
        try:
            # Error fields (type byte + string + null terminator)
            fields = {}
            offset = 0

            while offset < len(msg_body):
                field_type = chr(msg_body[offset]) if msg_body[offset] != 0 else None
                if not field_type:
                    break

                offset += 1

                # Find null terminator
                value_end = msg_body.find(b'\x00', offset)
                if value_end == -1:
                    break

                value = msg_body[offset:value_end].decode('utf-8', errors='ignore')
                offset = value_end + 1

                fields[field_type] = value

            return {
                "type": "response",
                "status": "error",
                "severity": fields.get('S'),
                "code": fields.get('C'),
                "error": fields.get('M'),
                "detail": fields.get('D'),
                "hint": fields.get('H'),
            }

        except Exception as e:
            return {"type": "response", "status": "error", "parse_error": str(e)}

    def _parse_auth_response(self, msg_body: bytes) -> dict:
        """Parse Authentication response."""
        try:
            if len(msg_body) < 4:
                return {"type": "response", "status": "auth"}

            auth_type = struct.unpack('>I', msg_body[0:4])[0]

            auth_types = {
                0: "AuthenticationOk",
                2: "AuthenticationKerberosV5",
                3: "AuthenticationCleartextPassword",
                5: "AuthenticationMD5Password",
                6: "AuthenticationSCMCredential",
                7: "AuthenticationGSS",
                8: "AuthenticationGSSContinue",
                9: "AuthenticationSSPI",
                10: "AuthenticationSASL",
                11: "AuthenticationSASLContinue",
                12: "AuthenticationSASLFinal",
            }

            return {
                "type": "response",
                "status": "auth",
                "auth_type": auth_types.get(auth_type, f"Unknown_{auth_type}"),
                "success": auth_type == 0,
            }

        except Exception as e:
            return {"type": "response", "status": "auth", "parse_error": str(e)}

    def _identify_query_type(self, query: str) -> str:
        """Identify SQL query type."""
        query_upper = query.strip().upper()

        query_types = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE',
            'CREATE', 'DROP', 'ALTER', 'TRUNCATE',
            'COPY', 'VACUUM', 'ANALYZE',
            'BEGIN', 'COMMIT', 'ROLLBACK',
            'GRANT', 'REVOKE',
            'EXPLAIN', 'WITH',
        ]

        for qtype in query_types:
            if query_upper.startswith(qtype):
                return qtype

        return 'OTHER'
