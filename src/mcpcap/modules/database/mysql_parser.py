"""MySQL protocol parser."""

import struct
from typing import Optional


class MySQLParser:
    """Parser for MySQL protocol packets."""

    # MySQL command types
    COM_SLEEP = 0x00
    COM_QUIT = 0x01
    COM_INIT_DB = 0x02
    COM_QUERY = 0x03
    COM_FIELD_LIST = 0x04
    COM_CREATE_DB = 0x05
    COM_DROP_DB = 0x06
    COM_REFRESH = 0x07
    COM_SHUTDOWN = 0x08
    COM_STATISTICS = 0x09
    COM_PROCESS_INFO = 0x0A
    COM_CONNECT = 0x0B
    COM_PROCESS_KILL = 0x0C
    COM_DEBUG = 0x0D
    COM_PING = 0x0E
    COM_TIME = 0x0F
    COM_DELAYED_INSERT = 0x10
    COM_CHANGE_USER = 0x11
    COM_STMT_PREPARE = 0x16
    COM_STMT_EXECUTE = 0x17
    COM_STMT_CLOSE = 0x19

    def parse_packet(self, payload: bytes, context: dict) -> Optional[dict]:
        """
        Parse MySQL protocol packet.

        Args:
            payload: Raw packet payload
            context: Parsing context (direction, connection state, etc.)

        Returns:
            Parsed packet information or None
        """
        if len(payload) < 4:
            return None

        try:
            # MySQL packet header: [3 bytes length][1 byte sequence]
            pkt_len = payload[0] | (payload[1] << 8) | (payload[2] << 16)
            seq_num = payload[3]

            # Check if we have the complete packet
            if len(payload) < 4 + pkt_len:
                return {"type": "incomplete", "expected_length": 4 + pkt_len}

            # Extract packet data
            data = payload[4:4+pkt_len]

            if len(data) == 0:
                return None

            direction = context.get("direction", "unknown")

            # Server handshake (sequence 0, from server)
            if seq_num == 0 and direction == "server->client":
                return self._parse_server_handshake(data)

            # Client authentication response (sequence 1)
            elif seq_num == 1 and direction == "client->server":
                return self._parse_client_auth(data)

            # Command packet (from client)
            elif direction == "client->server" and len(data) > 0:
                return self._parse_command_packet(data)

            # Response packet (from server)
            elif direction == "server->client" and len(data) > 0:
                return self._parse_response_packet(data)

            return {"type": "unknown", "sequence": seq_num, "length": pkt_len}

        except Exception as e:
            return {"type": "parse_error", "error": str(e)}

    def _parse_server_handshake(self, data: bytes) -> dict:
        """Parse MySQL server handshake packet."""
        if len(data) < 10:
            return {"type": "invalid_handshake"}

        try:
            protocol_version = data[0]

            # Extract server version string (null-terminated)
            version_end = data.find(b'\x00', 1)
            if version_end == -1:
                return {"type": "invalid_handshake"}

            server_version = data[1:version_end].decode('utf-8', errors='ignore')

            # Extract connection ID (4 bytes after version)
            offset = version_end + 1
            if len(data) < offset + 4:
                return {"type": "invalid_handshake"}

            connection_id = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            # Auth plugin data part 1 (8 bytes)
            if len(data) < offset + 8:
                return {"type": "invalid_handshake"}

            auth_plugin_data_part1 = data[offset:offset+8]
            offset += 8

            # Filler (1 byte, should be 0x00)
            offset += 1

            # Capability flags lower 2 bytes
            if len(data) < offset + 2:
                return {"type": "server_handshake", "version": server_version}

            cap_flags_lower = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            # Parse capability flags
            capabilities = []
            if cap_flags_lower & 0x0001:
                capabilities.append("long_password")
            if cap_flags_lower & 0x0002:
                capabilities.append("found_rows")
            if cap_flags_lower & 0x0004:
                capabilities.append("long_flag")
            if cap_flags_lower & 0x0008:
                capabilities.append("connect_with_db")
            if cap_flags_lower & 0x0800:
                capabilities.append("ssl")
            if cap_flags_lower & 0x8000:
                capabilities.append("secure_connection")

            result = {
                "type": "server_handshake",
                "protocol_version": protocol_version,
                "server_version": server_version,
                "connection_id": connection_id,
                "capabilities": capabilities,
                "supports_ssl": bool(cap_flags_lower & 0x0800),
            }

            # Extract auth plugin name if available
            if len(data) > offset + 20:
                # Skip charset, status flags, capability flags upper
                offset += 1 + 2 + 2 + 1 + 10

                # Auth plugin data part 2 (if available)
                if len(data) > offset + 12:
                    auth_plugin_data_part2 = data[offset:offset+12]
                    offset += 13  # 12 bytes + null terminator

                    # Auth plugin name (null-terminated)
                    if len(data) > offset:
                        plugin_end = data.find(b'\x00', offset)
                        if plugin_end != -1:
                            auth_plugin = data[offset:plugin_end].decode('utf-8', errors='ignore')
                            result["auth_plugin"] = auth_plugin

            return result

        except Exception as e:
            return {"type": "handshake_parse_error", "error": str(e)}

    def _parse_client_auth(self, data: bytes) -> dict:
        """Parse client authentication response."""
        if len(data) < 32:
            return {"type": "invalid_auth"}

        try:
            # Client capability flags (4 bytes)
            cap_flags = struct.unpack('<I', data[0:4])[0]

            # Max packet size (4 bytes)
            max_packet_size = struct.unpack('<I', data[4:8])[0]

            # Character set (1 byte)
            charset = data[8]

            # Skip reserved bytes (23 bytes)
            offset = 32

            # Extract username (null-terminated)
            username_end = data.find(b'\x00', offset)
            if username_end == -1:
                return {"type": "invalid_auth"}

            username = data[offset:username_end].decode('utf-8', errors='ignore')
            offset = username_end + 1

            result = {
                "type": "client_auth",
                "username": username,
                "charset": charset,
                "max_packet_size": max_packet_size,
                "requested_ssl": bool(cap_flags & 0x0800),
            }

            # Try to extract database name if CLIENT_CONNECT_WITH_DB flag is set
            if cap_flags & 0x0008 and len(data) > offset:
                # Skip auth response
                auth_response_len = data[offset] if offset < len(data) else 0
                offset += 1 + auth_response_len

                # Database name (null-terminated)
                if offset < len(data):
                    db_end = data.find(b'\x00', offset)
                    if db_end != -1:
                        database = data[offset:db_end].decode('utf-8', errors='ignore')
                        result["database"] = database

            return result

        except Exception as e:
            return {"type": "auth_parse_error", "error": str(e)}

    def _parse_command_packet(self, data: bytes) -> dict:
        """Parse MySQL command packet from client."""
        if len(data) == 0:
            return None

        command_type = data[0]

        # COM_QUERY - SQL query
        if command_type == self.COM_QUERY:
            query = data[1:].decode('utf-8', errors='ignore')
            return {
                "type": "query",
                "command": "COM_QUERY",
                "sql": query,
                "query_type": self._identify_query_type(query),
            }

        # COM_INIT_DB - Change database
        elif command_type == self.COM_INIT_DB:
            database = data[1:].decode('utf-8', errors='ignore')
            return {
                "type": "command",
                "command": "COM_INIT_DB",
                "database": database,
            }

        # COM_QUIT - Close connection
        elif command_type == self.COM_QUIT:
            return {
                "type": "command",
                "command": "COM_QUIT",
            }

        # COM_PING - Keepalive
        elif command_type == self.COM_PING:
            return {
                "type": "command",
                "command": "COM_PING",
            }

        # COM_STMT_PREPARE - Prepared statement
        elif command_type == self.COM_STMT_PREPARE:
            query = data[1:].decode('utf-8', errors='ignore')
            return {
                "type": "command",
                "command": "COM_STMT_PREPARE",
                "sql": query,
                "query_type": self._identify_query_type(query),
            }

        # Other commands
        else:
            command_names = {
                self.COM_SLEEP: "COM_SLEEP",
                self.COM_FIELD_LIST: "COM_FIELD_LIST",
                self.COM_CREATE_DB: "COM_CREATE_DB",
                self.COM_DROP_DB: "COM_DROP_DB",
                self.COM_REFRESH: "COM_REFRESH",
                self.COM_SHUTDOWN: "COM_SHUTDOWN",
                self.COM_STATISTICS: "COM_STATISTICS",
                self.COM_PROCESS_INFO: "COM_PROCESS_INFO",
                self.COM_CONNECT: "COM_CONNECT",
                self.COM_PROCESS_KILL: "COM_PROCESS_KILL",
                self.COM_DEBUG: "COM_DEBUG",
                self.COM_TIME: "COM_TIME",
                self.COM_CHANGE_USER: "COM_CHANGE_USER",
                self.COM_STMT_EXECUTE: "COM_STMT_EXECUTE",
                self.COM_STMT_CLOSE: "COM_STMT_CLOSE",
            }

            return {
                "type": "command",
                "command": command_names.get(command_type, f"UNKNOWN_0x{command_type:02x}"),
            }

    def _parse_response_packet(self, data: bytes) -> dict:
        """Parse MySQL response packet from server."""
        if len(data) == 0:
            return None

        first_byte = data[0]

        # OK packet (0x00)
        if first_byte == 0x00 and len(data) > 1:
            return self._parse_ok_packet(data)

        # ERR packet (0xFF)
        elif first_byte == 0xFF:
            return self._parse_err_packet(data)

        # EOF packet (0xFE) - deprecated in newer versions
        elif first_byte == 0xFE and len(data) < 9:
            return {
                "type": "response",
                "status": "eof",
            }

        # ResultSet - field count
        else:
            # First byte is field count (1-250)
            if 1 <= first_byte <= 250:
                return {
                    "type": "response",
                    "status": "resultset",
                    "field_count": first_byte,
                }

        return {"type": "unknown_response", "first_byte": f"0x{first_byte:02x}"}

    def _parse_ok_packet(self, data: bytes) -> dict:
        """Parse OK packet."""
        try:
            offset = 1  # Skip 0x00

            # Affected rows (length-encoded integer)
            affected_rows, offset = self._read_length_encoded_int(data, offset)

            # Last insert ID (length-encoded integer)
            last_insert_id, offset = self._read_length_encoded_int(data, offset)

            # Status flags (2 bytes)
            status_flags = 0
            if len(data) >= offset + 2:
                status_flags = struct.unpack('<H', data[offset:offset+2])[0]
                offset += 2

            # Warnings (2 bytes)
            warnings = 0
            if len(data) >= offset + 2:
                warnings = struct.unpack('<H', data[offset:offset+2])[0]

            return {
                "type": "response",
                "status": "ok",
                "affected_rows": affected_rows,
                "last_insert_id": last_insert_id,
                "warnings": warnings,
            }

        except Exception as e:
            return {"type": "ok", "parse_error": str(e)}

    def _parse_err_packet(self, data: bytes) -> dict:
        """Parse ERR packet."""
        try:
            offset = 1  # Skip 0xFF

            # Error code (2 bytes)
            if len(data) < offset + 2:
                return {"type": "response", "status": "error"}

            error_code = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            # SQL state marker (1 byte '#')
            sql_state = None
            if len(data) > offset and data[offset] == ord('#'):
                offset += 1
                # SQL state (5 bytes)
                if len(data) >= offset + 5:
                    sql_state = data[offset:offset+5].decode('utf-8', errors='ignore')
                    offset += 5

            # Error message (rest of packet)
            error_message = ""
            if len(data) > offset:
                error_message = data[offset:].decode('utf-8', errors='ignore')

            return {
                "type": "response",
                "status": "error",
                "error_code": error_code,
                "sql_state": sql_state,
                "error": error_message,
            }

        except Exception as e:
            return {"type": "error", "parse_error": str(e)}

    def _read_length_encoded_int(self, data: bytes, offset: int) -> tuple[int, int]:
        """Read MySQL length-encoded integer."""
        if offset >= len(data):
            return 0, offset

        first_byte = data[offset]

        if first_byte < 0xFB:
            return first_byte, offset + 1
        elif first_byte == 0xFC:
            value = struct.unpack('<H', data[offset+1:offset+3])[0]
            return value, offset + 3
        elif first_byte == 0xFD:
            value = struct.unpack('<I', data[offset+1:offset+4] + b'\x00')[0]
            return value, offset + 4
        elif first_byte == 0xFE:
            value = struct.unpack('<Q', data[offset+1:offset+9])[0]
            return value, offset + 9
        else:
            return 0, offset + 1

    def _identify_query_type(self, query: str) -> str:
        """Identify SQL query type."""
        query_upper = query.strip().upper()

        query_types = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'REPLACE',
            'CREATE', 'DROP', 'ALTER', 'TRUNCATE',
            'SHOW', 'DESCRIBE', 'EXPLAIN',
            'SET', 'USE',
            'GRANT', 'REVOKE',
            'BEGIN', 'COMMIT', 'ROLLBACK',
            'CALL',
        ]

        for qtype in query_types:
            if query_upper.startswith(qtype):
                return qtype

        return 'OTHER'
