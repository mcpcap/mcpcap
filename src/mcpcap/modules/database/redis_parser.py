"""Redis protocol parser."""

from typing import Optional


class RedisParser:
    """Parser for Redis RESP (REdis Serialization Protocol) packets."""

    def parse_packet(self, payload: bytes, context: dict) -> Optional[dict]:
        """
        Parse Redis RESP protocol packet.

        RESP data types:
        - Simple Strings: +<string>\r\n
        - Errors: -<error>\r\n
        - Integers: :<number>\r\n
        - Bulk Strings: $<length>\r\n<data>\r\n
        - Arrays: *<count>\r\n<elements>

        Args:
            payload: Raw packet payload
            context: Parsing context

        Returns:
            Parsed packet information or None
        """
        if len(payload) == 0:
            return None

        try:
            first_char = chr(payload[0])

            # Array (typically commands)
            if first_char == '*':
                return self._parse_array(payload)

            # Simple String (typically responses like +OK)
            elif first_char == '+':
                return self._parse_simple_string(payload)

            # Error
            elif first_char == '-':
                return self._parse_error(payload)

            # Integer
            elif first_char == ':':
                return self._parse_integer(payload)

            # Bulk String
            elif first_char == '$':
                return self._parse_bulk_string(payload)

            return None

        except Exception as e:
            return {"type": "parse_error", "error": str(e)}

    def _parse_array(self, payload: bytes) -> dict:
        """Parse Redis array (command)."""
        try:
            lines = payload.split(b'\r\n')

            if len(lines) < 2:
                return {"type": "incomplete"}

            # Parse count
            count_str = lines[0][1:].decode('utf-8', errors='ignore')
            count = int(count_str)

            # Extract array elements
            elements = []
            line_idx = 1

            for _ in range(count):
                if line_idx >= len(lines):
                    break

                # Should be bulk string: $<length>
                if not lines[line_idx].startswith(b'$'):
                    break

                length_str = lines[line_idx][1:].decode('utf-8', errors='ignore')
                length = int(length_str)

                line_idx += 1

                # Get data
                if line_idx < len(lines):
                    data = lines[line_idx].decode('utf-8', errors='ignore')
                    elements.append(data)
                    line_idx += 1

            if len(elements) > 0:
                # First element is the command
                command = elements[0].upper()
                args = elements[1:] if len(elements) > 1 else []

                return {
                    "type": "command",
                    "command": command,
                    "args": args,
                    "full_command": " ".join(elements),
                    "arg_count": len(args),
                }

            return {"type": "array", "count": count}

        except Exception as e:
            return {"type": "array", "parse_error": str(e)}

    def _parse_simple_string(self, payload: bytes) -> dict:
        """Parse simple string response."""
        try:
            end = payload.find(b'\r\n')
            if end == -1:
                return {"type": "incomplete"}

            value = payload[1:end].decode('utf-8', errors='ignore')

            return {
                "type": "response",
                "status": "ok",
                "value": value,
            }

        except Exception as e:
            return {"type": "response", "parse_error": str(e)}

    def _parse_error(self, payload: bytes) -> dict:
        """Parse error response."""
        try:
            end = payload.find(b'\r\n')
            if end == -1:
                return {"type": "incomplete"}

            error_msg = payload[1:end].decode('utf-8', errors='ignore')

            # Extract error type and message
            parts = error_msg.split(' ', 1)
            error_type = parts[0] if parts else "ERR"
            error_detail = parts[1] if len(parts) > 1 else error_msg

            return {
                "type": "response",
                "status": "error",
                "error_type": error_type,
                "error": error_detail,
            }

        except Exception as e:
            return {"type": "response", "status": "error", "parse_error": str(e)}

    def _parse_integer(self, payload: bytes) -> dict:
        """Parse integer response."""
        try:
            end = payload.find(b'\r\n')
            if end == -1:
                return {"type": "incomplete"}

            value_str = payload[1:end].decode('utf-8', errors='ignore')
            value = int(value_str)

            return {
                "type": "response",
                "status": "ok",
                "value": value,
                "value_type": "integer",
            }

        except Exception as e:
            return {"type": "response", "parse_error": str(e)}

    def _parse_bulk_string(self, payload: bytes) -> dict:
        """Parse bulk string."""
        try:
            lines = payload.split(b'\r\n', 2)

            if len(lines) < 2:
                return {"type": "incomplete"}

            # Parse length
            length_str = lines[0][1:].decode('utf-8', errors='ignore')
            length = int(length_str)

            # Null bulk string
            if length == -1:
                return {
                    "type": "response",
                    "status": "ok",
                    "value": None,
                }

            # Get data
            if len(lines) >= 2:
                data = lines[1][:length].decode('utf-8', errors='ignore')

                return {
                    "type": "response",
                    "status": "ok",
                    "value": data,
                    "value_type": "bulk_string",
                }

            return {"type": "incomplete"}

        except Exception as e:
            return {"type": "response", "parse_error": str(e)}
