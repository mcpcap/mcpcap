"""Text extraction utility for extracting readable text from binary payloads."""

import re
from typing import Optional


class TextExtractor:
    """Extract readable text from binary payloads."""

    def extract_text(
        self,
        payload: bytes,
        min_length: int = 4,
        encoding: str = 'utf-8',
    ) -> list[dict]:
        """
        Extract all readable text fragments from payload.

        Args:
            payload: Binary payload data
            min_length: Minimum length of text fragment to extract
            encoding: Text encoding (default: utf-8)

        Returns:
            List of text fragments with metadata:
            [
                {
                    "offset": 10,
                    "length": 25,
                    "text": "SELECT * FROM users",
                    "encoding": "utf-8",
                    "is_sql": True,
                    "is_command": False
                }
            ]
        """
        texts = []
        current_text = bytearray()
        start_offset = 0

        for i, byte in enumerate(payload):
            # Check if byte is printable ASCII or whitespace
            if 32 <= byte < 127 or byte in [9, 10, 13]:  # tab, lf, cr
                if not current_text:
                    start_offset = i
                current_text.append(byte)
            else:
                # Non-printable character encountered
                if len(current_text) >= min_length:
                    text_str = current_text.decode(encoding, errors='ignore')
                    texts.append(self._analyze_text_fragment(
                        text_str,
                        start_offset,
                        len(current_text),
                        encoding
                    ))
                current_text = bytearray()

        # Handle last fragment
        if len(current_text) >= min_length:
            text_str = current_text.decode(encoding, errors='ignore')
            texts.append(self._analyze_text_fragment(
                text_str,
                start_offset,
                len(current_text),
                encoding
            ))

        return texts

    def _analyze_text_fragment(
        self,
        text: str,
        offset: int,
        length: int,
        encoding: str,
    ) -> dict:
        """Analyze a text fragment and add metadata."""
        return {
            "offset": offset,
            "length": length,
            "text": text,
            "encoding": encoding,
            "is_sql": self._looks_like_sql(text),
            "is_command": self._looks_like_command(text),
            "confidence": self._calculate_text_confidence(text),
        }

    def _looks_like_sql(self, text: str) -> bool:
        """Check if text looks like SQL statement."""
        # SQL keywords
        sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP',
            'ALTER', 'FROM', 'WHERE', 'JOIN', 'TABLE', 'DATABASE',
            'SHOW', 'SET', 'USE', 'GRANT', 'REVOKE', 'INDEX',
            'VIEW', 'TRIGGER', 'PROCEDURE', 'FUNCTION'
        ]

        text_upper = text.upper()

        # Count matching keywords
        keyword_count = sum(1 for kw in sql_keywords if kw in text_upper)

        # Check for SQL operators
        has_operators = any(op in text for op in ['=', '>', '<', 'AND', 'OR', '(', ')'])

        # SQL-like if has 2+ keywords or 1 keyword + operators
        return keyword_count >= 2 or (keyword_count >= 1 and has_operators)

    def _looks_like_command(self, text: str) -> bool:
        """Check if text looks like a command (Redis, MongoDB, etc.)."""
        # Redis commands
        redis_cmds = [
            'GET', 'SET', 'HGET', 'HSET', 'LPUSH', 'RPUSH', 'LPOP', 'RPOP',
            'SADD', 'SREM', 'ZADD', 'ZREM', 'DEL', 'EXISTS', 'KEYS',
            'SCAN', 'INCR', 'DECR', 'EXPIRE', 'TTL', 'PING', 'AUTH',
            'SELECT', 'FLUSHDB', 'FLUSHALL', 'INFO', 'CONFIG'
        ]

        # MongoDB commands
        mongo_cmds = [
            'find', 'insert', 'update', 'delete', 'aggregate', 'count',
            'distinct', 'findOne', 'findAndModify', 'createIndex',
            'dropIndex', 'createCollection', 'drop'
        ]

        text_upper = text.upper()

        # Check Redis commands
        if any(cmd in text_upper for cmd in redis_cmds):
            return True

        # Check MongoDB commands (case-sensitive)
        if any(cmd in text for cmd in mongo_cmds):
            return True

        return False

    def _calculate_text_confidence(self, text: str) -> float:
        """Calculate confidence that this is meaningful text."""
        if not text:
            return 0.0

        # Factors that increase confidence
        confidence = 0.5  # Base confidence

        # Has spaces (likely structured text)
        if ' ' in text:
            confidence += 0.1

        # Has punctuation
        if any(c in text for c in '.,;:!?'):
            confidence += 0.1

        # Has SQL keywords
        if self._looks_like_sql(text):
            confidence += 0.2

        # Has command patterns
        if self._looks_like_command(text):
            confidence += 0.2

        # Long text (more likely meaningful)
        if len(text) > 20:
            confidence += 0.1

        return min(confidence, 1.0)

    def extract_sql_statements(self, payload: bytes) -> list[str]:
        """
        Extract SQL statements specifically.

        Returns:
            List of SQL statement strings
        """
        texts = self.extract_text(payload)
        return [
            t["text"] for t in texts
            if t["is_sql"] and t["confidence"] >= 0.7
        ]

    def extract_commands(self, payload: bytes) -> list[str]:
        """
        Extract commands (Redis, MongoDB, etc.) specifically.

        Returns:
            List of command strings
        """
        texts = self.extract_text(payload)
        return [
            t["text"] for t in texts
            if t["is_command"] and t["confidence"] >= 0.7
        ]
