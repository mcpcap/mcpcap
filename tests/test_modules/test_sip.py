"""Tests for the SIP analysis module."""

import os
import tempfile

from scapy.all import IP, TCP, UDP, Raw, wrpcap

from mcpcap.core.config import Config
from mcpcap.modules.sip import SIPModule


def _build_sip_request(call_id: str = "call-1234") -> str:
    """Build a SIP INVITE request payload."""
    return (
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.0.2.10:5060;rport;branch=z9hG4bK-1234\r\n"
        "From: Alice <sip:alice@example.com>;tag=111\r\n"
        "To: Bob <sip:bob@example.com>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:alice@192.0.2.10:5060>\r\n"
        "User-Agent: TestPhone/1.0\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "test"
    )


def _build_sip_response(call_id: str = "call-1234") -> str:
    """Build a SIP 200 OK response payload."""
    return (
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-1234\r\n"
        "From: Alice <sip:alice@example.com>;tag=111\r\n"
        "To: Bob <sip:bob@example.com>;tag=222\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Server: TestPBX/2.0\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


class TestSIPModule:
    """Test SIP packet analysis."""

    def test_protocol_name(self):
        """Test SIP protocol name."""
        module = SIPModule(Config())
        assert module.protocol_name == "SIP"

    def test_analyze_sip_packets_missing_file(self):
        """Test handling of missing SIP PCAP file."""
        module = SIPModule(Config())
        result = module.analyze_sip_packets("/nonexistent/file.pcap")

        assert "error" in result
        assert result["pcap_file"] == "/nonexistent/file.pcap"

    def test_analyze_sip_packets_extracts_request_and_response(self):
        """Test SIP request and response parsing over UDP and TCP."""
        module = SIPModule(Config())
        packets = [
            IP(src="192.0.2.10", dst="198.51.100.20")
            / UDP(sport=5060, dport=5060)
            / Raw(load=_build_sip_request()),
            IP(src="198.51.100.20", dst="192.0.2.10")
            / TCP(sport=5060, dport=5060)
            / Raw(load=_build_sip_response()),
        ]

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_file:
            temp_path = tmp_file.name

        try:
            wrpcap(temp_path, packets)
            result = module._analyze_protocol_file(temp_path)
        finally:
            os.unlink(temp_path)

        assert result["sip_packets_found"] == 2
        assert result["sip_packets_analyzed"] == 2
        assert result["statistics"]["requests"] == 1
        assert result["statistics"]["responses"] == 1
        assert result["statistics"]["methods"] == {"INVITE": 1}
        assert result["statistics"]["response_classes"] == {"2xx": 1}
        assert result["statistics"]["transports"] == {"TCP": 1, "UDP": 1}
        assert result["statistics"]["user_agents"] == ["TestPhone/1.0"]
        assert result["statistics"]["unique_call_ids"] == 1

        request_packet = result["packets"][0]
        response_packet = result["packets"][1]

        assert request_packet["message_type"] == "request"
        assert request_packet["method"] == "INVITE"
        assert request_packet["request_uri"] == "sip:bob@example.com"
        assert request_packet["content_length"] == 4
        assert request_packet["body_length"] == 4
        assert request_packet["known_sip_port"] is True
        assert request_packet["call_id"] == "call-1234"

        assert response_packet["message_type"] == "response"
        assert response_packet["status_code"] == 200
        assert response_packet["reason_phrase"] == "OK"
        assert response_packet["server"] == "TestPBX/2.0"

    def test_analyze_sip_packets_no_matches(self):
        """Test SIP analysis when no SIP packets are present."""
        module = SIPModule(Config())
        packets = [
            IP(src="203.0.113.1", dst="203.0.113.2")
            / UDP(sport=9999, dport=9998)
            / Raw(load="not sip"),
        ]

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_file:
            temp_path = tmp_file.name

        try:
            wrpcap(temp_path, packets)
            result = module._analyze_protocol_file(temp_path)
        finally:
            os.unlink(temp_path)

        assert result["sip_packets_found"] == 0
        assert result["message"] == "No SIP packets found in this capture"

    def test_analyze_sip_packets_respects_max_packets(self):
        """Test SIP analysis honors max_packets configuration."""
        module = SIPModule(Config(max_packets=1))
        packets = [
            IP(src="192.0.2.10", dst="198.51.100.20")
            / UDP(sport=5060, dport=5060)
            / Raw(load=_build_sip_request("call-a")),
            IP(src="192.0.2.11", dst="198.51.100.21")
            / UDP(sport=5060, dport=5060)
            / Raw(load=_build_sip_request("call-b")),
        ]

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_file:
            temp_path = tmp_file.name

        try:
            wrpcap(temp_path, packets)
            result = module._analyze_protocol_file(temp_path)
        finally:
            os.unlink(temp_path)

        assert result["sip_packets_found"] == 2
        assert result["sip_packets_analyzed"] == 1
        assert "Analysis limited to first 1 SIP packets" in result["note"]
