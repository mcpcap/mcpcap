"""Tests for TCP module."""

import os
import tempfile

from scapy.all import IP, TCP, Raw, wrpcap

from mcpcap.core.config import Config
from mcpcap.modules.tcp import TCPModule


class TestTCPModule:
    """Test TCP module functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        config = Config(modules=["tcp"], max_packets=None)
        self.tcp_module = TCPModule(config)

    def _write_packets(self, packets) -> str:
        """Write packets to a temporary PCAP file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            wrpcap(tmp_file.name, packets)
            return tmp_file.name

    def test_analyze_tcp_connections_merges_bidirectional_flow(self):
        """A TCP handshake should be treated as one connection, not two."""
        client_ip = "10.0.0.10"
        server_ip = "10.0.0.20"
        client_port = 43210
        server_port = 443

        packets = [
            IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="S", seq=1000),
            IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001),
            IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001),
        ]

        temp_path = self._write_packets(packets)

        try:
            result = self.tcp_module.analyze_tcp_connections(temp_path, detailed=True)

            assert result["summary"]["total_connections"] == 1
            assert result["summary"]["successful_handshakes"] == 1
            assert result["summary"]["failed_handshakes"] == 0
            assert len(result["connections"]) == 1

            connection = result["connections"][0]
            assert connection["client"] == f"{client_ip}:{client_port}"
            assert connection["server"] == f"{server_ip}:{server_port}"
            assert connection["handshake_completed"] is True
            assert connection["syn_count"] == 2
            assert connection["syn_ack_count"] == 1
        finally:
            os.unlink(temp_path)

    def test_analyze_tcp_connections_tracks_retransmissions_per_direction(self):
        """Matching sequence numbers in opposite directions are not retransmissions."""
        client_ip = "192.0.2.10"
        server_ip = "192.0.2.20"
        client_port = 40000
        server_port = 80

        packets = [
            IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="S", seq=1000),
            IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, flags="SA", seq=5000, ack=1001),
            IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=5001),
            IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="PA", seq=7000, ack=5001)
            / Raw(load=b"GET / HTTP/1.1\r\n\r\n"),
            IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, flags="PA", seq=7000, ack=7019)
            / Raw(load=b"HTTP/1.1 200 OK\r\n\r\n"),
        ]

        temp_path = self._write_packets(packets)

        try:
            result = self.tcp_module.analyze_tcp_connections(temp_path, detailed=True)

            assert result["summary"]["total_connections"] == 1
            assert result["connections"][0]["retransmissions"] == 0
            assert "retransmissions detected" not in " ".join(result["issues"])
        finally:
            os.unlink(temp_path)
