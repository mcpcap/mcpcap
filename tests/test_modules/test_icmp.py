"""Tests for ICMP module."""

from unittest.mock import patch

from scapy.all import ICMP, IP, UDP, Ether, ICMPv6DestUnreach, IPv6, Raw, wrpcap

from mcpcap.core.config import Config
from mcpcap.modules.icmp import ICMPModule


class TestICMPModule:
    """Test ICMP module functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        config = Config(modules=["icmp"], max_packets=None)
        self.icmp_module = ICMPModule(config)

    def test_protocol_name(self):
        """Test protocol name property."""
        assert self.icmp_module.protocol_name == "ICMP"

    @patch("mcpcap.modules.icmp.rdpcap")
    def test_analyze_icmp_packets_no_packets(self, mock_rdpcap):
        """Test analysis with no ICMP packets."""
        # Mock empty packet capture
        mock_rdpcap.return_value = []

        with patch("os.path.exists", return_value=True):
            result = self.icmp_module.analyze_icmp_packets("test.pcap")

        assert result["icmp_packets_found"] == 0
        assert "No ICMP packets found" in result["message"]

    def test_generate_statistics_empty(self):
        """Test statistics generation with empty packet list."""
        stats = self.icmp_module._generate_statistics([])

        assert stats["unique_sources_count"] == 0
        assert stats["unique_destinations_count"] == 0
        assert stats["echo_sessions"] == 0

    def test_generate_statistics_with_packets(self):
        """Test statistics generation with sample packets."""
        packets = [
            {
                "icmp_type_name": "Echo Request",
                "icmp_type": 8,
                "icmp_id": 123,
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
            },
            {
                "icmp_type_name": "Echo Reply",
                "icmp_type": 0,
                "icmp_id": 123,
                "src_ip": "8.8.8.8",
                "dst_ip": "192.168.1.100",
            },
            {
                "icmp_type_name": "Destination Unreachable",
                "icmp_type": 3,
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.100",
                "original_dst_ip": "203.0.113.20",
            },
        ]

        stats = self.icmp_module._generate_statistics(packets)

        assert stats["icmp_type_counts"]["Echo Request"] == 1
        assert stats["icmp_type_counts"]["Echo Reply"] == 1
        assert stats["icmp_type_counts"]["Destination Unreachable"] == 1
        assert stats["unique_sources_count"] == 3  # 192.168.1.100, 8.8.8.8, 192.168.1.1
        assert stats["unique_destinations_count"] == 2  # 8.8.8.8, 192.168.1.100
        assert stats["echo_sessions"] == 1
        assert stats["echo_pairs"][123]["requests"] == 1
        assert stats["echo_pairs"][123]["replies"] == 1
        assert stats["unreachable_destinations"] == ["203.0.113.20"]

    def test_unreachable_capture_uses_quoted_destination(self, tmp_path):
        """The outer destination is the reporting recipient, not the failed host."""
        packets = [
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.10")
            / ICMP(type=3, code=3)
            / IP(src="192.0.2.10", dst="198.51.100.25")
            / UDP(sport=12345, dport=9999),
            Ether()
            / IPv6(src="2001:db8::1", dst="2001:db8::10")
            / ICMPv6DestUnreach(code=4)
            / IPv6(src="2001:db8::10", dst="2001:db8:1::25")
            / UDP(sport=12345, dport=9999),
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.10")
            / ICMP(type=3, code=1)
            / Raw(load=b"truncated"),
        ]
        capture = tmp_path / "unreachable.pcap"
        wrpcap(str(capture), packets)

        result = self.icmp_module.analyze_icmp_packets(str(capture))

        assert result["icmp_packets_found"] == 3
        ipv4, ipv6, truncated = result["packets"]
        assert ipv4["dst_ip"] == "192.0.2.10"
        assert ipv4["original_dst_ip"] == "198.51.100.25"
        assert ipv6["dst_ip"] == "2001:db8::10"
        assert ipv6["original_dst_ip"] == "2001:db8:1::25"
        assert "original_dst_ip" not in truncated
        assert set(result["statistics"]["unreachable_destinations"]) == {
            "198.51.100.25",
            "2001:db8:1::25",
        }
        assert result["statistics"]["unreachable_destinations_count"] == 2
