"""Tests for DHCP module."""

import tempfile
from unittest.mock import Mock, patch

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, wrpcap

from mcpcap.core.config import Config
from mcpcap.modules.dhcp import DHCPModule


class TestDHCPModule:
    """Test DHCP analysis module."""

    def test_protocol_name(self):
        """Test that protocol name is correct."""
        config = Mock()
        module = DHCPModule(config)
        assert module.protocol_name == "DHCP"

    def test_analyze_dhcp_packets_file_not_found(self):
        """Test analyzing DHCP packets when file doesn't exist."""
        config = Config()
        module = DHCPModule(config)

        result = module.analyze_dhcp_packets("/nonexistent/file.pcap")

        assert "error" in result
        assert "not found" in result["error"]
        assert result["pcap_file"] == "/nonexistent/file.pcap"

    def test_analyze_dhcp_packets_success(self):
        """Test successful DHCP packet analysis."""
        # Create test DHCP packets
        discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(
                op=1,
                xid=0x12345678,
                chaddr=b"\x00\x11\x22\x33\x44\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )
            / DHCP(
                options=[
                    ("message-type", 1),
                    ("client_id", b"\x01\x00\x11\x22\x33\x44\x55"),
                    "end",
                ]
            )
        )

        offer = (
            Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")
            / IP(src="192.168.1.1", dst="192.168.1.100")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                xid=0x12345678,
                yiaddr="192.168.1.100",
                siaddr="192.168.1.1",
                chaddr=b"\x00\x11\x22\x33\x44\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )
            / DHCP(
                options=[
                    ("message-type", 2),
                    ("server_id", "192.168.1.1"),
                    ("lease_time", 3600),
                    ("subnet_mask", "255.255.255.0"),
                    "end",
                ]
            )
        )

        # Create temporary PCAP file
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_file:
            wrpcap(tmp_file.name, [discover, offer])
            temp_path = tmp_file.name

        try:
            config = Config()
            module = DHCPModule(config)

            result = module._analyze_protocol_file(temp_path)

            # Verify basic structure
            assert "file" in result
            assert "total_packets" in result
            assert "dhcp_packets_found" in result
            assert "packets" in result
            assert "statistics" in result

            # Verify packet counts
            assert result["total_packets"] == 2
            assert result["dhcp_packets_found"] == 2
            assert result["dhcp_packets_analyzed"] == 2

            # Verify packet analysis
            packets = result["packets"]
            assert len(packets) == 2

            # Check DISCOVER packet
            discover_pkt = packets[0]
            assert discover_pkt["message_type"] == "DISCOVER"
            assert discover_pkt["op"] == "Request"
            assert discover_pkt["client_mac"] == "00:11:22:33:44:55"
            assert discover_pkt["transaction_id"] == "0x12345678"

            # Check OFFER packet
            offer_pkt = packets[1]
            assert offer_pkt["message_type"] == "OFFER"
            assert offer_pkt["op"] == "Reply"
            assert offer_pkt["your_ip"] == "192.168.1.100"
            assert offer_pkt["server_id"] == "192.168.1.1"

            # Verify statistics
            stats = result["statistics"]
            assert stats["unique_clients_count"] == 1
            assert stats["unique_servers_count"] == 1
            assert stats["message_type_counts"]["DISCOVER"] == 1
            assert stats["message_type_counts"]["OFFER"] == 1
            assert stats["transaction_count"] == 1

        finally:
            import os

            os.unlink(temp_path)

    def test_analyze_packets_no_dhcp(self):
        """Test analysis when no DHCP packets are found."""
        # Create non-DHCP packet
        packet = (
            Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")
            / IP(src="192.168.1.1", dst="192.168.1.2")
            / UDP(sport=1234, dport=5678)
            / b"non-dhcp-data"
        )

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_file:
            wrpcap(tmp_file.name, [packet])
            temp_path = tmp_file.name

        try:
            config = Config()
            module = DHCPModule(config)

            result = module._analyze_protocol_file(temp_path)

            assert result["total_packets"] == 1
            assert result["dhcp_packets_found"] == 0
            assert "No DHCP packets found" in result["message"]

        finally:
            import os

            os.unlink(temp_path)

    def test_max_packets_limit(self):
        """Test that max_packets limit is respected."""
        # Create 3 DHCP packets
        packets = []
        for i in range(3):
            packet = (
                Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
                / IP(src="0.0.0.0", dst="255.255.255.255")
                / UDP(sport=68, dport=67)
                / BOOTP(
                    op=1,
                    xid=i,
                    chaddr=b"\x00\x11\x22\x33\x44\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                )
                / DHCP(options=[("message-type", 1), "end"])
            )
            packets.append(packet)

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_file:
            wrpcap(tmp_file.name, packets)
            temp_path = tmp_file.name

        try:
            config = Config(max_packets=2)
            module = DHCPModule(config)

            result = module._analyze_protocol_file(temp_path)

            assert result["dhcp_packets_found"] == 3  # Total found
            assert result["dhcp_packets_analyzed"] == 2  # Limited to 2
            assert len(result["packets"]) == 2
            assert "note" in result
            assert "limited to first 2" in result["note"]

        finally:
            import os

            os.unlink(temp_path)

    def test_parse_dhcp_options(self):
        """Test DHCP options parsing."""
        config = Mock()
        module = DHCPModule(config)

        # Test various DHCP options
        options = [
            ("message-type", 1),  # DISCOVER
            ("lease_time", 7200),
            ("server_id", "10.0.0.1"),
            ("subnet_mask", "255.255.255.0"),
            ("client_id", b"\x01\x00\x11\x22\x33\x44\x55"),
            ("requested_addr", "10.0.0.100"),
            ("param_req_list", [1, 3, 6, 15]),
            "end",
        ]

        result = module._parse_dhcp_options(options)

        assert result["message_type"] == "DISCOVER"
        assert result["message_type_code"] == 1
        assert result["lease_time"] == 7200
        assert result["options"]["lease_time"] == "7200 seconds"
        assert result["server_id"] == "10.0.0.1"
        assert result["options"]["subnet_mask"] == "255.255.255.0"
        assert result["client_id"] == "01:00:11:22:33:44:55"
        assert result["requested_ip"] == "10.0.0.100"
        assert result["options"]["parameter_request_list"] == [1, 3, 6, 15]

    def test_capture_preserves_multiple_router_and_dns_addresses(self, tmp_path):
        """Scapy's multi-value DHCP tuples must retain every advertised address."""
        packet = (
            Ether()
            / IP(src="192.0.2.1", dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2)
            / DHCP(
                options=[
                    ("message-type", 2),
                    ("router", "192.0.2.1", "192.0.2.2"),
                    ("name_server", "198.51.100.1", "198.51.100.2"),
                    "end",
                ]
            )
        )
        capture = tmp_path / "dhcp.pcap"
        wrpcap(str(capture), [packet])

        result = DHCPModule(Config()).analyze_dhcp_packets(str(capture))

        options = result["packets"][0]["options"]
        assert options["router"] == "192.0.2.1, 192.0.2.2"
        assert options["dns_servers"] == "198.51.100.1, 198.51.100.2"

    def test_single_address_options_retain_string_values(self):
        """Keep the existing response shape for single address DHCP options."""
        result = DHCPModule(Config())._parse_dhcp_options(
            [("router", "192.0.2.1"), ("name_server", "198.51.100.1")]
        )
        assert result["options"]["router"] == "192.0.2.1"
        assert result["options"]["dns_servers"] == "198.51.100.1"

    def test_generate_statistics(self):
        """Test statistics generation."""
        config = Mock()
        module = DHCPModule(config)

        packets = [
            {
                "packet_number": 1,
                "client_mac": "00:11:22:33:44:55",
                "message_type": "DISCOVER",
                "transaction_id": "0x12345678",
                "timestamp": 1234567890.0,
            },
            {
                "packet_number": 2,
                "server_id": "192.168.1.1",
                "message_type": "OFFER",
                "transaction_id": "0x12345678",
                "timestamp": 1234567891.0,
            },
            {
                "packet_number": 3,
                "client_mac": "00:11:22:33:44:66",  # Different client
                "message_type": "DISCOVER",
                "transaction_id": "0x87654321",
                "timestamp": 1234567892.0,
            },
        ]

        stats = module._generate_statistics(packets)

        assert stats["unique_clients_count"] == 2
        assert stats["unique_servers_count"] == 1
        assert "00:11:22:33:44:55" in stats["unique_clients"]
        assert "00:11:22:33:44:66" in stats["unique_clients"]
        assert "192.168.1.1" in stats["unique_servers"]
        assert stats["message_type_counts"]["DISCOVER"] == 2
        assert stats["message_type_counts"]["OFFER"] == 1
        assert stats["transaction_count"] == 2
        assert "0x12345678" in stats["transactions"]
        assert "0x87654321" in stats["transactions"]


class TestDHCPModuleRemoteFiles:
    """Test DHCP module with remote files."""

    def test_remote_direct_file_url(self):
        """Test analyzing DHCP packets from a direct remote file URL."""
        config = Config()
        module = DHCPModule(config)

        with (
            patch.object(module, "_download_pcap_file") as mock_download,
            patch.object(module, "_analyze_protocol_file") as mock_analyze,
            patch("tempfile.NamedTemporaryFile") as mock_temp,
            patch("os.unlink"),
        ):
            mock_temp.return_value.__enter__.return_value.name = "/tmp/temp.pcap"
            mock_download.return_value = "/tmp/downloaded.pcap"
            mock_analyze.return_value = {"packets": [], "stats": {}}

            module.analyze_dhcp_packets("http://example.com/remote.pcap")

            mock_download.assert_called_once_with(
                "http://example.com/remote.pcap", "/tmp/temp.pcap"
            )
            mock_analyze.assert_called_once_with("/tmp/downloaded.pcap")

    def test_remote_download_failure(self):
        """Test handling of remote file download failures."""
        config = Config()
        module = DHCPModule(config)

        with (
            patch.object(module, "_download_pcap_file") as mock_download,
            patch("tempfile.NamedTemporaryFile") as mock_temp,
        ):
            mock_temp.return_value.__enter__.return_value.name = "/tmp/temp.pcap"
            mock_download.side_effect = ValueError("Download failed")

            result = module.analyze_dhcp_packets("http://example.com/dhcp.pcap")

            assert "error" in result
            assert "Download failed" in result["error"]
            assert result["pcap_url"] == "http://example.com/dhcp.pcap"


class TestDHCPConfig:
    """Test DHCP-specific configuration scenarios."""

    def test_config_with_dhcp_module(self):
        """Test configuration with DHCP module specified."""
        config = Config(modules=["dhcp"])
        assert "dhcp" in config.modules

    def test_config_with_multiple_modules(self):
        """Test configuration with multiple modules including DHCP."""
        config = Config(modules=["dns", "dhcp"])
        assert "dns" in config.modules
        assert "dhcp" in config.modules
