"""Tests for DNS module."""

from unittest.mock import Mock

import pytest

from mcpcap.core.config import Config
from mcpcap.modules.dns import DNSModule


class TestDNSModule:
    """Test DNS analysis module."""

    def test_protocol_name(self):
        """Test that protocol name is correct."""
        config = Mock()
        module = DNSModule(config)
        assert module.protocol_name == "DNS"

    def test_analyze_dns_packets_file_not_found(self):
        """Test analyzing DNS packets when file doesn't exist."""
        config = Config()
        module = DNSModule(config)

        result = module.analyze_dns_packets("/nonexistent/file.pcap")

        assert "error" in result
        assert "not found" in result["error"]
        assert result["pcap_file"] == "/nonexistent/file.pcap"


class TestConfig:
    """Test configuration management."""

    def test_config_validation_success(self):
        """Test successful config validation."""
        config = Config()
        assert config.modules == ["dns", "dhcp", "icmp", "tcp", "sip", "capinfos"]

    def test_config_validation_nonexistent_path(self):
        """Test config validation with invalid max_packets."""
        with pytest.raises(ValueError, match="max_packets must be a positive integer"):
            Config(max_packets=0)

    def test_config_validation_not_directory(self):
        """Test config validation with negative max_packets."""
        with pytest.raises(ValueError, match="max_packets must be a positive integer"):
            Config(max_packets=-1)

    def test_custom_modules(self):
        """Test configuration with custom modules."""
        config = Config(modules=["dns"])
        assert config.modules == ["dns"]

    def test_max_packets_setting(self):
        """Test max_packets configuration."""
        config = Config(max_packets=100)
        assert config.max_packets == 100
