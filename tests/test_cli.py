"""Tests for CLI functionality."""

from unittest.mock import Mock, patch

from mcpcap.cli import main


class TestCLI:
    """Test CLI functionality."""

    @patch("mcpcap.cli.MCPServer")
    @patch("mcpcap.cli.Config")
    @patch("sys.argv", ["mcpcap"])
    def test_main_success(self, mock_config, mock_server):
        """Test successful main execution."""
        # Setup mocks
        config_instance = Mock()
        mock_config.return_value = config_instance

        server_instance = Mock()
        mock_server.return_value = server_instance

        # Run main
        result = main()

        # Verify behavior
        mock_config.assert_called_once_with(
            modules=["dns", "dhcp", "icmp", "capinfos", "tcp"],
            max_packets=None,
        )
        mock_server.assert_called_once_with(config_instance)
        server_instance.run.assert_called_once()
        assert result == 0

    @patch("mcpcap.cli.Config")
    @patch("sys.argv", ["mcpcap", "--max-packets", "-1"])
    def test_main_invalid_config(self, mock_config):
        """Test main with invalid configuration."""
        # Setup mock to raise ValueError
        mock_config.side_effect = ValueError("max_packets must be a positive integer")

        # Run main and capture output
        with patch("sys.stderr") as mock_stderr:
            result = main()

        # Verify error handling
        mock_stderr.write.assert_any_call(
            "Error: max_packets must be a positive integer"
        )
        assert result == 1

    @patch("mcpcap.cli.MCPServer")
    @patch("mcpcap.cli.Config")
    @patch("sys.argv", ["mcpcap"])
    def test_main_keyboard_interrupt(self, mock_config, mock_server):
        """Test main with keyboard interrupt."""
        # Setup mocks
        config_instance = Mock()
        mock_config.return_value = config_instance

        server_instance = Mock()
        server_instance.run.side_effect = KeyboardInterrupt()
        mock_server.return_value = server_instance

        # Run main and capture output
        with patch("sys.stderr") as mock_stderr:
            result = main()

        # Verify graceful shutdown
        mock_stderr.write.assert_any_call("\\nServer stopped by user")
        assert result == 0

    @patch("mcpcap.cli.MCPServer")
    @patch("mcpcap.cli.Config")
    @patch("sys.argv", ["mcpcap"])
    def test_main_unexpected_error(self, mock_config, mock_server):
        """Test main with unexpected error."""
        # Setup mocks
        config_instance = Mock()
        mock_config.return_value = config_instance

        server_instance = Mock()
        server_instance.run.side_effect = RuntimeError("Unexpected error")
        mock_server.return_value = server_instance

        # Run main and capture output
        with patch("sys.stderr") as mock_stderr:
            result = main()

        # Verify error handling
        mock_stderr.write.assert_any_call("Unexpected error: Unexpected error")
        assert result == 1

    @patch("mcpcap.cli.MCPServer")
    @patch("mcpcap.cli.Config")
    @patch("sys.argv", ["mcpcap", "--modules", "dhcp"])
    def test_main_dhcp_module(self, mock_config, mock_server):
        """Test main with DHCP module specified."""
        # Setup mocks
        config_instance = Mock()
        mock_config.return_value = config_instance

        server_instance = Mock()
        mock_server.return_value = server_instance

        # Run main
        result = main()

        # Verify DHCP configuration
        mock_config.assert_called_once_with(
            modules=["dhcp"],
            max_packets=None,
        )
        assert result == 0

    @patch("mcpcap.cli.MCPServer")
    @patch("mcpcap.cli.Config")
    @patch("sys.argv", ["mcpcap", "--modules", "dns,dhcp"])
    def test_main_multiple_modules(self, mock_config, mock_server):
        """Test main with multiple modules specified."""
        # Setup mocks
        config_instance = Mock()
        mock_config.return_value = config_instance

        server_instance = Mock()
        mock_server.return_value = server_instance

        # Run main
        result = main()

        # Verify multi-module configuration
        mock_config.assert_called_once_with(
            modules=["dns", "dhcp"],
            max_packets=None,
        )
        assert result == 0
