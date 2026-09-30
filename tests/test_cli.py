"""Tests for CLI functionality."""

from unittest.mock import Mock, patch

import pytest

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
            modules=["dns", "dhcp", "icmp", "tcp", "sip", "capinfos"],
            max_packets=None,
            transport="stdio",
            host="127.0.0.1",
            port=8080,
            allow_unauthenticated_http=False,
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
            transport="stdio",
            host="127.0.0.1",
            port=8080,
            allow_unauthenticated_http=False,
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
            transport="stdio",
            host="127.0.0.1",
            port=8080,
            allow_unauthenticated_http=False,
        )
        assert result == 0


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "example.com"])
def test_cli_rejects_unauthenticated_remote_http(monkeypatch, capsys, host):
    """Remote binds must fail before starting the server unless secured."""
    monkeypatch.delenv("MCPCAP_AUTH_TOKEN", raising=False)
    monkeypatch.setattr("sys.argv", ["mcpcap", "--transport", "http", "--host", host])
    with patch("mcpcap.cli.MCPServer") as server:
        assert main() == 1
    server.assert_not_called()
    assert "requires MCPCAP_AUTH_TOKEN" in capsys.readouterr().err


def test_cli_explicit_unauthenticated_container_bind(monkeypatch):
    """Allow the documented exception for loopback-published containers."""
    monkeypatch.delenv("MCPCAP_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        [
            "mcpcap",
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--allow-unauthenticated-http",
        ],
    )
    with patch("mcpcap.cli.MCPServer") as server:
        assert main() == 0
    assert server.call_args.args[0].allow_unauthenticated_http is True


def test_cli_remote_http_uses_environment_secret(monkeypatch, capsys):
    """The environment secret enables authentication and is never printed."""
    secret = "secret-for-cli-test"
    monkeypatch.setenv("MCPCAP_AUTH_TOKEN", secret)
    monkeypatch.setattr(
        "sys.argv", ["mcpcap", "--transport", "http", "--host", "0.0.0.0"]
    )
    with patch("mcpcap.cli.MCPServer") as server:
        assert main() == 0
    assert server.call_args.args[0].auth_token == secret
    output = capsys.readouterr()
    assert secret not in output.err + output.out
