"""Tests for MCP server module registration."""

from unittest.mock import Mock, patch

from mcpcap.core import Config, MCPServer


@patch("mcpcap.core.server.FastMCP")
def test_server_registers_sip_tool(mock_fastmcp):
    """Test that SIP tools are registered when SIP module is enabled."""
    mcp_instance = Mock()
    mock_fastmcp.return_value = mcp_instance

    MCPServer(Config(modules=["sip"]))

    registered_tools = [
        call.args[0].__name__ for call in mcp_instance.tool.call_args_list
    ]
    assert "analyze_sip_packets" in registered_tools
