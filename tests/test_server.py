"""Tests for MCP server module registration."""

from unittest.mock import Mock, patch

import pytest
from scapy.all import DNS, DNSQR, IP, UDP, wrpcap
from starlette.testclient import TestClient

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


@pytest.mark.parametrize("token", [None, "incorrect-token"])
def test_http_requires_valid_bearer_token(monkeypatch, token):
    """Protected MCP endpoints reject missing and invalid bearer credentials."""
    monkeypatch.setenv("MCPCAP_AUTH_TOKEN", "correct-token")
    server = MCPServer(Config(modules=["dns"], transport="http", host="0.0.0.0"))
    app = server.mcp.http_app(json_response=True, stateless_http=True)
    headers = {"Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with TestClient(app) as client:
        response = client.post("/mcp", headers=headers, json=_initialize_request())
    assert response.status_code == 401


def _initialize_request():
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "auth-test", "version": "1.0"},
        },
    }


def test_http_initializes_with_valid_bearer_token(monkeypatch):
    """Use the real HTTP auth middleware and MCP initialize handler."""
    monkeypatch.setenv("MCPCAP_AUTH_TOKEN", "correct-token")
    server = MCPServer(Config(modules=["dns"], transport="http", host="0.0.0.0"))
    app = server.mcp.http_app(json_response=True, stateless_http=True)
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": "Bearer correct-token",
            },
            json=_initialize_request(),
        )
    assert response.status_code == 200
    assert response.json()["result"]["serverInfo"]["name"] == "mcpcap"


def test_authenticated_http_tool_call(monkeypatch, tmp_path):
    """Authentication gates real analysis calls, including subsequent requests."""
    monkeypatch.setenv("MCPCAP_AUTH_TOKEN", "correct-token")
    pcap = tmp_path / "dns.pcap"
    wrpcap(str(pcap), IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com")))
    server = MCPServer(Config(modules=["dns"], transport="http", host="0.0.0.0"))
    app = server.mcp.http_app(json_response=True, stateless_http=True)
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer correct-token",
    }
    request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "analyze_dns_packets",
            "arguments": {"pcap_file": str(pcap)},
        },
    }
    with TestClient(app) as client:
        assert (
            client.post("/mcp", headers=headers, json=_initialize_request()).status_code
            == 200
        )
        response = client.post("/mcp", headers=headers, json=request)
        unauthenticated = client.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json=request,
        )
    assert response.status_code == 200
    assert response.json()["result"]["isError"] is False
    assert response.json()["result"]["structuredContent"]["dns_packets_found"] == 1
    assert unauthenticated.status_code == 401


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_loopback_http_can_initialize_without_auth(monkeypatch, host):
    """Preserve the local MCP client workflow for loopback binds."""
    monkeypatch.delenv("MCPCAP_AUTH_TOKEN", raising=False)
    server = MCPServer(Config(modules=["dns"], transport="http", host=host))
    app = server.mcp.http_app(json_response=True, stateless_http=True)
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json=_initialize_request(),
        )
    assert response.status_code == 200


@pytest.mark.parametrize("secret", ["", "secret with spaces", "secret\n"])
def test_invalid_http_token_fails_without_disclosing_it(monkeypatch, secret):
    monkeypatch.setenv("MCPCAP_AUTH_TOKEN", secret)
    with pytest.raises(ValueError, match="MCPCAP_AUTH_TOKEN must be nonempty"):
        Config(transport="http")


def test_stdio_ignores_http_auth_environment(monkeypatch):
    monkeypatch.setenv("MCPCAP_AUTH_TOKEN", "secret")
    server = MCPServer(Config(modules=["dns"]))
    assert server.config.auth_token is None
    assert server.mcp.auth is None
