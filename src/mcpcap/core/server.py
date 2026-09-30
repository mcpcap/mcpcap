"""MCP server setup and configuration."""

import hashlib
import hmac

from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier

from ..modules.capinfos import CapInfosModule
from ..modules.dhcp import DHCPModule
from ..modules.dns import DNSModule
from ..modules.icmp import ICMPModule
from ..modules.sip import SIPModule
from ..modules.tcp import TCPModule
from .config import Config


class _BearerTokenVerifier(TokenVerifier):
    """Verify an environment-provided bearer secret without storing it in claims."""

    def __init__(self, token: str):
        super().__init__()
        self._token_digest = hashlib.sha256(token.encode()).digest()

    async def verify_token(self, token: str) -> AccessToken | None:
        digest = hashlib.sha256(token.encode()).digest()
        if not hmac.compare_digest(digest, self._token_digest):
            return None
        return AccessToken(token=token, client_id="mcpcap", scopes=[])


class MCPServer:
    """MCP server for PCAP analysis."""

    def __init__(self, config: Config):
        """Initialize MCP server.

        Args:
            config: Configuration instance
        """
        self.config = config

        auth = (
            _BearerTokenVerifier(config.auth_token)
            if config.transport == "http" and config.auth_token
            else None
        )
        self.mcp = FastMCP("mcpcap", auth=auth)

        # Initialize modules based on configuration
        self.modules = {}
        if "dns" in self.config.modules:
            self.modules["dns"] = DNSModule(config)
        if "dhcp" in self.config.modules:
            self.modules["dhcp"] = DHCPModule(config)
        if "icmp" in self.config.modules:
            self.modules["icmp"] = ICMPModule(config)
        if "capinfos" in self.config.modules:
            self.modules["capinfos"] = CapInfosModule(config)
        if "tcp" in self.config.modules:
            self.modules["tcp"] = TCPModule(config)
        if "sip" in self.config.modules:
            self.modules["sip"] = SIPModule(config)

        # Register tools
        self._register_tools()

        # Setup prompts
        for module in self.modules.values():
            module.setup_prompts(self.mcp)

    def _register_tools(self) -> None:
        """Register all available tools with the MCP server."""
        # Register tools for each loaded module
        for module_name, module in self.modules.items():
            if module_name == "dns":
                self.mcp.tool(module.analyze_dns_packets)
            elif module_name == "dhcp":
                self.mcp.tool(module.analyze_dhcp_packets)
            elif module_name == "icmp":
                self.mcp.tool(module.analyze_icmp_packets)
            elif module_name == "capinfos":
                self.mcp.tool(module.analyze_capinfos)
            elif module_name == "tcp":
                self.mcp.tool(module.analyze_tcp_connections)
                self.mcp.tool(module.analyze_tcp_anomalies)
                self.mcp.tool(module.analyze_tcp_retransmissions)
                self.mcp.tool(module.analyze_traffic_flow)
            elif module_name == "sip":
                self.mcp.tool(module.analyze_sip_packets)

    def run(self) -> None:
        """Start the MCP server."""

        if self.config.transport == "http":
            self.mcp.run(
                transport="http",
                host=self.config.host,
                port=self.config.port,
                show_banner=False,
            )
        else:
            self.mcp.run(show_banner=False)
