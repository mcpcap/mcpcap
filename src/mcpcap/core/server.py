"""MCP server setup and configuration."""

from fastmcp import FastMCP

from ..modules.capinfos import CapInfosModule
from ..modules.dhcp import DHCPModule
from ..modules.dns import DNSModule
from ..modules.icmp import ICMPModule
from ..modules.payload import PayloadModule
from ..modules.tcp import TCPModule
from .config import Config


class MCPServer:
    """MCP server for PCAP analysis."""

    def __init__(self, config: Config):
        """Initialize MCP server.

        Args:
            config: Configuration instance
        """
        self.config = config

        self.mcp = FastMCP("mcpcap")

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
        if "payload" in self.config.modules:
            self.modules["payload"] = PayloadModule(config)

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
            elif module_name == "payload":
                self.mcp.tool(module.analyze_payload)
                self.mcp.tool(module.extract_database_queries)
                self.mcp.tool(module.detect_protocols)

    def run(self) -> None:
        """Start the MCP server."""

        self.mcp.run(show_banner=False)
