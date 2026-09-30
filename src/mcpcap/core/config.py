"""Configuration management for mcpcap."""

import ipaddress
import os


class Config:
    """Configuration management for mcpcap server."""

    def __init__(
        self,
        modules: list[str] | None = None,
        max_packets: int | None = None,
        transport: str = "stdio",
        host: str = "127.0.0.1",
        port: int = 8080,
        allow_unauthenticated_http: bool = False,
    ):
        """Initialize configuration.

        Args:
            modules: List of modules to load
            max_packets: Maximum number of packets to analyze per file
            transport: Transport type ('stdio' or 'http')
            host: Host to bind to (for HTTP transport)
            port: Port to bind to (for HTTP transport)
            allow_unauthenticated_http: Permit HTTP without a token on non-loopback
                interfaces, for isolated deployments such as local Docker publishing
        """
        self.modules = modules or ["dns", "dhcp", "icmp", "tcp", "sip", "capinfos"]
        self.max_packets = max_packets
        self.transport = transport
        self.host = host
        self.port = port
        self.allow_unauthenticated_http = allow_unauthenticated_http
        self.auth_token = (
            os.environ.get("MCPCAP_AUTH_TOKEN") if transport == "http" else None
        )

        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """Validate the configuration parameters."""
        if self.max_packets is not None and self.max_packets <= 0:
            raise ValueError("max_packets must be a positive integer")

        if self.transport not in ("stdio", "http"):
            raise ValueError("transport must be 'stdio' or 'http'")

        if self.port <= 0 or self.port > 65535:
            raise ValueError("port must be between 1 and 65535")

        if self.transport == "http":
            if self.auth_token is not None and (
                not self.auth_token or any(c.isspace() for c in self.auth_token)
            ):
                raise ValueError(
                    "MCPCAP_AUTH_TOKEN must be nonempty without whitespace"
                )

            try:
                loopback = ipaddress.ip_address(self.host).is_loopback
            except ValueError:
                loopback = self.host.lower() == "localhost"

            if (
                not loopback
                and not self.auth_token
                and not self.allow_unauthenticated_http
            ):
                raise ValueError(
                    "HTTP on non-loopback hosts requires MCPCAP_AUTH_TOKEN. "
                    "Use --allow-unauthenticated-http only for an isolated local deployment."
                )
