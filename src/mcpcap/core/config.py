"""Configuration management for mcpcap."""


class Config:
    """Configuration management for mcpcap server."""

    def __init__(
        self,
        modules: list[str] | None = None,
        max_packets: int | None = None,
        transport: str = "stdio",
        host: str = "127.0.0.1",
        port: int = 8080,
    ):
        """Initialize configuration.

        Args:
            modules: List of modules to load
            max_packets: Maximum number of packets to analyze per file
            transport: Transport type ('stdio' or 'http')
            host: Host to bind to (for HTTP transport)
            port: Port to bind to (for HTTP transport)
        """
        self.modules = modules or ["dns", "dhcp", "icmp", "tcp", "sip", "capinfos"]
        self.max_packets = max_packets
        self.transport = transport
        self.host = host
        self.port = port

        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """Validate the configuration parameters."""
        if self.max_packets is not None and self.max_packets <= 0:
            raise ValueError("max_packets must be a positive integer")

        if self.transport not in ("stdio", "http"):
            raise ValueError("transport must be 'stdio' or 'http'")

        if self.port <= 0 or self.port > 65535:
            raise ValueError("port must be between 1 and 65535")
