"""CLI entry point for mcpcap.

This module provides the command-line interface for mcpcap, handling argument parsing
and server initialization.
"""

import argparse
import sys

from .core import Config, MCPServer


def main():
    """Main function to parse arguments and start the MCP server.

    Parses command-line arguments, initializes the configuration and MCP server,
    and handles graceful shutdown and error conditions.

    Returns:
        int: Exit code (0 for success, 1 for error)

    Raises:
        KeyboardInterrupt: If the user interrupts the server
        Exception: For any unexpected errors during server operation
    """
    parser = argparse.ArgumentParser(description="mcpcap MCP Server")

    # Analysis options
    parser.add_argument(
        "--modules",
        help="Comma-separated list of modules to load (default: dns,dhcp,icmp,capinfos,tcp,payload)",
        default="dns,dhcp,icmp,capinfos,tcp,payload",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        help="Maximum number of packets to analyze per file (default: unlimited)",
    )

    args = parser.parse_args()

    try:
        # Parse modules
        modules = (
            args.modules.split(",")
            if args.modules
            else ["dns", "dhcp", "icmp", "capinfos", "tcp", "payload"]
        )

        # Initialize configuration
        config = Config(
            modules=modules,
            max_packets=args.max_packets,
        )

        # Create and start MCP server
        server = MCPServer(config)
        server.run()
        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\\nServer stopped by user", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit(main())
