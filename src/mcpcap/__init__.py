"""mcpcap - A modular Python MCP server for analyzing PCAP files.

mcpcap exposes stateless MCP tools for working with packet captures. Start the
server, then call protocol-specific tools with a local PCAP path or remote HTTP
URL.

Included modules:
    - DNS
    - DHCP
    - ICMP
    - TCP
    - CapInfos

CLI usage::

    $ mcpcap [--modules MODULES] [--max-packets N]

Example tool calls from an MCP client::

    analyze_dns_packets("./examples/dns.pcap")
    analyze_tcp_connections("/absolute/path/to/capture.pcap")
"""

# Dynamic version detection
try:
    # First try to import from _version.py (created by setuptools-scm in built packages)
    from ._version import version as __version__
except ImportError:
    try:
        # Fall back to setuptools_scm for development environments
        from setuptools_scm import get_version

        __version__ = get_version(root="..", relative_to=__file__)
    except (ImportError, LookupError):
        # Final fallback for cases where setuptools_scm isn't available
        __version__ = "dev-unknown"

from .cli import main

__all__ = ["main", "__version__"]
