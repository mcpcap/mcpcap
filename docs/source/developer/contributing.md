# Contributing Guide

Welcome to the mcpcap developer guide! This section contains everything you need to contribute to mcpcap development.

## Quick Links

- **[Module Creation Tutorial](module-creation-tutorial.md)** - Step-by-step guide to creating new protocol analyzers
- **[CONTRIBUTING.md](https://github.com/mcpcap/mcpcap/blob/main/CONTRIBUTING.md)** - Full development setup and contribution guidelines

## Getting Started

### Development Environment

1. **Fork and clone the repository**
2. **Set up Python virtual environment** (3.10+)
3. **Install development dependencies**: `pip install -e ".[dev]"` or `uv sync --extra dev`
4. **Install pre-commit hooks**: `pre-commit install`

### Understanding the Architecture

mcpcap uses a modular architecture:

```
src/mcpcap/
├── core/              # Core MCP server and configuration
├── modules/           # Protocol analysis modules (DNS, DHCP, SIP, etc.)
│   ├── base.py       # Base module interface
│   ├── dns.py        # DNS analysis module
│   ├── dhcp.py       # DHCP analysis module
│   └── ...           # Your new modules here
├── cli.py            # Command-line interface
└── __main__.py       # Entry point
```

Each module inherits from `BaseModule` and implements:
- Protocol-specific packet analysis
- Statistics generation
- MCP tool registration
- Analysis prompts for different use cases

## Creating New Modules

The fastest way to get started is to follow our [Module Creation Tutorial](module-creation-tutorial.md), which walks through creating a complete HTTP analysis module.

### Module Requirements

Every new module must:

1. **Inherit from BaseModule** - Use the common interface
2. **Implement required methods** - `protocol_name`, `analyze_packets`, etc.
3. **Handle both local and remote files** - URLs and local paths
4. **Include comprehensive tests** - >95% coverage required
5. **Add MCP prompts** - Security, troubleshooting, and forensic analysis
6. **Update documentation** - User guides and examples

### Supported Protocols

Current modules:
- **DNS** - Domain name resolution analysis
- **DHCP** - Dynamic host configuration analysis
- **ICMP** - Network diagnostics and reachability analysis
- **TCP** - Connection lifecycle and traffic pattern analysis
- **SIP** - VoIP signaling analysis
- **CapInfos** - PCAP metadata and file statistics

Potential future modules:
- **HTTP/HTTPS** - Web traffic analysis
- **TLS/SSL** - Encryption and certificate analysis
- **ARP** - Address resolution protocol analysis
- **FTP** - File transfer protocol analysis
- **SMTP** - Email protocol analysis

## Development Workflow

### 1. Plan Your Module

- Choose a network protocol to analyze
- Research the protocol structure using Scapy
- Identify key analysis points (security, performance, troubleshooting)
- Plan your statistics and output format

### 2. Create Feature Branch

```bash
git checkout -b feature/add-[protocol]-module
```

### 3. Follow TDD Approach

- Write tests first
- Implement functionality incrementally
- Run tests frequently: `pytest`
- Check coverage: `pytest --cov`

### 4. Code Quality Checks

```bash
# Run all commit-time hooks
pre-commit run --all-files

# Run the opt-in type-check hook
pre-commit run mypy --all-files

# Format and lint directly
ruff format
ruff check

# Run all pre-commit hooks
pre-commit run --all-files
```

### 5. Update Documentation

- Add module to user guides
- Include practical examples
- Update API documentation
- Test documentation builds: `cd docs && make html`

### 6. Submit Pull Request

- Fill out PR template completely
- Include testing instructions
- Reference related issues
- Respond to review feedback promptly

## Testing Guidelines

### Test Structure

```
tests/
├── test_cli.py              # CLI tests
├── test_modules/            # Module-specific tests
│   ├── test_dns.py         # DNS module tests
│   ├── test_dhcp.py        # DHCP module tests
│   └── test_[protocol].py  # Your module tests
└── fixtures/               # Test data
    ├── dns.pcap
    ├── dhcp.pcap
    └── [protocol].pcap
```

### Testing Best Practices

1. **Mock external dependencies** - Network calls, file system, scapy
2. **Test error conditions** - Malformed packets, missing files, network failures
3. **Use realistic test data** - Real PCAP files when possible
4. **Test edge cases** - Empty files, large files, unusual protocols
5. **Verify output format** - JSON structure, required fields, data types

### Creating Test PCAP Files

Generate test data for your protocol:

```bash
# Capture live traffic
tcpdump -i any port [protocol-port] -w tests/fixtures/[protocol].pcap

# Generate synthetic traffic
scapy # Use scapy to craft specific packets

# Use existing samples
wget https://wiki.wireshark.org/uploads/[protocol].cap
```

## Code Style Guidelines

### Python Standards

- **PEP 8 compliant** - Enforced by ruff
- **Type hints required** - All functions must have type annotations
- **Docstrings required** - All public functions and classes
- **Error handling** - Use explicit exception handling
- **Logging over print** - Use proper logging for debugging

### Module Structure Template

```text
"""[Protocol] analysis module."""

from typing import Any
from datetime import datetime

from fastmcp import FastMCP
from scapy.all import [protocol-imports], rdpcap

from .base import BaseModule


class [Protocol]Module(BaseModule):
    """Module for analyzing [protocol] packets."""

    @property
    def protocol_name(self) -> str:
        return "[PROTOCOL]"

    def analyze_[protocol]_packets(self, pcap_file: str) -> dict[str, Any]:
        """Analyze [protocol] packets from PCAP file."""
        return self.analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform actual [protocol] analysis."""
        # Implementation here
        pass

    def _analyze_[protocol]_packet(self, packet, packet_num: int) -> dict[str, Any]:
        """Analyze single [protocol] packet."""
        # Implementation here
        pass

    def _generate_statistics(self, packets: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate [protocol]-specific statistics."""
        # Implementation here
        pass

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Setup [protocol] analysis prompts."""
        # Add security, troubleshooting, and forensic prompts
        pass
```

## Documentation Standards

### User Documentation

- **Clear examples** - Show both input and output
- **Multiple scenarios** - Basic usage, advanced features, error handling
- **Real-world context** - When and why to use each feature
- **Troubleshooting** - Common issues and solutions

### Developer Documentation

- **API documentation** - Complete docstrings with examples
- **Architecture decisions** - Why certain choices were made
- **Extension points** - How to extend or customize modules
- **Performance notes** - Memory usage, processing time, bottlenecks

## Performance Considerations

### Packet Processing

- **Filter early** - Use Scapy filters to reduce processing
- **Limit analysis** - Respect max_packets configuration
- **Stream processing** - Don't load entire files into memory
- **Efficient parsing** - Use appropriate data structures

### Memory Management

- **Large file handling** - Process packets incrementally
- **Object cleanup** - Release resources promptly
- **Cache wisely** - Cache expensive computations, not large data

### Scalability

- **Configurable limits** - Allow users to tune performance
- **Progress indicators** - For long-running analysis
- **Graceful degradation** - Handle resource constraints

## Security Considerations

### Input Validation

- **Sanitize file paths** - Prevent directory traversal
- **Validate URLs** - Check remote file sources
- **Handle malformed data** - Don't crash on bad packets
- **Limit resource usage** - Prevent DoS through large files

### Output Safety

- **Sanitize extracted data** - Remove potentially dangerous content
- **Log safely** - Don't expose sensitive data in logs
- **Error messages** - Don't leak system information
- **Data retention** - Don't persist sensitive analysis data

## Getting Help

### Resources

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and community help
- **Module Examples** - Study existing DNS and DHCP modules
- **Scapy Documentation** - Learn packet manipulation

### Common Questions

**Q: How do I debug packet parsing issues?**
A: Use `packet.show()` to inspect packet structure and add logging

**Q: My module isn't loading, what's wrong?**
A: Check import statements and module registration in `server.py`

**Q: How do I handle unknown packet formats?**
A: Return error information in your analysis results, don't crash

**Q: Can I add external dependencies?**
A: Yes, but add them to `pyproject.toml` and justify the need

### Community Guidelines

- **Be respectful** - Constructive feedback and collaboration
- **Help others** - Answer questions and review PRs
- **Share knowledge** - Document your learnings
- **Follow standards** - Maintain code quality and consistency

## Release Process

### Version Strategy

- **Semantic versioning** - Major.minor.patch format
- **Alpha/Beta phases** - For testing new features
- **Changelog maintenance** - Document all changes

### Release Checklist

1. All tests passing
2. Documentation updated
3. Version bumped appropriately
4. Changelog updated
5. Git tag created
6. PyPI package published
7. GitHub release created

Thank you for contributing to mcpcap! Your work helps make network analysis more accessible and powerful for everyone.
