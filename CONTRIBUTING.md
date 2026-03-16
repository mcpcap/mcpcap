# Contributing to mcpcap

Thank you for your interest in contributing to mcpcap! This guide will help you get started with development and contributing new features, especially new protocol analysis modules.

## Table of Contents

- [Development Setup](#development-setup)
- [Code Style and Standards](#code-style-and-standards)
- [Creating New Modules](#creating-new-modules)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Getting Help](#getting-help)

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Git
- Virtual environment tool (venv, conda, etc.)

### Setup Process

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/your-username/mcpcap.git
   cd mcpcap
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

   Or with `uv`:
   ```bash
   uv sync --extra dev
   ```

4. **Install Git hooks:**
   ```bash
   pre-commit install
   ```

   This installs both `pre-commit` and `pre-push` hooks from the repository config.

5. **Development tools are already included:**
   ```bash
   # The [dev] dependencies include ruff, mypy, pytest, etc.
   # No additional installation needed
   ```

6. **Verify installation:**
   ```bash
   # Run tests
   pytest

   # Start the server
   mcpcap
   ```

## Code Style and Standards

### Python Code Style

We use several tools to maintain code quality:

- **Ruff**: For linting and formatting
- **isort**: Import sorting (via ruff)
- **mypy**: Type checking
- **pre-commit**: Local automation for formatting, linting, and other guardrails

### Running Code Quality Checks

```bash
# Run all commit-time hooks against the whole repository
pre-commit run --all-files

# Run the opt-in type-check hook
pre-commit run mypy --all-files

# Format code directly
ruff format

# Check linting
ruff check

# Type checking (currently opt-in while the codebase is brought to strict mypy compliance)
mypy src

# Run tests
pytest
```

### Code Standards

1. **Type Hints**: All functions should have type hints (we're working to improve existing code)
2. **Docstrings**: All public functions and classes must have docstrings
3. **Error Handling**: Use explicit exception handling with meaningful messages
4. **Logging**: Use proper logging instead of print statements
5. **Testing**: All new code must have tests with >95% coverage

`pre-commit` currently runs fast hygiene hooks plus Ruff on each commit, and runs `pytest` before pushes. `mypy` is available as a manual hook because the current codebase still has existing strict-mode errors that should be fixed before making it a blocking check.

## Creating New Modules

### Module Architecture

mcpcap uses a modular architecture where each protocol analyzer inherits from `BaseModule`. Here's how to create a new module:

### 1. Create the Module File

Create a new file in `src/mcpcap/modules/` for your protocol (e.g., `http.py`):

```python
"""HTTP analysis module."""

from typing import Any
from fastmcp import FastMCP
from scapy.all import HTTP, TCP, rdpcap

from .base import BaseModule


class HTTPModule(BaseModule):
    """Module for analyzing HTTP packets in PCAP files."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "HTTP"

    def analyze_http_packets(self, pcap_file: str) -> dict[str, Any]:
        """
        Analyze HTTP packets from a PCAP file.

        Args:
            pcap_file: Path to local PCAP file or HTTP URL to remote PCAP file

        Returns:
            A structured dictionary containing HTTP packet analysis results
        """
        return self.analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform the actual HTTP packet analysis on a local PCAP file."""
        try:
            packets = rdpcap(pcap_file)
            http_packets = [pkt for pkt in packets if pkt.haslayer(HTTP)]

            if not http_packets:
                return {
                    "file": pcap_file,
                    "total_packets": len(packets),
                    "http_packets_found": 0,
                    "message": "No HTTP packets found in this capture",
                }

            # Apply max_packets limit if specified
            packets_to_analyze = http_packets
            limited = False
            if self.config.max_packets and len(http_packets) > self.config.max_packets:
                packets_to_analyze = http_packets[:self.config.max_packets]
                limited = True

            packet_details = []
            for i, pkt in enumerate(packets_to_analyze, 1):
                packet_info = self._analyze_http_packet(pkt, i)
                packet_details.append(packet_info)

            # Generate statistics
            stats = self._generate_statistics(packet_details)

            result = {
                "file": pcap_file,
                "total_packets": len(packets),
                "http_packets_found": len(http_packets),
                "http_packets_analyzed": len(packet_details),
                "statistics": stats,
                "packets": packet_details,
            }

            if limited:
                result["note"] = (
                    f"Analysis limited to first {self.config.max_packets} HTTP packets"
                )

            return result

        except Exception as e:
            return {
                "error": f"Error reading PCAP file '{pcap_file}': {str(e)}",
                "file": pcap_file,
            }

    def _analyze_http_packet(self, packet, packet_num: int) -> dict[str, Any]:
        """Analyze a single HTTP packet."""
        # Implement packet analysis logic
        return {
            "packet_number": packet_num,
            "timestamp": packet.time,
            # Add more fields as needed
        }

    def _generate_statistics(self, packets: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate statistics from analyzed HTTP packets."""
        # Implement statistics generation
        return {
            "total_requests": 0,
            "total_responses": 0,
            # Add more statistics as needed
        }

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Set up HTTP-specific analysis prompts."""

        @mcp.prompt
        def http_security_analysis():
            """Prompt for analyzing HTTP traffic from a security perspective"""
            return """You are analyzing HTTP traffic for security issues..."""
```

### 2. Register the Module

Add your module to `src/mcpcap/core/server.py`:

```python
from ..modules.http import HTTPModule  # Add import

# In the __init__ method:
if "http" in self.config.modules:
    self.modules["http"] = HTTPModule(config)

# In the _register_tools method:
elif module_name == "http":
    self.mcp.tool(module.analyze_http_packets)
```

### 3. Update Configuration

Add your module to the default modules list in `src/mcpcap/cli.py`:

```python
parser.add_argument(
    "--modules",
    default="dns,dhcp,http",  # Add your module here
    help="Comma-separated list of modules to load (dns,dhcp,http)",
)
```

### 4. Create Tests

Create tests in `tests/test_modules/test_http.py`:

```python
"""Tests for HTTP module."""

from unittest.mock import Mock, patch
import pytest

from mcpcap.modules.http import HTTPModule
from mcpcap.core.config import Config


class TestHTTPModule:
    """Test HTTP module functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        config = Config(modules=["http"], max_packets=None)
        self.http_module = HTTPModule(config)

    def test_protocol_name(self):
        """Test protocol name property."""
        assert self.http_module.protocol_name == "HTTP"

    @patch("mcpcap.modules.http.rdpcap")
    def test_analyze_http_packets_no_packets(self, mock_rdpcap):
        """Test analysis with no HTTP packets."""
        # Mock empty packet capture
        mock_rdpcap.return_value = []

        result = self.http_module.analyze_http_packets("test.pcap")

        assert result["http_packets_found"] == 0
        assert "No HTTP packets found" in result["message"]
```

### 5. Add Documentation

Create documentation in `docs/source/user-guide/` and add examples to the tutorial.

## Testing Requirements

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/mcpcap --cov-report=html

# Run specific test file
pytest tests/test_modules/test_http.py

# Run with verbose output
pytest -v
```

### Test Coverage Requirements

- All new modules must have >95% test coverage
- All public methods must have tests
- Error conditions must be tested
- Edge cases should be covered

### Test Structure

- Unit tests for individual functions
- Integration tests for module workflow
- Mock external dependencies (scapy, file system, network)
- Test both success and failure scenarios

## Documentation

### Required Documentation

1. **Module docstrings**: Complete API documentation
2. **User guide updates**: Add your module to relevant guides
3. **Examples**: Provide working examples with sample data
4. **Tutorial updates**: Add your module to the module creation tutorial

### Documentation Style

- Use clear, concise language
- Provide practical examples
- Include both simple and advanced use cases
- Follow the existing documentation structure

### Building Documentation Locally

```bash
# Install docs dependencies
pip install -e ".[docs]"

# Build documentation
cd docs
make html

# View documentation
open build/html/index.html
```

## Development Workflow

We follow **GitHub Flow** for all development:

1. **Create feature branches** from `main` for all changes
2. **Use descriptive branch names**: `feature/add-http-module`, `fix/dns-parsing-bug`, `docs/update-contributing`
3. **Keep branches focused** - one feature or fix per branch
4. **Create pull requests early** for feedback and collaboration
5. **Merge to main** only after review and CI passes
6. **Delete feature branches** after merging

### Branch Naming Convention

```bash
feature/description-of-feature    # New features
fix/description-of-bug           # Bug fixes
docs/description-of-change       # Documentation updates
refactor/description-of-change   # Code refactoring
test/description-of-test         # Test improvements
```

## Pull Request Process

### Before Submitting

1. **Run all checks:**
   ```bash
   # Format and lint your code
   ruff format
   ruff check

   # Run tests
   pytest

   # Optional: Check types (may show issues in existing code)
   mypy src/mcpcap --follow-imports=skip
   ```

2. **Update documentation:**
   - Add/update docstrings
   - Update user guides if needed
   - Add examples

3. **Write good commit messages:**
   ```
   Add HTTP analysis module

   - Implement HTTP packet parsing with request/response analysis
   - Add security-focused analysis prompts
   - Include comprehensive test coverage
   - Update documentation with HTTP examples
   ```

### Pull Request Guidelines

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/add-http-module
   ```

2. **Keep PRs focused:** One feature or fix per PR

3. **Write descriptive PR description:**
   - Explain what the PR does
   - Reference any related issues
   - Include testing notes
   - Add examples of usage

4. **Respond to review feedback:** Address all comments promptly

### PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature (new protocol module)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other (please describe)

## Testing
- [ ] Tests pass locally
- [ ] Added new tests for new functionality
- [ ] Coverage remains >95%

## Documentation
- [ ] Updated relevant documentation
- [ ] Added examples
- [ ] Docstrings updated

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Tests added/updated
- [ ] Documentation updated
```

## Getting Help

### Resources

- **Documentation**: https://mcpcap.readthedocs.io
- **Examples**: Check the `examples/` directory
- **Existing modules**: Study `dns.py` and `dhcp.py` as references

### Communication

- **Issues**: Open GitHub issues for bugs or feature requests
- **Discussions**: Use GitHub discussions for questions
- **Security**: Report security issues privately

### Module Development Tips

1. **Start simple:** Begin with basic packet parsing
2. **Follow patterns:** Use existing modules as templates
3. **Test incrementally:** Write tests as you develop
4. **Handle errors gracefully:** Provide meaningful error messages
5. **Document as you go:** Write docstrings immediately

## Contributing Guidelines Summary

- Fork the repository and create feature branches
- Follow code style and testing requirements
- Write comprehensive documentation
- Submit focused pull requests
- Respond to review feedback promptly

Thank you for contributing to mcpcap! Your contributions help make network analysis more accessible and powerful for everyone.
