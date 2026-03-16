# Installation

mcpcap requires Python 3.10 or greater.

## Using pip (Recommended)

Install mcpcap from PyPI:

```bash
pip install mcpcap
```

This will install mcpcap and all its dependencies.

## Using uv

If you're using [uv](https://github.com/astral-sh/uv):

```bash
uv add mcpcap
```

## Using uvx (One-time usage)

To run mcpcap without installing it permanently:

```bash
uvx mcpcap
```

Then connect with an MCP client and pass a PCAP path or URL to the analysis tool you want to call.

## Development Installation

If you want to contribute to mcpcap or modify it:

```bash
# Clone the repository
git clone https://github.com/mcpcap/mcpcap.git
cd mcpcap

# Install in development mode with all dependencies
pip install -e ".[dev,docs,test]"
```

## Verify Installation

Verify that mcpcap is installed correctly:

```bash
mcpcap --help
```

You should see the help message showing available command-line options.

## Dependencies

mcpcap depends on:

- **fastmcp**: MCP server framework
- **scapy**: Packet parsing and analysis
- **requests**: HTTP client for remote PCAP access
- **Python 3.10+**: Modern Python features and type hints

All dependencies are automatically installed when you install mcpcap.

## Troubleshooting

### Permission Issues

mcpcap analyzes existing capture files. It does not capture live traffic itself, so elevated packet-capture privileges are not normally required.

### Import Errors

If you encounter import errors, make sure you're using the correct Python version:

```bash
python --version  # Should be 3.10 or higher
```

### Virtual Environment

It's recommended to use a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install mcpcap
```
