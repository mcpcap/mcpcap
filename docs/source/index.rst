mcpcap Documentation
======================

.. only:: html

   .. image:: https://img.shields.io/pypi/v/mcpcap.svg
      :target: https://pypi.org/project/mcpcap/
      :alt: PyPI version

   .. image:: https://img.shields.io/pypi/pyversions/mcpcap.svg
      :target: https://pypi.org/project/mcpcap/
      :alt: Python versions

   .. image:: https://github.com/mcpcap/mcpcap/workflows/Test/badge.svg
      :target: https://github.com/mcpcap/mcpcap/actions
      :alt: Test status

A modular Python MCP (Model Context Protocol) server for analyzing PCAP files. mcpcap provides stateless analysis tools that accept a local file path or remote URL at call time, making it a good fit for Claude Desktop and other MCP clients.

Features
--------

- **Stateless MCP Tools**: Each analysis tool accepts PCAP file paths or URLs as parameters

- **Protocol Support**: DNS, DHCP, ICMP, TCP, and CapInfos analysis

- **Local & Remote Files**: Analyze files from local storage or HTTP URLs

- **Specialized Prompts**: Security, networking, and forensic analysis guidance

- **Robust Analysis**: Comprehensive packet parsing with error handling

- **Claude Desktop Ready**: Perfect integration with MCP clients

Quick Start
-----------

Install mcpcap:

.. code-block:: bash

   pip install mcpcap

Start the MCP server:

.. code-block:: bash

   mcpcap

Then use analysis tools with any PCAP file:

.. code-block:: javascript

   analyze_dns_packets("/path/to/dns.pcap")
   analyze_dhcp_packets("https://example.com/dhcp.pcap")
   analyze_icmp_packets("/path/to/network.pcap")
   analyze_tcp_connections("/path/to/tcp-session.pcap")
   analyze_capinfos("/path/to/capture.pcap")

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   user-guide/installation
   user-guide/quickstart
   user-guide/mcp-integration
   user-guide/analysis-guides

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/core
   api/modules
   api/cli

.. toctree::
   :maxdepth: 2
   :caption: Developer Guide

   developer/contributing
   developer/module-creation-tutorial

.. toctree::
   :maxdepth: 1
   :caption: Examples
   :hidden:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
