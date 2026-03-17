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

A modular Python MCP (Model Context Protocol) server for analyzing PCAP files. mcpcap provides stateless analysis tools that accept a local file path or remote URL at call time, making it a good fit for Claude Desktop, HTTP MCP clients, and containerized deployments.

Features
--------

- **Stateless MCP Tools**: Each analysis tool accepts PCAP file paths or URLs as parameters

- **Protocol Support**: DNS, DHCP, ICMP, TCP, SIP, and CapInfos analysis

- **Local & Remote Files**: Analyze files from local storage or HTTP URLs

- **Specialized Prompts**: Security, networking, and forensic analysis guidance

- **Robust Analysis**: Comprehensive packet parsing with error handling

- **Claude Desktop Ready**: Perfect integration with MCP clients

Quick Start
-----------

Install mcpcap:

.. code-block:: bash

   pip install mcpcap

Or run the published container with Docker Compose:

.. code-block:: bash

   docker compose up

This pulls ``ghcr.io/mcpcap/mcpcap:latest`` and exposes ``http://127.0.0.1:8080/mcp`` with ``./examples`` mounted as ``/pcaps``.

Start the MCP server locally:

.. code-block:: bash

   mcpcap

Or expose an HTTP MCP endpoint:

.. code-block:: bash

   mcpcap --transport http --host 127.0.0.1 --port 8080

Then use analysis tools with any PCAP file:

.. code-block:: javascript

   analyze_dns_packets("/path/to/dns.pcap")
   analyze_dns_packets("/pcaps/dns.pcap")
   analyze_dhcp_packets("https://example.com/dhcp.pcap")
   analyze_icmp_packets("/path/to/network.pcap")
   analyze_tcp_connections("/path/to/tcp-session.pcap")
   analyze_sip_packets("/path/to/voip-signaling.pcap")
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
