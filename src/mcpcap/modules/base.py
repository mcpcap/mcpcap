"""Base module interface for protocol analyzers."""

import os
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from ..core.config import Config


class BaseModule(ABC):
    """Base class for protocol analysis modules."""

    def __init__(self, config: Config):
        """Initialize the module.

        Args:
            config: Configuration instance
        """
        self.config = config

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        pass

    @abstractmethod
    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Analyze a local PCAP file for this protocol.

        This method should be implemented by each module to perform
        the actual protocol-specific analysis.

        Args:
            pcap_file: Path to local PCAP file

        Returns:
            Analysis results dictionary
        """
        pass

    def analyze_packets(
        self,
        pcap_file: str,
        *,
        analyzer: Callable[[str], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Analyze packets from a PCAP file (local or remote).

        Args:
            pcap_file: Path to local PCAP file or HTTP URL to remote PCAP file
            analyzer: Optional request-specific analysis callback

        Returns:
            A structured dictionary containing packet analysis results
        """
        # Check if this is a remote URL or local file
        if pcap_file.startswith(("http://", "https://")):
            return self._handle_remote_analysis(pcap_file, analyzer=analyzer)
        else:
            return self._handle_local_analysis(pcap_file, analyzer=analyzer)

    def _handle_remote_analysis(
        self,
        pcap_url: str,
        *,
        analyzer: Callable[[str], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Handle remote PCAP file analysis."""
        temp_path = None
        local_path = None
        try:
            # Download remote file to temporary location
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_file:
                temp_path = tmp_file.name

            local_path = self._download_pcap_file(pcap_url, temp_path)
            return (analyzer or self._analyze_protocol_file)(local_path)

        except Exception as e:
            return {
                "error": f"Failed to download PCAP file '{pcap_url}': {str(e)}",
                "pcap_url": pcap_url,
            }
        finally:
            # Downloads and analysis can both fail after creating the file.
            for path in {temp_path, local_path}:
                if path is None:
                    continue
                try:
                    os.unlink(path)
                except OSError:
                    pass  # Ignore cleanup errors

    def _handle_local_analysis(
        self,
        pcap_file: str,
        *,
        analyzer: Callable[[str], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Handle local PCAP file analysis."""
        # Validate file exists
        if not os.path.exists(pcap_file):
            return {
                "error": f"PCAP file not found: {pcap_file}",
                "pcap_file": pcap_file,
            }

        # Validate file extension
        if not pcap_file.lower().endswith((".pcap", ".pcapng", ".cap")):
            return {
                "error": f"File '{pcap_file}' is not a supported PCAP file (.pcap/.pcapng/.cap)",
                "pcap_file": pcap_file,
            }

        try:
            return (analyzer or self._analyze_protocol_file)(pcap_file)
        except Exception as e:
            return {
                "error": f"Failed to analyze PCAP file '{pcap_file}': {str(e)}",
                "pcap_file": pcap_file,
            }

    def _download_pcap_file(self, pcap_url: str, local_path: str) -> str:
        """Download a remote PCAP file to local storage.

        Args:
            pcap_url: URL of the PCAP file to download
            local_path: Local path to save the file

        Returns:
            Local path to the downloaded file
        """
        import requests

        try:
            with requests.get(pcap_url, timeout=60, stream=True) as response:
                response.raise_for_status()

                os.makedirs(os.path.dirname(local_path), exist_ok=True)

                with open(local_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

            return local_path

        except requests.RequestException as e:
            raise ValueError(
                f"Failed to download PCAP file '{pcap_url}': {str(e)}"
            ) from e
