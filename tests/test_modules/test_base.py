"""Regression tests for remote downloads and per-request analysis callbacks."""

import tempfile
from unittest.mock import Mock

import pytest
import requests

from mcpcap.core.config import Config
from mcpcap.modules.base import BaseModule


class RecordingModule(BaseModule):
    """Simple analyzer that records the file supplied by the base module."""

    protocol_name = "TEST"

    def _analyze_protocol_file(self, pcap_file):
        with open(pcap_file, "rb") as capture:
            return {"capture": capture.read()}


@pytest.mark.parametrize("failure", [None, "request", "status", "stream", "analysis"])
def test_remote_analysis_cleans_up_files_and_responses(tmp_path, monkeypatch, failure):
    """Release response connections and delete partial files on every exit path."""
    original_tempfile = tempfile.NamedTemporaryFile
    monkeypatch.setattr(
        "mcpcap.modules.base.tempfile.NamedTemporaryFile",
        lambda **kwargs: original_tempfile(dir=tmp_path, **kwargs),
    )
    response = requests.Response()
    response.status_code = 404 if failure == "status" else 200
    response.url = "https://example.test/capture.pcap"
    response.raw = Mock()

    def chunks(*args, **kwargs):
        yield b"partial capture"
        if failure == "stream":
            raise requests.ConnectionError("stream interrupted")
        yield b" complete"

    response.raw.stream = chunks
    get = Mock(return_value=response)
    if failure == "request":
        get.side_effect = requests.ConnectionError("connection failed")
    monkeypatch.setattr(requests, "get", get)
    module = RecordingModule(Config())
    if failure == "analysis":
        monkeypatch.setattr(
            module,
            "_analyze_protocol_file",
            Mock(side_effect=ValueError("bad capture")),
        )

    result = module.analyze_packets(response.url)

    assert list(tmp_path.iterdir()) == []
    if failure:
        assert "error" in result
        assert result["pcap_url"] == response.url
    else:
        assert result == {"capture": b"partial capture complete"}
    if failure != "request":
        response.raw.release_conn.assert_called_once()
    get.assert_called_once_with(response.url, timeout=60, stream=True)


@pytest.mark.parametrize("remote", [False, True])
def test_analysis_callback_applies_to_local_and_remote_files(
    tmp_path, monkeypatch, remote
):
    """The caller's analyzer receives the local capture, including downloads."""
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    module = RecordingModule(Config())
    if remote:

        def download(url, local_path):
            with open(local_path, "wb") as output:
                output.write(b"capture")
            return local_path

        monkeypatch.setattr(module, "_download_pcap_file", download)
    callback = Mock(return_value={"request_specific": True})

    result = module.analyze_packets(
        "https://example.test/capture.pcap" if remote else str(capture),
        analyzer=callback,
    )

    assert result == {"request_specific": True}
    callback.assert_called_once()
    if not remote:
        callback.assert_called_once_with(str(capture))
