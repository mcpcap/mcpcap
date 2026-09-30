"""Capture-based regressions for TCP tools and request isolation."""

import shutil
from concurrent.futures import ThreadPoolExecutor
from threading import Event, current_thread

import pytest
from scapy.all import IP, TCP, UDP, Ether, Padding, Raw, wrpcap

from mcpcap.core.config import Config
from mcpcap.modules import tcp as tcp_module
from mcpcap.modules.tcp import TCPModule

CLIENT = "192.0.2.10"
SERVER = "192.0.2.20"


def packet(flags="A", seq=101, ack=501, reverse=False, port=40000, payload=b""):
    src, dst = (SERVER, CLIENT) if reverse else (CLIENT, SERVER)
    sport, dport = (443, port) if reverse else (port, 443)
    result = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack
    )
    return result / Raw(load=payload) if payload else result


def capture(tmp_path, packets):
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), [Ether() / pkt for pkt in packets])
    return str(path)


def handshake():
    return [
        packet("S", seq=100, ack=0),
        packet("SA", seq=500, ack=101, reverse=True),
        packet(),
    ]


@pytest.mark.parametrize(
    "tool", ["analyze_tcp_anomalies", "analyze_tcp_retransmissions"]
)
def test_nested_connection_keys_work_for_ipv4_and_ipv6(tmp_path, tool):
    from scapy.all import IPv6

    packets = handshake() + [
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=40001, dport=80, flags="R", seq=100),
        packet("PA", payload=b"hello"),
        packet("PA", payload=b"hello"),
    ]
    result = getattr(TCPModule(Config()), tool)(capture(tmp_path, packets))
    assert "error" not in result
    if tool == "analyze_tcp_anomalies":
        assert result["statistics"]["total_connections"] == 2
        assert result["statistics"]["retransmissions"]["total"] == 1
        assert result["statistics"]["rst_distribution"]["connections_with_rst"]
    else:
        assert len(result["by_connection"]) == 2
        assert result["total_retransmissions"] == 1


@pytest.mark.parametrize(
    "packets, expected",
    [
        (handshake(), True),
        (handshake()[:2], False),
        (handshake()[::-1], False),
        ([handshake()[0], packet("SA", ack=999, reverse=True), packet()], False),
        ([*handshake()[:2], packet(ack=999)], False),
        ([*handshake()[:2], packet(seq=999)], False),
        ([*handshake()[:2], packet(reverse=True, seq=101, ack=501)], False),
        ([handshake()[0], packet("SA", seq=500, ack=101), packet()], False),
        ([*handshake()[:2], packet("R"), packet()], False),
        (
            [
                packet("S", seq=0xFFFFFFFF, ack=0),
                packet("SA", seq=0xFFFFFFFF, ack=0, reverse=True),
                packet(seq=0, ack=0),
            ],
            True,
        ),
    ],
)
def test_handshake_requires_order_direction_and_sequence_numbers(
    tmp_path, packets, expected
):
    result = TCPModule(Config()).analyze_tcp_connections(
        capture(tmp_path, packets), detailed=True
    )
    assert result["connections"][0]["handshake_completed"] is expected


@pytest.mark.parametrize(
    "packets, expected",
    [
        ([packet(), packet("PA", payload=b"hello")], 0),
        ([packet("S", seq=100), packet("PA", seq=100, payload=b"hello")], 0),
        (
            [packet("PA", payload=b"hello"), packet("PA", payload=b"hello")],
            1,
        ),
        (
            [packet("PA", payload=b"hello"), packet("PA", seq=104, payload=b"world")],
            1,
        ),
        (
            [packet("PA", payload=b"hello"), packet("PA", seq=106, payload=b"world")],
            0,
        ),
        (
            [
                packet("PA", payload=b"hello"),
                packet("PA", reverse=True, payload=b"hello"),
            ],
            0,
        ),
        (
            [
                packet("PA", payload=b"hello"),
                packet("PA", port=40001, payload=b"hello"),
            ],
            0,
        ),
        (
            [
                packet("PA", seq=0xFFFFFFFE, payload=b"abcd"),
                packet("PA", seq=0, payload=b"abcd"),
                packet("PA", seq=4, payload=b"abcd"),
            ],
            1,
        ),
        (
            [
                packet("PA", seq=110, payload=b"abcd"),
                packet("PA", seq=100, payload=b"abcd"),
                packet("PA", seq=102, payload=b"abcd"),
            ],
            1,
        ),
        (
            [
                packet("S", seq=100, payload=b"hello"),
                packet("PA", seq=101, payload=b"hello"),
            ],
            1,
        ),
    ],
)
def test_all_tools_count_only_overlapping_payload_per_connection_direction(
    tmp_path, packets, expected
):
    module = TCPModule(Config())
    path = capture(tmp_path, packets)
    connections = module.analyze_tcp_connections(path, detailed=True)
    assert sum(c["retransmissions"] for c in connections["connections"]) == expected
    assert module.analyze_tcp_retransmissions(path)["total_retransmissions"] == expected
    assert (
        module.analyze_tcp_anomalies(path)["statistics"]["retransmissions"]["total"]
        == expected
    )
    flow = module.analyze_traffic_flow(path, server_ip=SERVER)
    assert (
        flow["client_to_server"]["retransmissions"]
        + flow["server_to_client"]["retransmissions"]
        == expected
    )


def test_ethernet_padding_is_not_tcp_payload(tmp_path):
    module = TCPModule(Config())
    path = capture(
        tmp_path,
        [
            packet() / Padding(load=b"padding"),
            packet("PA", payload=b"abc") / Padding(load=b"padding"),
            packet("PA", seq=104, payload=b"def") / Padding(load=b"padding"),
        ],
    )
    connection = module.analyze_tcp_connections(path, detailed=True)["connections"][0]
    assert connection["data_packets"] == 2
    assert connection["retransmissions"] == 0
    assert module.analyze_tcp_retransmissions(path)["total_retransmissions"] == 0
    flow = module.analyze_traffic_flow(path, server_ip=SERVER)
    assert flow["client_to_server"]["data_packets"] == 2
    assert flow["client_to_server"]["retransmissions"] == 0


@pytest.mark.parametrize("remote", [False, True])
def test_concurrent_tools_keep_their_analysis_and_filters(
    tmp_path, monkeypatch, remote
):
    module = TCPModule(Config())
    packets = handshake() + [
        IP(src="198.51.100.10", dst="198.51.100.20")
        / TCP(sport=12345, dport=80, flags="PA", seq=50)
        / Raw(load=b"data")
    ]
    path = capture(tmp_path, packets)
    downloaded = []
    if remote:

        def download(url, local_path):
            shutil.copyfile(path, local_path)
            downloaded.append(local_path)
            return local_path

        monkeypatch.setattr(module, "_download_pcap_file", download)
    source = "https://example.test/capture.pcap" if remote else path
    entered, release = Event(), Event()
    original = module._analyze_protocol_file

    def delayed_analyze(*args, **kwargs):
        if current_thread().name.startswith("tcp-request"):
            entered.set()
            assert release.wait(5), "Concurrent analysis did not release the first call"
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "_analyze_protocol_file", delayed_analyze)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="tcp-request") as pool:
        first = pool.submit(
            module.analyze_tcp_connections,
            source,
            server_ip=SERVER,
            server_port=443,
            detailed=True,
        )
        try:
            assert entered.wait(5)
            second = module.analyze_tcp_retransmissions(
                source, server_ip="198.51.100.20", threshold=0.5
            )
        finally:
            release.set()
        result = first.result(timeout=5)
    assert result["filter"] == {"server_ip": SERVER, "server_port": 443}
    assert result["summary"]["successful_handshakes"] == 1
    assert result["tcp_packets_found"] == 3
    assert second["threshold"] == 0.5
    assert second["total_packets"] == 1
    if remote:
        from pathlib import Path

        assert all(not Path(filename).exists() for filename in downloaded)


@pytest.mark.parametrize(
    "count, limit, truncated", [(5, 2, True), (2, 2, False), (5, None, False)]
)
def test_packet_limit_bounds_reading_before_protocol_and_ip_filtering(
    tmp_path, monkeypatch, count, limit, truncated
):
    packets = [IP(src=CLIENT, dst=SERVER) / UDP(sport=123, dport=123)] + [
        packet(seq=index) for index in range(count - 1)
    ]
    path = capture(tmp_path, packets)
    original = tcp_module.PcapReader
    yielded = []

    class CountingReader:
        def __init__(self, filename):
            self.reader = original(filename)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.reader.close()

        def __iter__(self):
            for pkt in self.reader:
                yielded.append(pkt)
                yield pkt

    monkeypatch.setattr(tcp_module, "PcapReader", CountingReader)
    result = TCPModule(Config(max_packets=limit)).analyze_tcp_connections(
        path, server_ip=SERVER, detailed=True
    )
    analyzed = min(count, limit) if limit else count
    assert result["packets_analyzed"] == analyzed
    assert result["truncated"] is truncated
    assert result["max_packets"] == limit
    assert result["tcp_packets_found"] == analyzed - 1
    assert len(yielded) == analyzed + int(truncated)


def test_truncation_metadata_when_limit_precedes_tcp(tmp_path):
    path = capture(tmp_path, [IP() / UDP(), packet()])
    result = TCPModule(Config(max_packets=1)).analyze_tcp_anomalies(path)
    assert result["tcp_packets_found"] == 0
    assert result["truncated"] is True
    assert result["packets_analyzed"] == 1
