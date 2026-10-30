"""Step 2 error handling: notices for bad, truncated, oversized and pcapng input."""

from __future__ import annotations

import struct
import dpkt
from pathlib import Path

import pytest

from elpa.limits import MAX_FILE_BYTES


def _read_pcap(path: Path):
    # Imported inside tests so collection still works before pcap_reader exists.
    from elpa.pcap_reader import read_pcap

    return read_pcap(str(path))


def _global_header(network: int) -> bytes:
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, network)


def _record(payload: bytes, ts: int = 1112172466, usec: int = 496046) -> bytes:
    return struct.pack("<IIII", ts, usec, len(payload), len(payload)) + payload


def _pcap(packets: list[bytes], network: int = 1) -> bytes:
    return _global_header(network) + b"".join(_record(p) for p in packets)


def _udp_frame() -> bytes:
    payload = b"hello"
    udp = struct.pack("!HHHH", 12345, 53, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        0,
        0,
        64,
        17,
        0,
        bytes([192, 0, 2, 1]),
        bytes([198, 51, 100, 2]),
    )
    ethernet = (
        bytes.fromhex("001122334455")
        + bytes.fromhex("66778899aabb")
        + struct.pack("!H", 0x0800)
    )
    return ethernet + ip + udp


def test_truncated_file_returns_read_packets_and_notice(
    dns_cap: Path, tmp_path: Path
) -> None:
    path = tmp_path / "truncated.pcap"
    path.write_bytes(dns_cap.read_bytes()[:500])

    result = _read_pcap(path)

    assert len(result.records) == 4
    assert any("잘려" in n and "4개" in n for n in result.notices)


def test_huge_packet_caplen_is_bounded_and_warned(tmp_path: Path) -> None:
    path = tmp_path / "huge-caplen.pcap"
    path.write_bytes(_global_header(1) + struct.pack("<IIII", 0, 0, 0xFFFFFFFF, 0xFFFFFFFF))

    result = _read_pcap(path)

    assert result.records == []
    assert any("잘려" in n for n in result.notices)


def test_not_pcap_returns_no_records_and_notice(tmp_path: Path) -> None:
    path = tmp_path / "not.pcap"
    path.write_bytes(b"this is not a pcap file\n")

    result = _read_pcap(path)

    assert result.records == []
    assert any("pcap 파일이 아닙니다" in n for n in result.notices)


def test_unknown_link_type_is_raw_with_notice(tmp_path: Path) -> None:
    path = tmp_path / "unknown-link.pcap"
    path.write_bytes(_pcap([bytes(range(60))], network=999))

    result = _read_pcap(path)

    assert len(result.records) == 1
    assert result.records[0].fields["protocol"] == "Raw"
    assert result.records[0].fields["transport"] == "other"
    assert any("링크" in n for n in result.notices)


def test_pcapng_reads_packets(tmp_path: Path) -> None:
    path = tmp_path / "sample.pcapng"
    with path.open("wb") as f:
        writer = dpkt.pcapng.Writer(f)
        writer.writepkt(_udp_frame(), ts=1112172466.496046)

    result = _read_pcap(path)

    assert result.notices == []
    assert len(result.records) == 1
    assert result.records[0].line_number == 1
    assert result.records[0].fields["transport"] == "UDP"


def test_truncated_pcapng_returns_partial_records_and_notice(tmp_path: Path) -> None:
    path = tmp_path / "truncated.pcapng"
    with path.open("wb") as f:
        writer = dpkt.pcapng.Writer(f)
        writer.writepkt(_udp_frame(), ts=1)
        writer.writepkt(_udp_frame(), ts=2)
    path.write_bytes(path.read_bytes()[:-5])

    result = _read_pcap(path)

    assert len(result.records) == 1
    assert any("잘려" in n and "1개" in n for n in result.notices)


def test_oversized_file_is_rejected_with_notice(tmp_path: Path) -> None:
    path = tmp_path / "big.pcap"
    with path.open("wb") as f:
        f.seek(MAX_FILE_BYTES)
        f.write(b"\0")

    result = _read_pcap(path)

    assert result.records == []
    assert any("제한을 초과" in n for n in result.notices)
