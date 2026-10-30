"""Step 3 acceptance: packet conversations from docs/design.md."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from elpa.models import Record


def _read_pcap(path: Path) -> list[Record]:
    from elpa.pcap_reader import read_pcap

    return read_pcap(str(path)).records


def _record(
    number: int,
    *,
    protocol: str = "UDP",
    src: str | None = "192.0.2.1",
    dst: str | None = "198.51.100.2",
    sport: str | None = "12345",
    dport: str | None = "53",
    length: str = "60",
    seconds: int = 0,
) -> Record:
    return Record(
        line_number=number,
        kind=protocol,
        fields={
            "time": datetime(2026, 1, 1, tzinfo=timezone.utc)
            + timedelta(seconds=seconds),
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "protocol": protocol,
            "flags": None,
            "length": length,
        },
    )


def test_dns_cap_conversations(dns_cap: Path) -> None:
    from elpa.conversations import build_conversations

    conversations = build_conversations(_read_pcap(dns_cap))

    assert len(conversations) == 8
    assert [c.stream for c in conversations] == list(range(8))
    assert all(c.protocol == "UDP" for c in conversations)
    largest = max(conversations, key=lambda c: c.packets)
    assert (largest.a, largest.b) == (
        "192.168.170.20:53",
        "192.168.170.8:32795",
    )
    assert largest.packets == 24


def test_bidirectional_packets_merge_and_sum_bytes() -> None:
    from elpa.conversations import build_conversations

    conversations = build_conversations(
        [
            _record(1, length="60", seconds=0),
            _record(
                2,
                src="198.51.100.2",
                dst="192.0.2.1",
                sport="53",
                dport="12345",
                length="70",
                seconds=1,
            ),
        ]
    )

    assert len(conversations) == 1
    conversation = conversations[0]
    assert (conversation.a, conversation.b) == (
        "192.0.2.1:12345",
        "198.51.100.2:53",
    )
    assert conversation.packets == 2
    assert conversation.bytes == 130


def test_stream_numbers_are_separate_per_transport() -> None:
    from elpa.conversations import build_conversations

    conversations = build_conversations(
        [
            _record(1, protocol="TCP"),
            _record(2, protocol="UDP"),
            _record(3, protocol="TCP", dst="203.0.113.3"),
            _record(4, protocol="UDP", dst="203.0.113.3"),
        ]
    )

    assert [(c.protocol, c.stream) for c in conversations] == [
        ("TCP", 0),
        ("UDP", 0),
        ("TCP", 1),
        ("UDP", 1),
    ]


def test_portless_packets_are_ignored() -> None:
    from elpa.conversations import build_conversations

    conversations = build_conversations(
        [
            _record(1, sport=None),
            _record(2, dport=None),
            _record(3),
        ]
    )

    assert len(conversations) == 1
    assert conversations[0].packet_numbers == (3,)


def test_empty_input_returns_no_conversations() -> None:
    from elpa.conversations import build_conversations

    assert build_conversations([]) == []
