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
    transport: str = "UDP",
    protocol: str = "DNS",
    src: str = "192.0.2.1",
    dst: str = "198.51.100.2",
    sport: str = "12345",
    dport: str = "53",
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
            "transport": transport,
            "protocol": protocol,
            "flags": None,
            "length": length,
        },
    )


def test_dns_cap_conversations(dns_cap: Path) -> None:
    from elpa.conversations import build_conversations

    conversations = build_conversations(_read_pcap(dns_cap))

    expected = [
        ("udp-0", "192.168.170.8:32795", "192.168.170.20:53", 24, "SF", "Dd"),
        ("udp-1", "192.168.170.8:32796", "192.168.170.20:53", 2, "SF", "Dd"),
        ("udp-2", "192.168.170.8:32797", "192.168.170.20:53", 2, "SF", "Dd"),
        ("udp-3", "192.168.170.56:1707", "217.13.4.24:53", 2, "SF", "Dd"),
        ("udp-4", "192.168.170.56:1708", "217.13.4.24:53", 2, "SF", "Dd"),
        ("udp-5", "192.168.170.56:1709", "217.13.4.24:53", 2, "SF", "Dd"),
        ("udp-6", "192.168.170.56:1710", "217.13.4.24:53", 2, "SF", "Dd"),
        ("udp-7", "192.168.170.56:1711", "217.13.4.24:53", 2, "SF", "Dd"),
    ]
    assert len(conversations) == 8
    assert all((c.uid, c.a, c.b, c.packets, c.state, c.history) == row for c, row in zip(conversations, expected, strict=True))
    assert all(c.protocol == "UDP" and c.service == "DNS" for c in conversations)
    assert conversations[0].start == "2005-03-30T02:47:46.496046Z"


def test_conversation_fields_and_udp_directionality() -> None:
    from elpa.conversations import build_conversations

    conversations = build_conversations(
        [
            _record(1, length="60"),
            _record(2, transport="TCP", src="203.0.113.3", sport="80", dport="12345"),
            _record(
                3,
                src="198.51.100.2",
                dst="192.0.2.1",
                sport="53",
                dport="12345",
                length="70",
                seconds=1,
            ),
            _record(4, dst="203.0.113.4", seconds=2),
        ]
    )

    udp, tcp, one_way = conversations
    assert (udp.uid, udp.protocol, udp.service) == ("udp-0", "UDP", "DNS")
    assert (udp.a, udp.b, udp.history, udp.state) == (
        "192.0.2.1:12345",
        "198.51.100.2:53",
        "Dd",
        "SF",
    )
    assert udp.bytes == 130
    assert udp.start == "2026-01-01T00:00:00Z"
    assert udp.duration == 1
    assert (tcp.uid, tcp.protocol, tcp.service, tcp.a, tcp.b) == (
        "tcp-0",
        "TCP",
        "DNS",
        "203.0.113.3:80",
        "198.51.100.2:12345",
    )
    assert (one_way.uid, one_way.history, one_way.state) == ("udp-1", "D", "S0")


def test_portless_and_other_transport_packets_are_ignored() -> None:
    from elpa.conversations import build_conversations

    conversations = build_conversations(
        [
            _record(1, sport=""),
            _record(2, dport=""),
            _record(3, transport="other"),
            _record(4),
        ]
    )

    assert len(conversations) == 1
    assert conversations[0].packets == 1
