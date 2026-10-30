"""Step 2 acceptance: dns.cap counts and fields from docs/design.md."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

EXPECTED_FIRST_TS = 1112172466.496046
FIELD_KEYS = {
    "time",
    "src",
    "dst",
    "sport",
    "dport",
    "transport",
    "protocol",
    "flags",
    "length",
    "summary",
}


def _read_pcap(path: Path):
    # Imported inside tests so collection still works before pcap_reader exists.
    from elpa.pcap_reader import read_pcap

    return read_pcap(str(path))


def _utc_epoch(value: object) -> float:
    if isinstance(value, datetime):
        assert value.tzinfo is not None
        assert value.utcoffset() == timedelta(0)
        return value.timestamp()
    return float(value)  # type: ignore[arg-type]


def _conversation_key(record) -> tuple[str, tuple[str, str], tuple[str, str]]:
    fields = record.fields
    endpoints = sorted(
        (
            (fields["src"], fields["sport"]),
            (fields["dst"], fields["dport"]),
        )
    )
    return fields["transport"], endpoints[0], endpoints[1]


def test_dns_cap_counts_and_numbering(dns_cap: Path) -> None:
    result = _read_pcap(dns_cap)

    assert result.notices == []
    assert len(result.records) == 38
    assert [r.line_number for r in result.records] == list(range(1, 39))
    assert all(r.fields["protocol"] == "DNS" for r in result.records)
    assert all(r.fields["transport"] == "UDP" for r in result.records)
    assert all(r.fields["src"] and r.fields["dst"] for r in result.records)
    assert all(
        53 in (int(r.fields["sport"]), int(r.fields["dport"]))
        for r in result.records
    )
    assert len({_conversation_key(record) for record in result.records}) == 8


def test_dns_cap_first_packet(dns_cap: Path) -> None:
    result = _read_pcap(dns_cap)
    first = result.records[0]

    assert set(first.fields) >= FIELD_KEYS
    assert first.fields["src"] == "192.168.170.8"
    assert first.fields["dst"] == "192.168.170.20"
    assert int(first.fields["sport"]) == 32795
    assert int(first.fields["dport"]) == 53
    assert first.fields["protocol"] == "DNS"
    assert first.fields["transport"] == "UDP"
    assert first.fields["flags"] in (None, "")
    assert int(first.fields["length"]) == 70
    assert first.fields["summary"] == "Ethernet / IP / UDP / DNS"
    assert _utc_epoch(first.fields["time"]) == pytest.approx(
        EXPECTED_FIRST_TS, abs=1e-6
    )
