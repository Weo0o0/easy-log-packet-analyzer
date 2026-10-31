"""Step 6 acceptance: FilterCond, load_filters, apply_filters, to_wireshark, to_tshark, to_awk."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from elpa.filters import (
    FilterCond,
    apply_filters,
    load_filters,
    to_awk,
    to_tshark,
    to_wireshark,
)
from elpa.models import Record
from elpa.pcap_reader import read_pcap
from elpa.text_reader import read_text_log

ROOT = Path(__file__).resolve().parents[1]
FILTERS_YAML = ROOT / "filters.yaml"


def test_dns_cap_port_53_returns_38_records(dns_cap: Path) -> None:
    records = read_pcap(str(dns_cap)).records
    filtered = apply_filters(records, [FilterCond("port", "==", "53")])
    assert len(filtered) == 38
    assert [r.line_number for r in filtered] == list(range(1, 39))


def test_port_matches_sport_or_dport_and_combines_with_and() -> None:
    r1 = Record(1, "DNS", {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": "53", "dport": "12345", "protocol": "DNS"})
    r2 = Record(2, "DNS", {"src": "10.0.0.2", "dst": "10.0.0.1", "sport": "12345", "dport": "53", "protocol": "DNS"})
    r3 = Record(3, "TCP", {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": "12345", "dport": "80", "protocol": "TCP"})

    assert [r.line_number for r in apply_filters([r1, r2, r3], [FilterCond("port", "==", "53")])] == [1, 2]
    assert [
        r.line_number
        for r in apply_filters(
            [r1, r2, r3],
            [FilterCond("port", "==", "53"), FilterCond("src", "==", "10.0.0.2")],
        )
    ] == [2]


def test_apache_logs_status_404_matches_awk_line_count(apache_log: Path) -> None:
    records = read_text_log(str(apache_log), "access").records
    conds = [FilterCond("status", "==", "404")]
    filtered = apply_filters(records, conds)
    assert len(filtered) == 213

    table = load_filters(FILTERS_YAML)
    assert to_awk(conds, table, "apache_logs") == 'awk \'$9 == "404"\' apache_logs'

    cmd = to_awk(conds, table, str(apache_log))
    assert cmd is not None
    proc = subprocess.run(
        shlex.split(cmd),
        capture_output=True,
        text=True,
        check=True,
    )
    awk_lines = [line for line in proc.stdout.splitlines() if line]
    assert len(awk_lines) == len(filtered) == 213


def test_wireshark_and_tshark_exact_strings() -> None:
    table = load_filters(FILTERS_YAML)

    assert (
        to_wireshark([FilterCond("port", "==", "53")], table)
        == "udp.port == 53 || tcp.port == 53"
    )
    assert (
        to_tshark([FilterCond("port", "==", "53")], table, "dns.cap")
        == 'tshark -r dns.cap -Y "udp.port == 53 || tcp.port == 53"'
    )
    assert (
        to_wireshark([FilterCond("src", "==", "192.168.170.8")], table)
        == "ip.src == 192.168.170.8"
    )
    assert (
        to_wireshark([FilterCond("dst", "==", "192.168.170.20")], table)
        == "ip.dst == 192.168.170.20"
    )
    assert (
        to_wireshark([FilterCond("src", "==", "2001:db8::1")], table)
        == "ipv6.src == 2001:db8::1"
    )
    assert (
        to_wireshark([FilterCond("dst", "==", "fe80::1")], table)
        == "ipv6.dst == fe80::1"
    )
    assert (
        to_wireshark([FilterCond("protocol", "==", "DNS")], table)
        == "dns"
    )
    assert (
        to_wireshark(
            [
                FilterCond("src", "==", "192.168.170.8"),
                FilterCond("port", "==", "53"),
            ],
            table,
        )
        == "ip.src == 192.168.170.8 && (udp.port == 53 || tcp.port == 53)"
    )


def test_missing_translation_returns_none() -> None:
    table = load_filters(FILTERS_YAML)
    assert to_wireshark([FilterCond("status", "==", "404")], table) is None
    assert to_tshark([FilterCond("status", "==", "404")], table, "dns.cap") is None
    assert to_awk([FilterCond("port", "==", "53")], table, "apache_logs") is None
    assert to_wireshark([FilterCond("unknown", "==", "1")], table) is None


def test_missing_or_bad_filters_yaml_does_not_crash(tmp_path: Path) -> None:
    notices: list[str] = []
    missing_table = load_filters(tmp_path / "no_such_filters.yaml", notices)
    assert missing_table == {}
    assert len(notices) == 1
    assert to_wireshark([FilterCond("port", "==", "53")], missing_table) is None
    assert to_tshark([FilterCond("port", "==", "53")], missing_table, "dns.cap") is None
    assert to_awk([FilterCond("status", "==", "404")], missing_table, "apache_logs") is None

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("- not\n- a\n- dict\n", encoding="utf-8")
    bad_notices: list[str] = []
    assert load_filters(bad_yaml, bad_notices) == {}
    assert len(bad_notices) == 1


def test_filename_quoting_and_unsafe_value_rejection() -> None:
    table = load_filters(FILTERS_YAML)
    cmd = to_tshark([FilterCond("port", "==", "53")], table, "my file; rm -rf /.pcap")
    assert cmd == 'tshark -r \'my file; rm -rf /.pcap\' -Y "udp.port == 53 || tcp.port == 53"'

    assert to_wireshark([FilterCond("src", "==", '1.2.3.4"; id #')], table) is None
    assert to_awk([FilterCond("status", "==", '404" || system("id")')], table, "apache_logs") is None
