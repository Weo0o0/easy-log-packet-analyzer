from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import subprocess
import sys
from pathlib import Path

import dpkt

from elpa.conversations import build_conversations
from elpa.pcap_reader import read_pcap
from elpa.text_reader import read_text_log


DOC_IP_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


IPV4_RE = re.compile(r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")

DNS_NAME_RE = re.compile(r"(?:^|\.)(?:example\.(?:com|net|org)|example|test)$")


def _is_doc_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return any(ip in net for net in DOC_IP_NETS)


def _is_doc_dns_name(name: str | bytes) -> bool:
    if isinstance(name, bytes):
        name = name.decode()
    return bool(DNS_NAME_RE.search(name))


def test_all_files_have_source_and_license_lines_in_readme():
    repo_root = Path(__file__).resolve().parents[1]
    examples_dir = repo_root / "examples"
    readme = examples_dir / "README.md"
    content = readme.read_text(encoding="utf-8")

    for path in examples_dir.rglob("*"):
        if path.is_dir():
            continue
        if path.name == "README.md":
            continue
        rel_str = path.relative_to(examples_dir).as_posix()
        rows = [
            line for line in content.splitlines()
            if line.startswith("|") and rel_str in line
        ]
        assert rows, f"{rel_str} has no row in examples/README.md"
        cells = [c.strip() for c in rows[0].strip().strip("|").split("|")]
        assert len(cells) >= 4, f"{rel_str} row missing source/license columns"
        source, license_ = cells[2], cells[3]
        assert source, f"{rel_str} has no source line in examples/README.md"
        assert license_, f"{rel_str} has no license line in examples/README.md"
        expected_license = "Apache-2.0" if rel_str.startswith("apache_logs/") else "MIT"
        assert expected_license in license_, f"{rel_str} wrong license {license_!r}"


def test_synthetic_files_only_doc_ips_in_text_and_pcaps():
    repo_root = Path(__file__).resolve().parents[1]
    examples_dir = repo_root / "examples"

    for text_path in [
        examples_dir / "ssh_repeated_fail" / "auth.log",
        examples_dir / "README.md",
    ]:
        for m in IPV4_RE.findall(text_path.read_text(encoding="utf-8")):
            assert _is_doc_ip(m), f"non-doc IP {m} in {text_path}"

    for pcap_path in [
        examples_dir / "dns_query_answer" / "dns_query_answer.pcap",
        examples_dir / "udp_one_side" / "udp_one_side.pcap",
    ]:
        with pcap_path.open("rb") as f:
            for _ts, buf in dpkt.pcap.Reader(f):
                cur = dpkt.ethernet.Ethernet(buf)
                while True:
                    if isinstance(cur, dpkt.ip.IP):
                        for ipb in (cur.src, cur.dst):
                            ipstr = socket.inet_ntop(socket.AF_INET, ipb)
                            assert _is_doc_ip(ipstr), f"non-doc IP {ipstr} in {pcap_path}"
                    if isinstance(cur, dpkt.udp.UDP):
                        dns = dpkt.dns.DNS(cur.data)
                        for question in dns.qd:
                            assert _is_doc_dns_name(question.name), (
                                f"non-example DNS name {question.name!r} in {pcap_path}"
                            )
                        for answer in dns.an:
                            assert _is_doc_dns_name(answer.name), (
                                f"non-example DNS name {answer.name!r} in {pcap_path}"
                            )
                            if answer.type == dpkt.dns.DNS_A:
                                addr = socket.inet_ntop(socket.AF_INET, answer.rdata)
                                assert _is_doc_ip(addr), f"non-doc DNS A {addr} in {pcap_path}"
                    data = getattr(cur, "data", None)
                    if data is None or isinstance(data, (bytes, bytearray)):
                        break
                    cur = data


def test_make_examples_twice_identical_to_committed(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    examples_dir = repo_root / "examples"
    make_examples = repo_root / "tools" / "make_examples.py"
    py = sys.executable

    out1 = tmp_path / "out1"
    out2 = tmp_path / "out2"
    out1.mkdir()
    out2.mkdir()

    subprocess.run([py, str(make_examples), str(out1)], check=True, cwd=str(repo_root))
    subprocess.run([py, str(make_examples), str(out2)], check=True, cwd=str(repo_root))

    gen_files = [
        ("ssh_repeated_fail/auth.log", examples_dir / "ssh_repeated_fail" / "auth.log"),
        ("dns_query_answer/dns_query_answer.pcap", examples_dir / "dns_query_answer" / "dns_query_answer.pcap"),
        ("udp_one_side/udp_one_side.pcap", examples_dir / "udp_one_side" / "udp_one_side.pcap"),
    ]
    for rel, committed in gen_files:
        b1 = (out1 / rel).read_bytes()
        b2 = (out2 / rel).read_bytes()
        bc = committed.read_bytes()
        assert b1 == b2, f"{rel} not identical between runs"
        assert b1 == bc, f"{rel} differs from committed"


def test_all_example_files_le_10mb():
    repo_root = Path(__file__).resolve().parents[1]
    examples_dir = repo_root / "examples"
    for path in examples_dir.rglob("*"):
        if path.is_dir():
            continue
        size = path.stat().st_size
        assert size <= 10 * 1024 * 1024, f"{path} too large: {size}"


def test_pinned_counts_with_readers():
    repo_root = Path(__file__).resolve().parents[1]
    examples_dir = repo_root / "examples"

    r_ap = read_text_log(str(examples_dir / "apache_logs" / "apache_logs"), "access")
    assert len(r_ap.records) == 10000
    status_counts = {}
    for rec in r_ap.records:
        st = rec.fields.get("status")
        status_counts[st] = status_counts.get(st, 0) + 1
    assert status_counts.get("404") == 213

    r_sh = read_text_log(str(examples_dir / "ssh_repeated_fail" / "auth.log"), "sshd")
    assert len(r_sh.records) == 12
    kinds = [rec.kind for rec in r_sh.records]
    assert kinds.count("sshd 실패") == 8
    for rec in r_sh.records:
        if rec.kind == "sshd 실패":
            assert rec.fields.get("srcip") == "203.0.113.50"
    assert kinds.count("sshd 성공") == 1

    pr_d = read_pcap(str(examples_dir / "dns_query_answer" / "dns_query_answer.pcap"))
    cs_d = build_conversations(pr_d.records)
    assert len(pr_d.records) == 2
    assert len(cs_d) == 1
    c_d = cs_d[0]
    assert c_d.protocol == "UDP"
    assert c_d.b.endswith(":53")
    assert c_d.state == "SF"
    assert c_d.history == "Dd"

    pr_u = read_pcap(str(examples_dir / "udp_one_side" / "udp_one_side.pcap"))
    cs_u = build_conversations(pr_u.records)
    assert len(pr_u.records) == 1
    assert len(cs_u) == 1
    c_u = cs_u[0]
    assert c_u.protocol == "UDP"
    assert c_u.b.endswith(":53")
    assert c_u.state == "S0"
    assert c_u.history == "D"


def test_apache_sha256_and_license():
    repo_root = Path(__file__).resolve().parents[1]
    examples_dir = repo_root / "examples"
    apache_path = examples_dir / "apache_logs" / "apache_logs"
    source_md = (examples_dir / "apache_logs" / "SOURCE.md").read_text(encoding="utf-8")
    m = re.search(r"SHA-256:\s*`?([0-9a-fA-F]{64})`?", source_md)
    assert m is not None
    expected = m.group(1).lower()
    h = hashlib.sha256(apache_path.read_bytes()).hexdigest()
    assert h == expected

    lic = (examples_dir / "apache_logs" / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in lic
    assert "Version 2.0" in lic
