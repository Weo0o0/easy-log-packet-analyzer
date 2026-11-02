from __future__ import annotations

import argparse
import socket
from pathlib import Path

import dpkt

SSHD_LOG = """\
Jan 15 09:00:01 srv1 sshd[1001]: Failed password for invalid user ftpuser from 203.0.113.50 port 51001 ssh2
Jan 15 09:00:03 srv1 sshd[1002]: Failed password for invalid user guest from 203.0.113.50 port 51002 ssh2
Jan 15 09:00:05 srv1 sshd[1003]: Failed password for admin from 203.0.113.50 port 51003 ssh2
Jan 15 09:00:07 srv1 sshd[1004]: Failed password for root from 203.0.113.50 port 51004 ssh2
Jan 15 09:00:09 srv1 sshd[1005]: Failed password for test from 203.0.113.50 port 51005 ssh2
Jan 15 09:00:11 srv1 sshd[1006]: Failed password for oracle from 203.0.113.50 port 51006 ssh2
Jan 15 09:00:13 srv1 sshd[1007]: Failed password for postgres from 203.0.113.50 port 51007 ssh2
Jan 15 09:00:15 srv1 sshd[1008]: Failed password for ubuntu from 203.0.113.50 port 51008 ssh2
Jan 15 09:05:01 srv1 sshd[1009]: Accepted password for alice from 192.0.2.10 port 52001 ssh2
Jan 15 09:05:01 srv1 sshd[1009]: pam_unix(sshd:session): session opened for user alice by (uid=0)
Jan 15 09:20:00 srv1 sshd[1009]: pam_unix(sshd:session): session closed for user alice
Jan 15 09:20:01 srv1 sshd[1010]: Received disconnect from 192.0.2.10 port 52001:11: disconnected by user
"""


def _ethernet(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload: bytes,
    src_mac: bytes,
    dst_mac: bytes,
) -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_UDP,
        ttl=64,
        data=udp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=src_mac, dst=dst_mac, type=dpkt.ethernet.ETH_TYPE_IP, data=ip
    )
    return bytes(eth)


def _dns_query(name: str, ident: int) -> bytes:
    dns = dpkt.dns.DNS()
    dns.id = ident
    dns.qr = dpkt.dns.DNS_Q
    dns.qd = [dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A)]
    return bytes(dns)


def _dns_answer(name: str, ident: int, address: str) -> bytes:
    dns = dpkt.dns.DNS()
    dns.id = ident
    dns.qr = dpkt.dns.DNS_R
    dns.qd = [dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A)]
    dns.an = [
        dpkt.dns.DNS.RR(
            name=name,
            type=dpkt.dns.DNS_A,
            ttl=300,
            rdata=socket.inet_aton(address),
        )
    ]
    return bytes(dns)


def _write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        writer = dpkt.pcap.Writer(f)
        for ts, buf in packets:
            writer.writepkt(buf, ts=ts)
        writer.close()


def make_ssh(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        f.write(SSHD_LOG)


def make_dns_query_answer(path: Path) -> None:
    client_ip, client_mac = "192.0.2.10", b"\x02\x00\x00\x00\x00\x01"
    server_ip, server_mac = "198.51.100.53", b"\x02\x00\x00\x00\x00\x02"
    query = _dns_query("example.com", 0x1234)
    answer = _dns_answer("example.com", 0x1234, "203.0.113.10")
    _write_pcap(
        path,
        [
            (
                1767225600.000000,
                _ethernet(client_ip, server_ip, 53000, 53, query, client_mac, server_mac),
            ),
            (
                1767225600.100000,
                _ethernet(server_ip, client_ip, 53, 53000, answer, server_mac, client_mac),
            ),
        ],
    )


def make_udp_one_side(path: Path) -> None:
    client_ip, client_mac = "203.0.113.20", b"\x02\x00\x00\x00\x00\x03"
    server_ip, server_mac = "192.0.2.53", b"\x02\x00\x00\x00\x00\x04"
    query = _dns_query("example.net", 0x5678)
    _write_pcap(
        path,
        [
            (
                1767225601.000000,
                _ethernet(client_ip, server_ip, 54000, 53, query, client_mac, server_mac),
            ),
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the synthetic examples.")
    parser.add_argument("output", nargs="?", default="examples")
    args = parser.parse_args()

    out = Path(args.output)
    make_ssh(out / "ssh_repeated_fail" / "auth.log")
    make_dns_query_answer(out / "dns_query_answer" / "dns_query_answer.pcap")
    make_udp_one_side(out / "udp_one_side" / "udp_one_side.pcap")


if __name__ == "__main__":
    main()
