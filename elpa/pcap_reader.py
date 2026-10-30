from __future__ import annotations

import os
import socket
from typing import Any

import dpkt

from elpa.limits import open_checked
from elpa.models import ParseResult, Record

_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_TCP_FLAG_BITS = (
    (dpkt.tcp.TH_FIN, "F"),
    (dpkt.tcp.TH_SYN, "S"),
    (dpkt.tcp.TH_RST, "R"),
    (dpkt.tcp.TH_PUSH, "P"),
    (dpkt.tcp.TH_ACK, "A"),
    (dpkt.tcp.TH_URG, "U"),
    (dpkt.tcp.TH_ECE, "E"),
    (dpkt.tcp.TH_CWR, "C"),
)


def _inet_str(addr: bytes) -> str | None:
    if len(addr) == 4:
        return socket.inet_ntop(socket.AF_INET, addr)
    if len(addr) == 16:
        return socket.inet_ntop(socket.AF_INET6, addr)
    return None


def _tcp_flags(flags: int) -> str:
    return "".join(ch for bit, ch in _TCP_FLAG_BITS if flags & bit)


def _layer_name(obj: Any) -> str:
    name = type(obj).__name__
    if name == "IP6":
        return "IPv6"
    return name


def _try_dns(payload: bytes) -> dpkt.dns.DNS | None:
    try:
        return dpkt.dns.DNS(payload)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return None


def _parse_packet(buf: bytes, ethernet: bool) -> tuple[str, dict[str, str | None]]:
    empty: dict[str, str | None] = {
        "src": None,
        "dst": None,
        "sport": None,
        "dport": None,
        "protocol": "Raw",
        "flags": None,
        "length": str(len(buf)),
        "summary": "Raw",
    }
    if not ethernet:
        return "Raw", empty

    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        raise

    names: list[str] = []
    src = dst = sport = dport = flags = None
    cur: Any = eth
    while True:
        names.append(_layer_name(cur))
        if isinstance(cur, (dpkt.ip.IP, dpkt.ip6.IP6)):
            src = _inet_str(cur.src)
            dst = _inet_str(cur.dst)
        if isinstance(cur, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            sport = str(cur.sport)
            dport = str(cur.dport)
            if isinstance(cur, dpkt.tcp.TCP):
                flags = _tcp_flags(cur.flags)
            payload = cur.data
            if isinstance(payload, (bytes, bytearray)) and payload:
                if cur.sport == 53 or cur.dport == 53:
                    dns = _try_dns(bytes(payload))
                    if dns is not None:
                        names.append("DNS")
            break
        data = getattr(cur, "data", None)
        if data is None or isinstance(data, (bytes, bytearray)):
            break
        cur = data

    protocol = names[-1] if names else "Raw"
    return protocol, {
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "protocol": protocol,
        "flags": flags,
        "length": str(len(buf)),
        "summary": " / ".join(names) if names else "Raw",
    }


def read_pcap(path: str) -> ParseResult:
    """Read a classic pcap file into Records. pcapng is not supported yet."""
    try:
        f = open_checked(path)
    except ValueError as e:
        return ParseResult(records=[], unparsed=0, notices=[str(e)])

    notices: list[str] = []
    records: list[Record] = []
    with f:
        magic = f.read(4)
        if magic == _PCAPNG_MAGIC:
            return ParseResult(
                records=[],
                unparsed=0,
                notices=["pcapng는 아직 지원 안 함"],
            )
        f.seek(0)
        try:
            reader = dpkt.pcap.Reader(f)
        except (ValueError, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return ParseResult(records=[], unparsed=0, notices=["pcap 파일이 아닙니다"])

        ethernet = reader.datalink() == dpkt.pcap.DLT_EN10MB
        if not ethernet:
            notices.append("모르는 링크 타입이라 Raw로 읽었습니다")

        # shortcut: dpkt.Reader private attrs — yields short buf on EOF with no error; check caplen.
        fh = reader._Reader__f
        ph = reader._Reader__ph
        hdr_len = ph.__hdr_len__
        divisor = reader._divisor
        line_number = 0
        try:
            while True:
                hbuf = fh.read(hdr_len)
                if not hbuf:
                    break
                if len(hbuf) < hdr_len:
                    notices.append(f"파일 끝이 잘려 {len(records)}개까지만 읽음")
                    break
                hdr = ph(hbuf)
                remaining = max(0, os.fstat(fh.fileno()).st_size - fh.tell())
                buf = fh.read(min(hdr.caplen, remaining))
                truncated = len(buf) < hdr.caplen
                ts = hdr.tv_sec + (hdr.tv_usec / divisor)
                line_number += 1
                try:
                    protocol, fields = _parse_packet(buf, ethernet)
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    notices.append(f"파일 끝이 잘려 {len(records)}개까지만 읽음")
                    break
                fields = {"time": f"{ts:.6f}", **fields}
                records.append(
                    Record(
                        line_number=line_number,
                        kind=protocol,
                        fields=fields,
                        raw=str(line_number),
                    )
                )
                if truncated:
                    notices.append(f"파일 끝이 잘려 {len(records)}개까지만 읽음")
                    break
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            notices.append(f"파일 끝이 잘려 {len(records)}개까지만 읽음")
        except ValueError:
            if not records:
                return ParseResult(records=[], unparsed=0, notices=["pcap 파일이 아닙니다"])
            notices.append(f"파일 끝이 잘려 {len(records)}개까지만 읽음")

    return ParseResult(records=records, unparsed=0, notices=notices)
