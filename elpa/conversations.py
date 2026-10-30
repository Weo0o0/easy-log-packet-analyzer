from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from elpa.models import Record


@dataclass(frozen=True)
class Conversation:
    uid: str
    protocol: str
    service: str
    stream: int
    a: str
    b: str
    start: str
    duration: float
    packets: int
    bytes: int
    state: str
    history: str
    packet_numbers: tuple[int, ...]


def _endpoint(ip: str, port: str) -> str:
    return f"{ip}:{port}"


def _iso_z(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _append_hist(hist: str, letters: str, from_orig: bool) -> str:
    for letter in letters:
        ch = letter.upper() if from_orig else letter.lower()
        if ch not in hist:
            hist += ch
    return hist


def _tcp_letters(flags: str) -> str:
    syn = "S" in flags
    ack = "A" in flags
    fin = "F" in flags
    rst = "R" in flags
    # shortcut: PSH≈payload for history D; store payload_len when more accuracy is needed
    has_payload = "P" in flags
    out: list[str] = []
    if syn:
        out.append("H" if ack else "S")
    if fin:
        out.append("F")
    if rst:
        out.append("R")
    if has_payload:
        out.append("D")
    elif ack and not syn and not fin and not rst:
        out.append("A")
    return "".join(out)


def _tcp_state(hist: str) -> str:
    has_s = "S" in hist
    has_h = "h" in hist
    if has_s and "r" in hist and not has_h:
        return "REJ"
    if has_s and has_h:
        if "R" in hist:
            return "RSTO"
        if "r" in hist:
            return "RSTR"
        return "SF"
    if has_s:
        return "S0"
    return "OTH"


def _udp_state(hist: str) -> str:
    return "SF" if ("D" in hist and "d" in hist) else "S0"


def build_conversations(records: list[Record]) -> list[Conversation]:
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []
    next_stream = {"TCP": 0, "UDP": 0}

    for rec in records:
        f = rec.fields
        transport = f.get("transport")
        src, dst = f.get("src"), f.get("dst")
        sport, dport = f.get("sport"), f.get("dport")
        if transport not in ("TCP", "UDP") or not src or not dst or not sport or not dport:
            continue

        key = (transport, tuple(sorted([(src, sport), (dst, dport)])))
        ts = float(f["time"])  # type: ignore[arg-type]
        length = int(f["length"] or 0)
        src_ep = _endpoint(src, sport)

        if key not in groups:
            stream = next_stream[transport]
            next_stream[transport] += 1
            groups[key] = {
                "protocol": transport,
                "stream": stream,
                "a": src_ep,
                "b": _endpoint(dst, dport),
                "service": f.get("protocol") or "Raw",
                "start_ts": ts,
                "end_ts": ts,
                "packets": 0,
                "bytes": 0,
                "packet_numbers": [],
                "history": "",
            }
            order.append(key)

        g = groups[key]
        g["packets"] += 1
        g["bytes"] += length
        if ts < g["start_ts"]:
            g["start_ts"] = ts
        if ts > g["end_ts"]:
            g["end_ts"] = ts
        g["packet_numbers"].append(rec.line_number)

        from_orig = src_ep == g["a"]
        if transport == "UDP":
            g["history"] = _append_hist(g["history"], "D", from_orig)
        else:
            g["history"] = _append_hist(
                g["history"], _tcp_letters(f.get("flags") or ""), from_orig
            )

    out: list[Conversation] = []
    for key in order:
        g = groups[key]
        proto = g["protocol"]
        stream = g["stream"]
        hist = g["history"]
        state = _udp_state(hist) if proto == "UDP" else _tcp_state(hist)
        out.append(
            Conversation(
                uid=f"{proto.lower()}-{stream}",
                protocol=proto,
                service=g["service"],
                stream=stream,
                a=g["a"],
                b=g["b"],
                start=_iso_z(g["start_ts"]),
                duration=g["end_ts"] - g["start_ts"],
                packets=g["packets"],
                bytes=g["bytes"],
                state=state,
                history=hist,
                packet_numbers=tuple(g["packet_numbers"]),
            )
        )
    return out
