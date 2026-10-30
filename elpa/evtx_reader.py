from __future__ import annotations

import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx

from elpa.limits import open_checked, read_bounded
from elpa.models import ParseResult, Record

_WANTED_DATA = frozenset({"IpAddress", "TargetUserName"})


class _BytesEvtx(evtx.Evtx):
    """python-evtx over an already size-checked in-memory buffer."""

    def __init__(self, data: bytes) -> None:
        super().__init__(None)
        self._buf = data
        self._fh = evtx.FileHeader(data, 0x0)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _fields_from_xml(xml_text: str) -> dict[str, str | None]:
    root = ET.fromstring(xml_text)
    fields: dict[str, str | None] = {
        "EventID": None,
        "time": None,
        "IpAddress": None,
        "TargetUserName": None,
    }
    for elem in root.iter():
        name = _local(elem.tag)
        if name == "EventID" and fields["EventID"] is None:
            fields["EventID"] = (elem.text or "").strip() or None
        elif name == "TimeCreated" and fields["time"] is None:
            fields["time"] = elem.get("SystemTime")
        elif name == "Data":
            key = elem.get("Name")
            if key in _WANTED_DATA and fields[key] is None:
                fields[key] = elem.text
    return fields


def read_evtx(path: str) -> ParseResult:
    """Read Windows .evtx; keep EventID, time, IpAddress, TargetUserName.

    Broken/empty/truncated files are counted as unparsed instead of crashing.
    """
    with open_checked(path) as f:
        data = read_bounded(f)
    records: list[Record] = []
    unparsed = 0
    try:
        log = _BytesEvtx(data)
        for line_number, record in enumerate(log.records(), start=1):
            try:
                fields = _fields_from_xml(record.xml())
            except Exception:
                unparsed += 1
                continue
            if not fields.get("EventID"):
                unparsed += 1
                continue
            records.append(
                Record(
                    line_number=line_number,
                    kind="evtx",
                    fields=fields,
                    raw="",
                )
            )
    except Exception:
        unparsed += 1
    if not records and unparsed == 0:
        # python-evtx can silently yield nothing for a bad/truncated file.
        unparsed = 1
    return ParseResult(records=records, unparsed=unparsed)
