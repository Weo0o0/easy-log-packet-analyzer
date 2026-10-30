"""Step 1 acceptance: counts from docs/design.md / docs/samples.md."""

from __future__ import annotations

from pathlib import Path

import pytest

from elpa import read_evtx, read_text_log
from elpa.limits import MAX_FILE_BYTES


def test_openssh_2k(openssh_log: Path) -> None:
    result = read_text_log(str(openssh_log), "sshd")
    assert len(result.records) == 2000
    assert sum(1 for r in result.records if r.kind == "sshd 실패") == 520
    assert result.unparsed == 0
    assert all(r.line_number >= 1 for r in result.records)


def test_apache_logs(apache_log: Path) -> None:
    result = read_text_log(str(apache_log), "access")
    assert len(result.records) == 10000
    assert sum(1 for r in result.records if r.fields.get("status") == "404") == 213
    assert result.unparsed == 0


def test_security_evtx(security_evtx: Path) -> None:
    result = read_evtx(str(security_evtx))
    assert sum(1 for r in result.records if r.fields.get("EventID") == "4624") == 583
    assert result.unparsed == 0
    # EventID / time / IpAddress / TargetUserName present on a 4624
    sample = next(r for r in result.records if r.fields.get("EventID") == "4624")
    assert "time" in sample.fields
    assert "IpAddress" in sample.fields
    assert "TargetUserName" in sample.fields


def test_unparsed_and_malformed_lines_are_counted(tmp_path: Path) -> None:
    sshd = tmp_path / "auth.log"
    sshd.write_text(
        "Dec 10 06:55:48 host sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
        "not an sshd line\n",
        encoding="utf-8",
    )
    result = read_text_log(str(sshd), "sshd")
    assert len(result.records) == 1
    assert result.records[0].kind == "sshd 실패"
    assert result.records[0].fields["srcip"] == "203.0.113.5"
    assert result.unparsed == 1

    access = tmp_path / "access.log"
    access.write_text(
        '203.0.113.5 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 2326\n'
        "malformed access line\n",
        encoding="utf-8",
    )
    result = read_text_log(str(access), "access")
    assert len(result.records) == 1
    assert result.records[0].fields["status"] == "200"
    assert result.unparsed == 1


def test_oversized_file_rejected(tmp_path: Path) -> None:
    big = tmp_path / "big.log"
    with big.open("wb") as f:
        f.seek(MAX_FILE_BYTES)
        f.write(b"\n")
    with pytest.raises(ValueError, match="제한을 초과"):
        read_text_log(str(big), "sshd")
