"""Security regressions for step 1 readers (F2/F3/F4)."""

from __future__ import annotations

import io
import os
import re
import time
from pathlib import Path

import pytest

import conftest
from elpa import read_evtx, read_text_log
from elpa.limits import MAX_FILE_BYTES, open_checked, read_bounded


def test_open_checked_rejects_non_regular(tmp_path: Path) -> None:
    if not os.path.exists("/dev/zero"):
        pytest.skip("/dev/zero missing")
    with pytest.raises(ValueError, match="일반 파일"):
        open_checked("/dev/zero")
    link = tmp_path / "zero"
    link.symlink_to("/dev/zero")
    with pytest.raises(ValueError, match="일반 파일"):
        open_checked(str(link))


def test_open_checked_rejects_fifo(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo missing")
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="일반 파일"):
        open_checked(str(fifo))


def test_read_bounded_refuses_bytes_beyond_cap() -> None:
    with pytest.raises(ValueError, match="제한을 초과"):
        read_bounded(io.BytesIO(b"x" * (MAX_FILE_BYTES + 1)))


def test_readers_reject_symlink_to_device(tmp_path: Path) -> None:
    if not os.path.exists("/dev/zero"):
        pytest.skip("/dev/zero missing")
    link = tmp_path / "zero"
    link.symlink_to("/dev/zero")
    with pytest.raises(ValueError, match="일반 파일"):
        read_text_log(str(link), "sshd")
    with pytest.raises(ValueError, match="일반 파일"):
        read_evtx(str(link))


def test_long_line_within_cap_is_counted(tmp_path: Path) -> None:
    path = tmp_path / "long.log"
    path.write_bytes(b"x" * (MAX_FILE_BYTES - 1))
    result = read_text_log(str(path), "sshd")
    assert result.records == []
    assert result.unparsed == 1


def test_crafted_long_sshd_line_is_fast(tmp_path: Path) -> None:
    path = tmp_path / "crafted.log"
    body = b"Dec 10 06:55:48 host sshd[1]: Failed password for " + b"for " * (128 * 1024 // 4)
    path.write_bytes(body + b"\n")
    start = time.perf_counter()
    result = read_text_log(str(path), "sshd")
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0
    assert result.unparsed == 1 or len(result.records) == 1


@pytest.mark.parametrize("data", [b"", b"ElfFile\x00", b"\x00" * 4096])
def test_broken_evtx_is_counted_not_crash(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "broken.evtx"
    path.write_bytes(data)
    result = read_evtx(str(path))
    assert result.records == []
    assert result.unparsed >= 1


def test_truncated_evtx_is_counted_not_crash(security_evtx: Path, tmp_path: Path) -> None:
    path = tmp_path / "truncated.evtx"
    path.write_bytes(security_evtx.read_bytes()[:4096])
    result = read_evtx(str(path))
    assert result.unparsed >= 1


def test_sample_urls_pinned_to_commit_sha() -> None:
    sha_url = re.compile(r"raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/")
    assert len(conftest.SAMPLE_URLS) == 3
    for url in conftest.SAMPLE_URLS.values():
        assert sha_url.search(url)


def test_fetch_caps_download(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *exc: object) -> None:
            pass

        def read(self, n: int) -> bytes:
            return b"x" * n

    monkeypatch.setattr(conftest, "MAX_DOWNLOAD_BYTES", 10)
    monkeypatch.setattr(conftest.urllib.request, "urlopen", lambda *a, **k: FakeResponse())
    with pytest.raises(ValueError, match="제한을 초과"):
        conftest._fetch("https://example.invalid/sample")
