from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from typing import BinaryIO

MAX_FILE_BYTES = 10 * 1024 * 1024


def open_checked(path: str) -> BinaryIO:
    """Open a regular file for binary reading, or raise ValueError.

    Rejects symlinks whose target is non-regular (e.g. /dev/zero) by
    checking the opened fd, and rejects files over MAX_FILE_BYTES.
    """
    # O_NONBLOCK keeps a FIFO from blocking before fstat can reject it.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("일반 파일이 아닙니다")
        if st.st_size > MAX_FILE_BYTES:
            raise ValueError(f"파일이 {MAX_FILE_BYTES}바이트 제한을 초과합니다 ({st.st_size} bytes)")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_bounded(f: BinaryIO) -> bytes:
    """Read at most MAX_FILE_BYTES bytes, refusing a file that grew past the cap."""
    data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"파일이 {MAX_FILE_BYTES}바이트 제한을 초과합니다")
    return data


def iter_bounded_lines(f: BinaryIO) -> Iterator[bytes]:
    """Yield lines while enforcing the cap, so huge input is never fully buffered."""
    total = 0
    while True:
        line = f.readline(MAX_FILE_BYTES + 1)
        if not line:
            return
        total += len(line)
        if total > MAX_FILE_BYTES:
            raise ValueError(f"파일이 {MAX_FILE_BYTES}바이트 제한을 초과합니다")
        yield line
