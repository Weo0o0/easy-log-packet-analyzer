from __future__ import annotations

import urllib.request
from pathlib import Path

import pytest

SAMPLES_DIR = Path(__file__).resolve().parents[1] / ".samples"
MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024

# Public raw URLs from docs/samples.md (files are not committed), pinned to the
# commit each file was verified at so upstream changes cannot alter test inputs.
SAMPLE_URLS = {
    "OpenSSH_2k.log": "https://raw.githubusercontent.com/logpai/loghub/dd61d0952749ee7963bde24220d1be5ede023033/OpenSSH/OpenSSH_2k.log",
    "apache_logs": "https://raw.githubusercontent.com/elastic/examples/6d86454ebb7a850bcd7e80abe86fe683370018a6/Common%20Data%20Formats/apache_logs/apache_logs",
    "security.evtx": "https://raw.githubusercontent.com/williballenthin/python-evtx/c0007441657899c39180de10a2be1a0e43dbeaf9/tests/data/security.evtx",
}

# samples.md links a wiki upload, so there is no commit SHA to pin.
DNS_CAP_URL = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap"


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310
        data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"샘플 다운로드가 {MAX_DOWNLOAD_BYTES}바이트 제한을 초과합니다")
    return data


def _download(name: str, url: str | None = None) -> Path:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    dest = SAMPLES_DIR / name
    if dest.exists() and 0 < dest.stat().st_size <= MAX_DOWNLOAD_BYTES:
        return dest
    # Untrusted remote input — store only under gitignored .samples/
    dest.write_bytes(_fetch(url or SAMPLE_URLS[name]))
    return dest


@pytest.fixture(scope="session")
def openssh_log() -> Path:
    return _download("OpenSSH_2k.log")


@pytest.fixture(scope="session")
def apache_log() -> Path:
    return _download("apache_logs")


@pytest.fixture(scope="session")
def security_evtx() -> Path:
    return _download("security.evtx")


@pytest.fixture(scope="session")
def dns_cap() -> Path:
    try:
        return _download("dns.cap", DNS_CAP_URL)
    except (OSError, TimeoutError) as exc:
        pytest.skip(f"dns.cap unavailable (offline?): {exc}")
