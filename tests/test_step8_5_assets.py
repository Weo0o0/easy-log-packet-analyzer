"""Step 8.5 static assets: theme, contrast, collapse defaults, local component."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".streamlit" / "config.toml"
APP = ROOT / "app.py"
SWIPER = ROOT / "elpa" / "components" / "card_swiper" / "index.html"


def _luminance(color: str) -> float:
    value = color.lstrip("#")
    channels = [int(value[index : index + 2], 16) / 255 for index in (0, 2, 4)]
    linear = [
        channel / 12.92
        if channel <= 0.03928
        else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    left, right = _luminance(first), _luminance(second)
    lighter, darker = max(left, right), min(left, right)
    return (lighter + 0.05) / (darker + 0.05)


def test_theme_uses_sky_primary_color_and_dark_palette():
    theme = tomllib.loads(CONFIG.read_text(encoding="utf-8"))["theme"]

    assert theme["base"] == "dark"
    assert theme["primaryColor"].lower() == "#38bdf8"
    assert theme["backgroundColor"].lower() == "#0e1117"
    assert theme["secondaryBackgroundColor"].lower() == "#262730"
    assert theme["textColor"].lower() == "#fafafa"
    assert theme["primaryColor"].lower() != "#ff4b4b"


def test_theme_contrast_matches_documented_numbers():
    theme = tomllib.loads(CONFIG.read_text(encoding="utf-8"))["theme"]

    assert round(_contrast(theme["primaryColor"], theme["backgroundColor"]), 2) == 8.82
    assert (
        round(_contrast(theme["primaryColor"], theme["secondaryBackgroundColor"]), 2)
        == 6.93
    )
    assert round(_contrast(theme["textColor"], theme["backgroundColor"]), 2) == 18.11


def test_no_expander_starts_expanded():
    assert "expanded=True" not in APP.read_text(encoding="utf-8")


def test_card_swiper_is_local_without_external_assets():
    assert SWIPER.is_file()
    html = SWIPER.read_text(encoding="utf-8")

    assert not re.search(
        r"<script[^>]+src\s*=\s*[\"']https?://", html, re.IGNORECASE
    )
    assert not re.search(r"<link[^>]+href\s*=\s*[\"']https?://", html, re.IGNORECASE)
    assert "innerHTML" not in html
    assert "textContent" in html
    assert "aria-label" in html
    assert "function move(delta){glide((index+delta)*STEP)}" in html
    assert "pv.addEventListener('click',function(){move(-1)})" in html
    assert "nx.addEventListener('click',function(){move(1)})" in html
    assert "e.preventDefault();move(1)" in html
    assert "e.preventDefault();move(-1)" in html
