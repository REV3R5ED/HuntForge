"""Render docs/images/08-report.png: dark terminal screenshot, house style.

Matches 07-correlate.png: 572px wide, (30,30,30) background,
(56,56,56) title bar, DejaVu Sans Mono, green `$` prompt, light-gray
body text. All text is genuine HuntForge v0.8 output captured from the
intrusion case (HUNTFORGE_STATE_DIR=/tmp/hf08docs); long lines wrap
like a real terminal.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH = 572
BG = (30, 30, 30)
TITLE_BAR = (56, 56, 56)
BODY = (220, 220, 220)
GREEN = (120, 220, 120)
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

# Genuine v0.8 output (HUNTFORGE_STATE_DIR=/tmp/hf08docs).
LINES: list[tuple[str, str]] = [
    (
        "prompt",
        'huntforge notes --case CASE-008 --add "Confirmed the invoice '
        'lure chain; escalating to IR."',
    ),
    ("out", "note #1 added"),
    ("prompt", "huntforge notes --case CASE-008 --list"),
    ("out", "1 note(s)"),
    (
        "out",
        "  [#1] 2026-10-03T06:51:11Z (analyst): Confirmed the invoice "
        "lure chain; escalating to IR.",
    ),
    (
        "prompt",
        "huntforge report case CASE-008 --output ./report-case-008 --format all",
    ),
    ("out", "report for CASE-008: 4 file(s) in ./report-case-008"),
    ("out", "  wrote ./report-case-008/CASE-008.html"),
    ("out", "  wrote ./report-case-008/CASE-008.json"),
    ("out", "  wrote ./report-case-008/CASE-008.md"),
    ("out", "  wrote ./report-case-008/CASE-008-findings.csv"),
    ("out", "  report schema 0.8.0"),
    ("out", "  executive summary is generated — analyst review required"),
]

TITLE = "huntforge -- v0.8 case reporting"
TITLE_BAR_H = 29
PAD_X = 14
PAD_TOP = 10
PAD_BOTTOM = 14
WRAP_COLS = 68


def render(font_size: int = 13) -> Image.Image:
    font = ImageFont.truetype(FONT_PATH, font_size)
    ascent, descent = font.getmetrics()
    line_h = ascent + descent + 4

    wrapped: list[tuple[str, str]] = []
    for kind, text in LINES:
        prefix = "$ " if kind == "prompt" else ""
        chunks = textwrap.wrap(text, WRAP_COLS) or [""]
        wrapped.append((kind, prefix + chunks[0]))
        wrapped.extend(("cont", c) for c in chunks[1:])

    height = TITLE_BAR_H + PAD_TOP + len(wrapped) * line_h + PAD_BOTTOM
    img = Image.new("RGB", (WIDTH, height), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, WIDTH, TITLE_BAR_H], fill=TITLE_BAR)
    draw.text((PAD_X, 6), TITLE, font=font, fill=BODY)

    y = TITLE_BAR_H + PAD_TOP
    for kind, text in wrapped:
        if kind == "prompt":
            draw.text((PAD_X, y), "$", font=font, fill=GREEN)
            prompt_w = draw.textlength("$ ", font=font)
            draw.text((PAD_X + prompt_w, y), text[2:], font=font, fill=BODY)
        else:
            draw.text((PAD_X, y), text, font=font, fill=BODY)
        y += line_h
    return img


def main() -> None:
    out = Path(__file__).parent / "images" / "08-report.png"
    img = render(13)
    img.save(out)
    print(f"saved {out} {img.size}")


if __name__ == "__main__":
    main()
