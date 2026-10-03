"""Render docs/images/02-ingest.png: dark terminal screenshot, house style.

Matches 01-scenario.png: 572px wide, (30,30,30) background, (56,56,56)
title bar, DejaVu Sans Mono, green `$` prompt, light-gray body text,
steel-blue flag highlights. All text is genuine HuntForge v0.2 output
captured from the fixture intrusion chain (see docs/USAGE.md).
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
ACCENT = (150, 170, 190)
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

# Genuine v0.2 output (HUNTFORGE_STATE_DIR=/tmp/hfdocs/state). Each entry
# is ("prompt"|"out"|"flag", text); long lines wrap like a real terminal.
LINES: list[tuple[str, str]] = [
    ("prompt", "huntforge ingest ./evidence --case CASE-001"),
    (
        "out",
        "registered 3 evidence file(s), parsed 16 event(s) "
        "[powershell: 4, security: 5, sysmon: 7]",
    ),
    ("out", "  #1 powershell_events.xml sha256=d2f1ff8aab11a161…"),
    ("out", "  #2 security_events.xml sha256=6f7721d5227b1e06…"),
    ("out", "  #3 sysmon_intrusion.xml sha256=a8c7da2f74ab43a3…"),
    ("prompt", "huntforge events --case CASE-001 --process powershell.exe"),
    ("out", "4 event(s) match"),
    ("out", "  count: 4"),
    (
        "out",
        "[8] 2026-10-02T09:12:41Z evtx:Security:4688 host=WS-FIN-014 "
        "user=FIN-014\\m.alvarez process=powershell.exe(7422)",
    ),
    (
        "out",
        "      command_line: powershell.exe -NoProfile -ExecutionPolicy Bypass "
        "-EncodedCommand aQBmACgAWwBJAG8ALgBGAFkAcwBpAG8AbgBdADoA",
    ),
    ("flag", "      flags: encoded-command (parser observation)"),
    (
        "out",
        "[13] 2026-10-02T09:12:41Z sysmon:1 host=WS-FIN-014 "
        "user=FIN-014\\m.alvarez process=powershell.exe(7422)",
    ),
    (
        "out",
        "      command_line: powershell.exe -NoProfile -ExecutionPolicy Bypass "
        "-EncodedCommand aQBmACgAWwBJAG8ALgBGAFkAcwBpAG8AbgBdADoA",
    ),
    ("flag", "      flags: encoded-command (parser observation)"),
    (
        "out",
        "[14] 2026-10-02T09:13:02Z sysmon:3 host=WS-FIN-014 "
        "user=FIN-014\\m.alvarez process=powershell.exe(7422)",
    ),
    ("out", "      dst_ip: 203.0.113.44"),
    (
        "out",
        "[15] 2026-10-02T09:13:20Z sysmon:11 host=WS-FIN-014 "
        "user=FIN-014\\m.alvarez process=powershell.exe(7422)",
    ),
    ("out", "      file_path: C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\svchost.exe"),
]

TITLE = "huntforge — v0.2 telemetry ingest"
TITLE_BAR_H = 29
PAD_X = 14
PAD_TOP = 10
PAD_BOTTOM = 14
WRAP_COLS = 72


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
        elif kind == "flag":
            draw.text((PAD_X, y), text, font=font, fill=ACCENT)
        else:
            draw.text((PAD_X, y), text, font=font, fill=BODY)
        y += line_h
    return img


def main() -> None:
    out = Path(__file__).parent.parent / "docs" / "images" / "02-ingest.png"
    # Keep the v0.1 screenshot's exact height.
    img = render(13)
    target_h = 460
    if img.height > target_h:
        img = render(12)
    img.save(out)
    print(f"saved {out} {img.size}")


if __name__ == "__main__":
    main()
