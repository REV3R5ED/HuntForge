"""Render docs/images/03-persistence.png: dark terminal screenshot, house style.

Matches 02-ingest.png: 572px wide, (30,30,30) background, (56,56,56)
title bar, DejaVu Sans Mono, green `$` prompt, light-gray body text,
steel-blue flag highlights. All text is genuine HuntForge v0.3 output
captured from the synthetic persistence fixtures (see docs/USAGE.md).
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

# Genuine v0.3 output (HUNTFORGE_STATE_DIR=/tmp/hfdocs3/state). Each entry
# is ("prompt"|"out"|"flag", text); long lines wrap like a real terminal.
LINES: list[tuple[str, str]] = [
    ("prompt", "huntforge ingest ./evidence-persist --case CASE-003"),
    (
        "out",
        "registered 4 evidence file(s), parsed 10 event(s) "
        "[prefetch: 1, registry: 5, services: 3, tasks: 1]",
    ),
    ("prompt", "huntforge events --case CASE-003 --keyword MALWARE"),
    ("out", "1 event(s) match"),
    (
        "out",
        "[1] 2026-10-01T08:30:00Z prefetch:prefetch host=- user=- "
        "process=MALWARE.EXE(-)",
    ),
    ("out", "      file_path: MALWARE.EXE"),
    (
        "prompt",
        "huntforge registry NTUSER.DAT "
        "'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    ),
    (
        "out",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run: 0 subkey(s), 2 value(s)",
    ),
    ("out", "    Updater [REG_SZ] = C:\\Users\\test\\AppData\\Roaming\\updater.exe"),
    ("out", "    BadThing [REG_SZ] = C:\\Temp\\evil.exe"),
    ("prompt", "huntforge events --case CASE-003 --event-id task"),
    ("out", "1 event(s) match"),
    (
        "out",
        "[10] 2026-09-28T14:30:00Z tasks:task host=- user=S-1-5-18 process=evil.exe(-)",
    ),
    ("out", "      command_line: C:\\Temp\\evil.exe --silent --persist"),
    ("flag", "      flags: runs-as-system, action-in-temp-dir (parser observation)"),
    ("prompt", "huntforge events --case CASE-003 --event-id service"),
    (
        "out",
        "[8] 2026-09-15T08:30:00Z services:service host=- user=LocalSystem "
        "process=badsvc.exe(-)",
    ),
    ("out", "      command_line: C:\\Temp\\badsvc.exe -k netsvcs"),
    ("out", "      registry_key: ControlSet001\\Services\\BadSvc"),
    ("flag", "      flags: auto-start, image-in-temp-dir (parser observation)"),
]

TITLE = "huntforge — v0.3 persistence artifacts"
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
    out = Path(__file__).parent / "images" / "03-persistence.png"
    img = render(13)
    target_h = 460
    if img.height > target_h:
        img = render(12)
    img.save(out)
    print(f"saved {out} {img.size}")


if __name__ == "__main__":
    main()
