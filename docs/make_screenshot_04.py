"""Render docs/images/04-timeline.png: dark terminal screenshot, house style.

Matches 03-persistence.png: 572px wide, (30,30,30) background,
(56,56,56) title bar, DejaVu Sans Mono, green `$` prompt, light-gray
body text, steel-blue highlights. All text is genuine HuntForge v0.4
output captured from the extended intrusion fixtures (see
docs/USAGE.md); long lines wrap like a real terminal.
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

# Genuine v0.4 output (HUNTFORGE_STATE_DIR=/tmp/hf04docs). Each entry is
# ("prompt"|"out"|"flag", text); long lines wrap like a real terminal.
LINES: list[tuple[str, str]] = [
    ("prompt", "huntforge timeline --case CASE-004"),
    ("out", "timeline: 14 timed event(s), 0 untimed"),
    (
        "out",
        "2026-10-02T09:11:03Z [10] WINWORD.EXE(3131) started by explorer.exe(2048)",
    ),
    (
        "out",
        "2026-10-02T09:12:41Z [11] powershell.exe(7422) started by WINWORD.EXE(3131)",
    ),
    (
        "out",
        "2026-10-02T09:13:02Z [12] powershell.exe(7422) -> 203.0.113.44:443",
    ),
    (
        "out",
        "2026-10-02T09:13:20Z [13] powershell.exe(7422) created file "
        "C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\svchost.exe",
    ),
    (
        "out",
        "2026-10-02T09:14:55Z [14] svchost.exe(8110) registry "
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    ),
    ("prompt", "huntforge lineage --case CASE-004"),
    ("out", "lineage: 2 process instance(s)"),
    (
        "flag",
        "WINWORD.EXE (3131)  [2026-10-02T09:11:03Z] user=FIN-014\\m.alvarez  "
        "<parent pid 2048 not observed>",
    ),
    (
        "out",
        "   └─ powershell.exe (7422)  [2026-10-02T09:12:41Z] "
        "user=FIN-014\\m.alvarez  <2 related event(s)>",
    ),
    ("prompt", "huntforge entities --case CASE-004 --type user"),
    ("out", "4 entities of type user"),
    (
        "out",
        "    m.alvarez@fin-014 (seen as: FIN-014\\m.alvarez) "
        "-- 8 observation(s) [evtx:Security, sysmon, tasks]",
    ),
]

TITLE = "huntforge — v0.4 timeline, lineage, entities"
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
    out = Path(__file__).parent / "images" / "04-timeline.png"
    img = render(13)
    target_h = 460
    if img.height > target_h:
        img = render(12)
    img.save(out)
    print(f"saved {out} {img.size}")


if __name__ == "__main__":
    main()
