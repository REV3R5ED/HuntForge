"""Render docs/images/05-detect.png: dark terminal screenshot, house style.

Matches 04-timeline.png: 572px wide, (30,30,30) background,
(56,56,56) title bar, DejaVu Sans Mono, green `$` prompt, light-gray
body text. All text is genuine HuntForge v0.5 output captured from the
intrusion fixture (HUNTFORGE_STATE_DIR=/tmp/hf05docs); long lines wrap
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

# Genuine v0.5 output (HUNTFORGE_STATE_DIR=/tmp/hf05docs).
LINES: list[tuple[str, str]] = [
    ("prompt", "huntforge detect --case CASE-005 --severity medium+"),
    ("out", "3 finding(s): 2 high, 1 medium"),
    (
        "out",
        "[HF-0001] HIGH HF-DET-ENCPSH -- Encoded PowerShell execution (confidence 80)",
    ),
    (
        "out",
        "  why: parser observation 'encoded-command' on event #2 (not a verdict)",
    ),
    ("out", "  why: command line contains an -EncodedCommand/-enc switch"),
    ("out", "  why: process is powershell.exe (PowerShell host)"),
    (
        "out",
        "  evidence: event #2 (sysmon:1) -- process creation: powershell.exe pid 7422",
    ),
    (
        "out",
        "[HF-0002] HIGH HF-DET-OFFICE -- Office application spawning "
        "shell (confidence 70)",
    ),
    ("out", "  why: parent process is winword.exe (Office application)"),
    ("out", "  why: child process is powershell.exe (shell/script host)"),
    (
        "out",
        "[HF-0003] MEDIUM HF-DET-RUNKEY -- Run-key persistence (confidence 60)",
    ),
    (
        "out",
        "  why: persistence target: "
        "C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\svchost.exe",
    ),
    ("out", "  why: no execution of the target binary observed"),
    ("prompt", "huntforge detect --case CASE-005 --rule HF-DET-ENCPSH --explain"),
    (
        "out",
        "  what: PowerShell executed with an encoded command on "
        "WS-FIN-014 as FIN-014\\m.alvarez",
    ),
    ("out", "  observed: powershell.exe started with an encoded-command switch"),
    ("out", "  inferred (analyst decides): the actor may be hiding the command"),
]

TITLE = "huntforge -- v0.5 explainable detections"
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
    out = Path(__file__).parent / "images" / "05-detect.png"
    img = render(13)
    img.save(out)
    print(f"saved {out} {img.size}")


if __name__ == "__main__":
    main()
