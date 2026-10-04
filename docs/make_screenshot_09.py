"""Render docs/images/09-batch.png: dark terminal screenshot, house style.

Matches 08-report.png: 572px wide, (30,30,30) background,
(56,56,56) title bar, DejaVu Sans Mono, green `$` prompt, light-gray
body text. All text is genuine HuntForge v0.9 output captured from the
batch triage run (HUNTFORGE_STATE_DIR=/tmp/hf09docs); long lines wrap
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

# Genuine v0.9 output (HUNTFORGE_STATE_DIR=/tmp/hf09docs).
LINES: list[tuple[str, str]] = [
    ("prompt", "huntforge batch ./evidence-drop --output ./batch-out"),
    (
        "out",
        "4 case(s) from 4 file(s), 14 event(s), "
        "6 finding(s): 5 high, 1 medium",
    ),
    ("out", "  input: ./evidence-drop"),
    ("out", "  output: ./batch-out"),
    ("out", "  files: 4 found, 4 case(s) created, 0 skipped"),
    ("out", "  events: 14, findings: 6"),
    ("out", "  by severity: 5 high, 1 medium"),
    ("out", "  top techniques:"),
    ("out", "    T1059.001 PowerShell (2 finding(s))"),
    ("out", "    T1204.002 Malicious File (2 finding(s))"),
    ("out", "    T1105 Ingress Tool Transfer (1 finding(s))"),
    ("prompt", "huntforge batch ./evidence-drop --output ./batch-out"),
    (
        "out",
        "0 case(s) from 4 file(s), 14 event(s), 6 finding(s): "
        "5 high, 1 medium; 4 skipped (manifest)",
    ),
    (
        "prompt",
        "huntforge export --case batch-0004-sysmon_intrusion "
        "--what findings -o sysmon-findings.jsonl",
    ),
    ("out", "exported 3 findings record(s) as jsonl"),
]

TITLE = "huntforge -- v0.9 batch triage + JSONL export"
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
    out = Path(__file__).parent / "images" / "09-batch.png"
    img = render(13)
    img.save(out)
    print(f"saved {out} {img.size}")


if __name__ == "__main__":
    main()
