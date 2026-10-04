"""Render docs/images/06-mitre.png: dark terminal screenshot, house style.

Matches 05-detect.png: 572px wide, (30,30,30) background,
(56,56,56) title bar, DejaVu Sans Mono, green `$` prompt, light-gray
body text. All text is genuine HuntForge v0.6 output captured from the
intrusion fixture (HUNTFORGE_STATE_DIR=/tmp/hf06docs); long lines wrap
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

# Genuine v0.6 output (HUNTFORGE_STATE_DIR=/tmp/hf06docs).
LINES: list[tuple[str, str]] = [
    ("prompt", "huntforge mitre --case CASE-006"),
    (
        "out",
        "technique coverage: 5 of 23 techniques have findings (7 stored finding(s))",
    ),
    (
        "out",
        "  T1059.001 PowerShell [Execution]",
    ),
    ("out", "    HF-DET-ENCPSH x2"),
    ("out", "    findings: HF-0002, HF-0003"),
    (
        "out",
        "  T1204.002 Malicious File [Execution]",
    ),
    ("out", "    HF-DET-OFFICE x2"),
    ("out", "    findings: HF-0004, HF-0005"),
    (
        "out",
        "  T1547.001 Registry Run Keys / Startup Folder [Persistence]",
    ),
    ("out", "    HF-DET-RUNKEY x1"),
    ("out", "    findings: HF-0006"),
    (
        "out",
        "  gaps (no findings in this case): T1003.001, T1016, T1021.001, ...",
    ),
    (
        "out",
        "  not observable with current parsers: T1003.001, T1070.001, T1070.004",
    ),
    ("prompt", "huntforge sigma run --case CASE-006 --rule hf-sigma-0001"),
    ("out", "1 finding(s) from sigma rule hf-sigma-0001"),
    (
        "out",
        "  [HF-0008] HIGH hf-sigma-0001 -- Encoded PowerShell Command Line "
        "(confidence 70)",
    ),
    (
        "out",
        "  why: selection 'selection' matched "
        "(command_line matches '*-EncodedCommand*')",
    ),
]

TITLE = "huntforge -- v0.6 ATT&CK mapping + Sigma"
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
    out = Path(__file__).parent / "images" / "06-mitre.png"
    img = render(13)
    img.save(out)
    print(f"saved {out} {img.size}")


if __name__ == "__main__":
    main()
