"""Render docs/images/07-correlate.png: dark terminal screenshot, house style.

Matches 06-mitre.png: 572px wide, (30,30,30) background,
(56,56,56) title bar, DejaVu Sans Mono, green `$` prompt, light-gray
body text. All text is genuine HuntForge v0.7 output captured from the
intrusion fixture (HUNTFORGE_STATE_DIR=/tmp/hf07docs); long lines wrap
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

# Genuine v0.7 output (HUNTFORGE_STATE_DIR=/tmp/hf07docs).
LINES: list[tuple[str, str]] = [
    ("prompt", "huntforge correlate --case CASE-007"),
    ("out", "1 activity cluster(s) from 12 event(s), 3 linkage(s)"),
    (
        "out",
        "  [0] confidence 80 -- 4 event(s), findings: 2 high, 1 medium "
        "[T1059.001, T1204.002, T1547.001]",
    ),
    ("out", "      same-process: #4 <-> #5 (INFERRED, conf 90)"),
    ("out", "      same-process: #5 <-> #6 (INFERRED, conf 90)"),
    ("out", "      same-file: #6 <-> #9 (INFERRED, conf 80)"),
    ("out", "  linkages: same-file: 1, same-process: 2"),
    ("out", "  uncorrelated events: 8"),
    ("out", "  note: linkages are INFERRED hypotheses; events are OBSERVED facts"),
    ("prompt", "huntforge narrative --case CASE-007 --cluster 0"),
    (
        "out",
        "cluster 0: powershell.exe on WS-FIN-014: 4 event(s), 3 finding(s); "
        "top finding: Run-key persistence (medium) (confidence 80)",
    ),
    (
        "out",
        "  powershell.exe on WS-FIN-014: 4 event(s), 3 finding(s); "
        "top finding: Run-key persistence (medium)",
    ),
    (
        "out",
        "  confidence 80: weakest linkage: same-file (events #6/#9, confidence 80)",
    ),
    ("out", "  OBSERVED (4 events):"),
    (
        "out",
        "    2026-10-02T09:12:41Z [#4] sysmon:1 powershell.exe (pid 7422): "
        "powershell.exe -NoProfile -ExecutionPolicy Bypass "
        "-EncodedCommand aQBmACgAWwBJAG",
    ),
    (
        "out",
        "    2026-10-02T09:13:02Z [#5] sysmon:3 powershell.exe (pid 7422); "
        "-> 203.0.113.44:443",
    ),
    (
        "out",
        "    2026-10-02T09:13:20Z [#6] sysmon:11 powershell.exe (pid 7422); "
        "file C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\svchost.exe",
    ),
    (
        "out",
        "    2026-10-02T09:14:55Z [#9] registry:run-key svchost.exe: "
        "C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\svchost.exe /silent",
    ),
    ("out", "  INFERRED linkages (3):"),
    (
        "out",
        "    [same-process] events #4 and #5 are hypothesized to describe the "
        "same activity: same host (ws-fin-014), PID 7422, and image "
        "(powershell.exe); 21s apart",
    ),
    (
        "out",
        "    [same-file] events #6 and #9 are hypothesized to describe the "
        "same activity: same normalized file path",
    ),
    ("out", "  detections (3):"),
    ("out", "    [HF-0001] high Encoded PowerShell execution (conf 80)"),
    ("out", "    [HF-0002] high Office application spawning shell (conf 70)"),
    ("out", "    [HF-0005] medium Run-key persistence (conf 60)"),
    ("out", "  techniques:"),
    ("out", "    T1059.001 PowerShell"),
    ("out", "    T1547.001 Registry Run Keys / Startup Folder"),
    ("out", "  what's missing (2):"),
    (
        "out",
        "    - file C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\svchost.exe "
        "was created but never observed executing",
    ),
]

TITLE = "huntforge -- v0.7 cross-source correlation"
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
    out = Path(__file__).parent / "images" / "07-correlate.png"
    img = render(13)
    img.save(out)
    print(f"saved {out} {img.size}")


if __name__ == "__main__":
    main()
