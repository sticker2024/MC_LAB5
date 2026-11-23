"""Render console output as a VS Code 'Terminal' panel (PowerShell prompt) PNG.

render(text, out, ps=r"PS D:\\LABS\\MC LAB4>", scripts={...})
Lines starting with '$ ' are shown as PowerShell commands after the prompt; everything else is the captured output.
"""
import re
from PIL import Image, ImageDraw, ImageFont

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
UI = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BG, TABBG, FG, DIM = (24, 26, 27), (45, 47, 49), (204, 204, 204), (150, 152, 155)


def to_powershell(cmd, scripts):
    m = re.match(r"MODE=(\w+) python (.*)", cmd)
    if m:
        cmd = f'$env:MODE="{m.group(1)}"; python {m.group(2)}'
    m = re.match(r"kill -9 (\d+)\s*(#.*)?", cmd)
    if m:
        return f"Stop-Process -Id {m.group(1)} -Force   {m.group(2) or ''}".rstrip()
    def fix(mm):
        s = mm.group(1)
        return "python " + (scripts[s] + "\\" if s in scripts else "") + s
    return re.sub(r"python ([\w\-]+\.py)", fix, cmd)


def render(text, out, ps=r"PS D:\LABS\MC LAB4>", scripts=None, max_lines=None, width_chars=None, size=15, final_prompt=True):
    scripts = scripts or {}
    lines = []
    for l in text.rstrip("\n").split("\n"):
        m = re.match(r"^(?:\d\d:\d\d:\d\d )?\$ (.*)$", l)
        lines.append(("cmd", to_powershell(m.group(1), scripts)) if m else ("out", l))
    if width_chars:
        lines = [(k, v[:width_chars]) for k, v in lines]
    if final_prompt:
        lines.append(("cmd", ""))
    font = ImageFont.truetype(MONO, size)
    ui = ImageFont.truetype(UI, size - 1)
    cw = font.getlength("M")
    lh = int(size * 1.45)
    maxc = max(len(ps) + 1 + len(v) if k == "cmd" else len(v) for k, v in lines)
    pad, bar = 16, 44
    W = max(int(maxc * cw + 2 * pad + 20), 1060)
    H = bar + 14 + lh * len(lines) + 18
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # tab bar
    x = 22
    for name in ("Problems", "Output", "Debug Console", "Terminal", "Ports"):
        w = ui.getlength(name)
        if name == "Terminal":
            d.rounded_rectangle([x - 12, 5, x + w + 12, bar - 5], radius=6, fill=TABBG)
            d.text((x, 13), name, font=ui, fill=(255, 255, 255))
        else:
            d.text((x, 13), name, font=ui, fill=(190, 192, 195))
        x += w + 38
    # right side: powershell label, +, chevron, split-panel icon
    rx = W - 26
    d.rounded_rectangle([rx - 16, 11, rx, 29], radius=3, outline=(200, 200, 200), width=2)
    d.line([rx - 8, 11, rx - 8, 29], fill=(200, 200, 200), width=2)
    cx = rx - 16 - 34
    d.line([cx - 8, 25, cx, 33, cx + 8, 25][0:2] + [cx, 33], fill=(200, 200, 200), width=2)
    d.line([cx - 6, 17, cx, 23, cx + 6, 17], fill=(200, 200, 200), width=2)
    px = cx - 30
    d.line([px - 7, 20, px + 7, 20], fill=(210, 210, 210), width=2); d.line([px, 13, px, 27], fill=(210, 210, 210), width=2)
    pw = "powershell"; pwx = px - 22 - ui.getlength(pw)
    d.text((pwx, 12), pw, font=ui, fill=(215, 215, 215))
    d.rectangle([pwx - 34, 11, pwx - 14, 29], outline=(200, 200, 200), width=2)
    d.text((pwx - 31, 11), ">_", font=ui, fill=(200, 200, 200))
    y = bar + 14
    for kind, v in lines:
        if kind == "cmd":
            d.ellipse([pad - 12, y + 5, pad - 3, y + 14], outline=DIM, width=2)   # shell-integration marker
            d.text((pad, y), ps + " ", font=font, fill=FG)
            xx = pad + (len(ps) + 1) * cw
            d.text((xx, y), v, font=font, fill=FG)
            if v == "" and final_prompt and (kind, v) == lines[-1]:
                d.rectangle([xx, y + 1, xx + cw * 0.95, y + lh - 3], fill=(190, 190, 190))
        else:
            d.text((pad, y), v, font=font, fill=FG)
        y += lh
    img.save(out)
