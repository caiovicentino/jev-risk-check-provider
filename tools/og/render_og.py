"""Renders the 1200x630 social preview (og.png) served by the Worker at /og.png.

    python3 tools/og/render_og.py            # writes tools/og/og.png and prints the base64 length
    python3 tools/og/render_og.py --embed    # also rewrites OG_PNG_B64 in src/landing.ts

Copy must match what docs/EVIDENCE.md supports (checked by test/landing.test.ts for the page).
"""
import base64
import os
import re
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FONTS = os.path.join(ROOT, "tools", "video", "fonts")
OUT = os.path.join(os.path.dirname(__file__), "og.png")

PAPER, INK, MUTED, FAINT, LINE, GREEN = "#fcfcfa", "#16181d", "#5d6472", "#8b90a0", "#e4e4de", "#0b6e4f"
W, H = 1200, 630


def sans(size):
    return ImageFont.truetype(os.path.join(FONTS, "SpaceGrotesk.ttf"), size)


def mono(size, medium=False):
    return ImageFont.truetype(os.path.join(FONTS, "PlexMono-Medium.ttf" if medium else "PlexMono.ttf"), size)


def wrap(draw, text, font, width):
    words, lines, line = text.split(), [], ""
    for w in words:
        trial = f"{line} {w}".strip()
        if draw.textlength(trial, font=font) <= width:
            line = trial
        else:
            lines.append(line)
            line = w
    lines.append(line)
    return lines


def render():
    img = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(img)
    # top bar
    d.text((80, 50), "x402check.xyz", font=mono(24, True), fill=INK)
    right = "pre-payment risk checks"
    d.text((W - 80 - d.textlength(right, font=mono(20)), 54), right, font=mono(20), fill=GREEN)
    d.line([(80, 96), (W - 80, 96)], fill=LINE, width=2)
    # kicker
    d.text((80, 128), "X402 RISK-CHECK PROVIDER · AGENTS & WALLETS", font=mono(17), fill=FAINT)

    # headline: confined to the left column so it never runs under the card
    col = 600
    y = 172
    head = sans(54)
    for part, color in (("Check the counterparty", INK), ("before an agent or a", GREEN), ("wallet pays.", GREEN)):
        for line in wrap(d, part, head, col):
            d.text((80, y), line, font=head, fill=color)
            y += 64

    # attestation card
    cx, cy, cw, ch = 720, 150, 400, 300
    d.rounded_rectangle([cx, cy, cx + cw, cy + ch], radius=8, outline=INK, width=2, fill="#ffffff")
    d.text((cx + 22, cy + 18), "ATTESTATION", font=mono(15), fill=FAINT)
    badge = "SIGNED · ES256"
    bw = d.textlength(badge, font=mono(14, True)) + 18
    d.rectangle([cx + cw - 22 - bw, cy + 14, cx + cw - 22, cy + 40], outline=GREEN, width=2)
    d.text((cx + cw - 22 - bw + 9, cy + 18), badge, font=mono(14, True), fill=GREEN)
    d.line([(cx + 2, cy + 54), (cx + cw - 2, cy + 54)], fill=LINE, width=1)
    rows = [
        ("iss", "did:web:x402check.xyz", INK),
        ("sanctions", "ofac-sdn · not_listed", INK),
        ("feeds", "phishing lists · clear", INK),
        ("simulation", "no hidden recipient", INK),
        ("code", "no drainer kit", INK),
        ("score", "94 · low", GREEN),
    ]
    ry = cy + 72
    for k, v, color in rows:
        d.text((cx + 22, ry), k, font=mono(16), fill=FAINT)
        d.text((cx + 140, ry), v, font=mono(16, True), fill=color)
        ry += 36

    # facts (what the evidence supports)
    d.text((80, 520), "OFAC SDN · phishing & drainer feeds · transaction simulation · drainer-kit code", font=mono(18), fill=MUTED)
    d.text((80, 556), "$0.001/evaluation · $0.005 with simulation · USDC via x402 on 7 mainnets · MIT", font=mono(18), fill=MUTED)
    img.save(OUT, optimize=True)
    return OUT


def embed(path):
    b64 = base64.b64encode(open(path, "rb").read()).decode()
    landing = os.path.join(ROOT, "src", "landing.ts")
    src = open(landing).read()
    new, n = re.subn(r'export const OG_PNG_B64 = "[A-Za-z0-9+/=]+";', f'export const OG_PNG_B64 = "{b64}";', src)
    if n != 1:
        raise SystemExit("OG_PNG_B64 not found exactly once in src/landing.ts")
    open(landing, "w").write(new)
    return len(b64)


if __name__ == "__main__":
    out = render()
    print(out, os.path.getsize(out), "bytes")
    if "--embed" in sys.argv:
        print("embedded base64 length", embed(out))
