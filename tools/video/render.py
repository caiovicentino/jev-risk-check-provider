#!/usr/bin/env python3
"""Render draft hackathon videos: pitch (2:30), demo (3:00), week-1 update (1:00).
Slides via PIL, narration via edge-tts, assembly via ffmpeg.
Design language mirrors the x402check.xyz landing (verification-document aesthetic)."""

import os, subprocess, sys, textwrap
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.abspath(__file__))
FONTS = os.path.join(ROOT, "fonts")
OUT = ROOT
W, H = 1280, 720

PAPER = (252, 252, 250)
INK = (22, 24, 29)
MUTED = (93, 100, 114)
FAINT = (139, 144, 160)
LINE = (228, 228, 222)
PANEL = (244, 244, 238)
GREEN = (11, 110, 79)
TERM_BG = (13, 15, 22)
TERM_FG = (214, 219, 231)
TERM_ACCENT = (20, 241, 149)
TERM_WARN = (245, 166, 35)

def font_sans(size): return ImageFont.truetype(os.path.join(FONTS, "SpaceGrotesk.ttf"), size)
def font_mono(size): return ImageFont.truetype(os.path.join(FONTS, "PlexMono.ttf"), size)
def font_mono_m(size): return ImageFont.truetype(os.path.join(FONTS, "PlexMono-Medium.ttf"), size)

def base_canvas():
    img = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(img)
    return img, d

def draw_topbar(d):
    d.line([(60, 74), (W - 60, 74)], fill=LINE, width=1)
    d.text((60, 40), "x402check.xyz", font=font_mono_m(17), fill=INK)
    w = d.textlength("PAYSOL", font=font_mono_m(15))
    d.text((W - 60 - w, 41), "PAYSOL", font=font_mono_m(15), fill=GREEN)

def slide_title(kicker, title_lines, sub=None):
    img, d = base_canvas()
    draw_topbar(d)
    d.text((60, 120), kicker.upper(), font=font_mono(13), fill=FAINT)
    y = 170
    for line in title_lines:
        d.text((60, y), line, font=font_sans(46), fill=INK)
        y += 56
    if sub:
        yy = y + 18
        for part in textwrap.wrap(sub, width=62):
            d.text((60, yy), part, font=font_sans(20), fill=MUTED)
            yy += 30
    return img

def slide_section(no, title, items, cols=2):
    img, d = base_canvas()
    draw_topbar(d)
    d.text((60, 110), f"{no}", font=font_mono(16), fill=FAINT)
    d.text((96, 104), title, font=font_sans(34), fill=INK)
    d.line([(60, 170), (W - 60, 170)], fill=LINE, width=1)
    col_w = (W - 140) // cols
    for i, (h, body) in enumerate(items):
        cx = 60 + (i % cols) * col_w
        cy = 200 + (i // cols) * 150
        d.text((cx, cy), h, font=font_mono_m(16), fill=GREEN)
        yy = cy + 30
        for part in textwrap.wrap(body, width=cols * 22):
            d.text((cx, yy), part, font=font_sans(16), fill=MUTED)
            yy += 24
    return img

def slide_metrics(rows, note=None):
    img, d = base_canvas()
    draw_topbar(d)
    d.text((60, 110), "03", font=font_mono(16), fill=FAINT)
    d.text((96, 104), "Evidence, not claims", font=font_sans(34), fill=INK)
    d.line([(60, 170), (W - 60, 170)], fill=LINE, width=1)
    x = 60
    colw = (W - 120) // len(rows)
    for i, (big, label) in enumerate(rows):
        cx = x + i * colw
        d.text((cx + 4, 210), big, font=font_mono_m(30), fill=GREEN)
        yy = 256
        for part in textwrap.wrap(label, width=20):
            d.text((cx + 4, yy), part, font=font_sans(13), fill=MUTED)
            yy += 19
        if i < len(rows) - 1:
            d.line([(cx + colw - 12, 200), (cx + colw - 12, 320)], fill=LINE, width=1)
    if note:
        yy = 380
        for part in textwrap.wrap(note, width=80):
            d.text((60, yy), part, font=font_sans(15), fill=FAINT)
            yy += 24
    return img

def slide_code(lines, header="Integration"):
    img, d = base_canvas()
    draw_topbar(d)
    d.text((60, 110), "04", font=font_mono(16), fill=FAINT)
    d.text((96, 104), header, font=font_sans(34), fill=INK)
    box_y = 176
    d.rounded_rectangle([(60, box_y), (W - 60, box_y + 430)], radius=4, fill=(247, 247, 243), outline=LINE, width=1)
    y = box_y + 22
    for ln in lines:
        color = TERM_FG if not ln.startswith("#") else FAINT
        if ln.startswith("#"):
            d.text((84, y), ln, font=font_mono(14), fill=FAINT)
        else:
            d.text((84, y), ln, font=font_mono(14), fill=INK)
        y += 24
    return img

def terminal_frame(lines, title="PAYSOL — live demo", note=None):
    img = Image.new("RGB", (W, H), (18, 20, 26))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([(40, 30), (W - 40, H - 60)], radius=8, fill=TERM_BG)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([(58 + i * 22, 46), (70 + i * 22, 58)], fill=c)
    d.text((130, 44), title, font=font_mono_m(14), fill=(120, 127, 145))
    y = 92
    for ln, color in lines:
        d.text((70, y), ln, font=font_mono(16), fill=color)
        y += 27
    if note:
        d.rounded_rectangle([(40, H - 52), (W - 40, H - 12)], radius=4, fill=(30, 33, 42))
        d.text((64, H - 44), note, font=font_mono_m(15), fill=TERM_ACCENT)
    return img

def c(s, col=TERM_FG): return (s, col)
def g(s): return (s, TERM_ACCENT)
def warn(s): return (s, TERM_WARN)

def write_png(img, path):
    img.save(path)

def tts(text, path, voice="pt-BR-AntonioNeural", rate="-8%"):
    esc = text.replace('"', "'")
    subprocess.run(["edge-tts", "--voice", voice, "--rate", rate, "--text", esc, "--write-media", path],
                   check=True, capture_output=True)

def build_video(name, frames):
    """frames: list of (image_path, narration_text, duration_hint_seconds)"""
    concat_txt = os.path.join(OUT, f"{name}-concat.txt")
    seg_files = []
    t = 0.0
    timeline = []
    for i, (img_path, narration, dur) in enumerate(frames):
        seg = os.path.join(OUT, f"{name}-seg{i}.mp4")
        if narration:
            audio = os.path.join(OUT, f"{name}-vo{i}.mp3")
            tts(narration, audio)
            probe = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                                    "-of", "default=nw=1:nk=1", audio], capture_output=True, text=True)
            adur = float(probe.stdout.strip()) + 0.6
        else:
            adur = dur
        timeline.append((img_path, adur))
        subprocess.run(["ffmpeg", "-y", "-loop", "1", "-i", img_path, "-t", f"{adur:.2f}",
                        "-r", "30", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-vf", "scale=1280:720",
                        seg], check=True, capture_output=True)
        seg_files.append(seg)
        t += adur
    with open(concat_txt, "w") as f:
        for seg in seg_files:
            f.write(f"file '{seg}'\n")
    silent = os.path.join(OUT, f"{name}-visual.mp4")
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", concat_txt,
                    "-c", "copy", silent], check=True, capture_output=True)
    final = os.path.join(OUT, f"{name}.mp4")
    vo_files = [os.path.join(OUT, f"{name}-vo{i}.mp3") for i, (_, n, _) in enumerate(frames) if n]
    if vo_files:
        vo_cat = os.path.join(OUT, f"{name}-vo.mp3")
        fargs = []
        for v in vo_files:
            fargs += ["-i", v]
        filter_inputs = "".join(f"[{i}:a]" for i in range(len(vo_files)))
        subprocess.run(["ffmpeg", "-y", *fargs, "-filter_complex",
                        f"{filter_inputs}concat=n={len(vo_files)}:v=0:a=1",
                        vo_cat], check=True, capture_output=True)
        subprocess.run(["ffmpeg", "-y", "-i", silent, "-i", vo_cat,
                        "-c:v", "copy", "-c:a", "aac", "-shortest", final],
                       check=True, capture_output=True)
    else:
        subprocess.run(["cp", silent, final], check=True)
    print(f"{name}.mp4 built ({t:.0f}s)")
    return final
