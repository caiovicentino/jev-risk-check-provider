#!/usr/bin/env python3
"""Animated draft-video renderer: PIL frame animation + ASS caption burn-in.
Design: verification-document aesthetic (paper, ink, one green accent)."""

import os, re, subprocess, textwrap
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.abspath(__file__))
FONTS = os.path.join(ROOT, "fonts")
OUT = ROOT
W, H = 1280, 720
FPS = 30

PAPER = (252, 252, 250)
INK = (22, 24, 29)
MUTED = (93, 100, 114)
FAINT = (139, 144, 160)
LINE = (228, 228, 222)
GREEN = (11, 110, 79)
TERM_BG = (13, 15, 22)
TERM_FG = (214, 219, 231)
TERM_ACCENT = (20, 241, 149)
TERM_WARN = (245, 166, 35)
TERM_DIM = (120, 127, 145)

from PIL import ImageFont

def font_sans(size): return ImageFont.truetype(os.path.join(FONTS, "SpaceGrotesk.ttf"), size)
def font_mono(size): return ImageFont.truetype(os.path.join(FONTS, "PlexMono.ttf"), size)
def font_mono_m(size): return ImageFont.truetype(os.path.join(FONTS, "PlexMono-Medium.ttf"), size)

def ease_out(t): return 1 - (1 - t) ** 3
def clamp01(t): return max(0.0, min(1.0, t))

def lerp(a, b, t): return a + (b - a) * t

def mix(c1, c2, t):
    return tuple(int(lerp(a, b, t)) for a, b in zip(c1, c2))

def base_canvas():
    img = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(img)
    d.line([(60, 74), (W - 60, 74)], fill=LINE, width=1)
    d.text((60, 40), "x402check.xyz", font=font_mono_m(17), fill=INK)
    w = d.textlength("x402CHECK", font=font_mono_m(15))
    d.text((W - 60 - w, 41), "x402CHECK", font=font_mono_m(15), fill=GREEN)
    return img, d

def alpha_img():
    return Image.new("RGBA", (W, H), (0, 0, 0, 0))

def stamp(base, layer):
    return Image.alpha_composite(base.convert("RGBA"), layer).convert("RGB")

def fade_in(d, t, dur):
    return clamp01(t / dur) if dur > 0 else 1.0

def anim_title(kicker, title_lines, sub):
    def draw(t):
        img, d = base_canvas()
        kt = clamp01(t / 0.12)
        d.text((60, 120 + (1 - kt) * 14), kicker.upper(), font=font_mono(13), fill=mix(PAPER, FAINT, kt))
        for i, line in enumerate(title_lines):
            lt = clamp01((t - 0.14 - i * 0.10) / 0.22)
            if lt <= 0: continue
            e = ease_out(lt)
            d.text((60, 168 + i * 58 + (1 - e) * 22), line, font=font_sans(46), fill=mix(PAPER, INK, e))
        if sub:
            st = clamp01((t - 0.14 - len(title_lines) * 0.10) / 0.25)
            if st > 0:
                yy = 170 + len(title_lines) * 58 + 16
                e = ease_out(st)
                for j, part in enumerate(textwrap.wrap(sub, width=62)):
                    if j / max(1, len(textwrap.wrap(sub, width=62))) > st: break
                    d.text((60, yy), part, font=font_sans(20), fill=mix(PAPER, MUTED, e))
                    yy += 30
        return img
    return draw

def anim_section(no, title, items, cols=2):
    def draw(t):
        img, d = base_canvas()
        e0 = ease_out(clamp01(t / 0.15))
        d.text((60, 110), no, font=font_mono(16), fill=mix(PAPER, FAINT, e0))
        d.text((96, 104), title, font=font_sans(34), fill=mix(PAPER, INK, e0))
        d.line([(60, 170), (60 + (W - 120) * e0, 170)], fill=LINE, width=1)
        col_w = (W - 140) // cols
        rows = (len(items) + cols - 1) // cols
        row_h = (H - 250) // max(1, rows)
        wrap_w = max(34, min(96, col_w // 8))
        for i, (h, body) in enumerate(items):
            it = clamp01((t - 0.2 - i * 0.09) / 0.22)
            if it <= 0: continue
            e = ease_out(it)
            cx = 60 + (i % cols) * col_w
            cy = 200 + (i // cols) * row_h
            d.text((cx, cy + (1 - e) * 10), h, font=font_mono_m(16), fill=mix(PAPER, GREEN, e))
            yy = cy + 30
            wrapped = textwrap.wrap(body, width=wrap_w)
            for j, part in enumerate(wrapped):
                if j > int(e * len(wrapped)): break
                d.text((cx, yy), part, font=font_sans(16), fill=MUTED)
                yy += 24
        return img
    return draw

def anim_metrics(rows, note=None):
    def draw(t):
        img, d = base_canvas()
        e0 = ease_out(clamp01(t / 0.15))
        d.text((60, 110), "03", font=font_mono(16), fill=mix(PAPER, FAINT, e0))
        d.text((96, 104), "Evidence, not claims", font=font_sans(34), fill=mix(PAPER, INK, e0))
        d.line([(60, 170), (60 + (W - 120) * e0, 170)], fill=LINE, width=1)
        x = 60
        colw = (W - 120) // len(rows)
        for i, (big, label) in enumerate(rows):
            it = clamp01((t - 0.18 - i * 0.06) / 0.5)
            if it <= 0: continue
            cx = x + i * colw
            num = re.match(r"^([^0-9]*)([0-9][0-9.,/]*)", big)
            if num:
                pre, val = num.group(1), num.group(2)
                rest = big[len(pre) + len(val):]
                if "/" in val:
                    parts = val.split("/")
                    v = int(ease_out(it) * int(parts[0].replace(",", "")))
                    cur = f"{v}/{parts[1]}"
                elif "," in val:
                    v = int(ease_out(it) * int(val.replace(",", "")))
                    cur = f"{v:,}"
                elif "." in val:
                    v = ease_out(it) * float(val)
                    cur = f"{v:.1f}"
                else:
                    v = int(ease_out(it) * int(val))
                    cur = str(v)
                shown = pre + cur + rest
            else:
                shown = big
            d.text((cx + 4, 210), shown, font=font_mono_m(30), fill=GREEN if it > 0.9 else mix(PAPER, GREEN, it))
            yy = 256
            for j, part in enumerate(textwrap.wrap(label, width=20)):
                if j > int(clamp01(it * 1.4) * len(textwrap.wrap(label, width=20))): break
                d.text((cx + 4, yy), part, font=font_sans(13), fill=MUTED)
                yy += 19
            if i < len(rows) - 1:
                d.line([(cx + colw - 12, 200), (cx + colw - 12, 320)], fill=LINE, width=1)
        if note:
            e = ease_out(clamp01((t - 0.6) / 0.3))
            yy = 380
            for j, part in enumerate(textwrap.wrap(note, width=80)):
                if j / len(textwrap.wrap(note, width=80)) > e: break
                d.text((60, yy), part, font=font_sans(15), fill=FAINT)
                yy += 24
        return img
    return draw

def anim_code(lines, header="Integration"):
    def draw(t):
        img, d = base_canvas()
        e0 = ease_out(clamp01(t / 0.15))
        d.text((60, 110), "04", font=font_mono(16), fill=mix(PAPER, FAINT, e0))
        d.text((96, 104), header, font=font_sans(34), fill=mix(PAPER, INK, e0))
        box_y = 176
        d.rounded_rectangle([(60, box_y), (W - 60, box_y + 430)], radius=4, fill=(247, 247, 243), outline=LINE, width=1)
        y = box_y + 22
        reveal = clamp01(t / 0.75) * len(lines)
        for k, ln in enumerate(lines):
            if k >= reveal: break
            frac = clamp01(reveal - k)
            color = FAINT if ln.startswith("#") else INK
            shown = ln if frac >= 1 else ln[: int(len(ln) * frac)]
            d.text((84, y), shown, font=font_mono(14), fill=color)
            y += 24
            if frac < 1:
                cx = 84 + d.textlength(shown, font=font_mono(14))
                d.rectangle([(cx + 2, y - 18), (cx + 12, y - 3)], fill=INK)
                break
        return img
    return draw

def anim_terminal(lines, note=None, reveal_span=0.75):
    def draw(t):
        img = Image.new("RGB", (W, H), (18, 20, 26))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([(40, 30), (W - 40, H - 60)], radius=8, fill=TERM_BG)
        for i, cc in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([(58 + i * 22, 46), (70 + i * 22, 58)], fill=cc)
        d.text((130, 44), "x402check — live demo", font=font_mono_m(14), fill=TERM_DIM)
        y = 92
        reveal = clamp01(t / reveal_span) * len(lines)
        for k, (ln, col) in enumerate(lines):
            if k >= reveal: break
            frac = clamp01(reveal - k)
            shown = ln if frac >= 1 else ln[: int(len(ln) * max(0.2, frac))]
            d.text((70, y), shown, font=font_mono(16), fill=col)
            y += 27
            if frac < 1:
                cx = 70 + d.textlength(shown, font=font_mono(16))
                d.rectangle([(cx + 3, y - 22), (cx + 14, y - 6)], fill=TERM_ACCENT)
                break
        if note and t > 0.92:
            e = clamp01((t - 0.92) / 0.08)
            d.rounded_rectangle([(40, H - 52), (W - 40, H - 12)], radius=4, fill=mix(TERM_BG, (30, 33, 42), e))
            d.text((64, H - 44), note, font=font_mono_m(15), fill=mix(TERM_BG, TERM_ACCENT, e))
        return img
    return draw

def apply_fades(img, t, dur, bg=PAPER):
    fin = clamp01(t / 0.35)
    fout = clamp01((dur - t) / 0.35)
    f = min(fin, fout)
    if f >= 1: return img
    return Image.blend(Image.new("RGB", (W, H), bg), img, f)

def chunk_phrases(text, max_chars=72):
    parts = re.split(r"(?<=[.!?;:]) +", text.strip())
    phrases, buf = [], ""
    for p in parts:
        cand = (buf + " " + p).strip()
        if len(cand) <= max_chars: buf = cand
        else:
            if buf: phrases.append(buf)
            buf = p
    if buf: phrases.append(buf)
    return phrases or [text]

def draw_caption(base_img, phrase, dark=False):
    d = ImageDraw.Draw(base_img)
    wrapped = textwrap.wrap(phrase, width=76)[:2]
    pad = 10
    line_h = 26
    box_h = pad * 2 + line_h * len(wrapped)
    y0 = H - 24 - box_h
    bg = (22, 24, 29, 216) if not dark else (18, 20, 26, 235)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    ld.rounded_rectangle([(44, y0), (W - 44, y0 + box_h)], radius=6, fill=bg)
    base_img_rgba = base_img.convert("RGBA")
    base_img_rgba.alpha_composite(layer)
    out = base_img_rgba.convert("RGB")
    d = ImageDraw.Draw(out)
    yy = y0 + pad
    for line in wrapped:
        d.text((64, yy), line, font=font_sans(19), fill=(250, 250, 248))
        yy += line_h
    return out

def with_captions(draw_fn, narration, dur, bg=PAPER):
    if not narration:
        return draw_fn
    phrases = chunk_phrases(narration)
    total = sum(len(p) for p in phrases) or 1
    bounds = []
    acc = 0.0
    for p in phrases:
        share = max(0.8, dur * len(p) / total)
        bounds.append((acc / dur, min(1.0, (acc + share) / dur)))
        acc += share
    def wrapped_draw(t):
        img = draw_fn(t)
        active = None
        for (a, b), ph in zip(bounds, phrases):
            if a <= t < b:
                active = ph
                break
        if active is None and t >= bounds[-1][0]:
            active = phrases[-1]
        return draw_caption(img, active, dark=(getattr(draw_fn, "_terminal", False)))
    return wrapped_draw

def seg_from_draw(draw_fn, dur, name, idx, bg=PAPER):
    n = max(2, int(dur * FPS))
    for i in range(n):
        t = i / max(1, n - 1)
        img = draw_fn(t)
        img = apply_fades(img, t, dur, bg=bg)
        img.save(os.path.join(OUT, f"{name}-{idx}-{i:04d}.png"))
    seg = os.path.join(OUT, f"{name}-seg{idx}.mp4")
    subprocess.run(["ffmpeg", "-y", "-framerate", str(FPS), "-i",
                    os.path.join(OUT, f"{name}-{idx}-%04d.png"),
                    "-frames:v", str(n), "-r", str(FPS), "-c:v", "libx264", "-pix_fmt", "yuv420p",
                    seg], check=True, capture_output=True)
    for i in range(n):
        os.remove(os.path.join(OUT, f"{name}-{idx}-{i:04d}.png"))
    return seg

def concat_visual(segs, out):
    concat_txt = os.path.join(OUT, f"{out}-concat.txt")
    with open(concat_txt, "w") as f:
        for s in segs:
            f.write(f"file '{s}'\n")
    visual = os.path.join(OUT, f"{out}-visual.mp4")
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", concat_txt, "-c", "copy", visual],
                   check=True, capture_output=True)
    os.remove(concat_txt)
    return visual

def build_ass(name, segments, durations):
    """segments: list of narration strings; durations: list of per-segment durations."""
    start = 0.0
    events = []
    for i, (narr, dur) in enumerate(zip(segments, durations)):
        phrases = chunk_phrases(narr)
        total_chars = sum(len(p) for p in phrases) or 1
        t = start + 0.15
        avail = max(1.0, dur - 0.3)
        for ph in phrases:
            share = max(0.8, avail * len(ph) / total_chars)
            events.append((t, min(t + share, start + dur - 0.05), ph))
            t += share
        start += dur
    def ts(x):
        h = int(x // 3600); m = int((x % 3600) // 60); s = x % 60
        return f"{h}:{m:02d}:{s:05.2f}"
    ass = os.path.join(OUT, f"{name}.ass")
    with open(ass, "w") as f:
        f.write("""[Script Info]
ScriptType: v4.00+
PlayResX: 1280
PlayResY: 720

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Cap,Space Grotesk,30,&H00FFFFFF,&H00FFFFFF,&H00101418,&H70000000,0,0,0,0,100,100,0,0,1,2,0,2,60,60,26,1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
""")
        for (a, b, ph) in events:
            ph = ph.replace("\n", "\\N")
            f.write(f"Dialogue: 0,{ts(a)},{ts(b)},Cap,,0,0,0,,{ph}\n")
    return ass

def build_video(name, segments):
    """segments: list of dicts {draw: fn(t)->img, narration: str, dur: hint, bg: optional}"""
    from render import tts as _tts  # noqa
    segs = []
    durations = []
    narrations = []
    for idx, seg in enumerate(segments):
        narration = seg["narration"]
        if narration:
            audio = os.path.join(OUT, f"{name}-vo{idx}.mp3")
            _tts(narration, audio)
            probe = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                                    "-of", "default=nw=1:nk=1", audio], capture_output=True, text=True)
            adur = float(probe.stdout.strip()) + 0.5
        else:
            adur = seg.get("dur", 4)
        dark = seg.get("bg") is not None
        capped = with_captions(seg["draw"], narration, adur)
        segs.append(seg_from_draw(capped, adur, name, idx, bg=seg.get("bg") or PAPER))
        durations.append(adur)
        narrations.append(narration)
    visual = concat_visual(segs, name)
    vo_files = [os.path.join(OUT, f"{name}-vo{i}.mp3") for i, n in enumerate(narrations) if n]
    final = os.path.join(OUT, f"{name}.mp4")
    if vo_files:
        vo_cat = os.path.join(OUT, f"{name}-vo.mp3")
        fargs = []
        for v in vo_files:
            fargs += ["-i", v]
        filter_inputs = "".join(f"[{i}:a]" for i in range(len(vo_files)))
        subprocess.run(["ffmpeg", "-y", *fargs, "-filter_complex",
                        f"{filter_inputs}concat=n={len(vo_files)}:v=0:a=1",
                        vo_cat], check=True, capture_output=True)
    else:
        vo_cat = None
    raw = os.path.join(OUT, f"{name}-raw.mp4")
    subprocess.run(["ffmpeg", "-y", "-i", visual, *(["-i", vo_cat] if vo_cat else []),
                    *(["-c:v", "copy", "-c:a", "aac"] if vo_cat else ["-c:v", "copy"]),
                    "-shortest", raw], check=True, capture_output=True)
    os.replace(raw, final)
    for x in segs:
        os.remove(x)
    if vo_cat: os.remove(vo_cat)
    total = sum(durations)
    print(f"{name}.mp4 built ({total:.0f}s, captions burned)")
    return final

# legacy helpers used by videos.py
def slide_title(kicker, title_lines, sub=None):
    return anim_title(kicker, title_lines, sub or "")

def slide_section(no, title, items, cols=2):
    return anim_section(no, title, items, cols)

def slide_metrics(rows, note=None):
    return anim_metrics(rows, note)

def slide_code(lines, header="Integration"):
    return anim_code(lines, header)

def terminal_frame(lines, title="x402check — live demo", note=None):
    return anim_terminal(lines, note)

def c(s, col=TERM_FG): return (s, col)
def g(s): return (s, TERM_ACCENT)
def warn(s): return (s, TERM_WARN)
def dim(s): return (s, TERM_DIM)

def write_png(img, path):
    img.save(path)

def tts(text, path, voice=None, rate=None):
    KOKORO_PY = "/tmp/paysol-video/venv/bin/python"
    KOKORO_TTS = os.path.join(ROOT, "kokoro_tts.py")
    KOKORO_VOICE = os.environ.get("KOKORO_VOICE", "am_michael")
    if os.path.exists(KOKORO_PY) and os.path.exists(KOKORO_TTS):
        wav = path.replace(".mp3", ".wav")
        try:
            subprocess.run([KOKORO_PY, KOKORO_TTS, text.replace('"', "'"), KOKORO_VOICE, wav],
                           check=True, capture_output=True, timeout=180)
            import shutil
            shutil.move(wav, path)
            return
        except Exception:
            pass
    esc = text.replace('"', "'")
    subprocess.run(["edge-tts", "--voice", voice or "pt-BR-AntonioNeural", "--rate", "-8%",
                    "--text", esc, "--write-media", path], check=True, capture_output=True)
