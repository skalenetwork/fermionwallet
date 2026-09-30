#!/usr/bin/env python3
"""Turn the frames recorded by record.js into the README's demo GIF.

record.js drives the real product flow on the real Safe{Wallet} and writes one
screenshot per beat plus frames.json (file, hold time, caption). This script adds
a title card, a caption strip under each frame, the Ledger window as an overlay on
the beats where the device is being read, and an end card — then writes one
optimized, looping GIF.

    python3 make_gif.py <frames-dir> <out.gif> [width]

GitHub renders a GIF inline in a README; it renders no video format inline, which
is why this is a GIF and not an mp4. Keep the result under a few megabytes: colour
depth first, then width, then holds.
"""
import json
import os
import sys
from PIL import Image, ImageDraw, ImageFont

W = int(sys.argv[3]) if len(sys.argv) > 3 else 900
CAPTION_H = 92
COLORS = 240
BG = (11, 14, 20)  # the product site's near-black
FG = (238, 242, 247)
ACCENT = (34, 197, 94)  # the Guard's green
MUTED = (148, 163, 184)

INTER = "/usr/share/fonts/opentype/inter/Inter-{}.otf"
DEJAVU = "/usr/share/fonts/truetype/dejavu/DejaVuSans{}.ttf"


def font(weight, size):
    for path in (INTER.format(weight), DEJAVU.format("-Bold" if weight != "Regular" else "")):
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default(size=size)


def wrap(draw, text, fnt, max_w):
    lines, line = [], ""
    for word in text.split():
        probe = f"{line} {word}".strip()
        if draw.textlength(probe, font=fnt) <= max_w or not line:
            line = probe
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def caption_strip(text, width):
    """The narration under each frame: two lines at most, centred."""
    img = Image.new("RGB", (width, CAPTION_H), BG)
    d = ImageDraw.Draw(img)
    d.line([(0, 0), (width, 0)], fill=(30, 41, 59), width=2)
    fnt = font("SemiBold", 25)
    lines = wrap(d, text, fnt, width - 80)
    while len(lines) > 2 and fnt.size > 18:
        fnt = font("SemiBold", fnt.size - 2)
        lines = wrap(d, text, fnt, width - 80)
    total = len(lines) * (fnt.size + 8) - 8
    y = (CAPTION_H - total) // 2
    for line in lines:
        d.text(((width - d.textlength(line, font=fnt)) // 2, y), line, font=fnt, fill=FG)
        y += fnt.size + 8
    return img


def card(width, height, lines):
    """A title or end card: (text, weight, size, colour) per line, centred."""
    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    rendered = [(text, font(weight, size), colour) for text, weight, size, colour in lines]
    total = sum(f.size + 22 for _, f, _ in rendered) - 22
    y = (height - total) // 2
    for text, fnt, colour in rendered:
        d.text(((width - d.textlength(text, font=fnt)) // 2, y), text, font=fnt, fill=colour)
        y += fnt.size + 22
    d.rectangle([(0, height - 6), (width, height)], fill=ACCENT)
    return img


def with_device(page, device_path, scale):
    """Dim the browser and lay the Ledger window over it: on these beats the device
    is what matters, and the page behind it has already been read."""
    page = Image.blend(page, Image.new("RGB", page.size, BG), 0.55)
    dev = Image.open(device_path).convert("RGB")
    dw = int(page.width * 0.62)
    dev = dev.resize((dw, round(dev.height * dw / dev.width)), Image.LANCZOS)
    x, y = (page.width - dev.width) // 2, (page.height - dev.height) // 2
    glow = Image.new("RGB", (dev.width + 8, dev.height + 8), (24, 32, 44))
    page.paste(glow, (x - 4, y - 4))
    page.paste(dev, (x, y))
    return page


def main():
    src, out = sys.argv[1], sys.argv[2]
    meta = json.load(open(os.path.join(src, "frames.json")))
    shots, holds = [], []

    page_h = None
    for f in meta["frames"]:
        page = Image.open(os.path.join(src, f["file"])).convert("RGB")
        page = page.resize((W, round(page.height * W / page.width)), Image.LANCZOS)
        page_h = page.height
        if f.get("device"):
            page = with_device(page, os.path.join(src, f["device"]), W)
        canvas = Image.new("RGB", (W, page.height + CAPTION_H), BG)
        canvas.paste(page, (0, 0))
        canvas.paste(caption_strip(f["caption"], W), (0, page.height))
        shots.append(canvas)
        holds.append(f["hold"])

    height = page_h + CAPTION_H
    title = card(W, height, [
        ("FermionGuard", "Bold", 64, FG),
        ("A second, post-quantum authorization on every transfer", "SemiBold", 27, MUTED),
        ("Recorded live in the real Safe{Wallet}. Nothing here is mocked.", "Regular", 22, ACCENT),
    ])
    end = card(W, height, [
        ("Keep the wallets you already trust.", "Bold", 40, FG),
        ("Make the next decade of cryptographic risk irrelevant.", "SemiBold", 27, MUTED),
        ("github.com/skalenetwork/fermionwallet", "SemiBold", 24, ACCENT),
    ])
    shots = [title] + shots + [end]
    holds = [2800] + holds + [4000]

    # One shared palette for every frame: Pillow only writes inter-frame deltas when
    # the palettes match, which is the difference between a 2 MB and a 15 MB GIF.
    strip = Image.new("RGB", (W, height * len(shots)))
    for i, s in enumerate(shots):
        strip.paste(s, (0, i * height))
    palette = strip.quantize(colors=COLORS, method=Image.MEDIANCUT)
    quantized = [s.quantize(palette=palette, dither=Image.NONE) for s in shots]

    quantized[0].save(out, save_all=True, append_images=quantized[1:], duration=holds,
                      loop=0, optimize=True, disposal=1)
    size = os.path.getsize(out)
    print(f"{out}: {len(quantized)} frames, {W}x{height}, {sum(holds) / 1000:.1f}s, "
          f"{size / 1e6:.2f} MB")


if __name__ == "__main__":
    main()
