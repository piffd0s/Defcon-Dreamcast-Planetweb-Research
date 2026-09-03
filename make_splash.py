#!/usr/bin/env python3
"""Generate a 640x480 'DistrictCon Junkyard' splash GIF for the Dreamcast browser.
GIF is used for maximum compatibility with the 2001-era PlanetWeb renderer."""
import os
from PIL import Image, ImageDraw, ImageFont

W, H = 640, 480
img = Image.new("RGB", (W, H), (8, 8, 12))
d = ImageDraw.Draw(img)

# subtle scanline / junkyard grit
for y in range(0, H, 4):
    d.line([(0, y), (W, y)], fill=(14, 14, 20))

def font(sz):
    for p in ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
              "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"):
        if os.path.exists(p):
            return ImageFont.truetype(p, sz)
    return ImageFont.load_default()

def center(text, y, f, fill):
    bb = d.textbbox((0, 0), text, font=f)
    d.text(((W - (bb[2] - bb[0])) // 2, y), text, font=f, fill=fill)

# warning band
d.rectangle([0, 70, W, 150], fill=(180, 30, 30))
center("// PWNED — REMOTE CODE EXECUTION //", 95, font(26), (255, 240, 200))

center("DISTRICTCON", 200, font(64), (235, 235, 245))
center("JUNKYARD", 270, font(64), (255, 90, 60))

center("Sega Dreamcast PlanetWeb Browser v3.0", 360, font(22), (150, 200, 255))
center("Eden service-subscription RCE  ·  no SecurityManager", 392, font(18), (120, 120, 140))
center(">>> press START / click to LAUNCH DOOM <<<", 432, font(20), (120, 255, 120))

# corner brackets
for (x0, y0, x1, y1) in [(10, 10, 60, 10), (10, 10, 10, 60),
                         (W-60, 10, W-10, 10), (W-10, 10, W-10, 60),
                         (10, H-10, 60, H-10), (10, H-60, 10, H-10),
                         (W-60, H-10, W-10, H-10), (W-10, H-60, W-10, H-10)]:
    d.line([(x0, y0), (x1, y1)], fill=(255, 90, 60), width=3)

out = os.path.join(os.path.dirname(__file__), "www", "junkyard.gif")
img.convert("P", palette=Image.ADAPTIVE, colors=256).save(out)
print("wrote", out)
