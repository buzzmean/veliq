#!/usr/bin/env python3
"""Собирает .ico из готовых PNG (сначала node design/tools/render-assets.mjs). Нужен Pillow."""
from pathlib import Path
from PIL import Image

ICONS = Path(__file__).resolve().parents[2] / "brand" / "icons"
PNG = ICONS / "png"


def ico(out: Path, stem: str, sizes):
    imgs = [Image.open(PNG / f"{stem}-{s}.png").convert("RGBA") for s in sizes]
    big = imgs[-1]
    big.save(out, format="ICO", sizes=[(s, s) for s in sizes], append_images=imgs[:-1])
    print("ico →", out.relative_to(ICONS.parents[1]))


ico(ICONS / "app-icon.ico", "app-icon", [16, 20, 24, 32, 40, 48, 64, 128, 256])
ico(ICONS / "favicon.ico", "app-icon", [16, 32, 48])
for st in ("off", "connecting", "on", "error"):
    for th in ("dark", "light"):
        ico(ICONS / f"tray-{st}-{th}.ico", f"tray-{st}-{th}", [16, 20, 24, 32, 48])
