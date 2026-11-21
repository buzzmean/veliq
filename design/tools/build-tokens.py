#!/usr/bin/env python3
"""Собирает design/tokens/tokens.css и icons.js из tokens.json и sprite.svg
и раскладывает общие файлы (токены, шрифт, иконки, логотипы) в website/ и app-ui/.

Запуск из корня репозитория:  python3 design/tools/build-tokens.py
Зависимостей нет (только стандартная библиотека).
"""
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "design"
TOKENS = json.loads((DESIGN / "tokens" / "tokens.json").read_text(encoding="utf-8"))
PRIM = TOKENS["color"]["primitive"]


def ref(value: str) -> str:
    m = re.fullmatch(r"\{([\w-]+)\}", value)
    return f"var(--c-{m.group(1)})" if m else value


def block(selector: str, pairs: dict, prefix: str, indent: str = "") -> str:
    lines = [f"{indent}{selector} {{"]
    for k, v in pairs.items():
        if k.startswith("$"):
            continue
        lines.append(f"{indent}  --{prefix}{k}: {ref(str(v))};")
    lines.append(f"{indent}}}")
    return "\n".join(lines)


def build_css() -> str:
    t = TOKENS
    out = [
        "/* VELIQ design tokens — СГЕНЕРИРОВАНО из design/tokens/tokens.json.",
        "   Не править вручную: python3 design/tools/build-tokens.py */",
        "",
        "@font-face {",
        '  font-family: "Onest";',
        '  src: url("fonts/Onest-var.woff2") format("woff2");',
        "  font-weight: 100 900;",
        "  font-style: normal;",
        "  font-display: swap;",
        "  /* Метрики шрифта зафиксированы, чтобы строка и прорезь в заголовках стояли одинаково на Windows, Android, macOS и iOS */",
        "  ascent-override: 97%;",
        "  descent-override: 30.5%;",
        "  line-gap-override: 0%;",
        "}",
        "",
    ]
    root = {}
    for k, v in PRIM.items():
        root[f"c-{k}"] = v
    for k, v in t["color"]["light"].items():
        root[k] = ref(v)
    root["font-sans"] = t["font"]["family"]["sans"]
    for group in ("weight", "size", "leading", "tracking"):
        for k, v in t["font"][group].items():
            root[f"{ {'weight':'fw','size':'fs','leading':'lh','tracking':'ls'}[group] }-{k}"] = v
    for k, v in t["space"].items():
        root[f"sp-{k}"] = v
    for k, v in t["radius"].items():
        if not k.startswith("$"):
            root[f"r-{k}"] = v
    root["slit-pos"] = t["slit"]["position"]
    root["slit-h"] = t["slit"]["thickness"]
    for k, v in t["shadow"].items():
        root[f"shadow-{k}"] = v
    for k, v in t["motion"]["duration"].items():
        root[f"dur-{k}"] = v
    for k, v in t["motion"]["easing"].items():
        root[f"ease-{k}"] = v
    for k, v in t["layout"].items():
        root[f"layout-{k}"] = v
    root["app-rail"] = t["app"]["rail"]
    root["app-titlebar"] = t["app"]["titlebar"]
    root["shadow-current"] = "var(--shadow-pop)"

    out.append(block(":root", root, ""))
    out.append("")
    dark = dict(t["color"]["dark"])
    dark["shadow-current"] = "var(--shadow-pop-dark)"
    out.append("@media (prefers-color-scheme: dark) {")
    out.append(block(":root:not([data-theme=\"light\"])", dark, "", "  ") + "\n  :root:not([data-theme=\"light\"]) { color-scheme: dark; }")
    out.append("}")
    out.append(block(':root[data-theme="dark"]', dark, "") + '\n:root[data-theme="dark"] { color-scheme: dark; }')
    out.append("")
    out.append("@media (prefers-reduced-motion: reduce) {")
    out.append("  :root { --dur-fast: 0ms; --dur-base: 0ms; --dur-slow: 0ms; --dur-route: 0ms; }")
    out.append("}")
    return "\n".join(out) + "\n"


def build_icons_js() -> str:
    svg = (DESIGN / "icons" / "sprite.svg").read_text(encoding="utf-8")
    svg = re.sub(r"<!--.*?-->", "", svg, flags=re.S)
    svg = re.sub(r">\s+<", "><", svg).strip()
    return (
        "/* VELIQ icons — СГЕНЕРИРОВАНО из design/icons/sprite.svg. Вставляет спрайт в страницу,\n"
        "   чтобы <svg><use href=\"#i-power\"/></svg> работал и при открытии файла двойным кликом. */\n"
        "(function(){var d=document.createElement('div');d.setAttribute('aria-hidden','true');"
        "d.style.cssText='position:absolute;width:0;height:0;overflow:hidden';d.innerHTML="
        + json.dumps(svg)
        + ";(document.body||document.documentElement).insertBefore(d,(document.body||document.documentElement).firstChild);})();\n"
    )


def main() -> None:
    css = build_css()
    js = build_icons_js()
    (DESIGN / "tokens" / "tokens.css").write_text(css, encoding="utf-8")
    (DESIGN / "icons" / "icons.js").write_text(js, encoding="utf-8")

    targets = {
        ROOT / "website" / "assets": "website",
        ROOT / "app-ui" / "assets": "app-ui",
        DESIGN / "assets": "design",
    }
    for dest in targets:
        (dest / "fonts").mkdir(parents=True, exist_ok=True)
        (dest / "img").mkdir(parents=True, exist_ok=True)
        (dest / "tokens.css").write_text(css, encoding="utf-8")
        (dest / "icons.js").write_text(js, encoding="utf-8")
        shutil.copy(DESIGN / "components.css", dest / "components.css")
        shutil.copy(DESIGN / "charts.js", dest / "charts.js")
        shutil.copy(DESIGN / "fonts" / "Onest-var.woff2", dest / "fonts" / "Onest-var.woff2")
        for logo in (ROOT / "brand" / "logo").glob("*.svg"):
            shutil.copy(logo, dest / "img" / logo.name)
        icons = ROOT / "brand" / "icons"
        for f in ("app-icon.svg", "favicon.svg", "favicon.ico", "png/app-icon-180.png", "png/app-icon-192.png", "png/app-icon-512.png"):
            if (icons / f).exists():
                shutil.copy(icons / f, dest / "img" / Path(f).name)
        (dest / "img" / "tray").mkdir(exist_ok=True)
        for tray in icons.glob("tray-*.svg"):
            shutil.copy(tray, dest / "img" / "tray" / tray.name)
        for og in (ROOT / "brand" / "social").glob("og-*.png"):
            shutil.copy(og, dest / "img" / og.name)
        print("обновлено:", dest.relative_to(ROOT))


if __name__ == "__main__":
    main()
