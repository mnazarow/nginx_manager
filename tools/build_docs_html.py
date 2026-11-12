#!/usr/bin/env python3
"""Сборка документации в один автономный HTML-файл (все главы, схемы и скриншоты внутри).

Файл открывается в любом браузере без установки панели и без сети; его можно распечатать в PDF.

Использование:
    python3 tools/build_docs_html.py [--out docs/nginx-manager-docs.html] [--quality 80]

Требуется: python3-markdown (pip install markdown), Pillow — для сжатия скриншотов в WebP (без Pillow
скриншоты встраиваются как PNG, файл получается крупнее).
"""
import argparse
import base64
import html
import io
import re
from pathlib import Path

import markdown
from markdown.extensions.toc import slugify_unicode

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

CSS = """
:root{--bg:#f9f9f7;--card:#fff;--ink:#0b0b0b;--ink2:#52514e;--line:#e4e3dc;--accent:#2a78d6;--code:#f2f1ec;--side:280px}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1c1c1a;--ink:#ecebe6;--ink2:#a9a8a2;--line:#33332f;
 --accent:#5b9bea;--code:#262624}img.shot{border-color:#33332f}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
nav{position:fixed;top:0;left:0;bottom:0;width:var(--side);overflow:auto;padding:22px 16px;border-right:1px solid var(--line);background:var(--card)}
nav h1{font-size:16px;margin:0 0 4px}nav .ver{color:var(--ink2);font-size:12px;margin-bottom:14px}
nav input{width:100%;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);margin-bottom:10px}
nav a{display:block;padding:5px 8px;border-radius:6px;color:var(--ink);text-decoration:none;font-size:13.5px}
nav a:hover{background:var(--code)}nav a.sub{padding-left:22px;color:var(--ink2);font-size:12.5px}
main{margin-left:var(--side);padding:28px 48px 80px;max-width:calc(var(--side) + 1100px)}
section.chapter{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px 36px;margin-bottom:28px}
h1,h2,h3,h4{line-height:1.3;scroll-margin-top:16px}h1{font-size:28px;margin-top:0}h2{font-size:21px;margin-top:34px;border-top:1px solid var(--line);padding-top:22px}
h3{font-size:17px;margin-top:26px}a{color:var(--accent)}
code{font:12.5px/1.5 ui-monospace,Menlo,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:5px}
pre{background:var(--code);padding:14px 16px;border-radius:10px;overflow:auto}pre code{background:none;padding:0}
table{border-collapse:collapse;width:100%;margin:14px 0;font-size:13.5px;display:block;overflow:auto}
th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}th{background:var(--code)}
blockquote{margin:14px 0;padding:10px 16px;border-left:4px solid var(--accent);background:var(--code);border-radius:0 8px 8px 0}
img{max-width:100%;height:auto}img.shot{border:1px solid var(--line);border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,.06)}
img.diagram{background:#fff;border-radius:10px;padding:6px}
.top{position:fixed;right:20px;bottom:20px;background:var(--accent);color:#fff;border-radius:20px;padding:6px 14px;text-decoration:none;font-size:13px}
@media (max-width:900px){nav{position:static;width:auto;border-right:0}main{margin:0;padding:12px}section.chapter{padding:18px}}
@media print{nav,.top{display:none}main{margin:0;padding:0;max-width:none}section.chapter{border:0;page-break-before:always;padding:0}}
"""

JS = """
const q=document.getElementById('q');q.addEventListener('input',()=>{const v=q.value.trim().toLowerCase();
document.querySelectorAll('nav a[data-t]').forEach(a=>{a.style.display=!v||a.dataset.t.includes(v)?'':'none'})});
"""


def image_data(path: Path, quality: int) -> str:
    if path.suffix == ".svg":
        return "data:image/svg+xml;base64," + base64.b64encode(path.read_bytes()).decode()
    try:
        from PIL import Image
        im = Image.open(path).convert("RGB")
        buf = io.BytesIO()
        im.save(buf, "WEBP", quality=quality, method=6)
        return "data:image/webp;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=str(DOCS / "nginx-manager-docs.html"))
    ap.add_argument("--quality", type=int, default=80, help="качество WebP для скриншотов (1–100)")
    a = ap.parse_args()

    version = (ROOT / "VERSION").read_text().strip()
    chapters = sorted(p for p in DOCS.glob("[0-9][0-9]-*.md"))
    stems = {p.name: p.stem[:2] for p in chapters}
    images: dict = {}
    nav, body = [], []

    for p in chapters:
        num = p.stem[:2]
        md = markdown.Markdown(extensions=["tables", "fenced_code", "sane_lists", "toc"],
                               extension_configs={"toc": {"slugify": slugify_unicode, "toc_depth": "1-3"}})
        out = md.convert(p.read_text(encoding="utf-8"))
        # уникальные якоря в пределах одного файла: chNN-<якорь>
        out = re.sub(r'id="([^"]+)"', lambda m, num=num: f'id="ch{num}-{m.group(1)}"', out)

        def link(m, num=num):
            href = m.group(1)
            if href.startswith(("http://", "https://", "mailto:")):
                return f'href="{href}" target="_blank" rel="noopener"'
            file, _, anchor = href.partition("#")
            if not file:
                return f'href="#ch{num}-{anchor}"'
            if file in stems:
                n = stems[file]
                return f'href="#ch{n}-{anchor}"' if anchor else f'href="#ch{n}"'
            return m.group(0)
        out = re.sub(r'href="([^"]+)"', link, out)

        def img(m, num=num):  # noqa: ARG001
            src = m.group(1)
            f = (DOCS / src).resolve()
            if not f.exists():
                return m.group(0)
            if src not in images:
                images[src] = image_data(f, a.quality)
            cls = "diagram" if f.suffix == ".svg" else "shot"
            return f'src="{images[src]}" class="{cls}"'
        out = re.sub(r'src="([^"]+)"', img, out)

        body.append(f'<section class="chapter" id="ch{num}">{out}</section>')
        title = next((t["name"] for t in md.toc_tokens), p.stem)
        nav.append(f'<a href="#ch{num}" data-t="{html.escape(title.lower())}">{html.escape(title)}</a>')
        for t in (md.toc_tokens[0]["children"] if md.toc_tokens else []):
            nav.append(f'<a class="sub" href="#ch{num}-{t["id"]}" data-t="{html.escape(t["name"].lower())}">'
                       f'{html.escape(t["name"])}</a>')

    doc = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nginx Manager {version} — документация</title><style>{CSS}</style></head>
<body><nav><h1>Nginx Manager</h1><div class="ver">Документация, версия {version}</div>
<input id="q" placeholder="Поиск по разделам…" aria-label="Поиск по разделам">{''.join(nav)}</nav>
<main>{''.join(body)}</main><a class="top" href="#ch01">↑ к началу</a><script>{JS}</script></body></html>"""
    Path(a.out).write_text(doc, encoding="utf-8")
    print(f"{a.out}: {len(chapters)} глав, {len(images)} изображений, {len(doc) / 1048576:.1f} МБ")


if __name__ == "__main__":
    main()
