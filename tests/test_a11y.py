"""Доступность интерфейса без браузера: контраст цветов палитры (WCAG 2.1 AA, 4,5:1 для обычного текста) в светлой
и тёмной темах и разметка, на которую опирается автоматическая подпись полей и кнопок.

Полная проверка в браузере (axe-core на всех страницах и в окнах) — tools/a11y_audit.py, см. docs/16-development.md."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / "web/css/app.css").read_text(encoding="utf-8")
JS = {p.name: p.read_text(encoding="utf-8") for p in (ROOT / "web/js").rglob("*.js")}


def _vars(block_start: str) -> dict:
    i = CSS.index(block_start)
    body = CSS[i:CSS.index("}", i)]
    return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", body))


LIGHT = _vars(":root {")
DARK = {**LIGHT, **_vars(':root[data-theme="dark"] {')}


def _lin(x: float) -> float:
    return x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4


def lum(c: str) -> float:
    r, g, b = (_lin(int(c[i:i + 2], 16) / 255) for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


TEXT = ("ink", "ink-2", "muted")
BACKS = ("surface", "surface-2", "surface-3", "page", "code-bg")
PAIRS = [("accent-ink", "accent-wash"), ("good-ink", "good-wash"), ("warning-ink", "warning-wash"),
         ("critical-ink", "critical-wash"), ("accent", "surface"), ("ink-2", "info-wash"), ("muted", "info-wash")]


@pytest.mark.parametrize("theme,pal", [("светлая", LIGHT), ("тёмная", DARK)])
def test_palette_contrast(theme, pal):
    bad = []
    for t in TEXT:
        for b in BACKS:
            if contrast(pal[t], pal[b]) < 4.5:
                bad.append(f"--{t} на --{b}: {contrast(pal[t], pal[b]):.2f}")
    for t, b in PAIRS:
        if contrast(pal[t], pal[b]) < 4.5:
            bad.append(f"--{t} на --{b}: {contrast(pal[t], pal[b]):.2f}")
    assert not bad, f"{theme} тема, контраст ниже 4,5:1 — " + "; ".join(bad)


def test_buttons_and_code_contrast():
    white = "#ffffff"
    assert contrast(white, LIGHT["accent"]) >= 4.5  # .btn.primary в светлой теме
    m = re.search(r':root\[data-theme="dark"\] \.btn\.primary \{ background: (#[0-9a-f]{6})', CSS)
    assert m and contrast(white, m.group(1)) >= 4.5, "в тёмной теме у основной кнопки свой, более тёмный фон"
    assert contrast(white, LIGHT["critical"]) >= 4.5  # .btn.danger.solid
    num = re.search(r"pre\.code \.n \{ color: (#[0-9a-f]{6})", CSS).group(1)
    assert contrast(num, LIGHT["code-bg"]) >= 4.5


def test_markup_hooks():
    ui = JS["ui.js"]
    assert "s.setAttribute('aria-hidden', 'true'); s.setAttribute('data-icon', name);" in ui  # значки не читаются
    assert "export function a11y(root)" in ui and "lab.htmlFor = ctl.id" in ui
    assert "h('span', { class: 'sr-only' }, c.srTitle || 'Действия')" in ui  # пустые заголовки столбцов
    assert ".sr-only {" in CSS and ".skip-link" in CSS and ":focus-visible" in CSS
    app = JS["app.js"]
    assert "new MutationObserver" in app and "a11y(n)" in app  # подписи для всего, что появляется позже
    assert "h('main', { class: 'login-wrap' }" in app and "h('h1', { class: 'brand-name' }" in app
    assert "'Перейти к содержимому'" in app
    # тепловая карта — группа ячеек-изображений, а не неполная «таблица» role=grid
    assert "role: 'grid'" not in JS["analytics-extra.js"]


def test_icon_buttons_named():
    """Кнопка только со значком без title/aria-label получает имя по значку — значок должен быть в словаре."""
    ui = JS["ui.js"]
    known = set(re.findall(r"(\w+): '", ui[ui.index("const ICON_LABEL"):ui.index("let a11ySeq")]))
    missing = set()
    for name, src in JS.items():
        for m in re.finditer(r"h\('button', \{([^{}]*)\}, icon\('(\w+)'\)\)", src):
            attrs, ic = m.groups()
            if "title" not in attrs and "aria-label" not in attrs and ic not in known:
                missing.add(f"{name}: {ic}")
    assert not missing, f"кнопки-значки без подписи: {sorted(missing)}"
