#!/usr/bin/env python3
"""Снимки экрана всех страниц панели (для документации и регрессионной проверки интерфейса).

python3 tools/screenshots.py --url http://127.0.0.1:8088 --user admin --password '...' --out docs/images
Требуется: pip install playwright; браузер Chromium/Chrome (--chrome /usr/bin/google-chrome).
"""
import argparse
import asyncio
import sys

PAGES = [
    ("dashboard", "#/", 6000), ("sites", "#/sites", 1500), ("site-editor", "#/sites?edit=1", 2500),
    ("site-editor-ssl", "#/sites?edit=1&tab=ssl", 2000), ("site-editor-locations", "#/sites?edit=1&tab=locations", 2000),
    ("site-editor-security", "#/sites?edit=1&tab=security", 2000), ("site-editor-cache", "#/sites?edit=1&tab=cache", 2000),
    ("streams", "#/streams", 1500), ("certs", "#/certs", 1500), ("analytics", "#/analytics", 4000),
    ("requests", "#/requests", 5000), ("errors", "#/errors", 2500), ("backends", "#/backends", 2000),
    ("system", "#/system", 4000), ("global", "#/global", 1500), ("global-ssl", "#/global?tab=ssl", 1500),
    ("versions", "#/versions", 1500), ("diagnostics", "#/diagnostics", 5000), ("alerts", "#/alerts", 1500),
    ("events", "#/events", 1500), ("users", "#/users", 1500), ("audit", "#/audit", 1500), ("settings", "#/settings", 1500),
    ("backup", "#/backup", 1500), ("profile", "#/profile", 1500), ("docs", "#/docs", 2000),
    ("bans", "#/bans", 2500), ("settings-bans", "#/settings?tab=bans", 1500),
    ("settings-reports", "#/settings?tab=reports", 1500), ("insights-thresholds", "#/insights?tab=thresholds", 3000),
    ("geo-tab", "#/bans?tab=countries", 3000), ("analytics-sla", "#/analytics?view=sla", 3000),
    ("analytics-heatmap", "#/analytics?view=heatmap", 3000), ("certs-dns", "#/certs?tab=dns", 2000),
    ("settings-acme", "#/settings?tab=acme", 1500),
]
SCENES = {"geo-site", "sites-bulk"}  # снимки с действиями: --only geo-site,sites-bulk или --extras


async def main(a):
    from playwright.async_api import async_playwright
    errors = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=a.chrome or None, args=["--no-sandbox"])
        ctx = await browser.new_context(viewport={"width": a.width, "height": a.height}, device_scale_factor=a.scale,
                                        locale="ru-RU", color_scheme=a.theme)
        page = await ctx.new_page()
        page.on("console", lambda m: errors.append(f"[console.{m.type}] {m.text}") if m.type in ("error",) else None)
        page.on("pageerror", lambda e: errors.append(f"[pageerror] {e}"))
        # адрес ответа с ошибкой (в консоли браузера его нет); 401 до входа — норма
        page.on("response", lambda r: errors.append(f"[http {r.status}] {r.request.method} {r.url}")
                if r.status >= 400 and r.status != 401 else None)
        await page.goto(a.url + "/")
        await page.add_init_script(f"localStorage.setItem('nm-theme', '{a.theme}')")
        await page.wait_for_selector("input[autocomplete=username]")
        await page.screenshot(path=f"{a.out}/login.png")
        await page.fill("input[autocomplete=username]", a.user)
        await page.fill("input[autocomplete=current-password]", a.password)
        await page.click("button[type=submit]")
        await page.wait_for_selector(".sidebar", timeout=15000)
        if not a.toasts:  # всплывающие уведомления о событиях стенда (бэкенд упал/поднялся) только мешают снимкам
            hide = ".toasts{display:none!important}"
            await page.add_style_tag(content=hide)
            await page.add_init_script("document.addEventListener('DOMContentLoaded', () => {"
                                       f"const s = document.createElement('style'); s.textContent = '{hide}';"
                                       "document.head.appendChild(s); });")
        only = set(a.only.split(",")) if a.only else None
        for name, hash_, wait in PAGES:
            if (only and name not in only) or a.only == "none":
                continue
            await page.goto(f"{a.url}/{hash_}")
            await page.wait_for_timeout(wait)
            before = len(errors)
            await page.screenshot(path=f"{a.out}/{name}.png", full_page=a.full)
            print(f"{name}: ok" + (f" ({len(errors) - before} ошибок)" if len(errors) > before else ""), flush=True)
        if a.extras or (only and only & SCENES):
            await scenes(page, a, None if a.extras else only)
        if a.extras:
            await extras(page, a)
        await browser.close()
    if errors:
        print("\n".join(errors[:50]))
    return 1 if errors else 0


async def scenes(page, a, only):
    """Доступ по странам в карточке сайта (с подсказкой поиска) и массовые действия в списке сайтов."""
    if not only or "geo-site" in only:
        await page.goto(f"{a.url}/#/sites?edit=1&tab=security")
        await page.wait_for_timeout(2500)
        await page.evaluate("""() => { const el = document.querySelector('[data-path="security.geo_mode"]');
            el.scrollIntoView({block: 'start'}); window.scrollBy(0, -90); }""")
        await page.fill(".cc-search input", "ка")
        await page.wait_for_timeout(900)
        await page.screenshot(path=f"{a.out}/geo-site.png")
        await page.fill(".cc-search input", "")
        print("geo-site: ok")
    if not only or "sites-bulk" in only:
        await page.goto(f"{a.url}/#/sites")
        await page.wait_for_timeout(2000)
        await page.click("table.t tbody tr:nth-child(1) input[type=checkbox]")
        await page.click("table.t tbody tr:nth-child(5) input[type=checkbox]")
        await page.wait_for_timeout(500)
        await page.screenshot(path=f"{a.out}/sites-bulk.png")
        print("sites-bulk: ok")


async def extras(page, a):
    """Снимки диалогов: мастер сайта, импорт, применение с изменениями, новый сертификат, тёмная тема."""
    await page.goto(f"{a.url}/#/sites")
    await page.wait_for_timeout(1500)
    await page.click("text=Добавить сайт")
    await page.wait_for_timeout(500)
    await page.fill(".modal input[placeholder='Мой сайт']", "Корпоративный портал")
    await page.fill(".modal input[placeholder='example.com www.example.com']", "portal.example.com www.portal.example.com")
    await page.wait_for_timeout(300)
    await page.screenshot(path=f"{a.out}/site-wizard.png")
    print("site-wizard: ok")
    await page.keyboard.press("Escape")
    await page.click("text=Импорт из nginx")
    await page.wait_for_timeout(2500)
    await page.screenshot(path=f"{a.out}/import.png")
    print("import: ok")
    await page.keyboard.press("Escape")
    await page.goto(f"{a.url}/#/certs")
    await page.wait_for_timeout(1200)
    await page.click(".page-head >> text=Добавить сертификат")
    await page.wait_for_timeout(800)
    # wildcard с DNS-проверкой — самый показательный вариант (нужна хотя бы одна учётная запись DNS)
    await page.evaluate("""() => { const s = document.querySelector('[data-path="challenge"] select');
        if (s) { s.value = '1'; s.dispatchEvent(new Event('change', {bubbles: true})); } }""")
    await page.wait_for_timeout(400)
    await page.fill('[data-path="domains"] textarea', "*.example.com\nexample.com")
    await page.fill('[data-path="name"] input', "example.com (wildcard)")
    await page.wait_for_timeout(400)
    await page.screenshot(path=f"{a.out}/cert-dialog.png")
    print("cert-dialog: ok")
    await page.keyboard.press("Escape")
    await page.goto(f"{a.url}/#/certs?tab=dns")
    await page.wait_for_timeout(1500)
    await page.click(".page-head >> text=Добавить учётную запись")
    await page.wait_for_timeout(600)
    await page.screenshot(path=f"{a.out}/dns-account-dialog.png")
    print("dns-account-dialog: ok")
    await page.keyboard.press("Escape")
    # изменение для диалога применения: меняем таймаут чтения сайта 3 через API страницы
    await page.evaluate("""async () => {
        const h = {'Content-Type': 'application/json', 'X-NM-CSRF': '1'};
        let s = await (await fetch('/api/sites/3')).json();
        if (s.data.proxy.read_timeout === '120s' || s.data.security.rate_limit) {  // повторный запуск: вернуть исходное
            s.data.proxy.read_timeout = '60s'; s.data.security.rate_limit = false;
            await fetch('/api/sites/3', {method: 'PUT', headers: h, body: JSON.stringify(s.data)});
            await fetch('/api/config/apply', {method: 'POST', headers: h, body: JSON.stringify({comment: 'screenshots: reset'})});
            s = await (await fetch('/api/sites/3')).json();
        }
        s.data.proxy.read_timeout = '120s'; s.data.security.rate_limit = true;
        await fetch('/api/sites/3', {method: 'PUT', headers: h, body: JSON.stringify(s.data)});
    }""")
    await page.goto(f"{a.url}/#/")
    await page.wait_for_timeout(11500)
    await page.click("text=Изменения")
    await page.wait_for_timeout(1500)
    await page.screenshot(path=f"{a.out}/pending-diff.png")
    print("pending-diff: ok")
    await page.keyboard.press("Escape")
    await page.click(".apply-bar >> text=Применить")
    await page.wait_for_timeout(500)
    await page.fill(".modal input[type=text]", "Блог: таймаут 120 с и ограничение частоты")
    await page.screenshot(path=f"{a.out}/apply-dialog.png")
    await page.click(".modal >> text=Проверить и применить")
    await page.wait_for_timeout(2500)
    print("apply-dialog: ok")
    dark = "document.documentElement.setAttribute('data-theme','dark'); localStorage.setItem('nm-theme','dark');" \
           "window.dispatchEvent(new HashChangeEvent('hashchange'))"
    await page.goto(f"{a.url}/#/")
    await page.wait_for_timeout(1500)
    await page.evaluate(dark)
    await page.wait_for_timeout(7000)
    await page.screenshot(path=f"{a.out}/dashboard-dark.png")
    await page.goto(f"{a.url}/#/sites?edit=1&tab=backends")
    await page.wait_for_timeout(1000)
    await page.evaluate(dark)
    await page.wait_for_timeout(2500)
    await page.screenshot(path=f"{a.out}/site-editor-dark.png")
    print("dark: ok")
    await page.evaluate("document.documentElement.setAttribute('data-theme','light'); localStorage.setItem('nm-theme','light')")
    # справка по странице и поиск по документации
    await page.goto(f"{a.url}/#/sites?edit=1&tab=ssl")
    await page.wait_for_timeout(2000)
    await page.click(".switch .info-i.link")
    await page.wait_for_timeout(2500)
    await page.screenshot(path=f"{a.out}/help-drawer.png")
    await page.keyboard.press("Escape")
    await page.goto(f"{a.url}/#/docs?p=01-overview.md")
    await page.wait_for_timeout(1500)
    await page.fill(".docs-nav input", "proxy_read_timeout")
    await page.wait_for_timeout(2500)
    await page.screenshot(path=f"{a.out}/docs-search.png")
    print("help: ok")
    # встроенный анализ: раскрытая находка и подсказка показателя
    await page.goto(f"{a.url}/#/insights")
    await page.wait_for_timeout(3500)
    await page.click(".finding-head")
    await page.wait_for_timeout(800)
    await page.screenshot(path=f"{a.out}/insights.png")
    await page.goto(f"{a.url}/#/")
    await page.wait_for_timeout(6000)
    await page.click(".kpi:nth-child(4) .kpi-hint")
    await page.wait_for_timeout(800)
    await page.screenshot(path=f"{a.out}/insights-hint.png")
    print("insights: ok")
    # быстрый поиск
    await page.keyboard.press("Escape")
    await page.goto(f"{a.url}/#/insights")
    await page.wait_for_timeout(1000)
    await page.goto(f"{a.url}/#/")
    await page.wait_for_timeout(3000)
    await page.keyboard.press("Control+k")
    await page.fill(".pal-input input", "таймаут")
    await page.wait_for_timeout(1800)
    await page.screenshot(path=f"{a.out}/palette.png")
    await page.keyboard.press("Escape")
    # тишина оповещений (создаётся и снимается через API)
    sid = await page.evaluate("""async () => {
        const h = {'Content-Type': 'application/json', 'X-NM-CSRF': '1'};
        const r = await fetch('/api/alerts/silences', {method: 'POST', headers: h,
            body: JSON.stringify({minutes: 120, reason: 'Обновление базы данных'})});
        return (await r.json()).id; }""")
    await page.goto(f"{a.url}/#/alerts")
    await page.wait_for_timeout(2500)
    await page.screenshot(path=f"{a.out}/alerts-silence.png")
    await page.evaluate("async (id) => fetch('/api/alerts/silences/' + id, {method: 'DELETE', headers: {'X-NM-CSRF': '1'}})", sid)
    print("palette, silence: ok")
    await mobile(page.context.browser, a)


async def mobile(browser, a):
    """Три экрана телефона рядом: дашборд, меню, редактор сайта."""
    from PIL import Image
    ctx = await browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=1, locale="ru-RU",
                                    is_mobile=True, has_touch=True)
    page = await ctx.new_page()
    await page.goto(a.url + "/")
    await page.wait_for_selector("input[autocomplete=username]")
    await page.fill("input[autocomplete=username]", a.user)
    await page.fill("input[autocomplete=current-password]", a.password)
    await page.click("button[type=submit]")
    await page.wait_for_selector(".main", timeout=15000)
    if not a.toasts:
        await page.add_style_tag(content=".toasts{display:none!important}")
    shots = []
    await page.goto(f"{a.url}/#/")
    await page.wait_for_timeout(6000)
    shots.append(await page.screenshot())
    await page.click(".menu-btn")
    await page.wait_for_timeout(600)
    shots.append(await page.screenshot())
    await page.goto(f"{a.url}/#/sites?edit=1&tab=ssl")
    await page.wait_for_timeout(2500)
    shots.append(await page.screenshot())
    import io
    ims = [Image.open(io.BytesIO(b)) for b in shots]
    gap = 24
    out = Image.new("RGB", (sum(i.width for i in ims) + gap * (len(ims) + 1), ims[0].height + gap * 2), (233, 232, 226))
    x = gap
    for im in ims:
        out.paste(im, (x, gap))
        x += im.width + gap
    out.save(f"{a.out}/mobile.png", optimize=True)
    await ctx.close()
    print("mobile: ok")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8088")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", required=True)
    ap.add_argument("--out", default="docs/images")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--width", type=int, default=1600)
    ap.add_argument("--height", type=int, default=1000)
    ap.add_argument("--scale", type=float, default=1)
    ap.add_argument("--theme", default="light")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--extras", action="store_true", help="снимки диалогов и тёмной темы")
    ap.add_argument("--toasts", action="store_true", help="не скрывать всплывающие уведомления")
    sys.exit(asyncio.run(main(ap.parse_args())))
