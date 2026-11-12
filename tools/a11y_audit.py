#!/usr/bin/env python3
"""Проверка доступности интерфейса в браузере: axe-core (WCAG 2.1 A/AA и рекомендации) на всех страницах панели,
в окнах создания объектов и в окне восстановления копии — в светлой и тёмной темах.

    npm install axe-core          # один раз, в любом каталоге
    python3 tools/a11y_audit.py --url http://127.0.0.1:8088 --user admin --password '...' \\
        --axe node_modules/axe-core/axe.min.js --chrome /usr/bin/google-chrome

Код выхода 0 — нарушений нет; иначе список: правило, важность, число элементов, страница и пример элемента.
Требуется: pip install playwright; браузер Chromium/Chrome.
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screenshots import PAGES  # noqa: E402 — тот же список страниц, что и для снимков экрана

TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"]
DIALOGS = ["#/sites", "#/streams", "#/certs", "#/users", "#/bans", "#/certs?tab=dns"]  # кнопка «Добавить…» в шапке
JS_RUN = """async (tags) => {
  const root = document.querySelector('.modal') || document;
  const r = await axe.run(root, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] });
  return r.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help, n: v.nodes.length,
    target: v.nodes[0].target.join(' '), html: v.nodes[0].html.slice(0, 160) }));
}"""


async def check(page, axe, where, out):
    await page.evaluate(axe)
    for v in await page.evaluate(JS_RUN, TAGS):
        out.append(dict(v, where=where))


async def theme_run(browser, a, axe, theme, out):
    ctx = await browser.new_context(viewport={"width": 1400, "height": 900}, locale="ru-RU", bypass_csp=True,
                                    color_scheme=theme)
    page = await ctx.new_page()
    await page.add_init_script(f"localStorage.setItem('nm-theme', '{theme}')")
    await page.goto(a.url + "/")
    await page.wait_for_selector("input[autocomplete=username]")
    await check(page, axe, f"{theme}: вход", out)
    await page.fill("input[autocomplete=username]", a.user)
    await page.fill("input[autocomplete=current-password]", a.password)
    await page.click("button[type=submit]")
    await page.wait_for_selector(".sidebar", timeout=15000)
    for name, hash_, wait in PAGES:
        await page.goto(f"{a.url}/{hash_}")
        await page.wait_for_timeout(min(wait, 2500))
        await check(page, axe, f"{theme}: {name}", out)
        print(f"{theme}: {name}", flush=True)
    for hash_ in DIALOGS:
        await page.goto(f"{a.url}/{hash_}")
        await page.wait_for_timeout(1500)
        btn = page.locator(".page-head .btn.primary").first
        if not await btn.count():
            continue
        await btn.click()
        await page.wait_for_timeout(1200)
        if await page.locator(".modal").count():
            await check(page, axe, f"{theme}: окно {hash_}", out)
            await page.keyboard.press("Escape")
    await page.goto(f"{a.url}/#/backup")
    await page.wait_for_timeout(1500)
    rst = page.locator("table.t tbody tr button", has_text="Восстановить").first
    if await rst.count():
        await rst.click()
        try:
            await page.wait_for_selector(".modal", timeout=15000)
            await check(page, axe, f"{theme}: окно восстановления копии", out)
        finally:
            await page.keyboard.press("Escape")
    await ctx.close()


async def main(a):
    from playwright.async_api import async_playwright
    axe = Path(a.axe).read_text(encoding="utf-8")
    out = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=a.chrome or None, args=["--no-sandbox"])
        for theme in a.themes.split(","):
            await theme_run(browser, a, axe, theme, out)
        await browser.close()
    if not out:
        print("Нарушений доступности не найдено")
        return 0
    print(f"\nНарушений: {len(out)}")
    for v in sorted(out, key=lambda x: (x["impact"] != "critical", x["impact"] != "serious", x["id"])):
        print(f"[{v['impact']}] {v['id']} ×{v['n']} — {v['where']}: {v['help']}\n    {v['target']}  {v['html']}")
    return 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", default="http://127.0.0.1:8088")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", required=True)
    ap.add_argument("--axe", required=True, help="путь к axe.min.js (npm install axe-core)")
    ap.add_argument("--chrome", default="", help="путь к Chrome/Chromium, если не установлен браузер Playwright")
    ap.add_argument("--themes", default="light,dark")
    sys.exit(asyncio.run(main(ap.parse_args())))
