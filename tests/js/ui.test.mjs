// Чистые функции интерфейса (форматирование, экранирование, якоря документации) — на граничных значениях.
// Запуск: node --test tests/js/  (вызывается и из pytest: tests/test_js_units.py)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as ui from '../../web/js/ui.js';
import { slugify } from '../../web/js/docrender.js';

const nbsp = (s) => s.replace(/ | /g, ' ');

test('числа: пусто, NaN, бесконечность, отрицательные', () => {
  for (const v of [null, undefined, NaN, 'abc']) {
    assert.equal(ui.fmtNum(v), '—');
    assert.equal(ui.fmtInt(v), '—');
    assert.equal(ui.fmtBytes(v), '—');
    assert.equal(ui.fmtBps(v), '—');
    assert.equal(ui.fmtMs(v), '—');
    assert.equal(ui.fmtPct(v), '—');
    assert.equal(ui.fmtCompact(v), '—');
  }
  assert.equal(nbsp(ui.fmtInt(1234567.6)), '1 234 568');
  assert.equal(nbsp(ui.fmtNum(-1234.56, 1)), '-1 234,6');
  assert.equal(ui.fmtPct(0), '0%');
});

test('байты и скорости: границы единиц', () => {
  assert.equal(ui.fmtBytes(0), '0 Б');
  assert.equal(nbsp(ui.fmtBytes(1023)), '1 023 Б');
  assert.equal(ui.fmtBytes(1024), '1 КБ');
  assert.equal(ui.fmtBytes(1536), '1,5 КБ');
  assert.equal(ui.fmtBytes(-2048), '-2 КБ');
  assert.match(ui.fmtBytes(1024 ** 6), /ПБ$/);  // больше петабайта — остаётся в ПБ
  assert.equal(ui.fmtBps(999), '999 бит/с');
  assert.equal(ui.fmtBps(1000), '1 Кбит/с');
  assert.equal(ui.fmtBps(2.5e9), '2,5 Гбит/с');
});

test('время: миллисекунды, длительности, «назад»', () => {
  assert.equal(ui.fmtMs(0.25), '0,3 мс');
  assert.equal(ui.fmtMs(999.7), '1 с');  // а не «1 000 мс»
  assert.equal(ui.fmtMs(1500), '1,5 с');
  assert.equal(ui.fmtDur(0), '0 с');
  assert.equal(ui.fmtDur(-30), '0 с');  // часы серверов расходятся
  assert.equal(ui.fmtDur(59.6), '1 мин');
  assert.equal(ui.fmtDur(3725), '1 ч 2 мин');
  assert.equal(ui.fmtDur(90061), '1 д 1 ч');
  assert.equal(ui.fmtAgo(0), '—');
  assert.equal(ui.fmtAgo(Date.now() / 1000 + 100), '0 с назад');  // время из будущего
  assert.equal(ui.fmtAgo(Date.now() / 1000 - 7200), '2 ч назад');
  assert.equal(ui.fmtDate(0), '—');
});

test('компактные числа', () => {
  assert.equal(ui.fmtCompact(5), '5');
  assert.equal(ui.fmtCompact(5.25), '5,3');
  assert.equal(nbsp(ui.fmtCompact(9999)), '9 999');
  assert.equal(ui.fmtCompact(12500), '12,5 тыс');
  assert.equal(ui.fmtCompact(-3.2e9), '-3,2 млрд');
});

test('страны и коды ответа', () => {
  assert.equal(ui.countryName('RU'), 'Россия');
  assert.equal(ui.countryName('LAN'), 'локальная сеть');
  assert.equal(ui.countryName('--'), '');
  assert.equal(ui.countryName(''), '');
  assert.equal(ui.countryName('ZZ'), 'неизвестный регион');
  assert.equal(ui.countryName('not-a-code'), 'not-a-code');
  assert.equal(ui.statusClass(503), 'status-5');
  assert.equal(ui.statusClass('404'), 'status-4');
});

test('экранирование HTML', () => {
  assert.equal(ui.esc(`<img src=x onerror="a('b')">&`), '&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;');
  assert.equal(ui.esc(null), 'null');
  assert.equal(ui.esc(42), '42');
});

test('якоря документации как на GitHub', () => {
  assert.equal(slugify('Кэш и статика'), 'кэш-и-статика');
  assert.equal(slugify('  HTTP/2 и HTTP/3 (QUIC)! '), 'http2-и-http3-quic');
  assert.equal(slugify('proxy_cache_lock — блокировка'), 'proxy_cache_lock--блокировка');
  assert.equal(slugify('Ёлка'), 'ёлка');
  assert.equal(slugify(''), '');
});

test('debounce: вызывается один раз с последними аргументами', async () => {
  const calls = [];
  const f = ui.debounce((x) => calls.push(x), 20);
  f(1); f(2); f(3);
  await new Promise((r) => setTimeout(r, 60));
  assert.deepEqual(calls, [3]);
});
