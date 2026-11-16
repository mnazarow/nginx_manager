// Защита от атак: обзор, фильтр запросов (WAF), проверка браузера и режим «Под атакой», свои правила, списки угроз,
// автоматика и ловушки, журнал атак, самопроверка, оценка защищённости, сеть и сервер.
import { api } from '../api.js';
import { h, mount, icon, toast, tabs, modal, loading, card, kpi, badge, table, hbars, fmtInt, fmtDate, fmtAgo, fmtTime, countryTag,
  confirmDlg, debounce, segmented, empty } from '../ui.js';
import { model, renderFields, errorsToMap } from '../forms.js';
import { timeChart, setData, chartCard, destroyAll } from '../charts.js';
import { can, refreshState } from '../app.js';
import { KIND_ORDER, kindColor, analyticsTab, attackersTab, botsTab, modsecTab, rateRulesCard, liveFeed, openIp, openRule, banIp } from './protection-more.js';
import { vulnsTab } from './protection-vulns.js';

const TABS = [
  ['overview', 'Обзор'], ['analytics', 'Аналитика'], ['attackers', 'Атакующие'], ['log', 'Журнал атак'],
  ['waf', 'Фильтр запросов'], ['modsec', 'Глубокая проверка'], ['vulns', 'Уязвимости'], ['challenge', 'Проверка браузера'], ['bots', 'Роботы'],
  ['rules', 'Свои правила'], ['threats', 'Списки угроз'], ['auto', 'Автоматика и ловушки'], ['selftest', 'Самопроверка'],
  ['score', 'Оценка защищённости'], ['server', 'Сеть и сервер'],
];
const MODE = { off: 'выключено', detect: 'запись', block: 'блокировать' };
const MODE_KIND = { off: '', detect: 'warn', block: 'good' };
const ACT_KIND = { blocked: 'bad', detected: 'warn', challenged: 'info', banned: 'bad', passed: 'good' };

const go = (tab, extra = '') => { location.hash = `#/protection?tab=${tab}${extra}`; };

export async function render(root, c) {
  const tab = (c.params && c.params.tab) || 'overview';
  const charts = [];
  const [cfg, sitesRaw] = await Promise.all([api('/protection/settings'), api('/sites')]);
  const sites = sitesRaw.map(s => ({ id: s.id, name: s.name, enabled: s.enabled, protection: s.protection || {} }));
  const view = h('div', {});
  const attack = cfg.attack || { global: null, sites: {} };
  const globalOn = !!(attack.global && (!attack.global.until || attack.global.until > Date.now() / 1000));
  mount(root,
    h('div', { class: 'page-head' },
      h('div', {}, h('h1', {}, 'Защита от атак'),
        h('p', {}, 'Фильтр запросов по сигнатурам атак, проверка браузера и режим «Под атакой», списки угроз, ловушки, свои правила, журнал атак и самопроверка.')),
      h('div', { class: 'row' },
        h('a', { class: 'btn ghost', href: '#/docs?p=19-protection.md' }, icon('book'), 'Как это работает'),
        can('operator') ? h('button', { class: 'btn ' + (globalOn ? 'danger solid' : ''), title: 'Проверка браузера для всех сайтов с режимом «В режиме «Под атакой»»',
          onclick: () => attackDialog(null, globalOn, cfg) }, icon('shield'), globalOn ? 'Под атакой: выключить' : 'Режим «Под атакой»') : null)),
    globalOn ? h('div', { class: 'alert bad mb' }, h('b', {}, 'Режим «Под атакой» включён для всех сайтов. '),
      attack.global.until ? `До ${fmtDate(attack.global.until)}. ` : 'Без срока. ', `Включил: ${attack.global.auto ? 'автоматика' : attack.global.by}.`) : null,
    !cfg.challenge_ready ? h('div', { class: 'alert warn mb' }, 'В установленном nginx нет модуля secure_link — проверка браузера и режим «Под атакой» недоступны. Остальные механизмы работают.') : null,
    tabs(TABS.map(([id, label]) => ({ id, label })), tab, (t) => go(t)), view);
  const R = { overview, analytics: analyticsTab, attackers: attackersTab, modsec: modsecTab, vulns: vulnsTab, bots: botsTab, waf, challenge,
    rules, threats, auto, log, selftest, score, server }[tab] || overview;
  await R(view, { cfg, sites, charts, c });
  return () => destroyAll(charts);
}

// ---------------------------------------------------------------- общие
async function saveSettings(obj, msg = 'Настройки защиты сохранены') {
  await api('/protection/settings', { method: 'PUT', body: obj });
  toast(msg + '. Примените конфигурацию, чтобы изменения попали в nginx.', 'good');
  refreshState();
}

function attackDialog(siteId, on, cfg) {
  if (on) {
    return api('/protection/attack', { method: 'POST', body: { site: siteId, on: false } }).then(() => { toast('Режим «Под атакой» выключен', 'good'); go(new URLSearchParams(location.hash.split('?')[1]).get('tab') || 'overview'); });
  }
  const sel = h('select', { 'aria-label': 'Срок' }, [['30', '30 минут'], ['60', '1 час'], ['240', '4 часа'], ['1440', 'сутки'], ['', 'без срока']].map(([v, l]) => h('option', { value: v, selected: v === '60' }, l)));
  const m = modal({ title: siteId == null ? 'Режим «Под атакой» для всех сайтов' : 'Режим «Под атакой» для сайта',
    body: h('div', { class: 'col' },
      h('p', {}, 'Новые посетители будут проходить проверку браузера (1–2 секунды, задача proof-of-work). Боты без JavaScript и простые флудеры отсекаются. Сайты с проверкой «Никогда» (API, вебхуки) не затрагиваются.'),
      h('div', { class: 'field' }, h('label', {}, 'Срок'), sel),
      h('div', { class: 'small muted' }, `Сложность задачи: ${cfg.settings.challenge_difficulty} бит, пропуск на ${cfg.settings.challenge_ttl_hours} ч.`)),
    footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'),
      h('button', { class: 'btn danger solid', onclick: async () => {
        await api('/protection/attack', { method: 'POST', body: { site: siteId, on: true, minutes: sel.value ? Number(sel.value) : null } });
        m.close(); toast('Режим «Под атакой» включён', 'good'); go(new URLSearchParams(location.hash.split('?')[1]).get('tab') || 'overview');
      } }, icon('shield'), 'Включить')] });
}

function siteAttack(cfg, sid) {
  const e = (cfg.attack.sites || {})[String(sid)];
  return e && (!e.until || e.until > Date.now() / 1000) ? e : null;
}

// ---------------------------------------------------------------- обзор
async function overview(view, { cfg, sites, charts }) {
  let hours = 24;
  const body = h('div', {});
  mount(view, h('div', { class: 'row mb', style: { justifyContent: 'space-between', flexWrap: 'wrap' } },
    segmented([['1', 'Час'], ['6', '6 часов'], ['24', 'Сутки'], ['168', 'Неделя'], ['720', 'Месяц']], '24',
      (v) => { hours = Number(v); load(); }),
    h('span', { class: 'muted small' }, 'Обновляется при открытии; журнал — во вкладке «Журнал атак»')), body);
  const load = async () => {
    mount(body, loading());
    destroyAll(charts);
    const [d, scores] = await Promise.all([api('/protection/overview', { query: { hours } }), api('/protection/score')]);
    const t = d.totals || {};
    const kinds = [...new Set(d.series.map(x => x.kind))].sort((a, b) => KIND_ORDER.indexOf(a) - KIND_ORDER.indexOf(b));
    const cc = chartCard('Атаки во времени', { sub: `запросов за ${d.step >= 3600 ? d.step / 3600 + ' ч' : d.step / 60 + ' мин'}, по механизмам защиты` });
    mount(body,
      h('div', { class: 'grid kpi5' },
        kpi('Заблокировано', fmtInt(t.blocked || 0), { foot: 'запросов', cls: (t.blocked ? 'bad' : '') }),
        kpi('Записано', fmtInt(t.detected || 0), { foot: 'режим «запись» и правила «записать»' }),
        kpi('Проверка браузера', fmtInt(t.challenged || 0), { foot: `решено за период: ${fmtInt((d.challenge_period || {}).solved || 0)}` }),
        kpi('Попались в ловушки', fmtInt(t.banned || 0), { foot: 'адреса сразу заблокированы' }),
        kpi('Под атакой', d.attack.global ? 'все сайты' : String(d.attack.sites.length), { foot: 'сайтов в режиме проверки', cls: d.attack.global || d.attack.sites.length ? 'warn' : '' })),
      cc.el,
      h('div', { class: 'grid g2 mt' },
        card('Сработавшие правила', d.rules.length ? table([
          { title: 'Правило', render: (r) => h('a', { href: '#', onclick: (e) => { e.preventDefault(); openRule(r.kind, r.rule, { sites }); } }, r.title || r.rule) },
          { title: 'Действие', render: (r) => badge(d.actions[r.action] || r.action, ACT_KIND[r.action]) },
          { title: 'Раз', num: true, render: (r) => fmtInt(r.n) },
        ], d.rules.slice(0, 12)) : empty('Правила не срабатывали', '', null, 'shield'), { flush: !!d.rules.length, sub: 'чаще всего за период; щелчок — карточка правила',
          actions: h('a', { class: 'btn sm', href: '#/protection?tab=analytics' }, icon('chart'), 'Аналитика') }),
        card('Атакующие адреса', d.ips.length ? table([
          { title: 'IP', render: (r) => h('a', { href: '#', onclick: (e) => { e.preventDefault(); openIp(r.ip, { sites }); } }, h('code', {}, r.ip)) }, { title: '', srTitle: 'Страна', render: (r) => countryTag(r.country) },
          { title: 'Запросов', num: true, render: (r) => fmtInt(r.n) }, { title: 'Виды', render: (r) => (r.kinds || '').split(',').map(k => d.kinds[k] || k).join(', ') },
          { title: '', srTitle: 'Действия', render: (r) => can('operator') ? h('button', { class: 'btn sm', onclick: () => banIp(r.ip) }, icon('ban'), 'Блокировать') : null },
        ], d.ips) : empty('Атак не было', 'За выбранный период защита ничего не отклонила', null, 'shield'), { flush: true,
          actions: h('a', { class: 'btn sm', href: '#/protection?tab=attackers' }, 'Все атакующие') })),
      liveFeed(d.kinds),
      h('div', { class: 'grid g3 mt' },
        card('Страны', hbars(d.countries.map(r => ({ label: r.country, value: r.n })))),
        card('Сайты', hbars(d.sites.map(r => ({ label: r.name, value: r.n })))),
        card('Цели атак (URI)', hbars(d.uris.map(r => ({ label: r.uri, value: r.n }))))),
      card('Защищённость сайтов', table([
        { title: 'Сайт', render: (s) => h('a', { href: `#/sites?edit=${s.site}&tab=protection` }, s.name) },
        { title: 'Оценка', render: (s) => h('span', {}, badge(s.grade, { A: 'good', B: 'good', C: 'warn', D: 'bad', F: 'bad' }[s.grade]), ' ', s.score) },
        { title: 'Фильтр', render: (s) => s.protection ? wafSummary(s.modes) : badge('выключена') },
        { title: 'Проверка браузера', render: (s) => ({ off: 'никогда', auto: 'под атакой', on: 'всегда' })[s.challenge] },
        { title: 'Под атакой', render: (s) => { const a = siteAttack(cfg, s.site); return a ? badge(a.auto ? 'да (авто)' : 'да', 'warn') : '—'; } },
        { title: '', srTitle: 'Действия', render: (s) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
          can('operator') && s.challenge !== 'off' && cfg.challenge_ready ? h('button', { class: 'btn sm', onclick: () => attackDialog(s.site, !!siteAttack(cfg, s.site), cfg) }, siteAttack(cfg, s.site) ? 'Снять «Под атакой»' : 'Под атакой') : null,
          h('a', { class: 'btn sm', href: `#/protection?tab=selftest&site=${s.site}` }, icon('check'), 'Проверить')) },
      ], scores), { flush: true, cls: 'mt', sub: 'оценка по 21 пункту — подробности во вкладке «Оценка защищённости»' }));
    if (kinds.length) {
      // все интервалы периода, включая пустые, — иначе единственный столбец растягивается на весь график
      const labels = [];
      for (let b = Math.floor(d.since / d.step) * d.step, end = Date.now() / 1000; b <= end; b += d.step) labels.push(b);
      const series = kinds.map(k => ({ label: d.kinds[k] || k, color: kindColor(k) }));
      const ch = timeChart(cc.canvas, series, { type: 'bar', stacked: true, legendEl: cc.legendEl, seconds: false,
        xFmt: (ts) => hours > 48 ? fmtDate(ts, { short: true }) : fmtTime(ts, false), yFmt: (v) => fmtInt(v) });
      const idx = new Map(d.series.map(x => [`${x.b}|${x.kind}`, x.n]));
      setData(ch, labels, kinds.map(k => labels.map(b => idx.get(`${b}|${k}`) || 0)));
      charts.push(ch);
    } else {
      cc.canvas.replaceWith(empty('Атак не было', 'Как только защита что-то отклонит или запишет, здесь появится график', null, 'shield'));
    }
  };
  await load();
}

function wafSummary(modes) {
  const vals = Object.values(modes || {});
  const b = vals.filter(v => v === 'block').length, dt = vals.filter(v => v === 'detect').length;
  if (!b && !dt) return badge('выключен');
  return h('span', {}, b ? badge(`блок: ${b}`, 'good') : null, ' ', dt ? badge(`запись: ${dt}`, 'warn') : null);
}


// ---------------------------------------------------------------- фильтр запросов
async function waf(view, { cfg }) {
  const cat = await api('/protection/rules');
  const obj = structuredClone(cfg.settings);
  let errors = {};
  const counts = {};
  cat.rules.forEach(r => { counts[r.cat] = counts[r.cat] || [0, 0]; counts[r.cat][r.level - 1]++; });
  const form = h('div', {});
  const drawForm = () => { mount(form); renderFields(form, model('protection'), obj, { root: obj, tab: 'waf', advanced: true, errors, rerender: drawForm }); };
  drawForm();
  const modeSel = (c) => h('select', { 'aria-label': `Режим: ${c.title}`, style: { width: 'auto', minWidth: '190px' }, disabled: !can('admin'), onchange: (e) => { obj.waf_modes[c.id] = e.target.value; } },
    Object.entries(MODE).map(([k, l]) => h('option', { value: k, selected: (obj.waf_modes[c.id] || c.default) === k }, l)));
  const ruleBox = h('div', {});
  const q = h('input', { type: 'search', placeholder: 'Поиск правила: код, название, CVE', 'aria-label': 'Поиск правила' });
  const drawRules = () => {
    const s = q.value.trim().toLowerCase();
    const rows = cat.rules.filter(r => !s || [r.id, r.title, r.cve, r.cat].join(' ').toLowerCase().includes(s));
    mount(ruleBox, table([
      { title: 'Правило', render: (r) => h('div', {}, h('code', {}, r.id), ' ', r.title, r.note ? h('div', { class: 'small muted' }, r.note) : null) },
      { title: 'Категория', render: (r) => (cat.categories.find(c => c.id === r.cat) || {}).title },
      { title: 'Ур.', num: true, render: (r) => r.level },
      { title: 'Поля', render: (r) => h('span', { class: 'small' }, r.fields.join(', ')) },
      { title: 'Пример атаки', render: (r) => h('code', { class: 'small ellipsis', style: { maxWidth: '320px', display: 'inline-block' }, title: r.example }, r.example) },
      { title: 'CVE', render: (r) => r.cve ? h('span', { class: 'small' }, r.cve) : '—' },
    ], rows.slice(0, 200), { empty: 'Ничего не найдено' }));
  };
  q.addEventListener('input', debounce(drawRules, 200));
  drawRules();
  // проверка строки
  const tUri = h('input', { type: 'text', placeholder: '/search?q=<script>alert(1)</script>', 'aria-label': 'Строка запроса для проверки' });
  const tUa = h('input', { type: 'text', placeholder: 'User-Agent (необязательно)', 'aria-label': 'User-Agent для проверки' });
  const tRes = h('div', { class: 'mt' });
  mount(view,
    card('Категории атак', h('div', {},
      h('div', { class: 'table-wrap' }, h('table', { class: 't' },
        h('thead', {}, h('tr', {}, h('th', {}, 'Категория'), h('th', {}, 'Режим'), h('th', { class: 'num' }, 'Правил'), h('th', {}, 'Что ловит'))),
        h('tbody', {}, cat.categories.map(c => h('tr', {},
          h('td', {}, h('b', {}, c.title), h('div', { class: 'small muted' }, h('code', {}, c.id))),
          h('td', {}, modeSel(c)),
          c.id === 'vuln' ? h('td', { class: 'num' }, h('a', { href: '#/protection?tab=vulns', title: 'Путей эксплойтов в карте — вкладка «Уязвимости»' }, 'база'))
            : h('td', { class: 'num' }, `${(counts[c.id] || [0, 0])[0]}`, (counts[c.id] || [0, 0])[1] ? h('span', { class: 'muted' }, ` + ${counts[c.id][1]}`) : null),
          h('td', { class: 'small' }, c.doc))))))),
    { sub: 'Режим по умолчанию для всех сайтов; сайт может переопределить его на вкладке «Защита от атак» своего редактора. «+N» — правила уровня строгости 2', flush: true }),
    card('Параметры фильтра', form, { cls: 'mt', actions: can('admin') ? h('button', { class: 'btn primary', onclick: async () => {
      try { await saveSettings(obj); errors = {}; } catch (e) { errors = errorsToMap(e); }
      drawForm();
    } }, icon('check'), 'Сохранить') : null }),
    card('Проверить строку', h('div', { class: 'col' },
      h('div', { class: 'small muted' }, 'Покажет, какие правила сработали бы на этот запрос (без отправки на сайт). Удобно для разбора ложных срабатываний и своих тестов.'),
      h('div', { class: 'row', style: { flexWrap: 'wrap' } }, h('div', { style: { flex: '2 1 320px' } }, tUri), h('div', { style: { flex: '1 1 220px' } }, tUa),
        h('button', { class: 'btn', onclick: async () => {
          const r = await api('/protection/test', { method: 'POST', body: { uri: tUri.value, ua: tUa.value, level: 2 } });
          mount(tRes, r.length ? table([{ title: 'Правило', render: (x) => h('span', {}, h('code', {}, x.id), ' ', x.title) },
            { title: 'Категория', render: (x) => x.cat_title }, { title: 'Ур.', num: true, render: (x) => x.level },
            { title: 'Режим сейчас', render: (x) => badge(MODE[cfg.effective_modes[x.cat]] || '—', MODE_KIND[cfg.effective_modes[x.cat]]) }], r)
            : h('div', { class: 'alert good' }, 'Ни одно правило не сработало бы.'));
        } }, icon('search'), 'Проверить')), tRes), { cls: 'mt' }),
    card(`Каталог правил (${cat.rules.length})`, h('div', { class: 'col' }, q, ruleBox), { cls: 'mt', sub: 'Сигнатуры атак по OWASP Core Rule Set, 7G Firewall и разборам эксплойтов; виртуальные патчи — по сигнатурам из сообщений CISA KEV' }));
  if (can('admin')) {
    view.prepend(h('div', { class: 'row mb', style: { justifyContent: 'flex-end' } }, h('button', { class: 'btn primary', onclick: () => saveSettings(obj) }, icon('check'), 'Сохранить режимы')));
  }
}

// ---------------------------------------------------------------- проверка браузера
async function challenge(view, { cfg, sites }) {
  const obj = structuredClone(cfg.settings);
  let errors = {};
  const form = h('div', {});
  const drawForm = () => { mount(form); renderFields(form, model('protection'), obj, { root: obj, tab: 'challenge', advanced: true, errors, rerender: drawForm }); };
  drawForm();
  const rows = sites.map(s => ({ ...s, mode: s.protection.enabled === false ? 'off' : (s.protection.challenge || 'auto') }));
  mount(view,
    h('div', { class: 'alert info mb' }, h('b', {}, 'Как это работает. '),
      'Посетитель без пропуска получает страницу, где браузер решает задачу proof-of-work (подбор числа, при котором хеш SHA-256 начинается с нужного числа нулевых бит) — 1–2 секунды на телефоне. ',
      'Решение проверяет панель и выдаёт cookie-пропуск, который дальше проверяет сам nginx (модуль secure_link), не обращаясь к панели. ',
      'Так защищаются от L7-флуда и ботов-сборщиков (подход Cloudflare «I\'m Under Attack» и Anubis).'),
    card('Сайты', table([
      { title: 'Сайт', render: (s) => h('a', { href: `#/sites?edit=${s.id}&tab=protection` }, s.name) },
      { title: 'Режим проверки', render: (s) => ({ off: 'никогда', auto: 'в режиме «Под атакой»', on: 'всегда' })[s.mode] },
      { title: 'Сейчас', render: (s) => { const a = siteAttack(cfg, s.id); const g = cfg.attack.global && (!cfg.attack.global.until || cfg.attack.global.until > Date.now() / 1000);
        if (s.mode === 'on') return badge('проверка включена', 'info');
        if (s.mode === 'auto' && (a || g)) return badge(a && a.auto ? 'под атакой (авто)' : 'под атакой', 'warn');
        return '—'; } },
      { title: 'До', render: (s) => { const a = siteAttack(cfg, s.id); return a ? (a.until ? fmtDate(a.until) : 'без срока') : ''; } },
      { title: '', srTitle: 'Действия', render: (s) => can('operator') && s.mode === 'auto' && cfg.challenge_ready ? h('button', { class: 'btn sm', onclick: () => attackDialog(s.id, !!siteAttack(cfg, s.id), cfg) }, siteAttack(cfg, s.id) ? 'Выключить' : 'Под атакой') : null },
    ], rows), { flush: true, sub: 'Режим сайта меняется в его редакторе, вкладка «Защита от атак»' }),
    card('Параметры проверки и автоматики', form, { cls: 'mt', actions: can('admin') ? h('button', { class: 'btn primary', onclick: async () => {
      try { await saveSettings(obj); errors = {}; } catch (e) { errors = errorsToMap(e); }
      drawForm();
    } }, icon('check'), 'Сохранить') : null }));
}

// ---------------------------------------------------------------- свои правила
async function rules(view, { cfg, sites }) {
  const obj = structuredClone(cfg.settings);
  const list = obj.custom_rules;
  const ACT = model('custom_rule').find(f => f.key === 'action').labels;
  const FIELD = model('custom_rule').find(f => f.key === 'field').labels;
  const OP = model('custom_rule').find(f => f.key === 'op').labels;
  const edit = (idx) => {
    const r = idx == null ? { name: '', enabled: true, sites: [], field: 'path', header: '', op: 'prefix', value: '', action: 'block' } : structuredClone(list[idx]);
    let errors = {};
    const form = h('div', {});
    const draw = () => { mount(form); renderFields(form, model('custom_rule').filter(f => f.key !== 'id'), r, { root: r, errors, sites, rerender: draw }); };
    draw();
    const m = modal({ title: idx == null ? 'Новое правило' : `Правило «${r.name}»`, size: 'lg', body: form,
      footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn primary', onclick: async () => {
        const next = structuredClone(list);
        if (idx == null) next.push(r); else next[idx] = r;
        try { await saveSettings({ ...obj, custom_rules: next }, 'Правило сохранено'); m.close(); go('rules'); } catch (e) { errors = errorsToMap(e); draw(); }
      } }, icon('check'), 'Сохранить')] });
  };
  const siteNames = (ids) => !ids.length ? 'все сайты' : ids.map(id => (sites.find(s => s.id === id) || {}).name || id).join(', ');
  mount(view,
    h('div', { class: 'alert info mb' }, '«Пропустить» действует раньше всех проверок защиты. Если запросу соответствуют несколько правил (своих и фильтра), побеждает самое строгое действие: блокировать → проверить браузер → записать; при равных — своё правило, стоящее в списке выше. Примеры: закрыть /admin для всех, кроме офиса; отбрасывать запросы с определённым User-Agent; проверять браузер на /checkout.'),
    card(`Правила (${list.length})`, list.length ? table([
      { title: 'Название', render: (r) => h('span', {}, r.enabled ? '' : badge('выкл'), ' ', h('b', {}, r.name)) },
      { title: 'Условие', render: (r) => h('span', { class: 'small' }, `${FIELD[r.field]}${r.field === 'header' ? ' ' + r.header : ''} ${OP[r.op]} `, h('code', {}, r.value.length > 60 ? r.value.slice(0, 60) + '…' : r.value)) },
      { title: 'Действие', render: (r) => badge(ACT[r.action], { block: 'bad', drop: 'bad', challenge: 'info', log: 'warn', allow: 'good' }[r.action]) },
      { title: 'Сайты', render: (r) => h('span', { class: 'small' }, siteNames(r.sites)) },
      { title: '', srTitle: 'Действия', render: (r) => can('admin') ? h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        h('button', { class: 'btn sm', onclick: () => edit(list.indexOf(r)) }, icon('edit'), 'Изменить'),
        h('button', { class: 'btn sm danger', 'aria-label': `Удалить правило ${r.name}`, onclick: async () => {
          if (!await confirmDlg(`Удалить правило «${r.name}»?`, { danger: true, ok: 'Удалить' })) return;
          await saveSettings({ ...obj, custom_rules: list.filter(x => x !== r) }, 'Правило удалено'); go('rules');
        } }, icon('trash'))) : null },
    ], list) : empty('Своих правил нет', 'Добавьте правило для того, что не покрывает каталог сигнатур', can('admin') ? h('button', { class: 'btn primary', onclick: () => edit(null) }, icon('plus'), 'Добавить правило') : null, 'shield'),
    { flush: true, actions: can('admin') && list.length ? h('button', { class: 'btn primary', onclick: () => edit(null) }, icon('plus'), 'Добавить правило') : null }),
    rateRulesCard(cfg, sites, () => go('rules')));
}

// ---------------------------------------------------------------- списки угроз
async function threats(view, { cfg }) {
  const obj = structuredClone(cfg.settings);
  const status = cfg.feed_status || {};
  const byId = Object.fromEntries(obj.threat_feeds.map(f => [f.id, f]));
  cfg.presets.forEach(p => { if (!byId[p.id]) { const f = { ...p, enabled: false, action: p.action || 'block' }; obj.threat_feeds.push(f); byId[p.id] = f; } });
  let errors = {};
  const form = h('div', {});
  const drawForm = () => { mount(form); renderFields(form, model('protection'), obj, { root: obj, tab: 'threats', advanced: true, errors, rerender: drawForm }); };
  drawForm();
  const ACTS = { block: 'блокировать', challenge: 'проверить браузер', detect: 'записать' };
  const addCustom = () => {
    const f = { id: '', name: '', url: '', enabled: true, action: 'block' };
    let errs = {};
    const fm = h('div', {});
    const draw = () => { mount(fm); renderFields(fm, model('threat_feed'), f, { root: f, errors: errs, rerender: draw }); };
    draw();
    const m = modal({ title: 'Свой список адресов', body: h('div', { class: 'col' }, h('div', { class: 'small muted' }, 'Текстовый файл: по адресу или подсети в строке; комментарии # и ; пропускаются. Подойдут списки AbuseIPDB (выгрузка), собственные «чёрные» списки, file:///путь для локального файла.'), fm),
      footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn primary', onclick: async () => {
        try { await saveSettings({ ...obj, threat_feeds: [...obj.threat_feeds.filter(x => x.enabled || !cfg.presets.some(p => p.id === x.id)), f] }, 'Список добавлен'); m.close(); go('threats'); } catch (e) { errs = errorsToMap(e); draw(); }
      } }, icon('check'), 'Добавить')] });
  };
  mount(view,
    h('div', { class: 'alert info mb' }, 'Адреса из списков проверяются в nginx до фильтра запросов (geo — мгновенно даже на миллионе записей). Списки скачиваются панелью и обновляются по расписанию без изменения версии конфигурации. Сайт может отказаться от списков на вкладке «Защита от атак».'),
    card('Списки', table([
      { title: 'Включён', render: (f) => h('input', { type: 'checkbox', checked: f.enabled, disabled: !can('admin'), 'aria-label': `Включить ${f.name}`, onchange: (e) => { f.enabled = e.target.checked; } }) },
      { title: 'Список', render: (f) => h('div', {}, h('b', {}, f.name), h('div', { class: 'small muted ellipsis', style: { maxWidth: '420px' } }, f.url)) },
      { title: 'Действие', render: (f) => h('select', { disabled: !can('admin'), style: { width: 'auto', minWidth: '190px' }, 'aria-label': `Действие для ${f.name}`, onchange: (e) => { f.action = e.target.value; } },
        Object.entries(ACTS).map(([k, l]) => h('option', { value: k, selected: f.action === k }, l))) },
      { title: 'Адресов', num: true, render: (f) => status[f.id] && status[f.id].count ? fmtInt(status[f.id].count) : '—' },
      { title: 'Обновлён', render: (f) => { const s = status[f.id]; if (!s) return '—'; return s.ok ? (s.updated ? fmtAgo(s.updated) : '—') : h('span', { class: 'bad small', title: s.error }, 'ошибка: ' + (s.error || '').slice(0, 60)); } },
      { title: '', srTitle: 'Действия', render: (f) => can('admin') && f.enabled && status[f.id] !== undefined ? h('button', { class: 'btn sm', onclick: async () => {
        const r = await api('/protection/feeds/update', { method: 'POST', body: { id: f.id } }); const s = r.feeds[f.id];
        toast(s && s.ok ? `«${f.name}»: ${fmtInt(s.count)} адресов` : `«${f.name}»: ${(s && s.error) || 'ошибка'}`, s && s.ok ? 'good' : 'bad'); go('threats');
      } }, icon('refresh'), 'Обновить') : null },
    ], obj.threat_feeds), { flush: true, actions: can('admin') ? h('div', { class: 'row' },
      h('button', { class: 'btn', onclick: addCustom }, icon('plus'), 'Свой список'),
      h('button', { class: 'btn primary', onclick: async () => {
        try { await saveSettings({ ...obj, threat_feeds: obj.threat_feeds.filter(f => f.enabled || !cfg.presets.some(p => p.id === f.id)) }, 'Списки сохранены'); go('threats'); } catch (e) { errors = errorsToMap(e); drawForm(); }
      } }, icon('check'), 'Сохранить')) : null }),
    card('Расписание', form, { cls: 'mt' }));
}

// ---------------------------------------------------------------- автоматика и ловушки
async function auto(view, { cfg }) {
  const obj = structuredClone(cfg.settings);
  let errors = {};
  const form = h('div', {});
  const drawForm = () => {
    const f1 = h('div', {}), f2 = h('div', {});
    mount(form, f1, h('h3', { class: 'mt', style: { fontSize: '14px' } }, 'Журнал атак'), f2);
    renderFields(f1, model('protection'), obj, { root: obj, tab: 'auto', advanced: true, errors, rerender: drawForm });
    renderFields(f2, model('protection'), obj, { root: obj, tab: 'log', advanced: true, errors, rerender: drawForm });
  };
  drawForm();
  mount(view,
    h('div', { class: 'alert info mb' }, 'Повторные срабатывания фильтра с одного адреса превращаются в блокировку IP (раздел «Блокировки IP», повторным нарушителям — дольше). Ловушки — пути, к которым обычный посетитель не обращается: первое же обращение блокирует адрес. Блокировка по фильтру требует включённой автоблокировки в «Настройки панели → Блокировки IP»; ловушки работают и без неё.'),
    card('Автоматика, ловушки и журнал', form, { actions: can('admin') ? h('button', { class: 'btn primary', onclick: async () => {
      try { await saveSettings(obj); errors = {}; } catch (e) { errors = errorsToMap(e); }
      drawForm();
    } }, icon('check'), 'Сохранить') : null }));
}

// ---------------------------------------------------------------- журнал атак
async function log(view, { cfg, sites, c }) {
  const p = c.params || {};
  const f = { site: p.site || '', kind: p.kind || '', action: '', ip: p.ip || '', q: p.q || '', rid: p.rid || '', test: false };
  const box = h('div', {});
  const inp = (key, ph, w = '160px') => { const el = h('input', { type: 'search', value: f[key], placeholder: ph, 'aria-label': ph, style: { width: w } });
    el.addEventListener('input', debounce(() => { f[key] = el.value.trim(); load(); }, 400)); return el; };
  const sel = (key, label, opts) => h('select', { 'aria-label': label, onchange: (e) => { f[key] = e.target.value; load(); } }, h('option', { value: '' }, label), opts.map(([v, l]) => h('option', { value: v, selected: f[key] === String(v) }, l)));
  const testBox = h('input', { type: 'checkbox', onchange: (e) => { f.test = e.target.checked; load(); } });
  mount(view, h('div', { class: 'toolbar' },
    sel('site', 'Все сайты', sites.map(s => [String(s.id), s.name])), sel('kind', 'Все механизмы', Object.entries(cfg.kinds)),
    sel('action', 'Все действия', Object.entries(cfg.actions)), inp('ip', 'IP'), inp('q', 'Текст: URI, User-Agent, правило', '240px'), inp('rid', 'Номер запроса', '220px'),
    h('label', { class: 'row small' }, testBox, 'самопроверка'),
    h('button', { class: 'btn', onclick: () => { const q = new URLSearchParams(Object.entries(f).filter(([k, v]) => v && k !== 'test' && k !== 'rid')); location.href = `/api/protection/events.csv?limit=50000&${q}`; } }, icon('download'), 'CSV')), box);
  const load = async () => {
    const rows = await api('/protection/events', { query: { ...f, limit: 300 } });
    const name = (sid) => (sites.find(s => String(s.id) === sid) || {}).name || sid;
    mount(box, card(`Записей: ${rows.length}${rows.length === 300 ? '+' : ''}`, table([
      { title: 'Время', render: (r) => h('span', { class: 'nowrap', title: fmtDate(r.ts, { sec: true }) }, fmtTime(r.ts)) },
      { title: 'Сайт', render: (r) => name(r.site) },
      { title: 'IP', render: (r) => h('span', { class: 'nowrap' }, h('a', { href: '#', onclick: (e) => { e.preventDefault(); e.stopPropagation(); openIp(r.ip, { sites }); } }, h('code', {}, r.ip)), ' ', countryTag(r.country)) },
      { title: 'Правило', render: (r) => h('a', { href: '#', class: 'small', onclick: (e) => { e.preventDefault(); e.stopPropagation(); openRule(r.kind, r.rule, { sites }); } }, r.title) },
      { title: 'Действие', render: (r) => badge(cfg.actions[r.action] || r.action, ACT_KIND[r.action]) },
      { title: 'Запрос', render: (r) => h('code', { class: 'small ellipsis', style: { maxWidth: '360px', display: 'inline-block' }, title: r.uri }, `${r.method} ${r.uri}`) },
      { title: 'Код', num: true, render: (r) => r.status || '' },
    ], rows, { empty: 'Записей нет', onRow: (r) => details(r, cfg, name) }), { flush: true, sub: 'Щёлкните строку: подробности, блокировка IP, исключение для ложного срабатывания' }));
  };
  await load();
}

function details(r, cfg, name) {
  const rule = r.rule.includes('/') ? r.rule.split('/')[1] : r.rule;
  const isWaf = r.kind === 'waf';
  const path = (r.uri || '').split('?')[0];
  const dl = h('dl', { class: 'kv' });
  const add = (k, v) => dl.append(h('dt', {}, k), h('dd', {}, v));
  add('Время', fmtDate(r.ts, { sec: true })); add('Сайт', `${name(r.site)} (${r.host})`); add('IP', h('span', {}, h('code', {}, r.ip), ' ', countryTag(r.country)));
  add('Механизм', cfg.kinds[r.kind] || r.kind); add('Правило', h('span', {}, r.title, ' ', h('code', {}, r.rule)));
  add('Действие', badge(cfg.actions[r.action] || r.action, ACT_KIND[r.action])); add('Запрос', h('code', { style: { wordBreak: 'break-all' } }, `${r.method} ${r.uri}`));
  add('User-Agent', h('span', { class: 'small' }, r.ua || '—')); add('Ответ', String(r.status || '—')); add('Номер запроса', h('code', {}, r.rid || '—'));
  const m = modal({ title: 'Событие защиты', size: 'lg', body: h('div', { class: 'col' }, dl,
    isWaf && can('admin') ? h('div', { class: 'alert info' }, 'Если это законный запрос (ложное срабатывание), исключите правило на сайте или не проверяйте этот путь. Изменение попадёт в «Неприменённые изменения».') : null),
  footer: [
    can('operator') && r.ip ? h('button', { class: 'btn danger', onclick: () => { m.close(); banIp(r.ip); } }, icon('ban'), 'Блокировать IP') : null,
    isWaf && can('admin') ? h('button', { class: 'btn', onclick: async () => { await api('/protection/exclude', { method: 'POST', body: { site: Number(r.site), rule } }); m.close(); toast(`Правило ${rule} отключено для сайта`, 'good'); refreshState(); } }, `Отключить ${rule} на сайте`) : null,
    isWaf && can('admin') && path ? h('button', { class: 'btn', onclick: async () => { await api('/protection/exclude', { method: 'POST', body: { site: Number(r.site), path } }); m.close(); toast(`Путь ${path} исключён из проверки`, 'good'); refreshState(); } }, 'Не проверять этот путь') : null,
    h('button', { class: 'btn', onclick: () => m.close() }, 'Закрыть')] });
}

// ---------------------------------------------------------------- самопроверка
async function selftest(view, { sites, c }) {
  const sel = h('select', { 'aria-label': 'Сайт' }, sites.filter(s => s.enabled !== false).map(s => h('option', { value: s.id, selected: String(s.id) === (c.params || {}).site }, s.name)));
  const out = h('div', { class: 'mt' });
  const show = (res) => {
    if (!res || !res.summary) { mount(out); return; }
    const s = res.summary;
    let onlyBad = s.failed > 0;
    const tb = h('div', {});
    const drawT = () => mount(tb, table([
      { title: 'Правило', render: (r) => h('span', {}, h('code', {}, r.rule), ' ', r.title) },
      { title: 'Поле', render: (r) => h('span', { class: 'small' }, r.method !== 'GET' ? 'метод' : r.field) },
      { title: 'Атака', render: (r) => h('code', { class: 'small ellipsis', style: { maxWidth: '300px', display: 'inline-block' }, title: r.payload }, r.payload) },
      { title: 'Режим', render: (r) => badge(MODE[r.mode] || r.mode, MODE_KIND[r.mode]) },
      { title: 'Ответ', num: true, render: (r) => r.status == null ? (r.error ? 'ошибка' : '444') : r.status },
      { title: 'Итог', render: (r) => r.mode === 'off' ? h('span', { class: 'muted small' }, 'не проверяется') : r.ok ? badge(r.mode === 'block' ? 'заблокировано' : 'записано', 'good') : badge(r.mode === 'block' ? 'НЕ заблокировано' : 'НЕ записано', 'bad') },
    ], (res.results || []).filter(r => !onlyBad || !r.ok), { empty: 'Все атаки обработаны как ожидалось' }));
    drawT();
    mount(out,
      h('div', { class: 'grid g4' },
        kpi('Заблокировано', `${s.blocked} из ${s.block_expected}`, { cls: s.blocked < s.block_expected ? 'bad' : 'good', foot: 'категории в режиме «блокировать»' }),
        kpi('Записано', `${s.detected} из ${s.detect_expected}`, { cls: s.detected < s.detect_expected ? 'warn' : '', foot: 'режим «запись»' }),
        kpi('Не проверяется', String(s.off), { foot: 'категории выключены' }),
        kpi('Ложные срабатывания', String(s.false_positives), { cls: s.false_positives ? 'bad' : 'good', foot: `из ${(res.benign || []).length} обычных запросов` })),
      res.note ? h('div', { class: 'alert warn mt' }, res.note) : null,
      card(`Атаки (${s.total}) — ${res.target}, ${fmtDate(res.ts)}`, h('div', {}, res.results ? h('label', { class: 'row small mb', style: { padding: '0 16px' } },
        h('input', { type: 'checkbox', checked: onlyBad, onchange: (e) => { onlyBad = e.target.checked; drawT(); } }), 'только с расхождениями') : null, tb), { cls: 'mt', flush: true }));
  };
  const load = async () => show(await api(`/protection/selftest/${sel.value}`));
  sel.addEventListener('change', load);
  const run = h('button', { class: 'btn primary', disabled: !can('operator'), onclick: async () => {
    run.disabled = true; mount(out, loading('Отправляю атаки в nginx на этом сервере…'));
    try { show(await api(`/protection/selftest/${sel.value}`, { method: 'POST' })); } finally { run.disabled = false; }
  } }, icon('play'), 'Запустить проверку');
  mount(view,
    h('div', { class: 'alert info mb' }, 'Панель отправляет в nginx на этом сервере по одному примеру каждого правила (SQL-инъекции, XSS, Log4Shell, обход каталогов, сканеры, виртуальные патчи…) и несколько обычных запросов, затем сверяет итог с настройками: что должно блокироваться — блокируется, что в режиме «запись» — попадает в журнал, обычные запросы проходят. Запросы помечены и не попадают в статистику атак и автоблокировку.'),
    h('div', { class: 'row', style: { flexWrap: 'wrap' } }, h('div', { class: 'field', style: { minWidth: '260px' } }, h('label', {}, 'Сайт'), sel), run), out);
  if (sites.length) await load();
}

// ---------------------------------------------------------------- оценка
async function score(view) {
  const list = await api('/protection/score');
  const TAB = { ssl: 'ssl', security: 'security', protection: 'protection', performance: 'performance' };
  mount(view, list.length ? h('div', { class: 'col' }, list.map(s => card(s.name, h('div', {},
    h('div', { class: 'row mb' }, h('span', { class: 'grade grade-' + s.grade, 'aria-label': `Оценка ${s.grade}` }, s.grade),
      h('div', {}, h('div', { style: { fontSize: '20px', fontWeight: 600 } }, `${s.score} из 100`), h('div', { class: 'small muted' }, `${s.checks.filter(x => x.ok).length} из ${s.checks.length} пунктов выполнено`))),
    h('ul', { class: 'checklist' }, s.checks.sort((a, b) => a.ok - b.ok || b.weight - a.weight).map(x => h('li', { class: x.ok ? 'ok' : 'no' },
      icon(x.ok ? 'check' : 'x'), h('span', {}, x.title, h('span', { class: 'muted small' }, ` · ${x.weight}`)),
      !x.ok ? h('div', { class: 'small muted' }, x.hint, ' ', TAB[x.tab] ? h('a', { href: `#/sites?edit=${s.site}&tab=${TAB[x.tab]}` }, 'Открыть') :
        x.tab === 'global' ? h('a', { href: '#/global' }, 'Открыть') : x.tab === 'panel-bans' ? h('a', { href: '#/settings?tab=bans' }, 'Открыть') : null) : null)))),
  { sub: 'Методика: OWASP ASVS, CIS NGINX Benchmark, рекомендации Mozilla Observatory — вес пункта после точки' }))) : empty('Сайтов нет', 'Добавьте сайт, чтобы оценить его защищённость', null, 'shield'));
}

// ---------------------------------------------------------------- сеть и сервер
async function server(view) {
  const [sys, slow] = await Promise.all([api('/protection/sysctl'), api('/protection/slow-profile')]);
  const LBL = { client_header_timeout: 'Ожидание заголовков (client_header_timeout)', client_body_timeout: 'Ожидание тела (client_body_timeout)',
    send_timeout: 'Отправка ответа (send_timeout)', keepalive_timeout: 'Keep-alive (keepalive_timeout)', reset_timedout_connection: 'Сбрасывать зависшие соединения',
    server_tokens: 'Показывать версию nginx (server_tokens)', large_client_header_buffers: 'Буферы больших заголовков', client_header_buffer_size: 'Буфер заголовков' };
  const fmtV = (v) => v === true ? 'да' : v === false ? 'нет' : v == null ? '—' : String(v);
  mount(view,
    card('Медленные атаки (Slowloris, R.U.D.Y., Slow Read)', h('div', {},
      h('div', { class: 'small muted', style: { padding: '0 16px 10px' } }, 'Атакующий держит тысячи соединений, присылая заголовки или тело по байту. Короткие таймауты и сброс зависших соединений освобождают воркеры nginx.'),
      table([{ title: 'Параметр', render: (r) => LBL[r.key] || r.key }, { title: 'Сейчас', render: (r) => fmtV(r.current) },
        { title: 'Рекомендуется', render: (r) => fmtV(r.recommended) }, { title: '', srTitle: 'Состояние', render: (r) => r.ok ? badge('ок', 'good') : badge('изменить', 'warn') }], slow)),
    { flush: true, actions: can('admin') && slow.some(x => !x.ok) ? h('button', { class: 'btn primary', onclick: async () => {
      await api('/protection/slow-profile', { method: 'POST' }); toast('Рекомендуемые значения записаны в «Настройки nginx». Примените конфигурацию.', 'good'); refreshState(); go('server');
    } }, icon('check'), 'Установить рекомендуемые') : null }),
    card('Сетевой стек ядра Linux (SYN-флуд, подмена адресов)', h('div', {},
      h('div', { class: 'small muted', style: { padding: '0 16px 10px' } }, 'Флуд на уровне TCP (L3/L4) nginx не видит — его отражает ядро: SYN cookies, длинные очереди соединений, отбрасывание пакетов с поддельным источником. Объёмные DDoS-атаки (десятки Гбит/с) отражают только у провайдера или в сети очистки трафика (Cloudflare, DDoS-Guard, Qrator, StormWall).'),
      table([{ title: 'Параметр', render: (r) => h('div', {}, h('code', {}, r.name), h('div', { class: 'small muted' }, r.title)) },
        { title: 'Сейчас', num: true, render: (r) => r.current ?? '—' }, { title: 'Рекомендуется', num: true, render: (r) => ({ ge: '≥ ', le: '≤ ', in12: '' })[r.rule] !== undefined ? (({ ge: '≥ ', le: '≤ ' })[r.rule] || '') + (r.rule === 'in12' ? '1 или 2' : r.recommended) : r.recommended },
        { title: '', srTitle: 'Состояние', render: (r) => r.ok == null ? badge('нет данных') : r.ok ? badge('ок', 'good') : badge('изменить', 'warn') }], sys.items)),
    { flush: true, cls: 'mt', sub: `Файл ${sys.file}${sys.installed ? ' — установлен' : ''}`, actions: can('admin') && sys.items.some(x => x.ok === false) ? h('button', { class: 'btn primary', onclick: async () => {
      const r = await api('/protection/sysctl/apply', { method: 'POST' });
      toast(r.ok ? 'Параметры ядра применены' : `Не применены: ${r.not_applied.join(', ')} (в контейнере ядро может быть недоступно для изменений)`, r.ok ? 'good' : 'warn'); go('server');
    } }, icon('check'), 'Применить рекомендуемые') : null }));
}
