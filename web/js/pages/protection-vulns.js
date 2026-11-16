// Защита от атак → Уязвимости: база известных уязвимостей (CISA KEV, nuclei-templates, FIRST EPSS), обновление
// всех баз защиты (списки угроз, адреса роботов, уязвимости, правила OWASP CRS), карта путей эксплойтов для фильтра
// запросов и карточка уязвимости.
import { api } from '../api.js';
import { h, mount, icon, toast, modal, loading, card, kpi, badge, table, fmtInt, fmtNum, fmtDate, fmtAgo, empty, segmented,
  debounce, confirmDlg } from '../ui.js';
import { model, renderFields, errorsToMap } from '../forms.js';
import { can, refreshState } from '../app.js';
import { openIp } from './protection-more.js';
import { techCard } from './protection-intel.js';

const GROUPS = { threats: 'Список угроз', bots: 'Адреса робота', vulns: 'База уязвимостей', crs: 'Правила ModSecurity' };
const FILTERS = [['', 'Все'], ['mine', 'Ваши продукты'], ['kev', 'Эксплуатируемые'], ['patched', 'В фильтре путей'], ['covered', 'Встроенные правила'],
  ['uncovered', 'Без защиты'], ['seen', 'Атаковали'], ['exploit', 'Есть эксплойт'], ['ransomware', 'Вымогатели'], ['critical', 'Критические']];
const SORTS = [['kev', 'Сначала эксплуатируемые'], ['new', 'Новые в каталоге KEV'], ['cvss', 'По CVSS'], ['epss', 'По EPSS'],
  ['seen', 'По попыткам на ваших сайтах'], ['cve', 'По номеру CVE']];
const SEV = { critical: ['критическая', 'bad'], high: ['высокая', 'warn'], medium: ['средняя', 'info'], low: ['низкая', ''] };
const go = (tab, extra = '') => { location.hash = `#/protection?tab=${tab}${extra}`; };

function sevOf(v) {
  if (SEV[v.severity]) return SEV[v.severity];
  if (!v.cvss) return null;
  return v.cvss >= 9 ? SEV.critical : v.cvss >= 7 ? SEV.high : v.cvss >= 4 ? SEV.medium : SEV.low;
}

export function sevBadge(v) {
  const s = sevOf(v);
  return s ? badge(s[0] + (v.cvss ? ` · ${fmtNum(v.cvss, 1)}` : ''), s[1]) : h('span', { class: 'muted' }, '—');
}

const epssText = (v) => v.epss ? `${fmtNum(v.epss * 100, v.epss < 0.1 ? 1 : 0)}%` : '—';
const product = (v) => [v.vendor, v.product].filter(Boolean).join(' · ') || '—';

function protection(v) {
  const out = [];
  if (v.active) out.push(badge('путь в фильтре', 'good'));
  if (v.covered && v.covered.length) out.push(badge('правило фильтра', 'good'));
  if (!out.length) out.push(h('span', { class: 'muted small' }, v.template ? 'путь не подходит для карты' : 'нет HTTP-сигнатуры'));
  return h('span', { class: 'row', style: { gap: '4px', flexWrap: 'wrap' } }, out);
}

async function saveSettings(obj, msg) {
  await api('/protection/settings', { method: 'PUT', body: obj });
  toast(msg, 'good');
  refreshState();
}

// ================================================================ вкладка
export async function vulnsTab(view, { cfg, sites }) {
  const obj = structuredClone(cfg.settings);
  const state = { q: '', filter: '', sort: 'kev', offset: 0 };
  let data = await api('/protection/vulns', { query: { limit: 30 } });
  let src = await api('/protection/sources');
  const s = data.summary;
  const mp = data.map || {};
  let errors = {};
  const form = h('div', {});
  const drawForm = () => { mount(form); renderFields(form, model('protection'), obj, { root: obj, tab: 'vulns', advanced: true, errors, rerender: drawForm }); };
  drawForm();

  // --- источники
  const srcBody = h('div', {});
  const drawSources = () => {
    const running = src.running;
    mount(srcBody,
      running ? h('div', { class: 'alert info mb', role: 'status' }, loading(), ' Обновление: ', src.progress || 'подготовка…') : null,
      table([
        { title: 'База', render: (r) => h('span', {}, h('b', {}, r.title), h('div', { class: 'small muted' }, GROUPS[r.group] || r.group)) },
        { title: 'Записей', num: true, render: (r) => r.version ? h('span', {}, r.version) : r.count != null ? fmtInt(r.count) : '—' },
        { title: 'Обновлена', render: (r) => r.updated ? h('span', { class: 'small', title: fmtDate(r.updated) }, fmtAgo(r.updated)) : h('span', { class: 'small muted' }, r.group === 'crs' && r.source === 'package' ? 'пакет дистрибутива' : 'ещё нет') },
        { title: 'Расписание', render: (r) => h('span', { class: 'small muted' }, !r.enabled ? 'выключено' : r.every ? `каждые ${r.every} ч` : 'с обновлением пакетов') },
        { title: 'Состояние', render: (r) => !r.enabled ? h('span', { class: 'muted small' }, '—') : r.error ? h('span', { class: 'bad-text small', title: r.error }, 'ошибка: ' + r.error.slice(0, 90)) : r.ok ? badge('в порядке', 'good') : h('span', { class: 'muted small' }, 'не загружена') },
      ], src.rows));
    if (running && view.isConnected) {
      setTimeout(async () => {
        if (!view.isConnected) return;
        src = await api('/protection/sources');
        if (!src.running) { toast('Базы защиты обновлены', 'good'); go('vulns'); return; }
        drawSources();
      }, 2500);
    }
  };
  drawSources();
  const update = async (what) => {
    try {
      await api('/protection/vulns/update', { method: 'POST', body: { what } });
      toast('Обновление запущено', 'good');
      src = await api('/protection/sources');
      drawSources();
    } catch (e) { toast(e.message, 'bad'); }
  };

  // --- таблица базы
  const tbl = h('div', {});
  const more = h('div', { class: 'row mt', style: { justifyContent: 'center' } });
  const count = h('span', { class: 'small muted', role: 'status' });
  const load = async (append = false) => {
    if (!append) state.offset = 0;
    const r = await api('/protection/vulns', { query: { q: state.q, filter: state.filter, sort: state.sort, limit: 30, offset: state.offset } });
    const rows = append ? [...(tbl._rows || []), ...r.rows] : r.rows;
    tbl._rows = rows;
    count.textContent = `${fmtInt(r.total)} ${r.total % 10 === 1 && r.total % 100 !== 11 ? 'уязвимость' : 'уязвимостей'}`;
    mount(tbl, rows.length ? table([
      { title: 'CVE', render: (v) => h('a', { href: '#', class: 'nowrap', onclick: (e) => { e.preventDefault(); openVuln(v.cve, { sites }); } }, v.cve) },
      { title: 'Уязвимость', render: (v) => h('div', { style: { minWidth: '220px' } }, h('div', {}, v.name || '—'), h('div', { class: 'small muted' }, product(v))) },
      { title: 'Критичность', render: (v) => sevBadge(v) },
      { title: 'EPSS', num: true, render: (v) => h('span', { title: 'Вероятность эксплуатации в ближайшие 30 дней (FIRST EPSS)' }, epssText(v)) },
      { title: 'В каталоге KEV', render: (v) => v.kev ? h('span', { class: 'nowrap' }, v.kev_added || 'да') : h('span', { class: 'muted' }, '—') },
      { title: 'Особенности', render: (v) => h('span', { class: 'row', style: { gap: '4px', flexWrap: 'wrap' } },
        v.ransomware ? badge('вымогатели', 'bad') : null, v.exploits ? badge('эксплойт опубликован', 'warn') : null) },
      { title: 'Защита', render: protection },
      { title: 'Попыток', num: true, render: (v) => v.seen ? h('b', { class: 'bad-text' }, fmtInt(v.seen)) : h('span', { class: 'muted' }, '0') },
    ], rows) : empty('Ничего не найдено', state.q ? 'Измените запрос или фильтр' : 'База ещё не загружена — нажмите «Обновить всё»', null, 'search'));
    mount(more, rows.length < r.total ? h('button', { class: 'btn', onclick: () => { state.offset += 30; load(true); } }, `Показать ещё (${fmtInt(r.total - rows.length)})`) : null);
  };
  const search = h('input', { type: 'search', placeholder: 'CVE, продукт, производитель…', 'aria-label': 'Поиск уязвимостей', style: { maxWidth: '280px' },
    oninput: debounce((e) => { state.q = e.target.value.trim(); load(); }, 300) });
  const sortSel = h('select', { 'aria-label': 'Сортировка', style: { width: 'auto' }, onchange: (e) => { state.sort = e.target.value; load(); } },
    SORTS.map(([v, l]) => h('option', { value: v }, l)));

  const segBox = h('span', {}, segmented(FILTERS, '', (v) => { state.filter = v; load(); }));
  const dbCard = card('База уязвимостей', h('div', {},
    h('div', { class: 'row mb', style: { gap: '8px', flexWrap: 'wrap' } }, search, segBox, sortSel, count),
    tbl, more), { cls: 'mt', sub: `всего ${fmtInt(s.total)}${s.ransomware ? ` · ${fmtInt(s.ransomware)} используют вымогатели` : ''}${s.exploits ? ` · ${fmtInt(s.exploits)} эксплуатируемых с опубликованным эксплойтом` : ''}` });

  // --- чаще всего атакуют
  const top = (await api('/protection/vulns', { query: { filter: 'seen', sort: 'seen', limit: 10 } })).rows;
  const watchNew = (data.new && data.new.watch) || [];
  const reasons = [['generic', 'типовые пути (/, /login, /wp-login.php…) и статика'], ['shared', 'общие для многих продуктов'],
    ['legit', 'ваши сайты обслуживают их обычным посетителям'], ['excluded', 'исключены вами']];

  mount(view,
    h('div', { class: 'alert info mb' }, 'Панель ведёт базу известных уязвимостей и обновляет её по расписанию из открытых источников: каталог CISA KEV — уязвимости, которые эксплуатируются на практике; шаблоны ProjectDiscovery nuclei-templates — как выглядит эксплойт, критичность CVSS и описание; FIRST EPSS — вероятность эксплуатации. Из шаблонов строится карта путей эксплойтов для фильтра запросов: по ней видно, какие уязвимости ищут на ваших сайтах, а в режиме блокировки такие запросы отклоняются. Здесь же обновляются все остальные базы защиты.'),
    watchNew.length ? h('div', { class: 'alert warn mb' }, h('b', {}, 'Новые эксплуатируемые уязвимости в ваших продуктах: '),
      watchNew.slice(0, 8).map((c, i) => [i ? ', ' : '', h('a', { href: '#', onclick: (e) => { e.preventDefault(); openVuln(c, { sites }); } }, c)]),
      `. Добавлены в каталог CISA KEV ${fmtAgo(data.new.ts)} — проверьте, что установлены исправления.`) : null,
    !s.enabled ? h('div', { class: 'alert warn mb' }, 'Автоматическое обновление базы выключено — включите его в настройках ниже.') : null,
    h('div', { class: 'grid kpi5 mb' },
      kpi('Эксплуатируемых', fmtInt(s.kev), { foot: s.kev_week ? `+${fmtInt(s.kev_week)} за неделю` : 'каталог CISA KEV', tip: 'Уязвимости, эксплуатацию которых подтвердило агентство CISA' }),
      kpi('В фильтре путей', fmtInt(s.active_paths), { foot: `${fmtInt(mp.entries || 0)} путей · режим «${{ off: 'выключено', detect: 'запись', block: 'блокировать' }[s.mode] || s.mode}»`, cls: s.active_paths ? 'good' : '' }),
      kpi('Встроенные правила', fmtInt(s.covered), { foot: 'CVE в каталоге фильтра запросов' }),
      kpi('Атаковали ваши сайты', fmtInt(s.seen), { foot: s.seen_hits ? `${fmtInt(s.seen_hits)} попыток` : 'попыток не было', cls: s.seen ? 'warn' : '' }),
      kpi('В ваших продуктах', fmtInt(s.mine_kev || 0), { foot: s.watch && s.watch.length ? `эксплуатируемых; продуктов: ${s.watch.length}` : 'продукты сайтов не определены', cls: s.mine_kev ? 'warn' : '', tip: (s.watch || []).join(', ') })),
    card('Источники и обновление', srcBody, { flush: true, sub: s.next && s.enabled ? `следующая проверка базы уязвимостей — ${fmtDate(s.next)}` : '',
      actions: can('admin') ? [
        h('button', { class: 'btn', onclick: () => update('vulns') }, icon('refresh'), 'Только уязвимости'),
        obj.crs_source === 'github' ? h('button', { class: 'btn', onclick: () => update('crs') }, icon('refresh'), 'Правила CRS') : null,
        h('button', { class: 'btn primary', onclick: () => update('all') }, icon('refresh'), 'Обновить всё')] : null }),
    h('div', { class: 'grid g2 mt' },
      card('Чаще всего пытаются эксплуатировать', top.length ? table([
        { title: 'CVE', render: (v) => h('a', { href: '#', onclick: (e) => { e.preventDefault(); openVuln(v.cve, { sites }); } }, v.cve) },
        { title: 'Продукт', render: (v) => h('span', { class: 'small' }, product(v)) },
        { title: 'Попыток', num: true, render: (v) => fmtInt(v.seen) },
        { title: 'Последняя', render: (v) => h('span', { class: 'small muted' }, v.last_seen ? fmtAgo(v.last_seen) : '—') },
      ], top) : empty('Попыток не было', 'Здесь появятся уязвимости, которые ищут на ваших сайтах', null, 'shield'), { flush: !!top.length, sub: 'по журналу атак за всё время хранения' }),
      card('Карта путей эксплойтов', h('div', {},
        h('dl', { class: 'facts' },
          h('dt', {}, 'Путей в карте'), h('dd', {}, fmtInt(mp.entries || 0)),
          h('dt', {}, 'Уязвимостей'), h('dd', {}, fmtInt(mp.cves || 0)),
          h('dt', {}, 'Охват'), h('dd', {}, { kev: 'эксплуатируемые (CISA KEV)', critical: 'эксплуатируемые и критические', high: 'эксплуатируемые, критические и высокие' }[obj.vulndb_scope]),
          h('dt', {}, 'Собрана'), h('dd', {}, mp.built ? fmtDate(mp.built) : '—')),
        h('div', { class: 'small muted mt' }, 'Не попали в карту, чтобы не задеть обычных посетителей:'),
        h('ul', { class: 'small', style: { margin: '4px 0 0', paddingLeft: '18px' } }, reasons.map(([k, l]) => h('li', {}, `${l}: ${fmtInt(mp[k] || 0)}`))),
        h('div', { class: 'small mt' }, 'Режим категории «Эксплойты известных уязвимостей» — на вкладке ', h('a', { href: '#/protection?tab=waf' }, 'Фильтр запросов'), '.')), { sub: 'точное совпадение пути, без потерь скорости' })),
    await techCard((f) => { state.filter = f; mount(segBox, segmented(FILTERS, f, (v) => { state.filter = v; load(); })); load(); dbCard.scrollIntoView({ behavior: 'smooth' }); }, (cve) => openVuln(cve, { sites })),
    dbCard,
    card('Настройки', h('div', {}, form, can('admin') ? h('div', { class: 'row mt' }, h('button', { class: 'btn primary', onclick: async () => {
      try { await saveSettings(obj, 'Настройки базы уязвимостей сохранены. Карта путей пересобирается'); errors = {}; } catch (e) { errors = errorsToMap(e); drawForm(); }
    } }, icon('check'), 'Сохранить')) : null), { cls: 'mt', sub: 'включение и выключение категории в nginx — после применения конфигурации' }));
  await load();
}

// ================================================================ карточка уязвимости
// пути эксплойта: в карте фильтра и отсеянные (типовые, общие для многих уязвимостей, законные на ваших сайтах)
function pathLists(v, paths) {
  const li = ([p, k]) => h('li', {}, h('code', { style: { wordBreak: 'break-all' } }, p), h('span', { class: 'muted' }, k === 'a' ? ' — любой запрос' : ' — с признаком атаки в параметрах'));
  const ul = (items) => h('ul', { class: 'small', style: { margin: '4px 0 0', paddingLeft: '18px' } }, items.slice(0, 12).map(li));
  if (v.excluded) return [h('div', { class: 'small muted' }, 'Уязвимость исключена — пути не проверяются.'), ul(paths)];
  const inMap = v.in_map || {};
  const on = paths.filter(([p]) => p in inMap).map(([p]) => [p, inMap[p]]);
  const off = paths.filter(([p]) => !(p in inMap));
  return [
    on.length ? [h('div', { class: 'small muted' }, 'Пути эксплойта в фильтре запросов:'), ul(on)] : null,
    off.length ? h('div', { class: on.length ? 'small muted mt' : 'small muted' }, on.length ? 'Не в карте (типовые, общие для многих уязвимостей или законные на ваших сайтах): ' : 'Пути эксплойта не попали в карту — типовые, общие для многих уязвимостей или законные на ваших сайтах: ',
      off.slice(0, 12).map(([p], i) => [i ? ', ' : '', h('code', {}, p)])) : null];
}

export async function openVuln(cve, { sites = [] } = {}) {
  const body = h('div', {}, loading());
  const m = modal({ title: cve, size: 'xl', body });
  let v;
  try { v = await api(`/protection/vulns/${encodeURIComponent(cve)}`); } catch (e) { mount(body, empty('Уязвимости нет в базе', e.message, null, 'search')); return; }
  const siteName = (id) => (sites.find(x => String(x.id) === String(id)) || {}).name || (id === '' || id === '0' ? 'панель и прочие' : `сайт ${id}`);
  const facts = [
    ['Продукт', product(v)],
    ['Критичность', h('span', {}, sevBadge(v), v.cvss_vector ? h('code', { class: 'small muted', style: { marginLeft: '8px' } }, v.cvss_vector) : null)],
    v.published ? ['Опубликована', v.published] : null,
    v.affected ? ['Затронутые версии', h('span', { class: 'small' }, v.affected)] : null,
    ['EPSS', v.epss ? `${epssText(v)}${v.epss_pct ? ` (выше, чем у ${fmtNum(v.epss_pct * 100, 0)}% уязвимостей)` : ''}` : '—'],
    ['Каталог CISA KEV', v.kev ? `добавлена ${v.kev_added}${v.kev_due ? `, срок устранения для госорганов США — ${v.kev_due}` : ''}` : 'нет'],
    v.ransomware ? ['Вымогатели', h('b', { class: 'bad-text' }, 'используется в атаках вымогателей')] : null,
    v.on_sites && v.on_sites.length ? ['На ваших сайтах', h('div', {}, v.on_sites.map(x => h('div', {}, `${x.name}: ${x.tech}${x.version ? ' ' + x.version : ''} — `,
      x.affected === true ? h('b', { class: 'bad-text' }, 'версия уязвима') : x.affected === false ? h('span', {}, 'версия не затронута') : h('span', { class: x.note ? 'warning-text' : 'muted' }, x.note ? 'проверьте пакет' : x.version ? 'не удалось сравнить версии' : 'версия неизвестна'),
      x.note ? h('div', { class: 'small muted' }, x.note) : null)))] : null,
    v.cwe ? ['Тип (CWE)', v.cwe] : null,
    v.exploits && v.exploits.length ? ['Публичные эксплойты', h('span', {}, v.exploits.slice(0, 6).map((id, i) => [i ? ', ' : '', h('a', { href: `https://www.exploit-db.com/exploits/${id}`, target: '_blank', rel: 'noopener noreferrer' }, `EDB-${id}`)]))] : null,
    v.tags ? ['Метки шаблона', h('span', { class: 'small' }, v.tags.split(',').join(', '))] : null,
  ].filter(Boolean);
  const paths = Object.entries(v.paths || {});
  const hits = v.hits || [];
  const hitTotal = hits.reduce((a, r) => a + r.n, 0);
  const actions = [];
  if (can('admin') && paths.length) {
    actions.push(h('button', { class: 'btn', onclick: async () => {
      const ex = !v.excluded;
      if (ex && !await confirmDlg(`Исключить ${v.cve} из карты путей? Её пути перестанут проверяться (например, при ложных срабатываниях на вашем приложении).`, { ok: 'Исключить' })) return;
      const r = await api(`/protection/vulns/${v.cve}/exclude`, { method: 'POST', body: { exclude: ex } });
      toast(r.ok ? (ex ? `${v.cve} исключена из карты путей` : `${v.cve} снова проверяется`) : `nginx не принял карту: ${r.output}`, r.ok ? 'good' : 'bad');
      m.close();
    } }, v.excluded ? 'Вернуть в карту путей' : 'Исключить из карты путей'));
  }
  if (hitTotal) actions.push(h('a', { class: 'btn', href: `#/protection?tab=log&kind=waf&q=${encodeURIComponent('vuln/' + v.cve)}`, onclick: () => m.close() }, 'Журнал атак'));
  const links = [['Карточка NVD', v.links.nvd], ['Каталог CISA KEV', v.links.kev], ['Шаблон nuclei', v.links.template]].filter(([, u]) => u);
  mount(body,
    h('h3', { style: { margin: '0 0 4px' } }, v.name || v.cve),
    v.description ? h('p', { class: 'small' }, v.description) : null,
    h('dl', { class: 'facts' }, facts.map(([k, val]) => [h('dt', {}, k), h('dd', {}, val)])),
    v.kev_action ? h('div', { class: 'alert info mt' }, h('b', {}, 'Что делать (CISA): '), v.kev_action) : null,
    h('div', { class: 'grid g2 mt' },
      card('Защита', h('div', {},
        paths.length ? h('div', {}, ...pathLists(v, paths)) : h('div', { class: 'small muted' }, 'Шаблона с HTTP-запросом нет — путь эксплойта неизвестен.'),
        v.rules.length ? h('div', { class: 'mt small' }, 'Встроенные правила фильтра: ', v.rules.map((r, i) => [i ? ', ' : '', h('code', {}, r.id), ` ${r.title}`])) : null,
        h('div', { class: 'small muted mt' }, 'Защита на nginx не заменяет обновление уязвимого продукта: она отсекает известные эксплойты и показывает, что уязвимость ищут.'))),
      card('Попытки на ваших сайтах', hits.length ? table([
        { title: 'Сайт', render: (r) => siteName(r.site) },
        { title: 'Действие', render: (r) => ({ blocked: 'заблокировано', detected: 'записано', challenged: 'проверка браузера' }[r.action] || r.action) },
        { title: 'Раз', num: true, render: (r) => fmtInt(r.n) },
        { title: 'Последняя', render: (r) => h('span', { class: 'small muted' }, fmtAgo(r.last)) },
      ], hits) : empty('Не было', 'Запросов по путям этой уязвимости не приходило', null, 'shield'), { flush: !!hits.length })),
    (v.events || []).length ? card('Последние попытки', table([
      { title: 'Время', render: (e) => h('span', { class: 'small nowrap' }, fmtDate(e.ts)) },
      { title: 'Адрес', render: (e) => h('a', { href: '#', onclick: (ev) => { ev.preventDefault(); m.close(); openIp(e.ip, { sites }); } }, e.ip) },
      { title: 'Сайт', render: (e) => h('span', { class: 'small' }, siteName(e.site)) },
      { title: 'Запрос', render: (e) => h('code', { class: 'small', style: { wordBreak: 'break-all' } }, `${e.method} ${e.uri}`) },
      { title: 'Ответ', num: true, render: (e) => e.status || '—' },
    ], v.events.slice(0, 10)), { flush: true, cls: 'mt' }) : null,
    links.length ? h('div', { class: 'row mt small', style: { gap: '12px' } }, links.map(([l, u]) => h('a', { href: u, target: '_blank', rel: 'noopener noreferrer' }, l, ' ↗'))) : null,
    actions.length ? h('div', { class: 'row mt' }, actions) : null);
}
