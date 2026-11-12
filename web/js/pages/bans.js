// Блокировки IP: ручные и автоматические (поиск уязвимостей, подбор паролей, флуд), подозрительные адреса.
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, confirmDlg, table, tabs, kpi, fmtAgo, fmtDur, fmtInt, fmtDate, empty, downloadText, debounce, countryTag, countryName } from '../ui.js';
import { can, ctx } from '../app.js';

const DURATIONS = [[15, '15 минут'], [60, '1 час'], [360, '6 часов'], [1440, '1 сутки'], [10080, '7 суток'], [43200, '30 суток'], [null, 'Бессрочно']];
const RULE_KIND = { scan: 'bad', auth: 'bad', default: 'warn', e4xx: 'warn', flood: 'warn', manual: 'outline' };

function remaining(b) {
  if (b.expires_at == null) return h('span', {}, 'бессрочно');
  return h('span', { class: b.remaining < 600 ? 'status-4' : '' }, fmtDur(b.remaining));
}

/** Диалог блокировки (используется также в журнале запросов и аналитике). */
export function banDialog(ip = '', { reason = '', onDone } = {}) {
  const ta = h('textarea', { rows: 4, placeholder: '203.0.113.7\n198.51.100.0/24' }, ip);
  const dur = h('select', {}, DURATIONS.map(([v, l]) => h('option', { value: v === null ? '' : String(v), selected: v === 1440 }, l)));
  const why = h('input', { type: 'text', value: reason, placeholder: 'Например: перебор паролей к /wp-login.php' });
  const err = h('div', {});
  const send = async (force = false) => {
    const nets = ta.value.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
    if (!nets.length) { mount(err, h('div', { class: 'alert bad mt' }, 'Укажите хотя бы один адрес')); return; }
    try {
      const r = await api('/bans', { method: 'POST', silent: true, body: { nets, minutes: dur.value ? Number(dur.value) : null, reason: why.value, force } });
      m.close();
      toast(r.ok ? `Заблокировано: ${r.count}` : 'Блокировка сохранена, но nginx не принял список — см. «Диагностику»', r.ok ? 'good' : 'warn');
      onDone && onDone();
    } catch (e) {
      const msg = e.data?.detail || e.message;
      if (!force && /доверенных/.test(msg)) {
        if (await confirmDlg(msg + '\n\nВсё равно заблокировать?', { danger: true, ok: 'Заблокировать' })) send(true);
        return;
      }
      mount(err, h('div', { class: 'alert bad mt' }, msg));
    }
  };
  const m = modal({
    title: 'Заблокировать IP-адреса',
    body: h('div', { class: 'col' },
      h('div', { class: 'field' }, h('label', {}, 'Адреса и подсети'), ta,
        h('div', { class: 'help' }, 'По одному в строке, через пробел или запятую. IPv4 и IPv6, подсети в формате CIDR (/24, /64).')),
      h('div', { class: 'grid g2' },
        h('div', { class: 'field' }, h('label', {}, 'Срок'), dur),
        h('div', { class: 'field' }, h('label', {}, 'Причина (для журнала)'), why)),
      h('div', { class: 'muted small' }, 'Запросы с этих адресов ко всем сайтам будут отклоняться сразу, без проксирования. Список обновляется в nginx за несколько секунд, без применения конфигурации.'),
      err),
    footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'),
      h('button', { class: 'btn danger solid', onclick: () => send(false) }, icon('ban'), 'Заблокировать')],
  });
  setTimeout(() => ta.focus(), 50);
}

const GEO_MODE = { deny: ['Запрещены выбранные', 'bad'], allow: ['Только выбранные', 'warn'] };

/** Вкладка «Страны»: база GeoIP, файл сетей, сайты с ограничениями по странам. */
function geoTab(box, g, reload) {
  const db = g.db, f = g.file;
  const dbState = db.loaded
    ? h('div', {}, badge('подключена', 'good'), ' ', h('code', {}, db.path), db.mtime ? h('span', { class: 'muted small' }, ` · обновлена ${fmtAgo(db.mtime)}`) : null)
    : h('div', {}, badge('нет', 'bad'), ' ', h('span', {}, !db.package ? 'Не установлен пакет maxminddb: sudo ./update.sh --with-geoip (или pip install maxminddb в окружении панели).' : (db.error || 'База не найдена') + '. Положите GeoLite2-Country.mmdb или dbip-country-lite.mmdb в /var/lib/nginx-manager/geoip/.'));
  const used = g.sites.length;
  const bl = g.blocked || { total: 0, countries: [] };
  mount(box, h('div', { class: 'col' },
    !db.loaded && used ? h('div', { class: 'alert bad' }, h('b', {}, 'Ограничения по странам не действуют. '), `У ${used} сайт(ов) заданы правила, но базы GeoIP нет — nginx пропускает всех. Подключите базу и примените конфигурацию.`) : null,
    h('div', { class: 'grid g2' },
      h('div', { class: 'card' }, h('div', { class: 'card-body' }, h('div', { class: 'muted small mb' }, 'База GeoIP'), dbState,
        h('div', { class: 'muted small mt' }, 'Та же база, что и для статистики по странам. Обновляйте её раз в месяц: панель заметит новую версию в течение 10 минут и пересоберёт сети без перерыва в работе.'))),
      h('div', { class: 'card' }, h('div', { class: 'card-body' }, h('div', { class: 'muted small mb' }, 'Сети стран в nginx'),
        f.countries.length ? h('div', {}, h('div', { class: 'chips' }, f.countries.map(c => h('span', { class: 'chip', title: countryName(c) }, c))),
          h('div', { class: 'muted small mt' }, `${fmtInt(f.nets)} сетей · собрано ${f.built ? fmtAgo(f.built) : '—'}${f.last_build?.seconds != null ? ` за ${f.last_build.seconds} с` : ''}`))
          : h('div', { class: 'muted' }, 'Пока не нужны — ни у одного применённого сайта нет правил по странам.'),
        can('operator') && db.loaded ? h('button', { class: 'btn sm mt', onclick: async () => { const r = await api('/geo/rebuild', { method: 'POST' }); toast(`Сети стран пересобраны: ${fmtInt(r.file.nets)}`, 'good'); reload(); } }, 'Пересобрать сейчас') : null))),
    used ? h('div', { class: 'card' }, h('div', { class: 'card-body' },
      h('div', { class: 'row between mb' }, h('div', { class: 'muted small' }, `Отклонено по странам с запуска панели ${fmtDate(bl.since)}`), h('b', {}, fmtInt(bl.total))),
      bl.countries.length ? h('div', { class: 'chips' }, bl.countries.map(([c, n]) => h('span', { class: 'chip', title: countryName(c) || 'страна не определена' }, h('b', {}, c === '--' ? '??' : c), ' ', countryName(c), ' · ', fmtInt(n))))
        : h('div', { class: 'muted small' }, 'Запросов из ограниченных стран пока не было.'))) : null,
    used ? table([
      { title: 'Сайт', render: (s) => h('a', { href: `#/sites?edit=${s.id}&tab=security` }, s.name, !s.enabled ? h('span', { class: 'muted small' }, ' (выключен)') : null) },
      { title: 'Режим', render: (s) => badge(GEO_MODE[s.mode][0], GEO_MODE[s.mode][1]) },
      { title: 'Страны', render: (s) => h('div', { class: 'chips' }, s.countries.slice(0, 12).map(c => h('span', { class: 'chip', title: countryName(c) }, c)), s.countries.length > 12 ? h('span', { class: 'muted small' }, `ещё ${s.countries.length - 12}`) : null) },
      { title: 'Ответ', render: (s) => h('code', {}, s.status) },
      { title: 'Исключений', num: true, render: (s) => fmtInt(s.exceptions) },
      { title: 'Отклонено за 24 ч', num: true, render: (s) => fmtInt(s.blocked_24h ?? s.blocked ?? 0) },
      { title: 'Действует', render: (s) => s.applied && db.loaded ? badge('да', 'good') : badge(db.loaded ? 'не применено' : 'нет базы', 'warn') },
    ], g.sites) : empty('Ограничений по странам нет', 'Настраивается в карточке сайта: вкладка «Безопасность» → «Доступ по странам». Можно запретить отдельные страны или разрешить доступ только из выбранных.', null, 'shield')));
}

export async function render(root) {
  let tab = ['active', 'suspicious', 'offenders', 'countries', 'history'].includes(ctx.params.tab) ? ctx.params.tab : 'active';
  let q = '', timer = null, data = null;
  const head = h('div', {});
  const kpis = h('div', { class: 'grid g4 mb' });
  const tabBar = h('div', {});
  const tools = h('div', {});
  const box = h('div', {});
  const search = h('input', { type: 'search', placeholder: 'Поиск по адресу, причине…', style: { maxWidth: '280px' } });
  search.addEventListener('input', debounce(() => { q = search.value.trim().toLowerCase(); draw(); }, 200));

  async function load() {
    data = await api('/bans');
    draw();
    clearTimeout(timer);
    timer = setTimeout(load, 5000);
  }

  function draw() {
    const r = data, s = r.stats, st = r.settings;
    mount(head,
      s.last_error ? h('div', { class: 'alert bad mb' }, h('b', {}, 'Nginx не принял список блокировок. '), 'Изменения сохранены в панели и будут повторно отправлены. Вывод nginx -t: ', h('code', {}, s.last_error.slice(-300))) : null,
      !st.autoban_enabled ? h('div', { class: 'alert mb row', style: { justifyContent: 'space-between' } },
        h('div', {}, h('b', {}, 'Автоблокировка выключена. '), 'Адреса, превысившие пороги, показываются во вкладке «Подозрительные», но не блокируются.'),
        can('admin') ? h('a', { class: 'btn sm', href: '#/settings?tab=bans' }, icon('gear'), 'Включить и настроить') : null) : null);
    mount(kpis,
      kpi('Активные блокировки', fmtInt(s.active), { foot: `автоматических ${s.auto} · ручных ${s.manual}` }),
      kpi('Автоблокировок за 24 ч', fmtInt(s.auto_24h), { foot: st.autoban_enabled ? `срок ${st.autoban_minutes} мин${st.autoban_escalate ? ', повторным — дольше' : ''}` : 'автоблокировка выключена' }),
      kpi('Отклонено запросов', fmtInt(s.blocked_total), { foot: `с запуска панели: ${fmtInt(s.blocked_since_start)} · ответ ${st.ban_response}` }),
      kpi('Подозрительные IP', fmtInt(s.suspicious), { cls: s.suspicious && !st.autoban_enabled ? 'warn' : '', foot: `превысили пороги за ${Math.round(st.autoban_window / 60)} мин` }));
    mount(tabBar, tabs([
      { id: 'active', label: 'Активные', badge: r.items.length || null },
      { id: 'suspicious', label: 'Подозрительные', badge: r.suspicious.length || null, badgeKind: st.autoban_enabled ? '' : 'warn' },
      { id: 'offenders', label: 'Нарушители сейчас', badge: r.offenders.length || null },
      { id: 'countries', label: 'Страны' },
      { id: 'history', label: 'История' },
    ], tab, (t) => { tab = t; ctx.params.tab = t; history.replaceState(null, '', '#/bans' + (t === 'active' ? '' : '?tab=' + t)); draw(); }));
    mount(tools, tab === 'countries' ? null : h('div', { class: 'row mb', style: { justifyContent: 'space-between' } }, search,
      h('div', { class: 'row' },
        tab === 'active' && r.items.length ? h('button', { class: 'btn sm', onclick: () => downloadText('banned-ips.txt', r.items.map(b => b.net).join('\n') + '\n', 'text/plain') }, icon('download'), 'Экспорт списка') : null,
        tab === 'active' && can('admin') && s.auto ? h('button', { class: 'btn sm', onclick: async () => {
          if (!await confirmDlg(`Снять все автоматические блокировки (${s.auto})?`, { ok: 'Снять' })) return;
          await api('/bans/clear', { method: 'POST', body: { source: 'auto' } }); toast('Автоматические блокировки сняты', 'good'); load();
        } }, 'Снять все автоматические') : null)));
    const match = (...xs) => !q || xs.some(x => String(x || '').toLowerCase().includes(q));
    if (tab === 'active') {
      const rows = r.items.filter(b => match(b.net, b.reason, b.username, b.country, b.rule_title));
      mount(box, rows.length ? table([
        { title: 'Адрес', render: (b) => h('div', {}, h('code', {}, b.net), b.country ? h('span', { style: { marginLeft: '6px' } }, countryTag(b.country)) : null) },
        { title: 'Причина', render: (b) => h('div', { style: { maxWidth: '420px' } }, badge(b.rule_title || b.rule || 'вручную', RULE_KIND[b.rule] || 'outline'), ' ',
          h('span', {}, (b.reason || '').replace((b.rule_title || '') + ': ', '')),
          b.details?.sample ? h('div', { class: 'muted small ellipsis', title: b.details.sample }, h('code', {}, b.details.sample)) : null) },
        { title: 'Кто', render: (b) => b.source === 'auto' ? h('span', { class: 'muted' }, 'автоматически', b.offenses > 1 ? h('div', { class: 'small status-4' }, `${b.offenses}-й раз`) : null) : h('span', {}, b.username || '—') },
        { title: 'Когда', render: (b) => h('span', { class: 'small', title: fmtDate(b.created_at, { year: true }) }, fmtAgo(b.created_at)) },
        { title: 'Осталось', render: remaining },
        { title: 'Отклонено', num: true, render: (b) => fmtInt(b.hits) },
        { title: '', render: (b) => can('operator') ? h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
          h('select', { class: 'sm', title: 'Изменить срок', onchange: async (e) => {
            const v = e.target.value; if (v === '-') return;
            await api('/bans', { method: 'POST', body: { nets: [b.net], minutes: v ? Number(v) : null, reason: b.reason, force: true } });
            toast('Срок изменён', 'good'); load();
          } }, h('option', { value: '-' }, 'Срок…'), DURATIONS.map(([v, l]) => h('option', { value: v === null ? '' : String(v) }, l))),
          h('button', { class: 'btn sm', onclick: async () => { await api(`/bans/${b.id}`, { method: 'DELETE' }); toast(`${b.net} разблокирован`, 'good'); load(); } }, 'Разблокировать')) : null },
      ], rows) : empty(q ? 'Ничего не найдено' : 'Заблокированных адресов нет', q ? '' : 'Заблокируйте адрес вручную или включите автоблокировку в настройках панели.',
        !q && can('operator') ? h('button', { class: 'btn primary', onclick: () => banDialog('', { onDone: load }) }, icon('ban'), 'Заблокировать') : null, 'ban'));
    } else if (tab === 'suspicious') {
      const rows = r.suspicious.filter(x => match(x.ip, x.title, x.sample, x.host, x.country));
      mount(box, rows.length ? table([
        { title: 'Адрес', render: (x) => h('div', {}, h('code', {}, x.ip), x.country ? h('span', { style: { marginLeft: '6px' } }, countryTag(x.country)) : null) },
        { title: 'Правило', render: (x) => badge(x.title, RULE_KIND[x.rule] || '') },
        { title: 'Показатели за окно', render: (x) => h('span', { class: 'small' }, `запросов ${x.requests} · 4xx ${x.e4xx} · 401 ${x.e401} · зондов ${x.scan} · по IP ${x.default}`) },
        { title: 'Пример запроса', render: (x) => h('div', { class: 'ellipsis small', style: { maxWidth: '360px' }, title: x.sample }, x.host ? h('span', { class: 'muted' }, x.host) : null, h('code', {}, x.sample || '—')) },
        { title: 'Когда', render: (x) => h('span', { class: 'small' }, fmtAgo(x.ts)) },
        { title: '', render: (x) => x.banned ? badge('заблокирован', 'outline') : can('operator') ? h('button', { class: 'btn sm danger', onclick: () => banDialog(x.ip, { reason: `${x.title}: ${x.count}`, onDone: load }) }, icon('ban'), 'Заблокировать') : null },
      ], rows) : empty('Подозрительных адресов нет', 'Здесь появляются IP, превысившие пороги автоблокировки (настройки панели → «Блокировки IP»).', null, 'shield'));
    } else if (tab === 'offenders') {
      const rows = r.offenders.filter(x => match(x.ip, x.sample));
      mount(box, h('div', {},
        h('div', { class: 'muted small mb' }, `Адреса с ошибочными или подозрительными запросами в текущем окне (${Math.round(st.autoban_window / 60)} мин), ещё не достигшие порогов. Пороги: зондов ${st.autoban_scan || '—'}, 401 — ${st.autoban_auth || '—'}, 4xx — ${st.autoban_4xx || '—'}, по IP — ${st.autoban_default_host || '—'}.`),
        rows.length ? table([
          { title: 'Адрес', render: (x) => h('code', {}, x.ip) },
          { title: 'Запросов', num: true, render: (x) => fmtInt(x.requests) },
          { title: '4xx', num: true, render: (x) => fmtInt(x.e4xx) },
          { title: '401', num: true, render: (x) => fmtInt(x.e401) },
          { title: 'Зондов', num: true, render: (x) => x.scan ? h('b', { class: 'status-5' }, x.scan) : '0' },
          { title: 'По IP', num: true, render: (x) => fmtInt(x.default) },
          { title: 'Последний подозрительный запрос', render: (x) => h('code', { class: 'small ellipsis', style: { maxWidth: '320px', display: 'inline-block' }, title: x.sample }, x.sample || '—') },
          { title: '', render: (x) => can('operator') ? h('button', { class: 'btn sm', onclick: () => banDialog(x.ip, { onDone: load }) }, icon('ban')) : null },
        ], rows) : empty('Нарушителей нет', 'В текущем окне нет адресов с заметным числом ошибок или зондирований.', null, 'shield')));
    } else if (tab === 'countries') {
      if (!box.querySelector('.col')) mount(box, h('div', {}, 'Загрузка…'));
      api('/geo').then(g => { if (tab === 'countries') geoTab(box, g, draw); });
    } else {
      mount(box, h('div', {}, 'Загрузка…'));
      api('/events', { query: { source: 'bans', limit: 300 } }).then(ev => {
        if (tab !== 'history') return;
        const rows = ev.filter(e => match(e.message));
        mount(box, rows.length ? table([
          { title: 'Время', render: (e) => h('span', { class: 'small nowrap' }, fmtDate(e.ts)) },
          { title: '', render: (e) => badge(e.level === 'warning' ? 'авто' : e.level === 'error' ? 'ошибка' : 'инфо', e.level === 'error' ? 'bad' : e.level === 'warning' ? 'warn' : '') },
          { title: 'Событие', render: (e) => h('span', {}, e.message) },
        ], rows) : empty('Событий нет', 'Здесь появятся автоматические блокировки и снятия блокировок.', null, 'activity'));
      });
    }
  }

  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Блокировки IP'),
      h('p', {}, 'Заблокированные адреса не получают ответа ни от одного сайта (кроме TCP/UDP-потоков — для них используйте списки доступа потока). Автоблокировка находит сканеры уязвимостей, подбор паролей и флуд по журналу доступа.')),
      h('div', { class: 'row' },
        can('admin') ? h('a', { class: 'btn', href: '#/settings?tab=bans' }, icon('gear'), 'Пороги и сроки') : null,
        can('operator') ? h('button', { class: 'btn primary', onclick: () => banDialog('', { onDone: load }) }, icon('ban'), 'Заблокировать') : null)),
    head, kpis, h('div', { class: 'card' }, h('div', { class: 'card-body' }, tabBar, h('div', { class: 'mt' }, tools), box)));
  await load();
  return () => clearTimeout(timer);
}
