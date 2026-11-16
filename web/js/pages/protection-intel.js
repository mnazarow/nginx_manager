// Защита от атак: сеть провайдера (ASN) и AbuseIPDB в профиле адреса, обмен данными об угрозах (AbuseIPDB, CrowdSec),
// технологии сайтов, другие серверы (общие блокировки и настройки защиты), базы GeoIP.
import { api } from '../api.js';
import { h, mount, icon, toast, loading, card, badge, table, fmtInt, fmtDate, fmtAgo, empty, confirmDlg, kpi } from '../ui.js';
import { model, renderFields, errorsToMap } from '../forms.js';
import { can, refreshState } from '../app.js';

const go = (hash) => { location.hash = hash; };

async function saveProt(obj, msg) {
  await api('/protection/settings', { method: 'PUT', body: obj });
  toast(msg, 'good');
  refreshState();
}

// ================================================================ сеть провайдера в профиле адреса
export function networkBlock(d, close) {
  const n = d.network;
  if (!n) return card('Сеть провайдера', h('div', { class: 'small muted' }, d.network_db ? 'Адреса нет в базе сетей провайдеров (частная, локальная или новая сеть).' : 'Нет базы ASN — включите «Скачивать и обновлять бесплатные базы DB-IP Lite» в настройках панели (вкладка «Статистика и хранение»).'));
  const addRule = async (action) => {
    const verb = action === 'block' ? 'блокировать' : 'проверять браузер для';
    if (!await confirmDlg(`Создать своё правило: ${verb} все адреса сети AS${n.asn} (${n.org || 'без названия'})? Действует на всех сайтах после применения конфигурации.`, { ok: 'Создать правило', danger: action === 'block' })) return;
    const cfg = await api('/protection/settings');
    const obj = cfg.settings;
    obj.custom_rules.push({ name: `Сеть AS${n.asn}${n.org ? ': ' + n.org : ''}`.slice(0, 100), enabled: true, sites: [], field: 'asn', op: 'in', value: String(n.asn), action });
    await saveProt(obj, `Правило для AS${n.asn} создано. Примените конфигурацию`);
    close();
  };
  return card('Сеть провайдера', h('div', {},
    h('dl', { class: 'facts' },
      h('dt', {}, 'Автономная система'), h('dd', {}, h('b', {}, `AS${n.asn}`), n.org ? ` — ${n.org}` : ''),
      h('dt', {}, 'Атак из этой сети'), h('dd', {}, `${fmtInt(n.n)} за неделю, адресов: ${fmtInt(n.ips)}`),
      n.rules.length ? [h('dt', {}, 'Свои правила'), h('dd', {}, n.rules.join(', '))] : null),
    h('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap' } },
      h('a', { class: 'btn sm', href: `#/protection?tab=attackers&hours=168&q=AS${n.asn}`, onclick: close }, 'Все адреса сети'),
      can('admin') && !n.rules.length ? h('button', { class: 'btn sm', onclick: () => addRule('challenge') }, 'Проверять браузер для сети') : null,
      can('admin') && !n.rules.length ? h('button', { class: 'btn sm danger', onclick: () => addRule('block') }, icon('ban'), 'Блокировать сеть') : null)),
  { sub: 'по базе ASN' });
}

// ================================================================ AbuseIPDB в профиле адреса
export function abuseBlock(ip) {
  const box = h('div', {}, loading());
  api(`/protection/ip/${encodeURIComponent(ip)}/intel`).then((d) => {
    const a = d.abuseipdb;
    if (!a) {
      mount(box, h('div', { class: 'small muted' }, 'Проверка в AbuseIPDB не настроена — ключ API на вкладке ', h('a', { href: '#/protection?tab=threats' }, '«Списки угроз»'), '.'));
      return;
    }
    if (a.error) { mount(box, h('div', { class: 'small bad-text' }, 'AbuseIPDB: ' + a.error)); return; }
    const report = async () => {
      if (!await confirmDlg(`Отправить жалобу на ${ip} в AbuseIPDB? В жалобе — только сработавшие правила за сутки, без адресов и доменов ваших сайтов.`, { ok: 'Пожаловаться' })) return;
      try {
        const r = await api(`/protection/ip/${encodeURIComponent(ip)}/report`, { method: 'POST' });
        toast(`Жалоба отправлена (категории ${r.categories.join(', ')})`, 'good');
        mount(btnBox, badge('жалоба отправлена', 'good'));
      } catch (e) { toast(e.message, 'bad'); }
    };
    const btnBox = h('span', {}, d.reported ? badge(`жалоба отправлена ${fmtAgo(d.reported)}`, 'good')
      : can('operator') && d.report_mode !== 'off' ? h('button', { class: 'btn sm', onclick: report }, 'Пожаловаться в AbuseIPDB') : null);
    mount(box,
      h('dl', { class: 'facts' },
        h('dt', {}, 'Уверенность'), h('dd', {}, badge(`${a.score}%`, a.score >= 75 ? 'bad' : a.score >= 25 ? 'warn' : 'good'), a.whitelisted ? [' ', badge('в белом списке AbuseIPDB', 'good')] : null, a.tor ? [' ', badge('Tor', 'warn')] : null),
        h('dt', {}, 'Жалоб'), h('dd', {}, `${fmtInt(a.reports)} от ${fmtInt(a.users)} пользователей за 90 дней`, a.last ? `, последняя ${a.last.slice(0, 10)}` : ''),
        a.isp ? [h('dt', {}, 'Провайдер'), h('dd', {}, a.isp, a.domain ? ` (${a.domain})` : '')] : null,
        a.usage ? [h('dt', {}, 'Тип сети'), h('dd', {}, a.usage)] : null),
      h('div', { class: 'row', style: { gap: '6px' } }, btnBox, h('a', { class: 'btn sm ghost', href: a.link, target: '_blank', rel: 'noopener noreferrer' }, 'Открыть в AbuseIPDB ↗')));
  }).catch((e) => mount(box, h('div', { class: 'small bad-text' }, e.message)));
  return card('AbuseIPDB', box, { sub: 'общая база жалоб на адреса' });
}

// ================================================================ обмен данными: настройки и состояние
export async function intelCard(cfg) {
  const obj = structuredClone(cfg.settings);
  let errors = {};
  const form = h('div', {});
  const drawForm = () => { mount(form); renderFields(form, model('protection'), obj, { root: obj, tab: 'intel', advanced: true, errors, rerender: drawForm }); };
  drawForm();
  let st = {};
  try { st = await api('/protection/intel'); } catch { st = {}; }
  const ab = st.abuseipdb || {};
  const cs = st.crowdsec || {};
  const line = (s) => !s || (!s.updated && !s.error) ? h('span', { class: 'muted' }, 'ещё не загружен')
    : s.error ? h('span', { class: 'bad-text' }, 'ошибка: ' + s.error.slice(0, 120)) : h('span', {}, `${fmtInt(s.count || 0)} адресов, ${fmtAgo(s.updated)}`);
  const test = async (what) => {
    const r = await api('/protection/intel/test', { method: 'POST', body: { what } });
    toast(r.ok ? r.message : r.error, r.ok ? 'good' : 'bad');
  };
  return card('Обмен данными об угрозах: AbuseIPDB и CrowdSec', h('div', {},
    h('p', { class: 'small muted', style: { marginTop: 0 } }, 'AbuseIPDB — общая база жалоб на адреса: оценка адреса в профиле атакующего, жалобы на атакующих и чёрный список как список угроз. CrowdSec — решения вашего агента CrowdSec (по журналам SSH, почты, веб-серверов и сигналам сообщества) применяются в nginx.'),
    h('dl', { class: 'facts' },
      h('dt', {}, 'Чёрный список AbuseIPDB'), h('dd', {}, ab.configured && obj.abuseipdb_blacklist ? line(ab.blacklist) : h('span', { class: 'muted' }, 'выключен')),
      h('dt', {}, 'Жалобы'), h('dd', {}, ab.configured ? `${{ off: 'не отправляются', manual: 'вручную', auto: 'автоматически' }[ab.report]}; за сутки: ${fmtInt(ab.sent_today || 0)}, за неделю адресов: ${fmtInt(ab.reported_week || 0)}` : h('span', { class: 'muted' }, 'нет ключа'),
        ab.report_error ? h('span', { class: 'bad-text' }, ' — ' + ab.report_error) : null),
      h('dt', {}, 'Решения CrowdSec'), h('dd', {}, cs.configured ? line(cs.decisions) : h('span', { class: 'muted' }, 'не подключён'))),
    form,
    can('admin') ? h('div', { class: 'row mt', style: { gap: '6px' } },
      h('button', { class: 'btn primary', onclick: async () => {
        try { await saveProt(obj, 'Настройки обмена данными сохранены. Примените конфигурацию, если включили список'); errors = {}; } catch (e) { errors = errorsToMap(e); drawForm(); }
      } }, icon('check'), 'Сохранить'),
      ab.configured ? h('button', { class: 'btn', onclick: () => test('abuseipdb') }, 'Проверить ключ AbuseIPDB') : null,
      cs.configured ? h('button', { class: 'btn', onclick: () => test('crowdsec') }, 'Проверить CrowdSec') : null) : null),
  { cls: 'mt' });
}

// ================================================================ технологии сайтов
export async function techCard(onFilter) {
  const box = h('div', {}, loading());
  const draw = (d) => {
    const rows = d.sites || [];
    mount(box, rows.length ? table([
      { title: 'Сайт', render: (r) => h('span', {}, h('b', {}, r.name), r.ts ? h('div', { class: 'small muted' }, fmtAgo(r.ts)) : null) },
      { title: 'Технологии', render: (r) => r.error ? h('span', { class: 'bad-text small' }, 'нет ответа: ' + r.error)
        : r.skipped ? h('span', { class: 'muted small' }, r.skipped)
          : r.tech.length ? h('div', { class: 'row', style: { gap: '4px', flexWrap: 'wrap' } }, r.tech.map(t => h('span', { class: 'badge' + (t.affected_n ? ' bad' : t.kev ? ' warn' : ''), title: `${t.evidence}${t.kev ? ` · эксплуатируемых уязвимостей продукта: ${t.kev}` : ''}${t.affected_n ? ` · затрагивают версию ${t.version}: ${t.affected.map(a => a.cve).join(', ')}` : ''}` }, t.name, t.version ? ' ' + t.version : '', t.affected_n ? ` · уязвима (${t.affected_n})` : t.kev ? ` · ${t.kev} KEV` : '')))
            : h('span', { class: 'muted small' }, 'не определены') },
      { title: 'Эксплуатируемых уязвимостей', num: true, render: (r) => { const n = r.tech.reduce((a, t) => a + (t.kev || 0), 0); return n ? h('b', {}, fmtInt(n)) : '0'; } },
      { title: 'Затрагивают ваши версии', num: true, render: (r) => { const n = r.tech.reduce((a, t) => a + (t.affected_n || 0), 0); return n ? h('b', { class: 'bad-text' }, fmtInt(n)) : '0'; } },
      { title: 'Новых за 90 дней', num: true, render: (r) => { const n = r.tech.reduce((a, t) => a + (t.recent || 0), 0); return n ? h('b', { class: 'bad-text' }, fmtInt(n)) : '0'; } },
    ], rows) : empty('Технологии ещё не определены', 'Панель определяет их раз в сутки; можно сейчас — кнопкой «Определить»', null, 'search'));
  };
  api('/protection/tech').then(draw).catch((e) => mount(box, h('div', { class: 'bad-text' }, e.message)));
  return card('Технологии ваших сайтов', box, { flush: true, cls: 'mt', sub: 'что работает за nginx — по главной странице с бэкенда; уязвимости найденных продуктов — фильтр «Ваши продукты»',
    actions: [h('button', { class: 'btn sm', onclick: () => onFilter('mine') }, 'Уязвимости ваших продуктов'),
      can('operator') ? h('button', { class: 'btn sm', onclick: async () => { mount(box, loading()); draw(await api('/protection/tech/scan', { method: 'POST', body: {} })); toast('Технологии сайтов определены', 'good'); } }, icon('refresh'), 'Определить') : null] });
}

// ================================================================ другие серверы
export async function peersCard() {
  let d;
  try { d = await api('/peers'); } catch { return null; }
  const push = async (what) => {
    const r = await api('/peers/push', { method: 'POST', body: { what } });
    const res = Object.values(r.results || {});
    const ok = res.filter(x => x.ok).length;
    toast(res.length ? `Отправлено на ${ok} из ${res.length} серверов${ok < res.length ? ': ' + res.filter(x => !x.ok).map(x => x.error).join('; ') : ''}` : 'Нет серверов для отправки', ok === res.length ? 'good' : 'bad');
    go('#/bans?tab=peers');
  };
  const test = async (p) => {
    const r = await api(`/peers/${p.id}/test`, { method: 'POST' });
    toast(r.ok ? `«${p.name}»: связь есть — ${r.name}, версия ${r.version}, роль токена «${r.role}»` : `«${p.name}»: ${r.error}`, r.ok ? 'good' : 'bad');
  };
  return h('div', {},
    h('div', { class: 'alert info mb' }, 'Серверы с Nginx Manager делятся блокировками IP: блокировка (ручная или автоматическая) на любом из них за минуту действует на всех. Настройки защиты от атак отправляются при сохранении или кнопкой. Добавьте серверы в «Настройки панели → Другие серверы» на каждом сервере — с API-токеном того сервера.'),
    h('div', { class: 'grid g3 mb' },
      kpi('Этот сервер', d.me.name, { foot: `идентификатор ${d.me.id}` }),
      kpi('Серверов', fmtInt(d.peers.length), { foot: `включено: ${d.peers.filter(p => p.enabled).length}` }),
      kpi('Получено блокировок', fmtInt(d.incoming.reduce((a, x) => a + (x.active || 0), 0)), { foot: `от ${d.incoming.length} серверов` })),
    card('Отправка', d.peers.length ? table([
      { title: 'Сервер', render: (p) => h('span', {}, h('b', {}, p.name), p.enabled ? '' : [' ', badge('выкл')], h('div', { class: 'small muted' }, p.url)) },
      { title: 'Блокировки', render: (p) => !p.bans ? h('span', { class: 'muted small' }, 'не отправляются') : p.bans_error ? h('span', { class: 'bad-text small' }, p.bans_error)
        : p.bans_at ? h('span', { class: 'small' }, `${fmtInt(p.bans_sent || 0)} отправлено ${fmtAgo(p.bans_at)}`) : h('span', { class: 'muted small' }, 'ещё не отправлялись') },
      { title: 'Настройки защиты', render: (p) => !p.protection ? h('span', { class: 'muted small' }, 'вручную') : p.prot_error ? h('span', { class: 'bad-text small' }, p.prot_error)
        : p.prot_at ? h('span', { class: 'small' }, `применены ${fmtAgo(p.prot_at)}`,
          p.prot_mapped || p.prot_dropped ? h('div', { class: 'muted small', title: 'Правила, привязанные к сайтам, сопоставляются по доменам: сайт с тем же доменом на получателе' },
            `правил сайтов: перенесено ${p.prot_mapped || 0}${p.prot_dropped ? `, нет таких сайтов — ${p.prot_dropped}` : ''}`) : null)
          : h('span', { class: 'muted small' }, 'при сохранении') },
      { title: '', srTitle: 'Действия', render: (p) => can('admin') ? h('button', { class: 'btn sm', onclick: () => test(p) }, 'Проверить связь') : null },
    ], d.peers) : empty('Серверов нет', 'Добавьте их в «Настройки панели → Другие серверы»', can('admin') ? h('a', { class: 'btn primary', href: '#/settings?tab=peers' }, 'Добавить сервер') : null, 'server'),
    { flush: !!d.peers.length, actions: can('admin') && d.peers.length ? [
      h('button', { class: 'btn', onclick: () => push('bans') }, icon('refresh'), 'Отправить блокировки'),
      h('button', { class: 'btn', onclick: async () => { if (await confirmDlg('Отправить настройки защиты от атак на все серверы? На каждом применится конфигурация с этими настройками (свои правила, привязанные к сайтам, и CrowdSec там останутся свои).', { ok: 'Отправить' })) push('protection'); } }, 'Отправить настройки защиты')] : null }),
    card('Получено от других серверов', d.incoming.length ? table([
      { title: 'Сервер', render: (x) => h('b', {}, x.name) },
      { title: 'Блокировок сейчас', num: true, render: (x) => fmtInt(x.active || 0) },
      { title: 'Последняя сверка', render: (x) => h('span', { class: 'small' }, `${fmtAgo(x.at)} (+${x.added}, −${x.removed})`) },
    ], d.incoming) : empty('Пока ничего', 'Блокировки появятся, когда другой сервер отправит их сюда', null, 'server'), { flush: !!d.incoming.length, cls: 'mt' }));
}

// ================================================================ базы GeoIP
export async function geoDbCard() {
  let d;
  try { d = await api('/geoip/databases'); } catch { return null; }
  const box = h('div', {});
  const draw = () => mount(box, table([
    { title: 'База', render: (f) => h('span', {}, h('b', {}, f.title), h('div', { class: 'small muted' }, f.file)) },
    { title: 'Файл', render: (f) => f.exists ? h('span', { class: 'small' }, `${Math.round((f.size || 0) / 1048576 * 10) / 10} МБ, ${fmtDate(f.mtime)}`) : h('span', { class: 'muted small' }, 'нет') },
    { title: 'Обновление', render: (f) => f.error ? h('span', { class: 'bad-text small', title: f.error }, 'ошибка: ' + f.error.slice(0, 80)) : f.updated ? h('span', { class: 'small' }, `${fmtAgo(f.updated)} (${(f.url || '').includes('github') ? 'зеркало GitHub' : 'DB-IP'})`) : h('span', { class: 'muted small' }, d.auto_update ? 'ожидает' : 'выключено') },
  ], d.files));
  draw();
  return card('Базы GeoIP', h('div', {},
    h('dl', { class: 'facts' },
      h('dt', {}, 'Страны'), h('dd', {}, d.country || h('span', { class: 'bad-text' }, d.country_error || 'нет базы')),
      h('dt', {}, 'Сети провайдеров (ASN)'), h('dd', {}, d.asn || h('span', { class: 'muted' }, d.asn_error || 'нет базы'))),
    box, h('div', { class: 'small muted mt' }, 'Бесплатные базы DB-IP Lite (CC BY 4.0) обновляются раз в месяц; база в «Путь к базе GeoIP» и GeoLite2 (MaxMind) в каталоге важнее.')),
  { cls: 'mt', actions: can('admin') ? h('button', { class: 'btn sm', onclick: async () => {
    try { const r = await api('/geoip/update', { method: 'POST' }); d.files = r.files; draw(); toast(r.ok ? 'Базы GeoIP обновлены' : 'Не все базы обновились — см. ошибку в таблице', r.ok ? 'good' : 'bad'); } catch (e) { toast(e.message, 'bad'); }
  } }, icon('refresh'), 'Обновить сейчас') : null });
}
