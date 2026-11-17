// Защита от атак: сеть провайдера (ASN) и AbuseIPDB в профиле адреса, обмен данными об угрозах (AbuseIPDB, CrowdSec),
// технологии сайтов, другие серверы (общие блокировки и настройки защиты), базы GeoIP.
import { api } from '../api.js';
import { h, mount, icon, toast, loading, card, badge, table, fmtInt, fmtDate, fmtAgo, empty, confirmDlg, kpi, modal } from '../ui.js';
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
const DISTRO = { ubuntu: 'Ubuntu', debian: 'Debian', rhel: 'RHEL', fedora: 'Fedora', alpine: 'Alpine' };

function techBadge(t) {
  const ver = t.pkgver || t.version;
  const tip = [t.evidence, t.distro ? `сборка ${DISTRO[t.distro] || t.distro}: исправления переносятся в пакет без смены версии` : '',
    t.kev ? `эксплуатируемых уязвимостей продукта: ${t.kev}` : '',
    t.affected_n ? `затрагивают версию ${ver}: ${t.affected.map(a => a.cve + (a.note ? ` (${a.note})` : '')).join(', ')}` : '',
    t.maybe_n ? `зависят от версии пакета: ${t.maybe.map(a => `${a.cve} — ${a.note}`).join('; ')}` : ''].filter(Boolean).join(' · ');
  const cls = t.affected_n ? ' bad' : t.maybe_n || t.kev ? ' warn' : '';
  return h('span', { class: 'badge' + cls, title: tip }, t.name, ver ? ' ' + ver : '', t.distro && !t.pkgver ? ` (${DISTRO[t.distro] || t.distro})` : '',
    t.affected_n ? ` · уязвима (${t.affected_n})` : t.maybe_n ? ` · проверьте пакет (${t.maybe_n})` : t.kev ? ` · ${t.kev} KEV` : '');
}

// уязвимости плагина или темы WordPress
async function openWp(w, openV) {
  const body = h('div', {}, loading());
  modal({ title: `${w.type === 'plugin' ? 'Плагин' : 'Тема'} WordPress: ${w.name}`, size: 'lg', body });
  const d = await api(`/protection/wp/${w.type}/${encodeURIComponent(w.slug)}`, { query: { version: w.version || '' } });
  const state = (a) => a.affected === true ? badge('затрагивает', 'bad') : a.affected === false ? badge('не затрагивает', 'good')
    : h('span', { title: w.version ? 'В записи уязвимости нет затронутых версий — проверьте описание уязвимости и обновите плагин' : 'Версия плагина на сайте не определена' }, badge(w.version ? 'версии не указаны' : 'версия неизвестна', 'warn'));
  mount(body,
    h('dl', { class: 'facts' }, [['Каталог', h('code', {}, w.slug)], ['Версия на сайте', w.version || 'не определена'], ['Как определена', w.evidence || '—']]
      .map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])),
    !w.version ? h('div', { class: 'alert warn mt' }, 'Версия не определена — уязвимости показаны все. Включите «Углублённо: проверять типовые адреса приложений»: версия будет взята из readme.txt плагина.') : null,
    d.rows.length ? table([
      { title: 'Уязвимость', render: (a) => h('span', {}, a.cve ? h('a', { href: '#', onclick: (e) => { e.preventDefault(); openV(a.cve); } }, a.cve) : '—', ' ', a.title) },
      { title: 'CVSS', num: true, render: (a) => a.cvss ? a.cvss.toFixed(1) : '—' },
      { title: 'Исправлено в', render: (a) => a.patched || '—' },
      { title: 'Эксплойт', render: (a) => a.kev ? badge('эксплуатируется', 'bad') : a.exploit ? badge('публичный', 'warn') : '—' },
      { title: 'Ваша версия', render: state },
    ], d.rows) : empty('Известных уязвимостей нет', d.wordfence ? 'по базе Wordfence и шаблонам nuclei' : 'Без ключа Wordfence известны только уязвимости с публичными эксплойтами', null, 'shield'));
}

export async function techCard(onFilter, openV = () => {}) {
  const box = h('div', {}, loading());
  const draw = (d) => {
    const rows = d.sites || [];
    mount(box, rows.length ? table([
      { title: 'Сайт', render: (r) => h('span', {}, h('b', {}, r.name), r.ts ? h('div', { class: 'small muted' }, fmtAgo(r.ts)) : null) },
      { title: 'Технологии', render: (r) => r.error ? h('span', { class: 'bad-text small' }, 'нет ответа: ' + r.error)
        : r.skipped ? h('span', { class: 'muted small' }, r.skipped)
          : r.tech.length ? h('div', {},
            h('div', { class: 'row', style: { gap: '4px', flexWrap: 'wrap' } }, r.tech.map(techBadge)),
            (r.wp || []).length ? h('div', { class: 'row mt-s', style: { gap: '4px', flexWrap: 'wrap', alignItems: 'center' } },
              h('span', { class: 'small muted' }, 'WordPress:'),
              r.wp.map(w => h('button', { class: 'badge badge-btn' + (w.affected_n ? ' bad' : w.maybe_n ? ' warn' : ''), type: 'button',
                title: `${w.type === 'plugin' ? 'плагин' : 'тема'} ${w.slug}${w.version ? ' ' + w.version : ', версия не определена'} · ${w.evidence}${w.known ? ` · известных уязвимостей: ${w.known}` : ''}`,
                onclick: () => openWp(w, openV) }, w.type === 'theme' ? 'тема ' : '', w.name, w.version ? ' ' + w.version : '',
                w.affected_n ? ` · уязвим (${w.affected_n})` : w.maybe_n ? (w.version ? ` · проверьте (${w.maybe_n})` : ` · ${w.maybe_n} уязв., версия?`) : ''))) : null)
            : h('span', { class: 'muted small' }, 'не определены') },
      { title: 'Эксплуатируемых уязвимостей', num: true, render: (r) => { const n = r.tech.reduce((a, t) => a + (t.kev || 0), 0); return n ? h('b', {}, fmtInt(n)) : '0'; } },
      { title: 'Затрагивают ваши версии', num: true, render: (r) => { const n = r.tech.reduce((a, t) => a + (t.affected_n || 0), 0) + (r.wp || []).reduce((a, w) => a + (w.affected_n || 0), 0); return n ? h('b', { class: 'bad-text' }, fmtInt(n)) : '0'; } },
      { title: 'Новых за 90 дней', num: true, render: (r) => { const n = r.tech.reduce((a, t) => a + (t.recent || 0), 0); return n ? h('b', { class: 'bad-text' }, fmtInt(n)) : '0'; } },
    ], rows) : empty('Технологии ещё не определены', 'Панель определяет их раз в сутки; можно сейчас — кнопкой «Определить»', null, 'search'));
  };
  api('/protection/tech').then(draw).catch((e) => mount(box, h('div', { class: 'bad-text' }, e.message)));
  return card('Технологии ваших сайтов', box, { flush: true, cls: 'mt', sub: 'что работает за nginx — по главной странице с бэкенда, плагины и темы WordPress; сборки Ubuntu и Debian сверяются с данными дистрибутива',
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
    h('div', { class: 'alert info mb' }, 'Серверы с Nginx Manager делятся блокировками IP и доверенными адресами: блокировка (ручная или автоматическая) на любом из них за минуту действует на всех. Настройки защиты от атак отправляются при сохранении или кнопкой, сайты с сертификатами — кнопкой «Перенести сайты». Добавьте серверы в «Настройки панели → Другие серверы» на каждом сервере — с API-токеном того сервера.'),
    h('div', { class: 'grid g3 mb' },
      kpi('Этот сервер', d.me.name, { foot: `идентификатор ${d.me.id}` }),
      kpi('Серверов', fmtInt(d.peers.length), { foot: `включено: ${d.peers.filter(p => p.enabled).length}` }),
      kpi('Получено блокировок', fmtInt(d.incoming.reduce((a, x) => a + (x.active || 0), 0)), { foot: `от ${d.incoming.length} серверов` })),
    card('Отправка', d.peers.length ? table([
      { title: 'Сервер', render: (p) => h('span', {}, h('b', {}, p.name), p.enabled ? '' : [' ', badge('выкл')], h('div', { class: 'small muted' }, p.url)) },
      { title: 'Блокировки', render: (p) => !p.bans ? h('span', { class: 'muted small' }, 'не отправляются') : p.bans_error ? h('span', { class: 'bad-text small' }, p.bans_error)
        : p.bans_at ? h('span', { class: 'small' }, `${fmtInt(p.bans_sent || 0)} отправлено ${fmtAgo(p.bans_at)}`) : h('span', { class: 'muted small' }, 'ещё не отправлялись') },
      { title: 'Доверенные адреса', render: (p) => !p.trusted ? h('span', { class: 'muted small' }, 'не отправляются') : p.trusted_skipped ? h('span', { class: 'warning-text small' }, `не приняты: ${p.trusted_skipped}`)
        : p.trusted_old ? h('span', { class: 'warning-text small' }, 'старая версия на сервере — не применяются') : p.bans_at ? h('span', { class: 'small' }, `${fmtInt(p.trusted_sent || 0)} отправлено`) : h('span', { class: 'muted small' }, '—') },
      { title: 'Сайты', render: (p) => !p.sites ? h('span', { class: 'muted small' }, 'по кнопке') : p.sites_error ? h('span', { class: 'bad-text small', title: p.sites_error }, p.sites_error.slice(0, 90))
        : p.sites_at ? h('span', { class: 'small', title: p.sites_result ? `создано ${p.sites_result.created}, обновлено ${p.sites_result.updated}, удалено ${p.sites_result.deleted}, без изменений ${p.sites_result.unchanged}` : '' },
          `версия ${p.sites_version || '—'} — ${fmtAgo(p.sites_at)}`, h('div', { class: 'muted small' }, `${fmtInt(p.sites_sent || 0)} сайтов${p.sites_tag ? ' с меткой «' + p.sites_tag + '»' : ''}${p.sites_applied ? ', применено' : ''}`),
          p.sites_note ? h('div', { class: 'warning-text small', title: p.sites_note }, 'не применено: ' + p.sites_note.slice(0, 80)) : null)
          : h('span', { class: 'muted small' }, 'ожидает') },
      { title: 'Настройки защиты', render: (p) => !p.protection ? h('span', { class: 'muted small' }, 'вручную') : p.prot_error ? h('span', { class: 'bad-text small' }, p.prot_error)
        : p.prot_at ? h('span', { class: 'small' }, `применены ${fmtAgo(p.prot_at)}`,
          p.prot_mapped || p.prot_dropped ? h('div', { class: 'muted small', title: 'Правила, привязанные к сайтам, сопоставляются по доменам: сайт с тем же доменом на получателе' },
            `правил сайтов: перенесено ${p.prot_mapped || 0}${p.prot_dropped ? `, нет таких сайтов — ${p.prot_dropped}` : ''}`) : null)
          : h('span', { class: 'muted small' }, 'при сохранении') },
      { title: '', srTitle: 'Действия', render: (p) => can('admin') ? h('button', { class: 'btn sm', onclick: () => test(p) }, 'Проверить связь') : null },
    ], d.peers) : empty('Серверов нет', 'Добавьте их в «Настройки панели → Другие серверы»', can('admin') ? h('a', { class: 'btn primary', href: '#/settings?tab=peers' }, 'Добавить сервер') : null, 'server'),
    { flush: !!d.peers.length, actions: can('admin') && d.peers.length ? [
      h('button', { class: 'btn', onclick: () => transferDialog(d.peers.filter(p => p.enabled)) }, icon('upload'), 'Перенести сайты…'),
      d.peers.some(p => p.sites) ? h('button', { class: 'btn', title: 'Отправить сайты последней применённой версии ещё раз', onclick: () => push('sites') }, icon('refresh'), 'Синхронизировать сайты') : null,
      h('button', { class: 'btn', onclick: () => push('bans') }, icon('refresh'), 'Отправить блокировки'),
      h('button', { class: 'btn', onclick: async () => { if (await confirmDlg('Отправить настройки защиты от атак на все серверы? На каждом применится конфигурация с этими настройками (свои правила, привязанные к сайтам, и CrowdSec там останутся свои).', { ok: 'Отправить' })) push('protection'); } }, 'Отправить настройки защиты')] : null }),
    card('Получено от других серверов', d.incoming.length ? table([
      { title: 'Сервер', render: (x) => h('b', {}, x.name) },
      { title: 'Блокировок сейчас', num: true, render: (x) => fmtInt(x.active || 0) },
      { title: 'Доверенных адресов', num: true, render: (x) => d.accept_trusted ? fmtInt(x.trusted || 0) : h('span', { class: 'muted small', title: 'Приём выключен в настройках панели' }, 'не принимаются') },
      { title: 'Последняя сверка', render: (x) => h('span', { class: 'small' }, `${fmtAgo(x.at)} (+${x.added}, −${x.removed})`) },
    ], d.incoming) : empty('Пока ничего', 'Блокировки появятся, когда другой сервер отправит их сюда', null, 'server'), { flush: !!d.incoming.length, cls: 'mt' }),
    (d.mirrors || []).length ? card('Синхронизация сайтов сюда', table([
      { title: 'С сервера', render: (x) => h('b', {}, x.name) },
      { title: 'Сайтов', num: true, render: (x) => fmtInt(x.sites) },
      { title: 'Последняя синхронизация', render: (x) => h('span', { class: 'small' }, x.at ? fmtAgo(x.at) : '—') },
    ], d.mirrors), { flush: true, cls: 'mt', sub: 'эти сайты обновляются с другого сервера — менять их нужно там' }) : null,
    (d.transfers || []).length ? card('Перенесённые сюда сайты', table([
      { title: 'Когда', render: (x) => h('span', { class: 'small', title: fmtDate(x.at) }, fmtAgo(x.at)) },
      { title: 'С сервера', render: (x) => h('b', {}, x.name) },
      { title: 'Сайты', render: (x) => h('span', { class: 'small' }, `создано ${x.sites.created}, обновлено ${x.sites.updated}${x.sites.skipped ? ', пропущено ' + x.sites.skipped : ''}`) },
      { title: 'Сертификаты', render: (x) => h('span', { class: 'small' }, x.certs.created || x.certs.updated ? `новых ${x.certs.created}, обновлено ${x.certs.updated}` : '—') },
      { title: 'Применено', render: (x) => x.applied ? h('span', { class: 'good-text small' }, 'да') : h('span', { class: 'muted small' }, 'нет') },
    ], d.transfers), { flush: true, cls: 'mt', sub: 'последние 20 переносов и обновлений сертификатов' }) : null);
}

const ACTION_RU = { created: 'создан', updated: 'обновлён', skipped: 'пропущен', error: 'ошибка' };

/** Окно «Перенести сайты»: сервер, сайты, сертификаты, замена одноимённых, применение на получателе. */
export async function transferDialog(peers, preselect = []) {
  if (!peers.length) { toast('Нет включённых серверов — добавьте их в «Настройки панели → Другие серверы»', 'bad'); return; }
  const sites = await api('/sites');
  const chosen = new Set(preselect.length ? preselect : []);
  const peerSel = h('select', { id: 'nm-tr-peer' }, peers.map(p => h('option', { value: p.id }, `${p.name} — ${p.url}`)));
  const flt = h('input', { type: 'search', placeholder: 'Поиск по названию и доменам', 'aria-label': 'Поиск сайтов' });
  const listBox = h('div', { class: 'tr-list', style: { maxHeight: '300px', overflow: 'auto', border: '1px solid var(--line)', borderRadius: '8px', padding: '4px 8px' } });
  const cnt = h('span', { class: 'small muted' });
  const drawList = () => {
    const q = flt.value.trim().toLowerCase();
    const rows = sites.filter(x => !q || x.name.toLowerCase().includes(q) || x.domains.some(dm => dm.includes(q)));
    mount(listBox, rows.length ? rows.map(x => h('label', { class: 'check', style: { display: 'flex', gap: '8px', padding: '4px 0', alignItems: 'baseline' } },
      h('input', { type: 'checkbox', checked: chosen.has(x.id), onchange: (e) => { if (e.target.checked) chosen.add(x.id); else chosen.delete(x.id); mount(cnt, `выбрано: ${chosen.size}`); } }),
      h('span', {}, h('b', {}, x.name), x.enabled ? '' : h('span', { class: 'muted small' }, ' (выключен)'),
        h('div', { class: 'small muted' }, x.domains.join(', ') || '—', x.ssl ? ' · HTTPS' : '')))) : h('div', { class: 'empty' }, 'Нет сайтов'));
    mount(cnt, `выбрано: ${chosen.size}`);
  };
  flt.addEventListener('input', drawList);
  drawList();
  const opt = (label, checked, help) => {
    const cb = h('input', { type: 'checkbox', checked });
    return [h('label', { class: 'check', style: { display: 'flex', gap: '8px', alignItems: 'baseline' } }, cb, h('span', {}, label, help ? h('div', { class: 'small muted' }, help) : null)), cb];
  };
  const [certsL, certsCb] = opt('Передать сертификаты (сертификат и закрытый ключ)', true, 'На получателе — как загруженные; после продления здесь они отправятся туда автоматически');
  const [overL, overCb] = opt('Заменить сайты с теми же доменами', false, 'Иначе такие сайты пропускаются');
  const [applyL, applyCb] = opt('Применить конфигурацию на получателе', true, 'Если там нет других неприменённых изменений; иначе сайты останутся черновиком');
  const out = h('div', {});
  const btn = h('button', { class: 'btn primary', onclick: async () => {
    if (!chosen.size) { toast('Выберите сайты', 'bad'); return; }
    btn.disabled = true;
    try {
      const r = await api(`/peers/${peerSel.value}/transfer`, { method: 'POST', body: { sites: [...chosen], certs: certsCb.checked, overwrite: overCb.checked, apply: applyCb.checked } });
      const items = r.sites?.items || [];
      mount(out, h('div', { class: 'alert ' + (r.apply_error || items.some(x => x.action === 'error') ? 'warn' : 'good') + ' mt' },
        h('b', {}, `Сервер «${r.name}»: создано ${r.sites?.created || 0}, обновлено ${r.sites?.updated || 0}, пропущено ${r.sites?.skipped || 0}; сертификатов новых ${r.certs?.created || 0}, обновлено ${r.certs?.updated || 0}.`),
        r.applied ? h('div', {}, `Конфигурация применена (версия ${r.applied}).`) : r.apply_error ? h('div', {}, `Не применено: ${r.apply_error}`) : null,
        (r.certs?.errors || []).map(e => h('div', { class: 'small' }, `Сертификат: ${e}`)),
        h('ul', { class: 'small', style: { margin: '6px 0 0', paddingLeft: '18px' } }, items.map(x => h('li', {}, `${x.name} — ${ACTION_RU[x.action] || x.action}${x.notes?.length ? ': ' + x.notes.join('; ') : ''}`)))));
      toast('Сайты перенесены', 'good');
    } catch (e) { mount(out, h('div', { class: 'alert bad mt' }, e.data?.detail || e.message)); }
    btn.disabled = false;
  } }, icon('upload'), 'Перенести');
  const m = modal({ title: 'Перенести сайты на другой сервер', size: 'lg', body: h('div', { class: 'col' },
    h('p', { class: 'small muted' }, 'Сайты переносятся со всеми настройками: локации, бэкенды, защита, доступ по IP, пользователи Basic Auth. Адреса бэкендов должны быть доступны с сервера-получателя. Нужен токен администратора того сервера.'),
    h('div', { class: 'field' }, h('label', { for: 'nm-tr-peer' }, 'Сервер'), peerSel),
    h('div', { class: 'row', style: { justifyContent: 'space-between' } }, flt, cnt, h('button', { class: 'btn sm ghost', type: 'button', onclick: () => { sites.forEach(x => chosen.add(x.id)); drawList(); } }, 'Выбрать все')),
    listBox, certsL, overL, applyL, out),
  footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Закрыть'), btn] });
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
