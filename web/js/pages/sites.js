// Сайты: список, мастер создания, полный редактор с предпросмотром конфигурации.
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, confirmDlg, promptDlg, table, tabs, loading, codeBlock, debounce, fmtNum, fmtBps, fmtPct, fmtMs,
  fmtAgo, empty, SITE_TYPES, copyBtn, countryName } from '../ui.js';
import { model, defaults, renderFields, errorsToMap, SCHEMA } from '../forms.js';
import { ctx, can, refreshState, applyDialog, applyErrorView } from '../app.js';
import { certDialog } from './certs.js';

export async function render(root) {
  if (ctx.params.edit || ctx.params.new !== undefined) return editor(root, ctx.params.edit ? +ctx.params.edit : null);
  return list(root);
}

// =============================================================================
async function list(root) {
  const sites = await api('/sites');
  let q = '', tag = '';
  const sel = new Set();
  const box = h('div', {});
  const bar = h('div', {});
  const tags = [...new Set(sites.flatMap(s => s.tags))].sort();
  const search = h('input', { type: 'search', placeholder: 'Поиск по названию, домену, бэкенду…', oninput: (e) => { q = e.target.value.toLowerCase(); draw(); } });
  const tagSel = h('select', { onchange: (e) => { tag = e.target.value; draw(); } }, h('option', { value: '' }, 'Все метки'), tags.map(t => h('option', { value: t }, t)));
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Сайты'),
      h('p', {}, 'Виртуальные хосты nginx: домены, бэкенды, HTTPS, кэш, безопасность. Изменения сохраняются в базе и вступают в силу после «Применить».')),
      can('operator') ? h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => importDialog() }, icon('import'), 'Импорт из nginx'),
        h('button', { class: 'btn primary', onclick: () => wizard() }, icon('plus'), 'Добавить сайт')) : null),
    h('div', { class: 'toolbar' }, search, tags.length ? tagSel : null, h('span', { class: 'muted small' }, `Всего: ${sites.length}`)),
    bar, h('div', { class: 'card' }, box));

  // ---- массовые действия
  const names = () => sites.filter(s => sel.has(s.id)).map(s => s.name);
  async function bulk(action, extra = {}) {
    try {
      const r = await api('/sites/bulk', { method: 'POST', body: { ids: [...sel], action, ...extra } });
      const applied = r.applied ? ' и применено' : r.changed && !action.startsWith('maintenance') ? ' — примените конфигурацию' : '';
      toast(r.changed ? `Изменено сайтов: ${r.changed}${applied}` : 'Изменений нет — у выбранных сайтов уже так', r.changed ? 'good' : 'info');
      sel.clear(); refreshState(); render(root);
    } catch { render(root); /* ошибку уже показал api() */ }
  }
  function drawBar() {
    if (!sel.size) { mount(bar); return; }
    const selTags = [...new Set(sites.filter(s => sel.has(s.id)).flatMap(s => s.tags))].sort();
    mount(bar, h('div', { class: 'bulk-bar' },
      h('b', {}, `Выбрано: ${sel.size}`),
      h('button', { class: 'btn sm', onclick: () => bulk('enable') }, 'Включить'),
      h('button', { class: 'btn sm', onclick: () => bulk('disable') }, 'Выключить'),
      h('button', { class: 'btn sm', onclick: async () => {
        if (await confirmDlg(`Включить режим обслуживания для ${sel.size} сайт(ов)?\n${names().join(', ')}\n\nКонфигурация будет применена сразу: посетители увидят страницу «Ведутся технические работы».`, { ok: 'Включить обслуживание' })) bulk('maintenance_on');
      } }, 'Обслуживание: вкл'),
      h('button', { class: 'btn sm', onclick: () => bulk('maintenance_off') }, 'Обслуживание: выкл'),
      h('button', { class: 'btn sm', onclick: async () => { const t = await promptDlg('Добавить метку', `Метка для ${sel.size} сайт(ов)`, '', { placeholder: 'прод, клиент-А, staging…' }); if (t && t.trim()) bulk('tag_add', { tag: t.trim() }); } }, 'Добавить метку'),
      selTags.length ? h('select', { class: 'sm', onchange: (e) => { if (e.target.value) bulk('tag_remove', { tag: e.target.value }); } },
        h('option', { value: '' }, 'Убрать метку…'), selTags.map(t => h('option', { value: t }, t))) : null,
      h('button', { class: 'btn sm danger', onclick: async () => {
        if (await confirmDlg(`Удалить ${sel.size} сайт(ов)?\n${names().join(', ')}\n\nКонфигурация будет удалена после применения. Версии конфигурации позволяют откатиться.`, { danger: true, ok: 'Удалить' })) bulk('delete');
      } }, icon('trash'), 'Удалить'),
      h('button', { class: 'btn sm ghost', onclick: () => { sel.clear(); draw(); } }, 'Снять выделение')));
  }

  function draw() {
    const rows = sites.filter(s => (!tag || s.tags.includes(tag)) &&
      (!q || (s.name + ' ' + s.domains.join(' ') + ' ' + s.backends.join(' ')).toLowerCase().includes(q)));
    drawBar();
    const allOn = rows.length > 0 && rows.every(s => sel.has(s.id));
    const pick = can('operator') ? [{ width: '32px', title: h('input', { type: 'checkbox', checked: allOn, title: 'Выбрать все показанные', 'aria-label': 'Выбрать все',
      onchange: (e) => { rows.forEach(s => e.target.checked ? sel.add(s.id) : sel.delete(s.id)); draw(); } }),
    render: (s) => h('input', { type: 'checkbox', checked: sel.has(s.id), 'aria-label': `Выбрать ${s.name}`,
      onchange: (e) => { e.target.checked ? sel.add(s.id) : sel.delete(s.id); draw(); } }) }] : [];
    mount(box, sites.length ? table([
      ...pick,
      { title: 'Сайт', render: (s) => h('div', {}, h('b', {}, s.name), ' ', s.tags.map(t => h('span', { class: 'tag' }, t)),
        h('div', { class: 'muted small' }, s.domains.slice(0, 4).join(', ') + (s.domains.length > 4 ? ` +${s.domains.length - 4}` : ''))) },
      { title: 'Тип', render: (s) => SITE_TYPES[s.type] || s.type },
      { title: 'Состояние', render: (s) => h('div', { class: 'row', style: { gap: '4px' } },
        s.enabled ? badge('включён', 'good') : badge('выключен'), s.ssl ? badge('HTTPS', 'info') : badge('HTTP', 'outline'),
        s.maintenance ? badge('обслуживание', 'warn') : null, s.cache ? badge('кэш', 'outline') : null,
        s.geo && s.geo.mode !== 'off' ? h('span', { title: (s.geo.mode === 'deny' ? 'Запрещены: ' : 'Только: ') + s.geo.countries.map(c => `${c} ${countryName(c)}`).join(', ') },
          badge(s.geo.mode === 'deny' ? 'запрет стран' : 'только страны', 'outline')) : null) },
      { title: 'Бэкенды', render: (s) => s.type !== 'proxy' ? h('span', { class: 'muted' }, '—') : h('div', { class: 'col', style: { gap: '2px' } },
        (s.health.length ? s.health : s.backends.map(b => ({ addr: b, state: 'unknown' }))).slice(0, 4).map(t => h('div', { class: 'row nowrap small', style: { gap: '6px' }, title: t.error || '' },
          h('span', { class: 'dot ' + (t.state === 'up' ? 'good' : t.state === 'down' ? 'bad' : '') }), h('code', {}, t.addr),
          t.state === 'up' ? h('span', { class: 'muted' }, fmtMs(t.latency_ms)) : t.state === 'down' ? h('span', { class: 'status-5' }, 'недоступен') : null))) },
      { title: 'Запр./с', num: true, render: (s) => fmtNum(s.rps, 1) },
      { title: 'Трафик', num: true, render: (s) => fmtBps(s.bps) },
      { title: '5xx', num: true, render: (s) => fmtPct(s.err5_pct) },
      { title: 'Изменён', render: (s) => h('span', { class: 'muted small' }, fmtAgo(s.updated_at)) },
      { title: '', render: (s) => h('div', { class: 'row nowrap', style: { gap: '4px', justifyContent: 'flex-end' } },
        can('operator') ? h('button', { class: 'btn sm', title: s.enabled ? 'Выключить' : 'Включить', onclick: async () => {
          await api(`/sites/${s.id}/toggle`, { method: 'POST' }); toast(`Сайт ${s.enabled ? 'выключен' : 'включён'} — не забудьте применить`, 'info'); refreshState(); render(root);
        } }, icon('power')) : null,
        h('button', { class: 'btn sm', title: 'Конфигурация', onclick: () => showConfig(s) }, icon('file')),
        can('operator') ? h('button', { class: 'btn sm', title: 'Копировать', onclick: async () => { const r = await api(`/sites/${s.id}/clone`, { method: 'POST' }); location.hash = `#/sites?edit=${r.id}`; } }, icon('copy')) : null,
        can('operator') ? h('button', { class: 'btn sm danger', title: 'Удалить', onclick: async () => {
          if (!await confirmDlg(`Удалить сайт «${s.name}»?\nКонфигурация будет удалена после применения.`, { danger: true, ok: 'Удалить' })) return;
          await api(`/sites/${s.id}`, { method: 'DELETE' }); toast('Сайт удалён — примените конфигурацию', 'info'); refreshState(); render(root);
        } }, icon('trash')) : null) },
    ], rows, { onRow: (s) => { location.hash = `#/sites?edit=${s.id}`; }, empty: 'Ничего не найдено', rowClass: (s) => sel.has(s.id) ? 'selected' : '' })
      : empty('Сайтов пока нет', 'Добавьте первый сайт — укажите домен и адрес приложения, остальное настроится по умолчанию.',
        can('operator') ? h('button', { class: 'btn primary', onclick: () => wizard() }, icon('plus'), 'Добавить сайт') : null, 'sites'));
  }
  draw();
}

async function showConfig(s) {
  const r = await api(`/sites/${s.id}/config`);
  modal({ title: `Конфигурация: ${s.name}`, size: 'xl', body: h('div', {}, h('div', { class: 'row mb' }, h('code', {}, r.file), copyBtn(r.config, 'Копировать')), codeBlock(r.config)) });
}

// =============================================================================
//  Мастер создания
// =============================================================================
const PRESETS = {
  generic: { label: 'Обычный сайт / приложение', data: {} },
  wordpress: { label: 'WordPress / PHP-сайт', data: {
    cache: { enabled: true, bypass_cookies: ['PHPSESSID'], bypass_cookie_pattern: 'wordpress_logged_in|wp-postpass|comment_author|woocommerce_items_in_cart|wordpress_sec' },
    performance: { client_max_body_size: '64m', static_expires: '7d' },
    locations: [{ path: '/xmlrpc.php', match: 'exact', action: 'deny' }, { path: '/wp-login.php', match: 'exact', action: 'proxy', rate_limit: 'custom', rate: '10r/m', burst: 5 }] } },
  node: { label: 'Node.js / WebSocket-приложение', data: { proxy: { websocket: true, read_timeout: '300s' }, balancing: 'ip_hash' } },
  api: { label: 'REST API', data: { balancing: 'least_conn', security: { rate_limit: true, rate: '50r/s', burst: 100, x_frame_options: 'DENY' },
    proxy: { next_upstream: ['error', 'timeout', 'http_502', 'http_503', 'http_504'] }, error_pages: { enabled: false } } },
  static: { label: 'Статический сайт / SPA', data: { type: 'static', static: { root: '/var/www/site', spa: true, expires: '1h' } } },
  redirect: { label: 'Перенаправление домена', data: { type: 'redirect' } },
};

function deepMerge(a, b) {
  for (const [k, v] of Object.entries(b)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && a[k] && typeof a[k] === 'object') deepMerge(a[k], v);
    else a[k] = structuredClone(v);
  }
  return a;
}

async function wizard() {
  const certs = (await api('/certs')).items;
  const st = { preset: 'generic', name: '', domains: '', backends: '127.0.0.1:8080', https: 'none', cert: '', redirect: 'https://' };
  const body = h('div', {});
  const draw = () => {
    const p = PRESETS[st.preset];
    const type = p.data.type || 'proxy';
    mount(body, h('div', { class: 'col', style: { gap: '14px' } },
      h('div', { class: 'field' }, h('label', {}, 'Шаблон'), h('div', { class: 'chips' }, Object.entries(PRESETS).map(([k, v]) =>
        h('span', { class: 'chip' + (st.preset === k ? ' on' : ''), onclick: () => { st.preset = k; draw(); } }, v.label)))),
      h('div', { class: 'form-grid' },
        h('div', { class: 'field' }, h('label', {}, 'Название'), h('input', { type: 'text', value: st.name, placeholder: 'Мой сайт', oninput: (e) => { st.name = e.target.value; } })),
        h('div', { class: 'field' }, h('label', {}, 'Домены'), h('input', { type: 'text', value: st.domains, placeholder: 'example.com www.example.com', oninput: (e) => { st.domains = e.target.value; } }),
          h('div', { class: 'help' }, 'Через пробел. DNS доменов должен указывать на внешний IP этого сервера.'))),
      type === 'proxy' ? h('div', { class: 'field' }, h('label', {}, 'Адреса приложения (бэкенды)'),
        h('textarea', { class: 'code', rows: 3, oninput: (e) => { st.backends = e.target.value; } }, st.backends),
        h('div', { class: 'help' }, 'По одному на строку: IP:порт или имя:порт. Например 10.0.0.5:8080 или https://10.0.0.6:8443')) : null,
      type === 'redirect' ? h('div', { class: 'field' }, h('label', {}, 'Перенаправлять на'), h('input', { type: 'text', value: st.redirect, oninput: (e) => { st.redirect = e.target.value; } })) : null,
      type === 'static' ? h('div', { class: 'help' }, 'Каталог с файлами укажете в редакторе (по умолчанию /var/www/site).') : null,
      h('div', { class: 'field' }, h('label', {}, 'HTTPS'), h('select', { onchange: (e) => { st.https = e.target.value; draw(); } },
        [['none', 'Пока без HTTPS'], ['le', 'Выпустить бесплатный сертификат сейчас (ACME, HTTP-проверка)'], ['existing', 'Выбрать имеющийся сертификат']].map(([v, l]) => h('option', { value: v, selected: st.https === v }, l)))),
      st.https === 'existing' ? h('div', { class: 'field' }, h('label', {}, 'Сертификат'), h('select', { onchange: (e) => { st.cert = e.target.value; } },
        h('option', { value: '' }, '—'), certs.map(c => h('option', { value: c.id, selected: String(c.id) === st.cert }, `${c.name} (${c.domains.join(', ')})`)))) : null,
      st.https === 'le' ? h('div', { class: 'alert' }, 'Сайт будет создан и применён сразу (для проверки домена центр сертификации обращается к нему по HTTP), затем запустится выпуск сертификата. HTTPS включится автоматически после выпуска.',
        /(^|\s)\*\./.test(st.domains) ? h('div', { class: 'status-5 mt' }, 'Wildcard (*.example.com) так не выпустить: нужна DNS-проверка. Выпустите сертификат на странице «Сертификаты» и выберите «Выбрать имеющийся сертификат».') : null) : null));
  };
  draw();
  const go = async (openEditor) => {
    const p = PRESETS[st.preset];
    const site = deepMerge(defaults(model('site')), structuredClone(p.data));
    site.name = st.name.trim() || st.domains.trim().split(/\s+/)[0] || 'Новый сайт';
    site.domains = st.domains.split(/[\s,]+/).filter(Boolean);
    if ((site.type || 'proxy') === 'proxy') {
      site.backends = st.backends.split('\n').map(s => s.trim()).filter(Boolean).map(line => {
        let scheme = 'http';
        const m0 = line.match(/^(https?):\/\//); if (m0) { scheme = m0[1]; line = line.slice(m0[0].length); site.backend_scheme = scheme; }
        const m = line.match(/^\[?([^\]]+?)\]?(?::(\d+))?$/);
        return { ...defaults(model('backend')), address: m ? m[1] : line, port: m && m[2] ? +m[2] : (scheme === 'https' ? 443 : 80) };
      });
    }
    if (site.type === 'redirect') site.redirect.url = st.redirect;
    site.locations = (site.locations || []).map(l => ({ ...defaults(model('location')), ...l, id: Math.random().toString(16).slice(2, 10) }));
    if (st.https === 'existing' && st.cert) { site.ssl.enabled = true; site.ssl.certificate_id = +st.cert; }
    if (st.https === 'le' && site.domains.some(d => d.startsWith('*.'))) {
      toast('Wildcard-домен требует DNS-проверки: выпустите сертификат на странице «Сертификаты» и выберите его здесь.', 'bad');
      return;
    }
    try {
      const r = await api('/sites', { method: 'POST', body: site, query: { apply: st.https === 'le' ? 1 : '' } });
      m.close();
      if (st.https === 'le') {
        // регулярные выражения и «.example.com» в сертификат не попадают
        const certDomains = site.domains.filter(d => !d.startsWith('~') && !d.startsWith('.'));
        const c = await api('/certs', { method: 'POST', body: { type: 'letsencrypt', domains: certDomains, name: certDomains[0] } });
        site.ssl.enabled = true; site.ssl.certificate_id = c.id;
        await api(`/sites/${r.id}`, { method: 'PUT', body: site });
        toast('Сайт создан. Выпуск сертификата запущен — следите за ходом на странице «Сертификаты». После выпуска примените конфигурацию.', 'info', 'Сертификат', 9000);
      }
      refreshState();
      if (openEditor) location.hash = `#/sites?edit=${r.id}`;
      else { toast('Сайт создан', 'good'); applyDialog(`Добавлен сайт «${site.name}»`); location.hash = '#/sites'; }
    } catch (e) { /* toast уже показан */ }
  };
  const m = modal({ title: 'Новый сайт', size: 'lg', body,
    footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn', onclick: () => go(true) }, 'Создать и настроить подробно'),
      h('button', { class: 'btn primary', onclick: () => go(false) }, icon('check'), 'Создать и применить')] });
}

// =============================================================================
//  Редактор
// =============================================================================
async function editor(root, id) {
  const [siteRes, certs, glob, extIps] = await Promise.all([
    id ? api(`/sites/${id}`) : Promise.resolve(null), api('/certs'), api('/settings/global'), Promise.resolve([])]);
  const fields = model('site');
  const site = siteRes ? siteRes.data : defaults(fields);
  if (!siteRes) { site.name = ''; site.backends = [{ ...defaults(model('backend')), address: '127.0.0.1', port: 8080 }]; }
  let tab = ctx.params.tab || 'main';
  let advanced = localStorage.getItem('nm-adv') === '1';
  let dirty = false, errors = {};
  const formBox = h('div', {});
  const preview = h('div', {});
  const status = h('div', { class: 'row' });
  const fctx = {
    root: site, get advanced() { return advanced; }, certs: certs.items, cacheZones: glob.cache_zones.map(z => z.name), ips: extIps,
    onChange: () => { dirty = true; mount(status, badge('есть несохранённые изменения', 'warn')); refreshPreview(); },
    rerender: () => drawForm(),
    onNewCert: (cb) => certDialog({ domains: site.domains, onCreated: async (cid) => { fctx.certs = (await api('/certs')).items; cb(cid); } }),
  };
  Object.defineProperty(fctx, 'errors', { get: () => errors });

  const tabCounts = () => ({ locations: (site.locations || []).length || '', backends: (site.backends || []).length || '' });
  const tabBar = h('div', {});
  const drawTabs = () => {
    const counts = tabCounts();
    const items = SCHEMA.tabs.site.filter(t => !(site.type !== 'proxy' && ['backends', 'proxy', 'cache'].includes(t.id)))
      .map(t => ({ ...t, badge: counts[t.id] || '' }));
    mount(tabBar, tabs(items, tab, (t) => { tab = t; drawForm(); history.replaceState(null, '', `#/sites?${id ? 'edit=' + id : 'new'}&tab=${t}`); }));
  };
  function drawForm() {
    drawTabs();
    const y = window.scrollY;
    mount(formBox);
    renderFields(formBox, fields, site, { ...fctx, tab, advanced, errors });
    if (tab === 'advanced' || tab === 'main') { /* без доп. содержимого */ }
    window.scrollTo(0, y);
  }

  const refreshPreview = debounce(async () => {
    try {
      const r = await api('/sites/preview', { method: 'POST', body: site, query: { sid: id || 0 }, silent: true });
      errors = {};
      mount(preview, r.warnings.length ? h('div', { class: 'alert warn mb' }, r.warnings.join('\n')) : null, codeBlock(r.config, { maxHeight: '70vh' }));
    } catch (e) {
      errors = errorsToMap(e);
      mount(preview, h('div', { class: 'alert bad' }, h('b', {}, 'Проверьте поля: '), h('div', { style: { whiteSpace: 'pre-wrap' } }, (e.data?.errors || []).map(x => `• ${x.loc ? x.loc + ': ' : ''}${x.msg}`).join('\n') || e.message)));
    }
  }, 500);

  const save = async (apply) => {
    try {
      const r = id ? await api(`/sites/${id}`, { method: 'PUT', body: site }) : await api('/sites', { method: 'POST', body: site });
      dirty = false;
      mount(status, badge('сохранено', 'good'));
      errors = {};
      if (!id) { id = r.id; history.replaceState(null, '', `#/sites?edit=${id}&tab=${tab}`); }
      await refreshState();
      if (apply) applyDialog(`Сайт «${site.name}»`);
      else toast('Сохранено. Изменения вступят в силу после применения конфигурации.', 'good');
      drawForm();
    } catch (e) { errors = errorsToMap(e); drawForm(); }
  };
  const test = async () => {
    const out = h('div', {}, loading('nginx -t…'));
    modal({ title: 'Проверка конфигурации', size: 'lg', body: out });
    try {
      const r = await api('/sites/preview', { method: 'POST', body: site, query: { sid: id || 0, test: 1 } });
      mount(out, r.test.ok ? h('div', { class: 'alert good' }, '✓ Конфигурация корректна. ', h('span', { class: 'muted' }, 'Проверка выполнена в отдельном каталоге, работающий nginx не затронут.'))
        : applyErrorView({ message: 'nginx -t обнаружил ошибки', data: { errors: r.test.errors, output: r.test.output } }),
      h('pre', { class: 'code mt' }, r.test.output));
    } catch (e) { mount(out, applyErrorView(e)); }
  };

  const ro = !can('operator');
  mount(root,
    h('div', { class: 'page-head' },
      h('div', {}, h('div', { class: 'small muted' }, h('a', { href: '#/sites' }, '← Сайты')), h('h1', {}, id ? (site.name || 'Сайт') : 'Новый сайт'),
        h('p', {}, id ? (site.domains || []).join(', ') : 'Заполните основные параметры; всё остальное имеет безопасные значения по умолчанию.')),
      h('div', { class: 'row' }, status,
        h('label', { class: 'switch small', title: 'Показать редко используемые параметры' }, h('input', { type: 'checkbox', checked: advanced, onchange: (e) => { advanced = e.target.checked; localStorage.setItem('nm-adv', advanced ? '1' : '0'); drawForm(); } }), h('span', { class: 'track' }), 'Расширенные'),
        ro ? null : h('button', { class: 'btn', onclick: test, title: 'Проверить черновик через nginx -t, ничего не сохраняя' }, icon('check'), 'Проверить'),
        ro ? null : h('button', { class: 'btn', onclick: () => save(false) }, 'Сохранить'),
        ro ? null : h('button', { class: 'btn primary', onclick: () => save(true) }, 'Сохранить и применить'))),
    h('div', { class: 'grid split' },
      h('div', { class: 'card' }, h('div', { class: 'card-body' }, tabBar, formBox)),
      h('div', { class: 'card sticky-preview' }, h('div', { class: 'card-head' }, h('h2', {}, 'Итоговая конфигурация nginx'), h('span', { class: 'muted small' }, 'обновляется при вводе')),
        h('div', { class: 'card-body' }, preview))));
  drawForm();
  refreshPreview();
  const before = (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } };
  window.addEventListener('beforeunload', before);
  return () => window.removeEventListener('beforeunload', before);
}

// =============================================================================
//  Импорт существующих конфигураций
// =============================================================================
async function importDialog() {
  const body = h('div', {}, loading('Чтение исходной конфигурации nginx (nginx -T)…'));
  const m = modal({ title: 'Импорт существующих сайтов из nginx', size: 'xl', body });
  let res;
  try { res = await api('/import/nginx/preview', { method: 'POST', body: { path: '' }, silent: true }); }
  catch (e) {
    mount(body, h('div', { class: 'alert bad' }, e.message), h('div', { class: 'field mt' }, h('label', {}, 'Путь к другому nginx.conf'),
      h('div', { class: 'row nowrap' }, h('input', { type: 'text', id: 'imp-path', placeholder: '/etc/nginx/nginx.conf.nm-orig' }),
        h('button', { class: 'btn', onclick: async () => { m.close(); } }, 'Закрыть'))));
    return;
  }
  const selected = new Set(res.sites.map((s, i) => i).filter(i => res.sites[i]._valid !== false));
  mount(body, h('div', { class: 'col' },
    h('div', { class: 'alert' }, 'Найдены server-блоки исходной конфигурации (сохранена при установке в nginx.conf.nm-orig). Сайты будут созданы ', h('b', {}, 'выключенными'),
      ' — проверьте их и включите. Нераспознанные директивы перенесены в «Свои директивы».'),
    res.warnings.length ? h('div', { class: 'alert warn' }, res.warnings.join('\n')) : null,
    table([
      { title: '', render: (s) => { const i = res.sites.indexOf(s); return h('input', { type: 'checkbox', checked: selected.has(i), onchange: (e) => e.target.checked ? selected.add(i) : selected.delete(i) }); } },
      { title: 'Сайт', render: (s) => h('div', {}, h('b', {}, s.name), h('div', { class: 'muted small' }, s.domains.join(', '))) },
      { title: 'Тип', render: (s) => SITE_TYPES[s.type] },
      { title: 'Бэкенды', render: (s) => (s.backends || []).map(b => `${b.address}:${b.port}`).join(', ') || '—' },
      { title: 'HTTPS', render: (s) => s.ssl ? badge('да', 'info') : '—' },
      { title: 'Локаций', num: true, render: (s) => s.locations.length },
      { title: 'Примечание', render: (s) => h('span', { class: 'small ' + (s._valid === false ? 'status-5' : 'muted') }, s._error || s.notes || '') },
    ], res.sites, { empty: 'Сайтов для импорта не найдено' })));
  m.el.querySelector('.modal-foot')?.remove();
  m.el.appendChild(h('div', { class: 'modal-foot' }, h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'),
    h('button', { class: 'btn primary', onclick: async () => {
      const sites = res.sites.filter((s, i) => selected.has(i));
      const r = await api('/import/nginx/commit', { method: 'POST', body: { sites, certificates: res.certificates } });
      m.close();
      toast(`Импортировано сайтов: ${r.created.length}` + (r.errors.length ? `\nОшибки:\n${r.errors.join('\n')}` : ''), r.errors.length ? 'warn' : 'good');
      location.hash = '#/sites'; window.dispatchEvent(new HashChangeEvent('hashchange'));
    } }, 'Импортировать выбранные')));
}
