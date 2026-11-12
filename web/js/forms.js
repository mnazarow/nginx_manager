// Генерация форм по схеме моделей сервера (/api/schema): поля, подсказки, условия видимости, вложенные списки.
import { h, mount, icon, badge, pickFile, toast, countryName } from './ui.js';
import { openHelp } from './help.js';

export let SCHEMA = null;
export function setSchema(s) { SCHEMA = s; }
export function model(name) { return SCHEMA.models[name]; }

export function defaults(fields) {
  const o = {};
  for (const f of fields) o[f.key] = structuredClone(f.default ?? null);
  return o;
}

function visible(f, obj, ctx) {
  if (f.ui === 'hidden') return false;
  if (f.adv && !ctx.advanced) return false;
  if (!f.show) return true;
  for (const [k, vals] of Object.entries(f.show)) {
    const v = k.startsWith('^') ? ctx.root[k.slice(1)] : obj[k];
    if (!vals.includes(v)) return false;
  }
  return true;
}

function tipText(f) {
  return [f.help, f.doc, f.rec ? 'Рекомендация: ' + f.rec : '', f.example ? 'Пример: ' + f.example : '',
    f.directive ? 'Директива nginx: ' + f.directive : '', f.doc_page ? 'Нажмите — подробнее в документации' : ''].filter(Boolean).join('\n\n');
}

/** Значок «i»: при наведении — краткая подсказка, по щелчку — раздел справочника с описанием параметра. */
function infoIcon(f) {
  const tip = tipText(f);
  if (!tip) return null;
  return h('span', { class: 'info-i' + (f.doc_page ? ' link' : ''), title: tip, role: f.doc_page ? 'button' : null, tabindex: f.doc_page ? 0 : null,
    onclick: f.doc_page ? (e) => { e.preventDefault(); e.stopPropagation(); openHelp(f.doc_page, f.anchor); } : null,
    onkeydown: f.doc_page ? (e) => { if (e.key === 'Enter') { e.preventDefault(); openHelp(f.doc_page, f.anchor); } } : null }, 'i');
}

function labelEl(f) {
  return h('label', {}, f.label, f.unit ? h('span', { class: 'muted', style: { fontWeight: 400 } }, `(${f.unit})`) : null,
    infoIcon(f),
    f.directive ? h('span', { class: 'directive' }, f.directive.length > 28 ? '' : f.directive) : null);
}

/**
 * Отрисовать поля модели в контейнер.
 * ctx: {root, advanced, onChange, rerender, certs, cacheZones, sites, channels, ips, tab, errors, path}
 */
export function renderFields(container, fields, obj, ctx, path = '') {
  const grid = h('div', { class: 'form-grid' });
  const blocks = [];
  for (const f of fields) {
    if (ctx.tab && path === '' && f.tab && f.tab !== ctx.tab) continue;
    if (!visible(f, obj, ctx)) continue;
    const p = path ? `${path}.${f.key}` : f.key;
    if (f.type === 'object') {
      if (obj[f.key] == null) obj[f.key] = {};
      const fs = h('fieldset', { class: 'group' }, h('legend', {}, f.label));
      renderFields(fs, f.fields, obj[f.key], ctx, p);
      if (f.doc) fs.insertBefore(h('div', { class: 'help mb', style: { fontSize: '12.5px', color: 'var(--muted)' } }, f.doc), fs.children[1]);
      blocks.push(fs);
      continue;
    }
    if (f.type === 'array' && f.ui === 'locations') { blocks.push(locationsEditor(f, obj, ctx, p)); continue; }
    if (f.type === 'array') { blocks.push(field(f, arrayTable(f, obj, ctx, p), true, ctx, p)); continue; }
    const wide = ['code', 'textarea', 'lines', 'pemfile', 'countries'].includes(f.ui) || f.type === 'multiselect';
    const w = widget(f, obj, ctx, p);
    const el = field(f, w, wide && !['tags'].includes(f.ui), ctx, p);
    grid.appendChild(el);
  }
  if (grid.children.length) container.appendChild(grid);
  blocks.forEach(b => { b.style.marginTop = '16px'; container.appendChild(b); });
  return container;
}

function field(f, w, wide, ctx, p) {
  const err = ctx.errors && ctx.errors[p];
  return h('div', { class: 'field' + (wide ? ' wide' : ''), 'data-path': p },
    f.type === 'bool' ? null : labelEl(f), w,
    f.help && f.type !== 'bool' ? h('div', { class: 'help' }, f.help) : null,
    err ? h('div', { class: 'err' }, err) : null);
}

/** Выбор стран: выбранные — метками, добавление поиском по названию или коду, быстрые группы. */
function countriesInput(f, obj, set, invalid) {
  const all = (SCHEMA.countries || []).map(c => ({ c, n: countryName(c) })).sort((a, b) => a.n.localeCompare(b.n, 'ru'));
  const cur = () => obj[f.key] || [];
  const chips = h('div', { class: 'chips' });
  const list = h('div', { class: 'cc-list', role: 'listbox', hidden: true });
  const input = h('input', { type: 'text', class: invalid, placeholder: 'Название или код страны, например «Германия» или DE',
    autocomplete: 'off', spellcheck: false, 'aria-label': 'Добавить страну' });
  let items = [], sel = 0;
  const update = (arr) => { set(arr); drawChips(); drawList(); };
  const add = (c) => { if (!cur().includes(c)) update([...cur(), c]); input.value = ''; drawList(); input.focus(); };
  const drawChips = () => mount(chips, cur().length
    ? cur().map(c => h('span', { class: 'chip on', title: 'Убрать', onclick: () => update(cur().filter(x => x !== c)) },
      h('b', {}, c), ' ', countryName(c), ' ×'))
    : h('span', { class: 'muted small' }, 'Страны не выбраны'));
  const drawList = () => {
    const q = input.value.trim().toLowerCase();
    // сначала точный код, затем названия, начинающиеся с запроса, затем содержащие его
    const rank = (x) => x.c.toLowerCase() === q ? 0 : x.n.toLowerCase().startsWith(q) ? 1 : x.c.toLowerCase().startsWith(q) ? 2 : 3;
    items = q ? all.filter(x => !cur().includes(x.c) && (x.c.toLowerCase().startsWith(q) || x.n.toLowerCase().includes(q)))
      .sort((a, b) => rank(a) - rank(b)).slice(0, 8) : [];
    sel = Math.min(sel, Math.max(0, items.length - 1));
    list.hidden = !items.length;
    mount(list, items.map((x, i) => h('div', { class: 'cc-item' + (i === sel ? ' on' : ''), role: 'option',
      onmousedown: (e) => { e.preventDefault(); add(x.c); } }, h('b', {}, x.c), ' ', x.n)));
  };
  input.addEventListener('input', () => { sel = 0; drawList(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); sel = (sel + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % Math.max(1, items.length); drawList(); }
    else if (e.key === 'Enter') { e.preventDefault(); if (items[sel]) add(items[sel].c); }
    else if (e.key === 'Escape') { list.hidden = true; }
    else if (e.key === 'Backspace' && !input.value && cur().length) update(cur().slice(0, -1));
  });
  input.addEventListener('blur', () => setTimeout(() => { list.hidden = true; }, 150));
  const groups = SCHEMA.country_groups || {};
  drawChips();
  return h('div', { class: 'col cc-input' }, chips, h('div', { class: 'cc-search' }, input, list),
    h('div', { class: 'row' },
      groups.eu ? h('button', { class: 'btn sm', type: 'button', onclick: () => update([...new Set([...cur(), ...groups.eu])]) }, 'Добавить Евросоюз (27)') : null,
      cur().length ? h('button', { class: 'btn sm ghost', type: 'button', onclick: () => update([]) }, 'Очистить') : null));
}

function changed(ctx, rerender) {
  ctx.onChange && ctx.onChange();
  if (rerender && ctx.rerender) ctx.rerender();
}

function widget(f, obj, ctx, p) {
  const v = obj[f.key];
  const set = (val, rer = false) => { obj[f.key] = val; changed(ctx, rer); };
  const invalid = ctx.errors && ctx.errors[p] ? ' invalid' : '';
  switch (f.type) {
    case 'bool': {
      const inp = h('input', { type: 'checkbox', checked: !!v, onchange: (e) => set(e.target.checked, true) });
      return h('div', {}, h('label', { class: 'switch' }, inp, h('span', { class: 'track' }), f.label, infoIcon(f)),
        f.help ? h('div', { class: 'help', style: { marginLeft: '44px' } }, f.help) : null);
    }
    case 'int': case 'float': {
      if (f.ui === 'certificate') return certSelect(f, obj, ctx);
      const inp = h('input', { type: 'number', value: v ?? '', min: f.min, max: f.max, step: f.type === 'float' ? 'any' : 1, class: invalid,
        placeholder: f.ph || '', oninput: (e) => { const s = e.target.value; set(s === '' ? (f.nullable ? null : f.default) : (f.type === 'int' ? parseInt(s, 10) : parseFloat(s))); } });
      return inp;
    }
    case 'select': {
      if (f.nullable && f.ui === 'tristate') return tristate(f, obj, ctx);
      const sel = h('select', { class: invalid, onchange: (e) => set(f.options[+e.target.value], true) },
        f.options.map((o, i) => h('option', { value: i, selected: o === v }, (f.labels && f.labels[String(o)]) || String(o))));
      return sel;
    }
    case 'multiselect': {
      const cur = new Set(v || []);
      const wrap = h('div', { class: 'chips' });
      const draw = () => mount(wrap, f.options.map(o => h('span', { class: 'chip' + (cur.has(o) ? ' on' : ''), title: (f.labels && f.labels[o]) || '',
        onclick: () => { cur.has(o) ? cur.delete(o) : cur.add(o); obj[f.key] = f.options.filter(x => cur.has(x)); draw(); changed(ctx); } }, String(o))));
      draw();
      return wrap;
    }
    case 'intlist': {
      if (f.ui === 'channels') {
        const cur = new Set(v || []);
        const wrap = h('div', { class: 'chips' });
        const list = ctx.channels || [];
        if (!list.length) return h('div', { class: 'help' }, 'Нет каналов — добавьте канал уведомлений на вкладке «Каналы».');
        const draw = () => mount(wrap, list.map(c => h('span', { class: 'chip' + (cur.has(c.id) ? ' on' : ''),
          onclick: () => { cur.has(c.id) ? cur.delete(c.id) : cur.add(c.id); obj[f.key] = [...cur]; draw(); changed(ctx); } }, c.data.name)));
        draw();
        return wrap;
      }
      return h('input', { type: 'text', value: (v || []).join(', '), oninput: (e) => set(e.target.value.split(/[\s,]+/).filter(Boolean).map(Number)) });
    }
    case 'list': {
      if (f.ui === 'countries') return countriesInput(f, obj, set, invalid);
      if (f.ui === 'tags') {
        return h('input', { type: 'text', value: (v || []).join(', '), placeholder: 'метка1, метка2',
          oninput: (e) => set(e.target.value.split(',').map(s => s.trim()).filter(Boolean)) });
      }
      const ta = h('textarea', { class: 'code' + invalid, rows: Math.min(10, Math.max(3, (v || []).length + 1)), placeholder: f.ph || '',
        oninput: (e) => set(e.target.value.split('\n').map(s => s.trim()).filter(Boolean)) }, (v || []).join('\n'));
      if (f.key === 'real_ip_from') {
        return h('div', { class: 'col' }, ta, h('div', { class: 'row' },
          h('button', { class: 'btn sm', type: 'button', onclick: () => {
            const cur = new Set(obj[f.key] || []); (SCHEMA.cloudflare_ips || []).forEach(x => cur.add(x));
            obj[f.key] = [...cur]; ta.value = obj[f.key].join('\n'); changed(ctx); toast('Добавлены диапазоны Cloudflare', 'good');
          } }, 'Добавить диапазоны Cloudflare'),
          h('button', { class: 'btn sm', type: 'button', onclick: () => {
            const cur = new Set(obj[f.key] || []); ['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].forEach(x => cur.add(x));
            obj[f.key] = [...cur]; ta.value = obj[f.key].join('\n'); changed(ctx);
          } }, 'Добавить частные сети')));
      }
      return ta;
    }
    default: {
      if (f.ui === 'cachezone') {
        const zones = ctx.cacheZones || ['default'];
        return h('select', { onchange: (e) => set(e.target.value) }, zones.map(z => h('option', { value: z, selected: z === v }, z)));
      }
      if (f.ui === 'site') {
        return h('select', { onchange: (e) => set(e.target.value) }, h('option', { value: '*', selected: v === '*' }, '* — все сайты'),
          (ctx.sites || []).map(s => h('option', { value: String(s.id), selected: String(s.id) === v }, s.name)));
      }
      if (f.ui === 'code' || f.ui === 'textarea') {
        return h('textarea', { class: (f.ui === 'code' ? 'code' : '') + invalid, rows: f.ui === 'code' ? 6 : 3, placeholder: f.ph || (f.ui === 'code' ? '# директивы nginx' : ''),
          oninput: (e) => set(e.target.value), spellcheck: false }, v || '');
      }
      if (f.ui === 'pemfile') {
        const ta = h('textarea', { class: 'code', rows: 6, placeholder: '-----BEGIN ...-----', oninput: (e) => set(e.target.value), spellcheck: false }, v || '');
        return h('div', { class: 'col' }, ta, h('div', {}, h('button', { class: 'btn sm', type: 'button', onclick: async () => {
          const file = await pickFile('.pem,.crt,.key,.cer,.txt'); if (file) { ta.value = file.text; set(file.text); }
        } }, icon('upload'), 'Загрузить из файла')));
      }
      const attrs = { type: f.ui === 'password' ? 'password' : 'text', value: v ?? '', placeholder: f.ph || '', class: invalid,
        oninput: (e) => set(e.target.value), autocomplete: f.ui === 'password' ? 'new-password' : 'off', spellcheck: false };
      if (f.ui === 'listenip' && ctx.ips) {
        const id = 'dl-' + Math.random().toString(36).slice(2);
        return h('div', {}, h('input', { ...attrs, list: id, placeholder: 'все адреса' }),
          h('datalist', { id }, ctx.ips.map(ip => h('option', { value: ip }))));
      }
      return h('input', attrs);
    }
  }
}

function tristate(f, obj, ctx) {
  const v = obj[f.key];
  const opts = [[null, 'Как у сайта'], [true, 'Да'], [false, 'Нет']];
  return h('select', { onchange: (e) => { obj[f.key] = opts[+e.target.value][0]; changed(ctx); } },
    opts.map(([val, lbl], i) => h('option', { value: i, selected: val === v }, lbl)));
}

function certSelect(f, obj, ctx) {
  const v = obj[f.key];
  const certs = ctx.certs || [];
  const sel = h('select', { onchange: (e) => { obj[f.key] = e.target.value ? +e.target.value : null; changed(ctx); } },
    h('option', { value: '' }, '— выберите сертификат —'),
    certs.map(c => h('option', { value: c.id, selected: c.id === v },
      `${c.name} — ${(c.domains || []).slice(0, 3).join(', ')}${c.status !== 'valid' ? ' [' + c.status + ']' : c.days_left != null ? ` (${Math.floor(c.days_left)} дн.)` : ''}`)));
  return h('div', { class: 'row nowrap' }, sel, ctx.onNewCert ? h('button', { class: 'btn', type: 'button', title: 'Выпустить новый',
    onclick: () => ctx.onNewCert((id) => { obj[f.key] = id; changed(ctx, true); }) }, icon('plus')) : null);
}

function arrayTable(f, obj, ctx, p) {
  if (!Array.isArray(obj[f.key])) obj[f.key] = [];
  const arr = obj[f.key];
  const cols = f.fields.filter(c => c.ui !== 'hidden' && (!c.adv || ctx.advanced));
  const wrap = h('div', {});
  const draw = () => {
    const rows = arr.map((item, i) => h('tr', {}, cols.map(c => {
      const cp = `${p}.${i}.${c.key}`;
      let w;
      if (c.type === 'bool') {
        w = h('label', { class: 'switch', title: c.help || c.label }, h('input', { type: 'checkbox', checked: !!item[c.key], onchange: (e) => { item[c.key] = e.target.checked; changed(ctx); } }), h('span', { class: 'track' }));
      } else if (c.type === 'select') {
        w = h('select', { onchange: (e) => { item[c.key] = c.options[+e.target.value]; changed(ctx); } }, c.options.map((o, j) => h('option', { value: j, selected: o === item[c.key] }, (c.labels && c.labels[String(o)]) || String(o))));
      } else if (c.type === 'int' || c.type === 'float') {
        w = h('input', { type: 'number', value: item[c.key] ?? '', min: c.min, max: c.max, class: ctx.errors && ctx.errors[cp] ? 'invalid' : '',
          oninput: (e) => { const s = e.target.value; item[c.key] = s === '' ? (c.nullable ? null : c.default) : Number(s); changed(ctx); } });
      } else {
        w = h('input', { type: c.ui === 'password' ? 'password' : 'text', value: item[c.key] ?? '', placeholder: c.ph || '',
          class: ctx.errors && ctx.errors[cp] ? 'invalid' : '', autocomplete: 'new-password', spellcheck: false,
          oninput: (e) => { item[c.key] = e.target.value; changed(ctx); } });
      }
      return h('td', { title: ctx.errors && ctx.errors[cp] || '' }, w);
    }), h('td', { class: 'ctl' },
      h('button', { class: 'btn sm icon ghost', type: 'button', title: 'Выше', disabled: i === 0, onclick: () => { [arr[i - 1], arr[i]] = [arr[i], arr[i - 1]]; draw(); changed(ctx); } }, '↑'),
      h('button', { class: 'btn sm icon ghost', type: 'button', title: 'Удалить', onclick: () => { arr.splice(i, 1); draw(); changed(ctx); } }, icon('trash')))));
    mount(wrap,
      arr.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'arr-table' },
        h('thead', {}, h('tr', {}, cols.map(c => h('th', { title: tipText(c) }, c.label)), h('th', {}))), h('tbody', {}, rows)))
        : h('div', { class: 'help', style: { padding: '6px 0' } }, 'Список пуст'),
      h('div', { class: 'mt-s' }, h('button', { class: 'btn sm', type: 'button', onclick: () => { arr.push(defaults(f.fields)); draw(); changed(ctx); } }, icon('plus'), 'Добавить')));
  };
  draw();
  return wrap;
}

const MATCH_SYM = { prefix: '', exact: '= ', prefix_priority: '^~ ', regex: '~ ', regex_ci: '~* ' };
const ACTION_LBL = { proxy: 'прокси', redirect: 'редирект', return: 'ответ', static: 'файлы', deny: 'запрет' };

function locationsEditor(f, obj, ctx, p) {
  if (!Array.isArray(obj[f.key])) obj[f.key] = [];
  const arr = obj[f.key];
  const wrap = h('div', {});
  const open = ctx._openLocs || (ctx._openLocs = new Set());
  const draw = () => {
    mount(wrap,
      h('div', { class: 'help mb' }, f.doc || ''),
      arr.map((loc, i) => {
        const body = h('div', {});
        const isOpen = open.has(loc.id);
        if (isOpen) {
          const sub = { ...ctx, root: ctx.root, rerender: () => { draw(); }, tab: null };
          renderFields(body, f.fields, loc, sub, `${p}.${i}`);
        }
        return h('div', { class: 'arr-card' },
          h('div', { class: 'arr-card-head' },
            h('label', { class: 'switch', title: 'Включена' }, h('input', { type: 'checkbox', checked: loc.enabled !== false, onchange: (e) => { loc.enabled = e.target.checked; changed(ctx); } }), h('span', { class: 'track' })),
            h('span', { class: 'ttl' }, 'location ' + (MATCH_SYM[loc.match] || '') + (loc.path || '?')),
            badge(ACTION_LBL[loc.action] || loc.action, 'info'),
            loc.action === 'proxy' && !loc.use_site_backends ? badge((loc.backends || []).map(b => `${b.address}:${b.port}`).join(', ') || 'нет бэкендов') : null,
            h('span', { class: 'grow' }),
            h('button', { class: 'btn sm', type: 'button', onclick: () => { isOpen ? open.delete(loc.id) : open.add(loc.id); draw(); } }, isOpen ? 'Свернуть' : 'Настроить'),
            h('button', { class: 'btn sm icon ghost', type: 'button', title: 'Выше', disabled: i === 0, onclick: () => { [arr[i - 1], arr[i]] = [arr[i], arr[i - 1]]; draw(); changed(ctx); } }, '↑'),
            h('button', { class: 'btn sm icon ghost', type: 'button', title: 'Удалить', onclick: () => { arr.splice(i, 1); draw(); changed(ctx); } }, icon('trash'))),
          body);
      }),
      h('div', { class: 'row' },
        h('button', { class: 'btn', type: 'button', onclick: () => { const d = defaults(f.fields); d.id = Math.random().toString(16).slice(2, 10); arr.push(d); open.add(d.id); draw(); changed(ctx); } }, icon('plus'), 'Добавить локацию'),
        h('span', { class: 'help' }, 'Шаблоны:'),
        ...LOC_TEMPLATES.map(t => h('button', { class: 'btn sm', type: 'button', onclick: () => {
          const d = { ...defaults(f.fields), ...structuredClone(t.data) }; d.id = Math.random().toString(16).slice(2, 10); arr.push(d); open.add(d.id); draw(); changed(ctx);
        } }, t.label))));
  };
  draw();
  return h('div', { class: 'field wide' }, draw && wrap);
}

const LOC_TEMPLATES = [
  { label: 'API на другой сервер', data: { path: '/api/', action: 'proxy', use_site_backends: false, backends: [{ address: '127.0.0.1', port: 8081, weight: 1, max_fails: 3, fail_timeout: '30s', backup: false, down: false, max_conns: 0, comment: '' }], proxy_path: '/' } },
  { label: 'WebSocket', data: { path: '/ws', action: 'proxy', websocket: true, read_timeout: '3600s', buffering: false } },
  { label: 'Админка по IP', data: { path: '/admin', action: 'proxy', allow: ['203.0.113.0/24'] } },
  { label: 'Логин: 5 запросов/мин', data: { path: '/login', match: 'exact', action: 'proxy', rate_limit: 'custom', rate: '5r/m', burst: 5 } },
  { label: 'Статика с диска', data: { path: '/static/', action: 'static', static_root: '/var/www/static', static_expires: '30d' } },
  { label: 'robots.txt', data: { path: '/robots.txt', match: 'exact', action: 'return', return_body: 'User-agent: *\nDisallow:', return_type: 'text/plain' } },
  { label: 'Запрет *.php', data: { path: '\\.php$', match: 'regex_ci', action: 'deny' } },
];

export function errorsToMap(err) {
  const m = {};
  for (const e of (err?.data?.errors || [])) if (e.loc) m[e.loc] = e.msg;
  return m;
}
