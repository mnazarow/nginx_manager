// Каркас приложения: вход, навигация, верхняя панель, применение конфигурации.
import { api, live, setUnauthorizedHandler, showError } from './api.js';
import { h, mount, icon, toast, modal, badge, fmtDur, diffBlock, codeBlock, loading, clear } from './ui.js';
import { setSchema } from './forms.js';
import { openPageHelp } from './help.js';

const NAV = [
  ['Мониторинг', [
    ['/', 'Дашборд', 'dash'], ['/insights', 'Анализ и подсказки', 'bulb'], ['/analytics', 'Аналитика', 'chart'], ['/requests', 'Журнал запросов', 'list'],
    ['/errors', 'Журнал ошибок', 'alert'], ['/backends', 'Бэкенды', 'server'], ['/system', 'Сервер', 'cpu']]],
  ['Конфигурация', [
    ['/sites', 'Сайты', 'sites'], ['/streams', 'TCP/UDP-потоки', 'stream'], ['/certs', 'Сертификаты', 'cert'],
    ['/bans', 'Блокировки IP', 'ban'],
    ['/global', 'Настройки nginx', 'sliders'], ['/versions', 'Версии конфигурации', 'history']]],
  ['Обслуживание', [
    ['/diagnostics', 'Диагностика', 'stethoscope'], ['/alerts', 'Оповещения', 'bell'], ['/events', 'События', 'activity']]],
  ['Администрирование', [
    ['/users', 'Пользователи', 'users', 'admin'], ['/audit', 'Аудит действий', 'shield', 'admin'],
    ['/settings', 'Настройки панели', 'gear', 'admin'], ['/backup', 'Копии и импорт', 'backup', 'admin']]],
  ['', [['/docs', 'Документация', 'book'], ['/profile', 'Мой профиль', 'user']]],
];

const PAGES = {
  '/': 'dashboard', '/analytics': 'analytics', '/requests': 'requests', '/errors': 'errors', '/backends': 'backends',
  '/system': 'system', '/sites': 'sites', '/streams': 'streams', '/certs': 'certs', '/global': 'global',
  '/versions': 'versions', '/diagnostics': 'diagnostics', '/alerts': 'alerts', '/events': 'events', '/users': 'users',
  '/audit': 'audit', '/settings': 'settings', '/backup': 'backup', '/docs': 'docs', '/profile': 'profile',
  '/bans': 'bans', '/insights': 'insights',
};

export const ctx = { state: null, schema: null, user: null, cleanup: null, route: '', params: {} };
const ROLE = { admin: 3, operator: 2, viewer: 1 };
export const can = (role) => ROLE[ctx.user?.role] >= ROLE[role];

// ---------- Тема ----------
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('nm-theme', t);
}
applyTheme(localStorage.getItem('nm-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));

// ---------- Вход ----------
function loginPage() {
  live.close();
  const root = document.getElementById('root');
  const user = h('input', { type: 'text', autocomplete: 'username', autofocus: true });
  const pass = h('input', { type: 'password', autocomplete: 'current-password' });
  const otp = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: '123456', maxlength: 8 });
  const otpField = h('div', { class: 'field hidden' }, h('label', {}, 'Код двухфакторной аутентификации'), otp);
  const err = h('div', { class: 'alert bad hidden' });
  const btn = h('button', { class: 'btn primary', type: 'submit', style: { width: '100%', height: '38px' } }, 'Войти');
  const form = h('form', { class: 'col', onsubmit: async (e) => {
    e.preventDefault(); err.classList.add('hidden'); btn.disabled = true;
    try {
      const r = await api('/auth/login', { method: 'POST', body: { username: user.value, password: pass.value, otp: otp.value }, silent: true });
      if (r.totp_required) { otpField.classList.remove('hidden'); otp.focus(); return; }
      await boot();
      if (r.must_change_password || r.require_2fa) location.hash = '#/profile';
    } catch (ex) { err.textContent = ex.message; err.classList.remove('hidden'); }
    finally { btn.disabled = false; }
  } },
  h('div', { class: 'field' }, h('label', {}, 'Пользователь'), user),
  h('div', { class: 'field' }, h('label', {}, 'Пароль'), pass), otpField, err, btn);
  mount(root, h('div', { class: 'login-wrap' }, h('div', { class: 'card login-card' },
    h('div', { class: 'brand' }, h('div', { class: 'brand-logo' }, icon('bolt')), h('div', {}, 'Nginx Manager', h('small', {}, 'Управление обратным прокси'))),
    form, h('div', { class: 'muted small mt' }, 'Забыли пароль? На сервере: ', h('code', {}, 'nmctl user passwd admin')))));
}
setUnauthorizedHandler(() => { if (ctx.user) { ctx.user = null; loginPage(); } });

// ---------- Каркас ----------
let topEls = {};
function layout() {
  const root = document.getElementById('root');
  const nav = h('nav', { class: 'nav' });
  for (const [group, items] of NAV) {
    if (group) nav.appendChild(h('div', { class: 'nav-group' }, group));
    for (const [path, label, ic, role] of items) {
      if (role && !can(role)) continue;
      nav.appendChild(h('a', { href: '#' + path, 'data-path': path }, icon(ic), label,
        path === '/diagnostics' ? h('span', { class: 'nav-badge-diag' }) : null,
        path === '/alerts' ? h('span', { class: 'nav-badge-alerts' }) : null,
        path === '/backends' ? h('span', { class: 'nav-badge-backends' }) : null,
        path === '/insights' ? h('span', { class: 'nav-badge-insights' }) : null));
    }
  }
  topEls = {
    title: h('div', { class: 'title' }), nginx: h('span', { class: 'pill' }), live: h('span', { class: 'pill', title: 'Соединение реального времени' }),
    pending: h('div', {}), alerts: h('div', {}),
  };
  const helpBtn = h('button', { class: 'btn ghost icon help-btn', title: 'Справка по этой странице (F1)', onclick: () => openPageHelp(ctx.route, ctx.params) }, '?');
  document.addEventListener('keydown', (e) => {
    if (e.key === 'F1' && ctx.user) { e.preventDefault(); openPageHelp(ctx.route, ctx.params); }
  });
  const themeBtn = h('button', { class: 'btn ghost icon', title: 'Сменить тему', onclick: () => {
    applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'); route();
  } }, icon('moon'));
  const menuBtn = h('button', { class: 'btn ghost icon menu-btn', title: 'Меню', 'aria-label': 'Меню', onclick: () => document.querySelector('.app')?.classList.toggle('nav-open') }, icon('list'));
  nav.addEventListener('click', (e) => { if (e.target.closest('a')) document.querySelector('.app')?.classList.remove('nav-open'); });
  mount(root, h('div', { class: 'app' },
    h('div', { class: 'nav-backdrop', onclick: () => document.querySelector('.app')?.classList.remove('nav-open') }),
    h('aside', { class: 'sidebar' },
      h('div', { class: 'brand' }, h('div', { class: 'brand-logo' }, icon('bolt')), h('div', {}, 'Nginx Manager', h('small', {}, 'v' + ctx.state.version))),
      nav,
      h('div', { class: 'sidebar-foot' }, h('div', {}, ctx.user.username, ' · ', ctx.user.role_label || ctx.user.role),
        h('a', { href: '#', onclick: async (e) => { e.preventDefault(); await api('/auth/logout', { method: 'POST' }); ctx.user = null; loginPage(); } }, 'Выйти'))),
    h('div', { class: 'main' },
      h('header', { class: 'topbar' }, menuBtn, topEls.title, h('span', { class: 'grow' }), topEls.alerts, topEls.pending, topEls.nginx, topEls.live, helpBtn, themeBtn),
      h('main', { class: 'content', id: 'page' }))));
  live.on('status', (ok) => drawLive(ok));
  drawLive(live.connected);
  drawTop();
}

function drawLive(ok) {
  if (!topEls.live) return;
  mount(topEls.live, h('span', { class: 'dot ' + (ok ? 'good pulse' : 'bad') }), ok ? 'онлайн' : 'нет связи');
}

export function drawTop() {
  const s = ctx.state;
  if (!s || !topEls.nginx) return;
  const n = s.nginx;
  mount(topEls.nginx, h('span', { class: 'dot ' + (n.running ? 'good' : 'bad') }), `nginx ${n.version} — ${n.running ? 'работает ' + fmtDur(n.uptime || 0) : 'остановлен'}`);
  topEls.nginx.title = n.running ? `PID ${n.pid}, воркеров ${n.workers}` : 'Nginx не запущен — откройте «Диагностику»';
  topEls.nginx.style.cursor = 'pointer';
  topEls.nginx.onclick = () => { location.hash = '#/diagnostics'; };
  const p = s.pending || {};
  if (p.error) {
    mount(topEls.pending, h('div', { class: 'apply-bar', style: { background: 'var(--critical-wash)', borderColor: 'var(--critical)', color: 'var(--critical-ink)' }, title: p.error },
      'Ошибка в настройках', h('button', { class: 'btn sm', onclick: () => toast(p.error, 'bad') }, 'Подробнее')));
  } else if (p.pending && can('operator')) {
    const n = (p.changed || []).filter(x => !x.endsWith('.keep')).length;
    mount(topEls.pending, h('div', { class: 'apply-bar' }, `Не применено: ${n} ${plural(n, 'файл', 'файла', 'файлов')}`,
      h('button', { class: 'btn sm', onclick: showPending }, 'Изменения'),
      h('button', { class: 'btn sm primary', onclick: () => applyDialog() }, icon('check'), 'Применить')));
  } else clear(topEls.pending);
  mount(topEls.alerts, s.alerts_firing ? h('a', { href: '#/alerts', class: 'badge bad', title: 'Сработавшие оповещения' }, icon('bell'), s.alerts_firing) : null);
  const d = s.diagnostics?.summary || {};
  document.querySelectorAll('.nav-badge-diag').forEach(el => mount(el, d.fail ? badge(d.fail, 'bad') : d.warn ? badge(d.warn, 'warn') : null));
  document.querySelectorAll('.nav-badge-alerts').forEach(el => mount(el, s.alerts_firing ? badge(s.alerts_firing, 'bad') : null));
  document.querySelectorAll('.nav-badge-backends').forEach(el => mount(el, s.backends_down ? badge(s.backends_down, 'bad') : null));
  const ins = s.insights || {};
  document.querySelectorAll('.nav-badge-insights').forEach(el => mount(el, ins.crit ? badge(ins.crit, 'bad') : ins.warn ? badge(ins.warn, 'warn') : null));
  document.querySelectorAll('.nav a').forEach(a => { a.classList.toggle('active', a.dataset.path === ctx.route); a.querySelector('.badge')?.classList.add('badge'); });
}

export function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return few;
  return many;
}

export async function refreshState() {
  try { ctx.state = await api('/state', { silent: true }); drawTop(); } catch { /* ignore */ }
  return ctx.state;
}

// ---------- Применение конфигурации ----------
async function showPending() {
  const body = h('div', {}, loading());
  modal({ title: 'Неприменённые изменения', size: 'xl', body, footer: [h('button', { class: 'btn primary', onclick: () => { document.querySelector('.modal-back')?.remove(); applyDialog(); } }, 'Применить…')] });
  const r = await api('/config/pending');
  mount(body, r.diff.length ? r.diff.map(d => h('div', { class: 'mb' }, h('div', { class: 'row mb', style: { marginBottom: '6px' } },
    h('code', {}, d.file), badge({ added: 'новый', removed: 'удалён', modified: 'изменён' }[d.status], d.status === 'removed' ? 'bad' : d.status === 'added' ? 'good' : 'info'),
    h('span', { class: 'muted small' }, `+${d.added} −${d.removed}`)), diffBlock(d.diff))) : h('div', { class: 'empty' }, 'Изменений нет'));
}

export async function applyDialog(defaultComment = '') {
  const comment = h('input', { type: 'text', placeholder: 'Например: добавлен сайт shop', value: defaultComment });
  const out = h('div', {});
  const btn = h('button', { class: 'btn primary' }, icon('check'), 'Проверить и применить');
  const m = modal({ title: 'Применить конфигурацию', size: 'lg', body: h('div', { class: 'col' },
    h('div', { class: 'alert' }, 'Конфигурация будет сгенерирована, проверена ', h('code', {}, 'nginx -t'),
      ' в отдельном каталоге и только после успешной проверки атомарно подключена с плавной перезагрузкой (reload) — активные соединения не обрываются. При любой ошибке остаётся предыдущая рабочая версия.'),
    h('div', { class: 'field' }, h('label', {}, 'Комментарий к версии'), comment), out),
    footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), btn] });
  setTimeout(() => comment.focus(), 50);
  const run = async () => {
    btn.disabled = true; mount(out, loading('Проверка и применение…'));
    try {
      const r = await api('/config/apply', { method: 'POST', body: { comment: comment.value }, silent: true });
      m.close();
      toast(`Версия ${r.version} применена за ${r.duration} с` + (r.warnings.length ? '\n' + r.warnings.join('\n') : ''), r.warnings.length ? 'warn' : 'good', 'Готово');
      await refreshState(); route(true);
    } catch (e) {
      btn.disabled = false;
      mount(out, applyErrorView(e));
    }
  };
  btn.onclick = run;
  comment.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
}

export function applyErrorView(e) {
  const d = e.data || {};
  return h('div', { class: 'col' },
    h('div', { class: 'alert bad' }, h('b', {}, e.message), d.site_id ? h('div', {}, 'Проблема в сайте: ', h('a', { href: `#/sites?edit=${d.site_id}` }, '#' + d.site_id)) : null),
    (d.errors || []).map(er => h('div', { class: 'card' }, h('div', { class: 'card-body' },
      h('div', { class: 'row' }, badge(er.level, er.level === 'warn' ? 'warn' : 'bad'), h('b', {}, er.message)),
      er.file ? h('div', { class: 'muted small mt-s' }, `${er.file}:${er.line}`, er.kind ? ` — ${er.kind === 'site' ? 'сайт' : 'поток'} #${er.object_id}` : '') : null,
      er.hint ? h('div', { class: 'alert warn mt-s' }, '💡 ', er.hint) : null,
      er.context ? h('pre', { class: 'code mt-s' }, er.context.map(c => h('span', { class: c.error ? 'errline' : '' }, String(c.n).padStart(4) + '  ' + c.text + '\n'))) : null))),
    d.output && !(d.errors || []).length ? h('pre', { class: 'code' }, d.output) : null);
}

// ---------- Маршрутизация ----------
async function route(keep = false) {
  const hash = location.hash.slice(1) || '/';
  const [path, qs] = hash.split('?');
  ctx.route = path; ctx.params = Object.fromEntries(new URLSearchParams(qs || ''));
  document.querySelector('.app')?.classList.remove('nav-open');
  const name = PAGES[path];
  const page = document.getElementById('page');
  if (!page) return;
  if (ctx.cleanup) { try { ctx.cleanup(); } catch { /* */ } ctx.cleanup = null; }
  live.send('live', { on: false }); live.send('errors', { on: false });
  drawTop();
  if (!name) { mount(page, h('div', { class: 'empty' }, h('h3', {}, 'Страница не найдена'))); return; }
  const navItem = NAV.flatMap(g => g[1]).find(i => i[0] === path);
  topEls.title.textContent = navItem ? navItem[1] : '';
  document.title = (navItem ? navItem[1] + ' — ' : '') + 'Nginx Manager';
  if (!keep) mount(page, loading());
  try {
    const mod = await import(`./pages/${name}.js`);
    const cleanup = await mod.render(page, ctx);
    if (typeof cleanup === 'function') ctx.cleanup = cleanup;
  } catch (e) {
    console.error(e);
    if (e.status !== 401) mount(page, h('div', { class: 'alert bad' }, 'Не удалось открыть страницу: ', e.message));
  }
}

async function boot() {
  try {
    ctx.user = await api('/auth/me', { silent: true });
  } catch { loginPage(); return; }
  [ctx.state, ctx.schema] = await Promise.all([api('/state'), api('/schema')]);
  setSchema(ctx.schema);
  layout();
  live.connect();
  window.onhashchange = () => route();
  await route();
  clearInterval(window._nmState);
  window._nmState = setInterval(refreshState, 10000);
  live.on('applied', () => refreshState());
  live.on('alert', (m) => toast(m.message, m.state === 'resolved' ? 'good' : m.severity === 'critical' ? 'bad' : 'warn', m.rule));
  live.on('health', (m) => { toast(m.message, m.state === 'down' ? 'bad' : 'good', 'Бэкенды'); refreshState(); });
  live.on('watchdog', (m) => { toast(m.ok ? 'Nginx был остановлен и запущен автоматически' : 'Nginx остановлен, запустить не удалось', m.ok ? 'warn' : 'bad', 'Сторож'); refreshState(); });
}

window.addEventListener('unhandledrejection', (e) => { if (e.reason && e.reason.status) e.preventDefault(); });
boot();

export { showError };
