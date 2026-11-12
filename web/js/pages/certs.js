// Сертификаты SSL/TLS: Let's Encrypt, загрузка, самоподписанные, файлы на диске.
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, confirmDlg, table, stateBadge, fmtDate, empty, loading, promptDlg } from '../ui.js';
import { model, defaults, renderFields, errorsToMap } from '../forms.js';
import { can, refreshState } from '../app.js';

export async function render(root) {
  let timer = null;
  const box = h('div', {});
  const head = h('div', {});
  async function load() {
    const r = await api('/certs');
    mount(head, !r.certbot ? h('div', { class: 'alert warn mb' }, h('b', {}, 'certbot не установлен. '), 'Выпуск Let\'s Encrypt недоступен. Установите: ',
      h('code', {}, 'apt install certbot'), ' или ', h('code', {}, 'dnf install certbot'), ' (или нажмите «Исправить» в Диагностике).') : null,
    !r.email ? h('div', { class: 'alert mb' }, 'Совет: укажите e-mail для Let\'s Encrypt в ', h('a', { href: '#/settings' }, 'настройках панели'), ' — на него придут предупреждения об истечении.') : null);
    mount(box, r.items.length ? table([
      { title: 'Сертификат', render: (c) => h('div', {}, h('b', {}, c.name), h('div', { class: 'muted small' }, c.domains.join(', ') || '—')) },
      { title: 'Тип', render: (c) => ({ letsencrypt: badge("Let's Encrypt", 'info'), upload: badge('загружен'), selfsigned: badge('самоподписанный', 'warn'), path: badge('файлы на диске') }[c.type]) },
      { title: 'Состояние', render: (c) => h('div', {}, stateBadge(c.status), c.job && c.job.state === 'running' ? h('span', { class: 'spinner', style: { marginLeft: '6px' } }) : null,
        c.last_error ? h('div', { class: 'small status-5', style: { maxWidth: '320px' } }, c.last_error) : null) },
      { title: 'Действует до', render: (c) => c.not_after ? h('div', {}, fmtDate(c.not_after, { year: true }),
        h('div', { class: 'small ' + (c.days_left < 7 ? 'status-5' : c.days_left < 21 ? 'status-4' : 'muted') }, `осталось ${Math.floor(c.days_left)} дн.`)) : '—' },
      { title: 'Издатель', render: (c) => h('span', { class: 'small muted ellipsis', style: { maxWidth: '220px', display: 'inline-block' } }, (c.issuer || '').replace(/^.*?O\s*=\s*/, '').split(',')[0]) },
      { title: 'Используется', render: (c) => c.used_by.length ? c.used_by.map(u => h('span', { class: 'tag' }, u)) : h('span', { class: 'muted small' }, 'нигде') },
      { title: '', render: (c) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        c.job ? h('button', { class: 'btn sm', onclick: () => jobLog(c) }, 'Журнал') : null,
        can('operator') && c.type !== 'upload' ? h('button', { class: 'btn sm', onclick: async () => { await api(`/certs/${c.id}/renew`, { method: 'POST' }); toast(c.type === 'letsencrypt' ? 'Продление запущено' : 'Обновлено', 'info'); load(); } },
          icon('refresh'), c.type === 'letsencrypt' ? 'Продлить' : c.type === 'selfsigned' ? 'Перевыпустить' : 'Перечитать') : null,
        can('operator') ? h('button', { class: 'btn sm danger', onclick: async () => {
          if (!await confirmDlg(`Удалить сертификат «${c.name}»?`, { danger: true, ok: 'Удалить' })) return;
          await api(`/certs/${c.id}`, { method: 'DELETE' }); toast('Удалён', 'good'); load();
        } }, icon('trash')) : null) },
    ], r.items) : empty('Сертификатов нет', 'Выпустите бесплатный сертификат Let\'s Encrypt — он будет продлеваться автоматически.',
      can('operator') ? h('button', { class: 'btn primary', onclick: () => certDialog({ onCreated: load }) }, icon('plus'), 'Добавить сертификат') : null, 'cert'));
    const running = r.items.some(c => c.status === 'pending' || (c.job && c.job.state === 'running'));
    clearTimeout(timer);
    if (running) timer = setTimeout(load, 2500);
  }
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Сертификаты'),
      h('p', {}, 'Let\'s Encrypt выпускается через HTTP-проверку (webroot): nginx отдаёт файл проверки по пути /.well-known/acme-challenge/ для любого домена. Продление — автоматически за 30 дней до истечения.')),
      h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => selfTest() }, icon('stethoscope'), 'Проверить домен'),
        can('operator') ? h('button', { class: 'btn primary', onclick: () => certDialog({ onCreated: load }) }, icon('plus'), 'Добавить сертификат') : null)),
    head, h('div', { class: 'card' }, box));
  await load();
  return () => clearTimeout(timer);
}

function jobLog(c) {
  modal({ title: `Журнал выпуска: ${c.name}`, size: 'lg', body: h('pre', { class: 'code' }, (c.job.log || []).join('\n') + (c.job.error ? `\n\nОШИБКА: ${c.job.error}` : '')) });
}

async function selfTest() {
  const d = await promptDlg('Проверка домена для Let\'s Encrypt', 'Домен', '', { placeholder: 'example.com' });
  if (!d) return;
  const body = h('div', {}, loading('Проверка DNS и доступности по HTTP…'));
  modal({ title: `Проверка ${d}`, body });
  try {
    const r = await api('/certs/selftest', { method: 'POST', body: { domain: d } });
    mount(body, h('div', { class: 'col' },
      h('div', { class: 'alert ' + (r.ok ? 'good' : r.local ? 'warn' : 'bad') }, r.ok ? '✓ Домен готов к выпуску сертификата' : (r.error || 'Проверка не пройдена')),
      h('dl', { class: 'kv' }, h('dt', {}, 'DNS'), h('dd', {}, (r.dns || []).join(', ') || '—'),
        h('dt', {}, 'Через nginx локально'), h('dd', {}, r.local ? '✓ файл проверки отдаётся' : '✗ ' + (r.local_error || 'нет')),
        h('dt', {}, 'По доменному имени'), h('dd', {}, r.remote ? '✓ доступен' : '✗ ' + (r.remote_error || 'нет')))));
  } catch (e) { mount(body, h('div', { class: 'alert bad' }, e.message)); }
}

export async function certDialog({ domains = [], onCreated } = {}) {
  const obj = defaults(model('certificate'));
  obj.domains = [...(domains || [])];
  obj.name = domains[0] || '';
  let errors = {};
  const box = h('div', {});
  const draw = () => { mount(box,
    obj.type === 'letsencrypt' ? h('div', { class: 'alert mb' }, 'Требования: домены указывают на внешний IP этого сервера (A/AAAA), порт 80 открыт снаружи, сайт с этими доменами уже применён или домен попадает в сервер по умолчанию. Wildcard (*.example.com) требует DNS-проверки — выпустите его certbot\'ом вручную и подключите как «Файлы уже на сервере».') : null,
    obj.type === 'selfsigned' ? h('div', { class: 'alert warn mb' }, 'Браузеры будут показывать предупреждение. Подходит для тестов, внутренних сервисов и как временная заглушка.') : null);
    renderFields(box, model('certificate'), obj, { root: obj, advanced: true, errors, rerender: draw, onChange: () => {} });
  };
  draw();
  const btn = h('button', { class: 'btn primary' }, 'Создать');
  const m = modal({ title: 'Новый сертификат', size: 'lg', body: box, footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), btn] });
  btn.onclick = async () => {
    btn.disabled = true;
    try {
      const r = await api('/certs', { method: 'POST', body: obj });
      m.close();
      toast(obj.type === 'letsencrypt' ? 'Выпуск запущен — это займёт до минуты' : 'Сертификат добавлен', 'good');
      refreshState();
      onCreated && onCreated(r.id);
    } catch (e) { errors = errorsToMap(e); draw(); btn.disabled = false; }
  };
}
