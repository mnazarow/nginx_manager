// Пользователи панели и роли.
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, confirmDlg, table, fmtAgo, fmtDate } from '../ui.js';
import { ctx } from '../app.js';

const ROLES = [['admin', 'Администратор — полный доступ'], ['operator', 'Оператор — сайты, сертификаты, применение'], ['viewer', 'Наблюдатель — только просмотр']];

export async function render(root) {
  const list = await api('/users');
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Пользователи'),
      h('p', {}, 'Роли: администратор (всё, включая пользователей и настройки панели), оператор (сайты, потоки, сертификаты, применение конфигурации), наблюдатель (только просмотр статистики и настроек).')),
      h('button', { class: 'btn primary', onclick: () => create() }, icon('plus'), 'Добавить пользователя')),
    h('div', { class: 'card' }, table([
      { title: 'Пользователь', render: (u) => h('div', {}, h('b', {}, u.username), u.id === ctx.user.id ? badge('это вы', 'info') : null) },
      { title: 'Роль', render: (u) => h('select', { style: { width: 'auto' }, onchange: async (e) => { await api(`/users/${u.id}`, { method: 'PUT', body: { role: e.target.value } }); toast('Роль изменена', 'good'); render(root); } },
        ROLES.map(([r, l]) => h('option', { value: r, selected: r === u.role }, l.split(' — ')[0]))) },
      { title: '2FA', render: (u) => u.totp_enabled ? badge('включена', 'good') : badge('нет') },
      { title: 'Состояние', render: (u) => u.disabled ? badge('заблокирован', 'bad') : u.must_change_password ? badge('временный пароль', 'warn') : badge('активен', 'good') },
      { title: 'Последний вход', render: (u) => h('span', { class: 'small muted' }, u.last_login ? fmtAgo(u.last_login) : 'не входил') },
      { title: 'Создан', render: (u) => h('span', { class: 'small muted' }, fmtDate(u.created_at, { year: true })) },
      { title: '', render: (u) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        h('button', { class: 'btn sm', onclick: () => resetPw(u) }, icon('key'), 'Пароль'),
        u.totp_enabled ? h('button', { class: 'btn sm', onclick: async () => { if (await confirmDlg(`Отключить 2FA у ${u.username}?`)) { await api(`/users/${u.id}/reset-2fa`, { method: 'POST' }); render(root); } } }, 'Сброс 2FA') : null,
        u.id !== ctx.user.id ? h('button', { class: 'btn sm', onclick: async () => { await api(`/users/${u.id}`, { method: 'PUT', body: { disabled: !u.disabled } }); render(root); } }, u.disabled ? 'Разблокировать' : 'Заблокировать') : null,
        u.id !== ctx.user.id ? h('button', { class: 'btn sm danger', onclick: async () => { if (await confirmDlg(`Удалить пользователя ${u.username}?`, { danger: true, ok: 'Удалить' })) { await api(`/users/${u.id}`, { method: 'DELETE' }); render(root); } } }, icon('trash')) : null) },
    ], list)));

  function create() {
    const name = h('input', { type: 'text', autocomplete: 'off' });
    const pw = h('input', { type: 'text', value: genPw(), autocomplete: 'off' });
    const role = h('select', {}, ROLES.map(([r, l]) => h('option', { value: r, selected: r === 'viewer' }, l)));
    const m = modal({ title: 'Новый пользователь', body: h('div', { class: 'col' },
      h('div', { class: 'field' }, h('label', {}, 'Имя пользователя'), name), h('div', { class: 'field' }, h('label', {}, 'Временный пароль'), pw,
        h('div', { class: 'help' }, 'Пользователь должен будет сменить его при первом входе.')), h('div', { class: 'field' }, h('label', {}, 'Роль'), role)),
    footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn primary', onclick: async () => {
      await api('/users', { method: 'POST', body: { username: name.value, password: pw.value, role: role.value } });
      m.close(); toast(`Пользователь создан. Передайте ему пароль: ${pw.value}`, 'good', '', 12000); render(root);
    } }, 'Создать')] });
  }
  function resetPw(u) {
    const pw = h('input', { type: 'text', value: genPw() });
    const m = modal({ title: `Новый пароль для ${u.username}`, body: h('div', { class: 'field' }, h('label', {}, 'Временный пароль'), pw, h('div', { class: 'help' }, 'Все сессии пользователя будут завершены.')),
      footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn primary', onclick: async () => {
        await api(`/users/${u.id}`, { method: 'PUT', body: { password: pw.value } }); m.close(); toast('Пароль изменён', 'good');
      } }, 'Сохранить')] });
  }
}

export function genPw() {
  const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789', arr = new Uint32Array(14);
  crypto.getRandomValues(arr);
  return [...arr].map(x => a[x % a.length]).join('') + '!7';
}
