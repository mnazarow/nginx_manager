// Аудит действий пользователей.
import { api } from '../api.js';
import { h, mount, table, fmtDate, debounce } from '../ui.js';

const A = {
  login: 'вход', login_failed: 'неудачный вход', password_changed: 'смена пароля', site_created: 'создан сайт', site_updated: 'изменён сайт',
  site_deleted: 'удалён сайт', site_enabled: 'сайт включён', site_disabled: 'сайт выключен', site_cloned: 'копия сайта', config_applied: 'применена конфигурация',
  config_rollback: 'откат конфигурации', global_settings_updated: 'глобальные настройки', panel_settings_updated: 'настройки панели', cert_created: 'сертификат',
  cert_deleted: 'удалён сертификат', cert_renew: 'продление сертификата', user_created: 'создан пользователь', user_updated: 'изменён пользователь',
  user_deleted: 'удалён пользователь', diag_fix: 'исправление из диагностики', maintenance_on: 'обслуживание включено', maintenance_off: 'обслуживание выключено',
  '2fa_enabled': '2FA включена', '2fa_disabled': '2FA выключена', token_created: 'создан API-токен', config_imported: 'импорт настроек', config_exported: 'экспорт настроек',
};

export async function render(root) {
  let q = '';
  const box = h('div', {});
  const load = async () => {
    const list = await api('/audit', { query: { limit: 500, q } });
    mount(box, h('div', { class: 'card' }, table([
      { title: 'Время', render: (r) => h('span', { class: 'nowrap small' }, fmtDate(r.ts, { sec: true, year: true })) },
      { title: 'Пользователь', render: (r) => h('b', {}, r.username || '—') }, { title: 'IP', render: (r) => h('span', { class: 'mono small' }, r.ip || '') },
      { title: 'Действие', render: (r) => A[r.action] || r.action }, { title: 'Объект', render: (r) => r.target || '' },
      { title: 'Детали', render: (r) => h('span', { class: 'mono small muted' }, r.details || '') },
    ], list, { cls: 'compact', empty: 'Записей нет' })));
  };
  mount(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Аудит действий'), h('p', {}, 'Кто, когда и что изменил. Хранится 365 дней.'))),
    h('div', { class: 'toolbar' }, h('input', { type: 'search', placeholder: 'Пользователь, действие, объект…', oninput: debounce((e) => { q = e.target.value; load(); }, 400) })), box);
  await load();
}
