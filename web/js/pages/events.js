// Журнал событий системы (применения, сторож, бэкенды, сертификаты, резервные копии).
import { api } from '../api.js';
import { h, mount, badge, table, fmtDate, segmented } from '../ui.js';

export async function render(root) {
  let level = '';
  const box = h('div', {});
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'События'), h('p', {}, 'Что происходило с сервисом: применения конфигурации, автоматический перезапуск nginx, смена состояния бэкендов, выпуск сертификатов, резервные копии.'))),
    h('div', { class: 'toolbar' }, segmented([['', 'Все'], ['error', 'Ошибки'], ['warning', 'Предупреждения'], ['info', 'Информация']], '', (v) => { level = v; load(); })),
    box);
  async function load() {
    const list = await api('/events', { query: { limit: 500, level } });
    mount(box, h('div', { class: 'card' }, table([
      { title: 'Время', render: (e) => h('span', { class: 'nowrap small' }, fmtDate(e.ts, { sec: true })) },
      { title: 'Уровень', render: (e) => badge(e.level, e.level === 'error' ? 'bad' : e.level === 'warning' ? 'warn' : 'info') },
      { title: 'Источник', render: (e) => h('span', { class: 'small' }, e.source) },
      { title: 'Сообщение', render: (e) => h('div', { class: 'small', style: { whiteSpace: 'pre-wrap' } }, e.message) },
    ], list, { empty: 'Событий нет', cls: 'compact' })));
  }
  await load();
}
