# 14. Консоль nmctl и REST API

## nmctl

Утилита для администрирования на сервере (работает напрямую с базой и nginx, не требует входа в панель).

| Команда | Описание |
|---|---|
| `nmctl status` | Версия, состояние сервиса и nginx, версия конфигурации, неприменённые изменения, число сайтов. |
| `nmctl apply [-m "комментарий"]` | Применить конфигурацию из базы (с проверкой и откатом). Ошибки — с файлом, строкой и подсказкой. |
| `nmctl test` | `nginx -t` текущей конфигурации. |
| `nmctl diag [-p]` | Полная диагностика в терминале (`-p` — только проблемы). Код возврата 1 при ошибках. |
| `nmctl sites` | Список сайтов. |
| `nmctl versions [--limit N]` | История применений. |
| `nmctl rollback ID` | Откат к версии. |
| `nmctl user list` | Пользователи. |
| `nmctl user add ИМЯ --role admin\|operator\|viewer [--password П]` | Создать пользователя. |
| `nmctl user passwd ИМЯ [--password П]` | Сменить пароль (и разблокировать). |
| `nmctl user reset-2fa ИМЯ` | Отключить 2FA (потерян телефон). |
| `nmctl user disable\|enable\|delete ИМЯ` | Блокировка, разблокировка, удаление. |
| `nmctl user role ИМЯ --role R` | Сменить роль. |
| `nmctl allowlist show\|clear` | Показать / снять ограничение доступа к панели по IP. |
| `nmctl backup` | Резервная копия БД и экспорт настроек в `/var/lib/nginx-manager/backups`. |
| `nmctl export [--users] > файл.json` | Экспорт настроек. |
| `nmctl import файл.json [--mode replace\|merge]` | Импорт настроек (перед импортом — резервная копия). |

Примеры:

```bash
# Забыли пароль администратора
nmctl user passwd admin

# Проверка в мониторинге (Zabbix/Nagios): ненулевой код при проблемах
nmctl diag -p > /tmp/nm-diag.txt || cat /tmp/nm-diag.txt

# Перенос настроек на другой сервер
nmctl export --users > nm.json && scp nm.json new-server:
ssh new-server 'nmctl import nm.json && nmctl apply -m "перенос"'
```

## REST API

Все функции панели доступны через HTTP API (`/api/…`, JSON). Интерактивная документация OpenAPI (Swagger UI) —
`http://сервер:8088/api/docs-ui`, схема — `/api/openapi.json`.

### Аутентификация

Создайте API-токен в профиле и передавайте его заголовком:

```bash
TOKEN=nm_xxxxxxxx
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8088/api/sites
```

Браузерная сессия (cookie) тоже работает, но изменяющие запросы требуют заголовок `X-NM-CSRF: 1`.

### Основные методы

| Метод и путь | Назначение |
|---|---|
| `GET /api/state` | Сводное состояние: nginx, неприменённые изменения, диагностика, оповещения. |
| `GET /api/schema` | Описание всех моделей и полей (для генерации форм). |
| `GET/POST /api/sites`, `GET/PUT/DELETE /api/sites/{id}` | Сайты. `?apply=1` — применить сразу. |
| `POST /api/sites/{id}/toggle` | Включить/выключить. |
| `POST /api/sites/{id}/maintenance` `{"enabled": true}` | Режим обслуживания (применяется сразу). |
| `POST /api/sites/preview?sid=ID&test=1` | Сгенерировать конфигурацию черновика и проверить `nginx -t`. |
| `GET/POST /api/streams`, `PUT/DELETE /api/streams/{id}` | Потоки. |
| `GET /api/certs`, `POST /api/certs`, `POST /api/certs/{id}/renew`, `DELETE /api/certs/{id}` | Сертификаты. |
| `POST /api/certs/selftest` `{"domain": "…"}` | Проверка домена для Let's Encrypt. |
| `GET /api/config/pending` | Разница неприменённых изменений (unified diff). |
| `POST /api/config/apply` `{"comment": "…"}` | Применить. Ошибка — HTTP 409 с разбором. |
| `GET /api/bans` | Блокировки IP, подозрительные адреса, статистика ([17](17-bans.md)). |
| `POST /api/bans` `{"nets": ["203.0.113.7"], "minutes": 1440, "reason": "…"}` | Заблокировать (`minutes: null` — бессрочно). |
| `DELETE /api/bans/{id}`, `POST /api/bans/clear` `{"source": "auto"}` | Разблокировать один адрес / снять все автоматические. |
| `GET /api/insights?from=&to=&site=` | Встроенный анализ за период: находки с причинами, действиями и данными ([18](18-insights.md)). |
| `GET /api/insights/catalog`, `PUT /api/insights/thresholds` | Справочник показателей и сценариев; свои пороги `{"thresholds": {"p95": {"warn": 2000, "crit": 5000}}}`. |
| `GET /api/reports/preview?period=day`, `POST /api/reports/send` | Предпросмотр и отправка регулярного отчёта. |
| `GET /api/alerts/silences`, `POST /api/alerts/silences` `{"minutes": 120, "starts_at": null, "rule_ids": [], "reason": "…"}`, `DELETE /api/alerts/silences/{id}` | Тишина оповещений на время работ ([11](11-alerts.md#тишина-на-время-работ)). |
| `GET /metrics` | Метрики Prometheus (вне `/api`; токен или IP из списка, см. [09](09-monitoring.md#метрики-prometheus)). |
| `GET /api/config/versions`, `GET /api/config/versions/{id}`, `…/diff`, `POST …/rollback` | Версии. |
| `GET/PUT /api/settings/global`, `GET/PUT /api/settings/panel` | Настройки. |
| `POST /api/nginx/{reload\|restart\|start\|stop\|reopen}` | Управление nginx. |
| `GET /api/stats/realtime?seconds=300&site=*` | Посекундные ряды из памяти. |
| `GET /api/stats/timeseries?from=&to=&site=` | История (минуты/часы). |
| `GET /api/stats/summary?from=&to=&site=` | Сводка за период: коды, перцентили, распределения, ошибки. |
| `GET /api/stats/top?kind=uri\|ip\|referer\|ua\|host\|upstream\|e4xx\|e5xx\|slow\|browser\|os\|device\|country` | Топы. |
| `GET /api/stats/sites`, `/api/stats/system`, `/api/stats/streams` | Сравнение сайтов, ресурсы, потоки. |
| `GET /api/requests?site=&status=5xx&ip=&uri=&min_rt=&start=&end=&limit=&offset=` | Поиск по журналу запросов. |
| `GET /api/errors?level=&category=&q=` | Журнал ошибок с категориями. |
| `GET /api/health`, `POST /api/health/check` | Состояние бэкендов, проверка сейчас. |
| `GET /api/diagnostics`, `POST /api/diagnostics/run`, `POST /api/diagnostics/fix` | Диагностика. |
| `GET/POST/PUT/DELETE /api/alerts/rules`, `/api/alerts/channels`, `GET /api/alerts/events` | Оповещения. |
| `GET/POST/PUT/DELETE /api/users`, `GET /api/audit`, `GET /api/events` | Администрирование. |
| `GET /api/backup/export`, `POST /api/backup/import`, `POST /api/backup/create` | Копии. |
| `GET /healthz` | Проверка живости сервиса (без аутентификации). |

### Примеры

```bash
API=http://127.0.0.1:8088/api; H="Authorization: Bearer $TOKEN"

# Создать сайт и сразу применить
curl -s -H "$H" -H 'Content-Type: application/json' -X POST "$API/sites?apply=1" -d '{
  "name": "Новый сервис", "domains": ["svc.example.com"],
  "backends": [{"address": "10.0.0.40", "port": 8080}],
  "health": {"path": "/health"}}'

# Включить режим обслуживания на время деплоя
curl -s -H "$H" -H 'Content-Type: application/json' -X POST "$API/sites/3/maintenance" -d '{"enabled": true}'
./deploy.sh
curl -s -H "$H" -H 'Content-Type: application/json' -X POST "$API/sites/3/maintenance" -d '{"enabled": false}'

# Вывести бэкенд из балансировки (down) и применить
curl -s -H "$H" "$API/sites/3" | jq '.data | .backends[1].down = true' \
 | curl -s -H "$H" -H 'Content-Type: application/json' -X PUT "$API/sites/3?apply=1" -d @-

# Доля 5xx за последний час
curl -s -H "$H" "$API/stats/summary?from=$(( $(date +%s) - 3600 ))" | jq .err5_pct

# Последние 20 ошибок 502
curl -s -H "$H" "$API/requests?status=502&limit=20" | jq '.items[] | {ts, host, uri, upstream}'

# Заблокировать адреса из файла на сутки (например, из списка вашей SIEM)
jq -Rn '{nets: [inputs], minutes: 1440, reason: "SIEM"}' bad-ips.txt | \
  curl -s -H "$H" -H 'Content-Type: application/json' -X POST "$API/bans" -d @-

# Тишина оповещений на время выкладки (в начале скрипта деплоя)
SID=$(curl -s -H "$H" -H 'Content-Type: application/json' -X POST "$API/alerts/silences" \
  -d '{"minutes": 30, "reason": "деплой"}' | jq .id)
# … выкладка …
curl -s -H "$H" -X DELETE "$API/alerts/silences/$SID"

# Метрики Prometheus
curl -s -H "$H" http://127.0.0.1:8088/metrics | grep '^nm_http_requests_total'
```

### Ошибки API

| Код | Значение | Тело |
|---|---|---|
| 400 | Неверные данные / действие невозможно | `{"detail": "…"}` |
| 401 | Нет сессии или токена | |
| 403 | Недостаточно прав / IP не разрешён / CSRF | |
| 404 | Объект не найден | |
| 409 | Конфигурация не прошла проверку | `{"detail", "output", "errors": [{level, message, file, line, kind, object_id, context, hint}], "site_id"}` |
| 422 | Ошибка проверки полей | `{"detail", "errors": [{"loc": "ssl.certificate_id", "msg": "…"}]}` |
| 429 | Слишком много неудачных входов | |

### WebSocket

`ws(s)://сервер:8088/api/ws` (cookie-сессия). Сервер присылает раз в секунду `{"type": "tick", "now", "w10", "w60",
"stub", "system", "sites"}`, а также события `applied`, `health`, `alert`, `watchdog`. Подписки клиента:
`{"type": "live", "on": true, "filter": {"site": "1", "status": "5xx", "ip": "", "q": "", "min_rt": 500,
"hide_bots": true}}` — поток запросов `{"type": "requests", "items": [...]}`; `{"type": "errors", "on": true}` —
поток ошибок.
