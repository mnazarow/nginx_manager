# -*- coding: utf-8 -*-
"""Сроки поддержки дистрибутивов: предупреждение в установщике, при обновлении и в «Диагностике».

Модуль без зависимостей и без «from __future__» — установщик запускает его системным python3 до создания
виртуального окружения (на RHEL 8 это Python 3.6):

    python3 app/services/osinfo.py            → строка «уровень|сообщение» (ok, soon, eol, unknown)
    python3 app/services/osinfo.py --json     → то же подробно

Дата — последний день бесплатных обновлений безопасности: стандартная поддержка Ubuntu (дальше — только Ubuntu
Pro/ESM), Debian вместе с Debian LTS, фаза Maintenance Support у RHEL и совместимых (Rocky, AlmaLinux, Oracle), конец
ветки CentOS Stream и Fedora. Для дат, которые производитель называет только месяцем, — «YYYY-MM» (истёкшей поддержка
считается после конца месяца, «скоро» — от начала).
"""
import datetime
import json
import sys

# Источники (проверено в ноябре 2026): documentation.ubuntu.com (list of releases), wiki.debian.org/LTS,
# access.redhat.com/support/policy/updates/errata, centos.org/download, fedorapeople/fedoraproject schedules.
EOL = {
    "ubuntu": {
        "18.04": ("2023-05-31", "есть ESM по подписке Ubuntu Pro — до 2028"),
        "20.04": ("2025-05-31", "есть ESM по подписке Ubuntu Pro до 2030, бесплатно до 5 машин"),
        "22.04": ("2027-05", "дальше — ESM по подписке Ubuntu Pro до 2032"),
        "23.10": ("2024-07", ""),
        "24.04": ("2029-05", "дальше — ESM по подписке Ubuntu Pro до 2034"),
        "24.10": ("2025-07", ""),
        "25.04": ("2026-01", ""),
        "25.10": ("2026-07", ""),
        "26.04": ("2031-05", "дальше — ESM по подписке Ubuntu Pro"),
        "26.10": ("2027-07", ""),
    },
    "debian": {
        "10": ("2024-06-30", "есть платная Freexian ELTS"),
        "11": ("2026-08-31", "есть платная Freexian ELTS"),
        "12": ("2028-06-30", "с июня 2026 — Debian LTS (обновления безопасности основных пакетов)"),
        "13": ("2030-06-30", "с августа 2028 — Debian LTS"),
    },
    "rhel": {  # RHEL, Rocky Linux, AlmaLinux, Oracle Linux — по фазе Maintenance Support RHEL
        "7": ("2024-06-30", ""),
        "8": ("2029-05-31", "только последний выпуск 8.10"),
        "9": ("2032-05-31", "полная поддержка — до 31.05.2027"),
        "10": ("2035-05-31", "полная поддержка — до 31.05.2030"),
    },
    "centos": {"7": ("2024-06-30", ""), "8": ("2021-12-31", "")},
    "centos-stream": {"8": ("2024-05-31", ""), "9": ("2027-05-31", ""), "10": ("2030-05-31", "")},
    "fedora": {
        "39": ("2024-11-26", ""), "40": ("2025-05-13", ""), "41": ("2025-12-15", ""),
        "42": ("2026-05-27", ""), "43": ("2026-12-09", ""), "44": ("2027-06-02", ""),
    },
}
RHEL_LIKE = ("rhel", "rocky", "almalinux", "ol")
NAMES = {"ubuntu": "Ubuntu", "debian": "Debian", "rhel": "RHEL", "centos": "CentOS Linux",
         "centos-stream": "CentOS Stream", "fedora": "Fedora", "rocky": "Rocky Linux", "almalinux": "AlmaLinux",
         "ol": "Oracle Linux"}
# в родительном падеже: «обновите систему до …»
NEXT = {"ubuntu": "Ubuntu 26.04 LTS", "debian": "Debian 13", "rhel": "версии 10 (или 9)", "centos": "Rocky Linux или "
        "AlmaLinux 9/10", "centos-stream": "CentOS Stream 10 или Rocky Linux / AlmaLinux", "fedora": "актуальной Fedora"}
MONTHS = ["января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября",
          "декабря"]
MONTHS_PREP = ["январе", "феврале", "марте", "апреле", "мае", "июне", "июле", "августе", "сентябре", "октябре",
               "ноябре", "декабре"]
SOON_DAYS = 183


def read_os_release(path="/etc/os-release"):
    d = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" not in line or line.startswith("#"):
                    continue
                k, v = line.split("=", 1)
                d[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return d


def _family(osr):
    """(семейство таблицы EOL, версия для таблицы, отображаемое имя)."""
    oid = osr.get("ID", "").lower()
    ver = osr.get("VERSION_ID", "")
    name = osr.get("PRETTY_NAME") or " ".join(x for x in (osr.get("NAME") or NAMES.get(oid, oid), ver) if x)
    if oid == "ubuntu":
        return "ubuntu", ".".join(ver.split(".")[:2]), name
    if oid == "debian":
        return "debian", ver.split(".")[0], name
    if oid in RHEL_LIKE:
        return "rhel", ver.split(".")[0], name
    if oid == "centos":
        fam = "centos-stream" if "stream" in (osr.get("NAME", "") + " " + name).lower() else "centos"
        return fam, ver.split(".")[0], name
    if oid == "fedora":
        return "fedora", ver.split(".")[0], name
    return "", ver, name


def _bounds(date):
    """(начало, конец) периода: для «YYYY-MM» — первый и последний день месяца."""
    parts = [int(x) for x in date.split("-")]
    if len(parts) == 3:
        d = datetime.date(*parts)
        return d, d
    y, m = parts
    first = datetime.date(y, m, 1)
    nxt = datetime.date(y + (m == 12), m % 12 + 1, 1)
    return first, nxt - datetime.timedelta(days=1)


def human(date, case="gen"):
    """«31 мая 2027»; для даты-месяца: «мая 2027» (case=gen, «до …») или «мае 2027» (case=prep, «в …»)."""
    parts = [int(x) for x in date.split("-")]
    if len(parts) == 3:
        return "{} {} {}".format(parts[2], MONTHS[parts[1] - 1], parts[0])
    return "{} {}".format((MONTHS_PREP if case == "prep" else MONTHS)[parts[1] - 1], parts[0])


def _ver_key(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def check(osr=None, today=None):
    """Состояние поддержки ОС: {level: ok|soon|eol|unknown, name, eol, eol_text, days_left, message, note}."""
    osr = osr if osr is not None else read_os_release()
    today = today or datetime.date.today()
    fam, ver, name = _family(osr)
    out = {"level": "unknown", "name": name, "family": fam, "version": ver, "eol": "", "eol_text": "",
           "days_left": None, "message": "", "note": ""}
    table = EOL.get(fam)
    if not table:
        out["message"] = "срок поддержки {} неизвестен панели".format(name)
        return out
    if ver not in table:
        known = sorted(table, key=_ver_key)
        if known and _ver_key(ver) < _ver_key(known[0]):
            out.update(level="eol", message="{} — давно без обновлений безопасности. Обновите систему до {}."
                       .format(name, NEXT.get(fam, "актуальной версии")))
        else:
            out["message"] = "срок поддержки {} неизвестен панели (новее известных)".format(name)
        return out
    date, note = table[ver]
    first, last = _bounds(date)
    out.update(eol=date, eol_text=human(date), note=note, days_left=(last - today).days)
    upgrade = NEXT.get(fam, "актуальной версии")
    month = len(date) == 7
    if today > last:
        out["level"] = "eol"
        out["message"] = ("Поддержка {} закончилась {}{}: бесплатных обновлений безопасности ОС больше нет{}. Обновите "
                          "систему до {}.").format(name, "в " if month else "", human(date, "prep"),
                                                    " (" + note + ")" if note else "", upgrade)
    elif out["days_left"] <= SOON_DAYS:
        out["level"] = "soon"
        out["message"] = ("Поддержка {} заканчивается {}{}{}: запланируйте обновление до {}.").format(
            name, "в " if month else "", human(date, "prep"), " (" + note + ")" if note else "", upgrade)
    else:
        out["level"] = "ok"
        out["message"] = "{}: обновления безопасности до {}{}".format(
            name, out["eol_text"], " (" + note + ")" if note else "")
    return out


def main(argv):
    r = check()
    if "--json" in argv:
        print(json.dumps(r, ensure_ascii=False))
    else:
        print("{}|{}".format(r["level"], r["message"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
