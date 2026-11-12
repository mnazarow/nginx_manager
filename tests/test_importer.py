"""Импорт существующих конфигураций nginx: реалистичный вывод `nginx -T` → сайты панели."""
import os
import shutil

import pytest

from app.models import GlobalSettings, PanelSettings, Site
from app.nginx.importer import import_config, split_dump, tokenize

DUMP = r'''nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
# configuration file /etc/nginx/nginx.conf:
user www-data;
events { worker_connections 768; }
http {
    include /etc/nginx/mime.types;
    upstream shop_app {
        least_conn;
        server 10.0.0.11:8080 weight=3;
        server 10.0.0.12:8080 max_fails=2 fail_timeout=20s;
        server 10.0.0.13:8080 backup;
    }
    include /etc/nginx/sites-enabled/*;
}

# configuration file /etc/nginx/mime.types:
types { text/html html; }

# configuration file /etc/nginx/sites-enabled/shop.conf:
server {
    listen 80;
    server_name shop.example.com www.shop.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name shop.example.com www.shop.example.com;
    ssl_certificate /etc/letsencrypt/live/shop/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/shop/privkey.pem;
    client_max_body_size 64m;
    gzip on;  # комментарий
    location / {
        proxy_pass http://shop_app;
        proxy_read_timeout 120s;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
    }
    location /api/ {
        proxy_pass http://127.0.0.1:9000/v1/;
    }
    location ~* \.(php|asp)$ {
        return 403;
    }
    location = /robots.txt {
        return 200 "User-agent: *\nDisallow: /admin";
    }
    location /old/ {
        return 301 https://shop.example.com/new/;
    }
    location /static/ {
        alias /var/www/shop/static/;
    }
    location @fallback { proxy_pass http://shop_app; }
    location /weird/ {
        sub_filter 'a' 'b';
    }
}

# configuration file /etc/nginx/sites-enabled/redirect.conf:
server {
    listen 80;
    server_name old.example.com;
    return 301 https://new.example.com$request_uri;
}

# configuration file /etc/nginx/sites-enabled/spa.conf:
server {
    listen 8080;
    server_name "app.example.com";
    location / {
        root /var/www/app;
        try_files $uri $uri/ /index.html;
    }
}

# configuration file /etc/nginx/sites-enabled/default:
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
'''


def test_split_and_tokenize():
    files = split_dump(DUMP)
    assert set(files) >= {"/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/shop.conf", "/etc/nginx/mime.types"}
    toks = tokenize('return 200 "a;b {c}"; # comment\nlisten 80;')
    assert toks == ["return", "200", "a;b {c}", ";", "listen", "80", ";"]


def test_import_realistic_dump():
    res = import_config(DUMP, "/etc/nginx/nginx.conf")
    by = {s["name"]: s for s in res["sites"]}
    assert set(by) == {"shop.example.com", "old.example.com", "app.example.com"}
    shop = by["shop.example.com"]
    assert shop["domains"] == ["shop.example.com", "www.shop.example.com"]
    assert shop["ssl"]["force_https"] is True and shop["ssl"]["certificate_ref"][0].endswith("fullchain.pem")
    assert shop["balancing"] == "least_conn"
    addrs = {(b["address"], b["port"]): b for b in shop["backends"]}
    assert addrs[("10.0.0.11", 8080)]["weight"] == 3 and addrs[("10.0.0.13", 8080)]["backup"] is True
    assert shop["proxy"]["read_timeout"] == "120s"
    locs = {loc["path"]: loc for loc in shop["locations"]}
    assert locs["/api/"]["action"] == "proxy" and locs["/api/"]["proxy_path"] == "/v1/"
    assert locs[r"\.(php|asp)$"]["action"] == "deny" and locs[r"\.(php|asp)$"]["match"] == "regex_ci"
    assert locs["/robots.txt"]["action"] == "return" and "Disallow" in locs["/robots.txt"]["return_body"]
    assert locs["/old/"]["action"] == "redirect" and locs["/static/"]["action"] == "static"
    assert "/weird/" not in locs and "sub_filter" in shop["custom_server"] and "не распознан" in shop["notes"]
    assert by["old.example.com"]["type"] == "redirect" and by["old.example.com"]["redirect"]["preserve_path"]
    app_ = by["app.example.com"]
    assert app_["type"] == "static" and app_["static"]["spa"] is True and app_["http_port"] == 8080
    assert res["certificates"][0]["name"] == "shop.example.com"


def test_imported_sites_validate_and_render():
    """Импортированное должно проходить проверку модели и давать рабочую конфигурацию (как при «Импортировать»)."""
    from app.nginx.generator import Generator, NginxCaps, Paths, State
    res = import_config(DUMP, "/etc/nginx/nginx.conf")
    sites = []
    for i, s in enumerate(res["sites"], 1):
        data = {k: v for k, v in s.items() if not k.startswith("_") and k != "ssl"}
        data["enabled"] = True
        sites.append((i, Site.model_validate(data)))
    tmp = os.environ["NM_TEST_TMP"]
    p = Paths(f"{tmp}/imp/stage", f"{tmp}/imp/live", "/var/acme", f"{tmp}/logs", f"{tmp}/cache", 8089, 8088,
              f"{tmp}/data", bans_file=f"{tmp}/imp-bans.conf")
    files = Generator(State(sites, [], GlobalSettings(), PanelSettings(), {}), NginxCaps(version=(1, 24, 0)), p).render()
    assert any("server_name shop.example.com www.shop.example.com;" in v for v in files.values())
    if shutil.which("nginx") and os.geteuid() == 0:
        from app.db import Database
        from app.nginx.manager import NginxManager
        caps = NginxManager(Database(f"{tmp}/imp-caps.db")).caps()
        files = Generator(State(sites, [], GlobalSettings(), PanelSettings(), {}), caps, p).render()
        open(f"{tmp}/imp-bans.conf", "w").close()
        os.makedirs(f"{tmp}/logs", exist_ok=True)
        stage = f"{tmp}/imp/stage"
        shutil.rmtree(stage, ignore_errors=True)
        for rel, content in files.items():
            os.makedirs(os.path.dirname(f"{stage}/{rel}"), exist_ok=True)
            with open(f"{stage}/{rel}", "w") as f:
                f.write(content)
        mgr = NginxManager(Database(f"{tmp}/imp.db"))
        ok, out = mgr.test_config(f"{stage}/nginx.conf")
        mgr.db.close()
        assert ok, out


def test_import_without_http_block():
    res = import_config("# configuration file /x.conf:\nevents {}\n", "/x.conf")
    assert res["sites"] == [] and res["warnings"]


@pytest.mark.parametrize("text", ["", "server {", "http { server { listen 80; server_name a.test; location / { proxy_pass; } } }",
                                  "http { upstream { } server { server_name ; } }", "}}}{{{;;;"])
def test_import_garbage_does_not_crash(text):
    import_config("# configuration file /x.conf:\n" + text, "/x.conf")
