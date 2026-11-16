"""Проверка браузера (proof-of-work): страница с задачей и приём решения.

nginx отправляет сюда посетителя без действующего пропуска (location = /.nm-challenge, internal) и принимает
решение (location = /.nm-challenge/verify). Запросы приходят только от nginx на этом сервере: проверяются адрес
(loopback) и ключ X-NM-Key. Задача: найти число a, при котором SHA-256(nonce + a) начинается с d нулевых бит.
Nonce подписан HMAC (адрес клиента, время, сложность) — состояние на сервере не хранится; повторное использование
решения запрещено. Пропуск — cookie nm_pass = base64url(md5(срок + IP + " " + секрет)) и nm_pass_e = срок;
его проверяет сам nginx модулем secure_link, не обращаясь к панели.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import secrets
import time
from collections import OrderedDict
from typing import Tuple
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

router = APIRouter(include_in_schema=False)
_used: "OrderedDict[str, float]" = OrderedDict()
NONCE_TTL = 600


def _guard(request: Request) -> Tuple[object, str]:
    nm = request.app.state.nm
    peer = request.client.host if request.client else ""
    if peer not in ("127.0.0.1", "::1", "::ffff:127.0.0.1") and peer != nm_bind(nm):
        raise PermissionError("Страница проверки доступна только через nginx")
    if not hmac.compare_digest(request.headers.get("x-nm-key", ""), nm.nginx.challenge_key()):
        raise PermissionError("Неверный ключ проверки")
    ip = request.headers.get("x-real-ip", "") or peer
    return nm, ip


def nm_bind(nm) -> str:
    from ..config import settings
    return settings.bind_host


def _sign(secret: str, *parts) -> str:
    return hmac.new(secret.encode(), "|".join(str(p) for p in parts).encode(), hashlib.sha256).hexdigest()[:32]


def pass_token(secret: str, expires: int, ip: str) -> str:
    """Значение cookie nm_pass — то же, что вычисляет secure_link_md5 nginx."""
    raw = hashlib.md5(f"{expires}{ip} {secret}".encode()).digest()  # noqa: S324 — формат secure_link nginx
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def leading_zero_bits(h: bytes) -> int:
    n = 0
    for b in h:
        if b == 0:
            n += 8
            continue
        n += 8 - b.bit_length()
        break
    return n


def safe_return(u: str) -> str:
    u = (u or "/").strip()
    if not u.startswith("/") or u.startswith("//") or u.startswith("/\\") or "\r" in u or "\n" in u:
        return "/"
    if u.startswith("/.nm-challenge"):
        return "/"
    return u[:2000]


@router.get("/challenge/page")
async def challenge_page(request: Request):
    nm, ip = _guard(request)
    p = nm.protection.settings()
    d = p.challenge_difficulty
    ts = int(time.time())
    nonce = secrets.token_hex(12)
    sig = _sign(nm.nginx.challenge_secret(), nonce, ts, ip, d)
    ret = safe_return(request.headers.get("x-nm-original", "/"))
    nm.protection.challenge_stats["pages"] += 1
    nonce_js = secrets.token_urlsafe(12)
    body = PAGE.format(nonce=nonce, ts=ts, sig=sig, d=d, ret=html.escape(ret, quote=True), js_nonce=nonce_js,
                       host=html.escape(request.headers.get("host", ""), quote=True))
    return HTMLResponse(body, status_code=403, headers={
        "Cache-Control": "no-store", "X-NM-Challenge": "1", "X-Robots-Tag": "noindex",
        "Content-Security-Policy": f"default-src 'none'; script-src 'nonce-{nonce_js}'; style-src 'unsafe-inline'; "
                                   "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})


@router.post("/challenge/verify")
async def challenge_verify(request: Request):
    nm, ip = _guard(request)
    p = nm.protection.settings()
    raw = (await request.body())[:4096].decode("utf-8", "replace")
    f = {k: v[0] for k, v in parse_qs(raw).items()}
    nonce, answer, ret = f.get("n", ""), f.get("a", ""), safe_return(f.get("r", "/"))
    try:
        ts, d = int(f.get("t", "0")), int(f.get("d", "0"))
    except ValueError:
        ts, d = 0, 0
    secret = nm.nginx.challenge_secret()
    now = time.time()
    ok = (len(nonce) == 24 and len(answer) <= 20 and d >= p.challenge_difficulty and now - ts < NONCE_TTL
          and hmac.compare_digest(f.get("s", ""), _sign(secret, nonce, ts, ip, d)) and nonce not in _used
          and leading_zero_bits(hashlib.sha256((nonce + answer).encode()).digest()) >= d)
    if not ok:
        nm.protection.record_challenge(request.headers.get("x-nm-site", ""), "failed")
        return Response("Проверка не пройдена — обновите страницу.", status_code=403,
                        media_type="text/plain; charset=utf-8", headers={"Cache-Control": "no-store"})
    _used[nonce] = now
    while _used and next(iter(_used.values())) < now - NONCE_TTL:
        _used.popitem(last=False)
    nm.protection.record_challenge(request.headers.get("x-nm-site", ""), "solved", max(0.0, now - ts))
    expires = int(now + p.challenge_ttl_hours * 3600)
    token = pass_token(secret, expires, ip if p.challenge_bind_ip else "")
    secure = request.headers.get("x-forwarded-proto") == "https"
    resp = RedirectResponse(ret, status_code=303, headers={"Cache-Control": "no-store"})
    for name, val in (("nm_pass", token), ("nm_pass_e", str(expires))):
        resp.set_cookie(name, val, max_age=p.challenge_ttl_hours * 3600, path="/", httponly=True, samesite="lax",
                        secure=secure)
    return resp


PAGE = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Проверка браузера</title>
<style>body{{font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f4f4f1;color:#1f1f1c;
margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}}main{{max-width:520px;margin:24px;
background:#fff;border:1px solid #e1e0d9;border-radius:12px;padding:32px}}h1{{font-size:21px;margin:0 0 10px}}
p{{margin:0 0 12px;color:#45443f}}.bar{{height:6px;background:#eaeae5;border-radius:3px;overflow:hidden;margin:18px 0 8px}}
.bar i{{display:block;height:100%;width:5%;background:#2470cc;transition:width .2s}}small{{color:#6b6963}}
@media (prefers-color-scheme:dark){{body{{background:#141413;color:#ecebe4}}main{{background:#1a1a19;border-color:#2f2f2c}}
p{{color:#c3c2b7}}.bar{{background:#2c2c2a}}.bar i{{background:#3987e5}}small{{color:#9a988f}}}}</style></head>
<body><main><h1>Проверяем ваш браузер</h1>
<p>Сайт {host} защищается от автоматических запросов. Это займёт несколько секунд — страница откроется сама.</p>
<div class="bar" role="progressbar" aria-label="Ход проверки"><i id="b"></i></div>
<small id="s" role="status">Вычисление…</small>
<noscript><p><b>Включите JavaScript</b>: без него проверку пройти нельзя.</p></noscript>
<form id="f" method="post" action="/.nm-challenge/verify">
<input type="hidden" name="n" value="{nonce}"><input type="hidden" name="t" value="{ts}">
<input type="hidden" name="s" value="{sig}"><input type="hidden" name="d" value="{d}">
<input type="hidden" name="r" value="{ret}"><input type="hidden" name="a" id="a" value=""></form></main>
<script nonce="{js_nonce}">(function(){{
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,
0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,
0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,
0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function h0(m){{var l=m.length,i,j,w=new Array(64),H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,
0x1f83d9ab,0x5be0cd19],n=((l+9+63)>>6)<<4,x=new Array(n);for(i=0;i<n;i++)x[i]=0;for(i=0;i<l;i++)x[i>>2]|=m.charCodeAt(i)
<<(24-(i&3)*8);x[l>>2]|=0x80<<(24-(l&3)*8);x[n-1]=l*8;for(i=0;i<n;i+=16){{var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],
g=H[6],h=H[7];for(j=0;j<64;j++){{if(j<16)w[j]=x[i+j];else{{var s0=w[j-15],s1=w[j-2];w[j]=(((s0>>>7|s0<<25)^(s0>>>18|s0<<14)^
(s0>>>3))+w[j-16]+((s1>>>17|s1<<15)^(s1>>>19|s1<<13)^(s1>>>10))+w[j-7])|0}}var t1=(h+((e>>>6|e<<26)^(e>>>11|e<<21)^(e>>>25|
e<<7))+((e&f)^(~e&g))+K[j]+w[j])|0,t2=(((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+((a&b)^(a&c)^(b&c)))|0;h=g;g=f;f=e;
e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0}}H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;
H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0}}return H}}
function zb(H){{var n=0;for(var i=0;i<8;i++){{var v=H[i]>>>0;if(v===0){{n+=32;continue}}return n+Math.clz32(v)}}return n}}
var N="{nonce}",D={d},k=0,t0=Date.now(),exp=Math.pow(2,D),B=document.getElementById("b"),S=document.getElementById("s");
function step(){{for(var i=0;i<4000;i++,k++){{if(zb(h0(N+k))>=D){{document.getElementById("a").value=String(k);
S.textContent="Готово, открываем сайт…";B.style.width="100%";document.getElementById("f").submit();return}}}}
B.style.width=Math.min(95,5+90*k/exp/1.5)+"%";S.textContent="Вычисление… "+((Date.now()-t0)/1000).toFixed(1)+" с";
setTimeout(step,0)}}setTimeout(step,30)}})();</script></body></html>
"""
