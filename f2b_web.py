#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
f2b-mikrotik web - painel para consultar o que esta bloqueado (fail2ban, blacklist e cada
MikroTik) e cadastrar os roteadores adicionais que recebem os mesmos bloqueios.

Usa o proprio f2b_mikrotik.py para falar com o fail2ban e com os roteadores; nao tem
dependencias externas (Python 3.7+). O painel so le: quem bloqueia e libera e o agente.
Os roteadores cadastrados aqui vao para o routers.json, que o agente rele sozinho.

    python3 f2b_web.py -c /etc/f2b-mikrotik/config.ini [--port 8088]
"""

import argparse
import base64
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import f2b_mikrotik as core  # noqa: E402

STATIC_DIR = os.path.join(HERE, "web")
STATIC_FILES = {"/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "application/javascript; charset=utf-8"),
                "/app.css": ("app.css", "text/css; charset=utf-8")}
MAX_BODY = 64 * 1024
QUERY_TIMEOUT = 5.0  # o painel nao espera um roteador fora do ar pelo timeout inteiro do agente
HOST_RE = re.compile(r"^[A-Za-z0-9.:\-\[\]]{1,253}$")

log = logging.getLogger("f2b-web")


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def relation(target, entry):
    """Como `target` (IP ou rede consultado) se relaciona com `entry`: 'igual', 'dentro', 'contem' ou None."""
    if entry is None or target.version != entry.version:
        return None
    t_net, e_net = core.is_network(target), core.is_network(entry)
    if not t_net and not e_net:
        return "igual" if target == entry else None
    if not t_net:
        return "dentro" if target in entry else None
    if not e_net:
        return "contem" if entry in target else None
    if target == entry:
        return "igual"
    if target.subnet_of(entry):
        return "dentro"
    if entry.subnet_of(target):
        return "contem"
    return None


def public_router(r):
    out = {k: r[k] for k in core.ROUTER_FIELDS if k != "password"}
    out["primary"] = bool(r.get("primary"))
    out["has_password"] = bool(r.get("password"))
    return out


class Panel:
    def __init__(self, cfg):
        self.agent = core.Agent(cfg)
        self.agent_log = cfg["agent"].get("logfile").strip()
        self.write_lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=8)

    # -- leitura ------------------------------------------------------------------
    def routers(self):
        self.agent.reload_routers()
        return list(self.agent.routers)

    def _sources(self):
        """Fail2ban, blacklist e o conjunto desejado, sem tocar nos roteadores."""
        a = self.agent
        f2b = {"ok": True, "error": None, "jails": []}
        try:
            per_jail = a.f2b.per_jail()
            banned = a._from_fail2ban(per_jail)
            for jail in sorted(per_jail):
                f2b["jails"].append({"name": jail, "replicated": not a.f2b.jails or jail in a.f2b.jails,
                                     "ips": sorted(per_jail[jail], key=sort_key)})
        except core.Fail2banError as e:
            f2b.update(ok=False, error=str(e))
            per_jail, banned = {}, {}
        bl = {"ok": True, "error": None, "file": a.blacklist_file, "entries": []}
        try:
            blacklist = a._blacklist()
            bl["entries"] = sorted(blacklist, key=sort_key)
        except core.BlacklistError as e:
            bl.update(ok=False, error=str(e))
            blacklist = {}
        return f2b, bl, per_jail, blacklist, a._merge(banned, blacklist)

    def _query_router(self, router):
        out = public_router(router)
        if not router["enabled"]:
            out.update(status="desabilitado", rows=[])
            return out
        started = time.monotonic()
        try:
            with self.agent.api(dict(router, timeout=min(router["timeout"], QUERY_TIMEOUT))) as api:
                res, _ = api.talk(["/system/resource/print"])
                info = res[0] if res else {}
                ident, _ = api.talk(["/system/identity/print"])
                rows = self.agent.router_rows(api)
            out.update(status="online", board=info.get("board-name", ""), version=info.get("version", ""),
                       uptime=info.get("uptime", ""), identity=ident[0].get("name", "") if ident else "",
                       rows=rows)
        except (core.RouterOSError, OSError) as e:
            out.update(status="offline", error=str(e) or e.__class__.__name__, rows=[])
        out["latency_ms"] = int((time.monotonic() - started) * 1000)
        return out

    def _query_routers(self):
        return list(self.pool.map(self._query_router, self.routers()))

    def overview(self):
        a = self.agent
        sources_future = self.pool.submit(self._sources)
        routers = self._query_routers()
        f2b, bl, _per_jail, _blacklist, desired = sources_future.result()

        keys = set(desired)
        for r in routers:
            keys.update(row["key"] for row in r["rows"])
        entries = []
        for key in sorted(keys, key=sort_key):
            item = {"key": key, "sources": sorted(desired[key][1]) if key in desired else [], "routers": {}}
            entries.append(item)
        index = {e["key"]: e for e in entries}

        for r in routers:
            by_key = {row["key"]: row for row in r["rows"]}
            missing, extra = [], []
            for key, item in index.items():
                row = by_key.get(key)
                if r["status"] != "online":
                    state = "?"
                elif row is None:
                    state = "faltando" if key in desired else ""
                    if state:
                        missing.append(key)
                elif row["managed"]:
                    state = "agente" if key in desired else "a remover"
                    if key not in desired:
                        extra.append(key)
                else:
                    state = "manual"
                if row is not None and row["disabled"]:
                    state = "desativado"
                item["routers"][r["id"]] = state
            r["managed_count"] = sum(1 for row in r["rows"] if row["managed"])
            r["other_count"] = len(r["rows"]) - r["managed_count"]
            r["missing"], r["extra"] = missing, extra
            del r["rows"]

        return {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "version": core.__version__,
                "list_name": a.list_name,
                "families": a.families, "fail2ban": f2b, "blacklist": bl,
                "whitelist": [str(n) for n in a.whitelist], "desired_count": len(desired),
                "routers": routers, "entries": entries, "agent_service": service_state("f2b-mikrotik")}

    def check(self, text):
        target = core.normalize_ip(text or "")
        if target is None:
            raise ApiError(400, "informe um IP ou rede valido (ex.: 203.0.113.5 ou 198.51.100.0/24)")
        a = self.agent
        # fontes no pool e roteadores nesta thread: nenhuma tarefa do pool espera por outra (sem deadlock)
        sources_future = self.pool.submit(self._sources)
        routers = self._query_routers()
        f2b, bl, per_jail, blacklist, desired = sources_future.result()

        result = {"query": str(target), "is_network": core.is_network(target),
                  "whitelist": [], "fail2ban": {"ok": f2b["ok"], "error": f2b["error"], "matches": []},
                  "blacklist": {"ok": bl["ok"], "error": bl["error"], "matches": []},
                  "desired": [], "routers": []}
        for net in a.whitelist:
            rel = relation(target, net)
            if rel:
                result["whitelist"].append({"entry": str(net), "relation": rel})
        for jail, ips in sorted(per_jail.items()):
            for raw in ips:
                rel = relation(target, core.normalize_ip(raw))
                if rel:
                    result["fail2ban"]["matches"].append({"jail": jail, "entry": raw, "relation": rel,
                                                          "replicated": not a.f2b.jails or jail in a.f2b.jails})
        for key, (entry, _tags) in sorted(blacklist.items()):
            rel = relation(target, entry)
            if rel:
                result["blacklist"]["matches"].append({"entry": key, "relation": rel})
        for key, (entry, tags) in sorted(desired.items()):
            rel = relation(target, entry)
            if rel:
                result["desired"].append({"entry": key, "relation": rel, "sources": sorted(tags)})

        for r in routers:
            matches = []
            for row in r["rows"]:
                rel = relation(target, row["entry"])
                if rel:
                    matches.append({"entry": row["key"], "relation": rel, "comment": row["comment"],
                                    "managed": row["managed"], "timeout": row["timeout"],
                                    "disabled": row["disabled"]})
            del r["rows"]
            r["matches"] = matches
            r["blocked"] = any(m["relation"] in ("igual", "dentro") and not m["disabled"] for m in matches)
            result["routers"].append(r)
        return result

    def agent_log_tail(self, lines):
        if not self.agent_log:
            return {"file": "", "lines": [], "error": "log do agente desativado no config.ini"}
        try:
            with open(self.agent_log, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 512 * 1024))
                data = fh.read().decode("utf-8", "replace").splitlines()
        except OSError as e:
            return {"file": self.agent_log, "lines": [], "error": str(e)}
        return {"file": self.agent_log, "lines": data[-lines:], "error": None}

    # -- cadastro de roteadores -----------------------------------------------------
    def _validate(self, data, current=None):
        if not isinstance(data, dict):
            raise ApiError(400, "corpo invalido")

        def text(field, required=True, limit=128):
            value = data.get(field, current.get(field) if current else "")
            value = "" if value is None else str(value).strip()
            if required and not value:
                raise ApiError(400, "campo obrigatorio: %s" % field)
            if len(value) > limit:
                raise ApiError(400, "campo muito longo: %s" % field)
            return value

        use_ssl = bool(data.get("use_ssl", current["use_ssl"] if current else False))
        host = text("host")
        if not HOST_RE.match(host):
            raise ApiError(400, "host invalido")
        try:
            port = int(data.get("port") or (current["port"] if current else (8729 if use_ssl else 8728)))
            timeout = float(data.get("timeout") or (current["timeout"] if current else 10))
        except (TypeError, ValueError):
            raise ApiError(400, "porta ou timeout invalido")
        if not 1 <= port <= 65535 or not 1 <= timeout <= 60:
            raise ApiError(400, "porta (1-65535) ou timeout (1-60 s) fora do intervalo")
        password = data.get("password") or ""
        if not password:
            if current is None:
                raise ApiError(400, "campo obrigatorio: password")
            password = current["password"]  # em branco na edicao = manter a senha atual
        return dict(id=current["id"] if current else secrets.token_hex(4), name=text("name", limit=40),
                    host=host, port=port, username=text("username", limit=64), password=str(password),
                    use_ssl=use_ssl, timeout=timeout,
                    enabled=bool(data.get("enabled", current["enabled"] if current else True)), primary=False)

    def _save(self, routers):
        if not self.agent.routers_file:
            raise ApiError(409, "routers_file esta vazio no config.ini; cadastro de roteadores desativado")
        core.write_routers_file(self.agent.routers_file, routers)
        self.agent.reload_routers()

    def _find(self, routers, rid):
        for r in routers:
            if r["id"] == rid:
                if r.get("primary"):
                    raise ApiError(403, "o roteador principal e definido no config.ini; edite-o la")
                return r
        raise ApiError(404, "roteador nao encontrado")

    def create_router(self, data, who):
        with self.write_lock:
            routers = self.routers()
            new = self._validate(data)
            self._save(routers + [new])
        log.info("roteador cadastrado por %s: %s (%s:%s)", who, new["name"], new["host"], new["port"])
        return public_router(new)

    def update_router(self, rid, data, who):
        with self.write_lock:
            routers = self.routers()
            cur = self._find(routers, rid)
            new = self._validate(data, cur)
            self._save([new if r["id"] == rid else r for r in routers])
        log.info("roteador alterado por %s: %s (%s:%s)", who, new["name"], new["host"], new["port"])
        return public_router(new)

    def delete_router(self, rid, flush, who):
        with self.write_lock:
            routers = self.routers()
            cur = self._find(routers, rid)
            removed = 0
            if flush:
                try:
                    with self.agent.api(cur) as api:
                        managed, _ = self.agent._router_entries(api)
                        for _key, (fam, entry_id, _c) in managed.items():
                            api.talk([core.LIST_PATHS[fam] + "/remove", "=.id=" + entry_id])
                            removed += 1
                except (core.RouterOSError, OSError) as e:
                    raise ApiError(502, "nao foi possivel limpar os bloqueios em %s (%s); o roteador nao foi "
                                        "excluido. Tente de novo ou exclua sem limpar." % (cur["name"], e))
            self._save([r for r in routers if r["id"] != rid])
        log.info("roteador excluido por %s: %s (%d bloqueio(s) removidos)", who, cur["name"], removed)
        return {"removed_entries": removed}

    def test_router(self, data):
        current = None
        if data.get("id"):
            current = next((r for r in self.routers() if r["id"] == data["id"]), None)
        if current is not None and current.get("primary"):
            router = current
        else:
            router = self._validate(dict(data, name=data.get("name") or "teste"), current)
        out = self._query_router(dict(router, enabled=True))
        out["entries"] = len(out.pop("rows"))
        return out


def sort_key(key):
    entry = core.normalize_ip(key)
    if entry is None:
        return (9, 0, key)
    addr = entry.network_address if core.is_network(entry) else entry
    return (entry.version, int(addr), key)


def service_state(name):
    try:
        p = subprocess.run(["systemctl", "is-active", name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=5)
        return p.stdout.strip() or "desconhecido"
    except (OSError, subprocess.TimeoutExpired):
        return "desconhecido"


class Handler(BaseHTTPRequestHandler):
    server_version = "f2b-web"
    sys_version = ""
    panel = None
    username = ""
    password = ""

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.client_address[0], fmt % args)

    # -- respostas ----------------------------------------------------------------
    def _headers(self, status, ctype, length):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")

    def _json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                user, _, pwd = base64.b64decode(header[6:]).decode("utf-8").partition(":")
            except (ValueError, UnicodeDecodeError):
                user = pwd = ""
            ok_user = hmac.compare_digest(user.encode(), self.username.encode())
            ok_pwd = hmac.compare_digest(pwd.encode(), self.password.encode())
            if ok_user and ok_pwd:
                return True
            log.warning("login invalido de %s (usuario %r)", self.client_address[0], user)
            time.sleep(1)  # freia tentativas de forca bruta
        body = b"autenticacao necessaria"
        self._headers(401, "text/plain; charset=utf-8", len(body))
        self.send_header("WWW-Authenticate", 'Basic realm="f2b-mikrotik", charset="UTF-8"')
        self.end_headers()
        self.wfile.write(body)
        return False

    def _body(self):
        # exige cabecalho proprio e JSON: um site de terceiros nao consegue forjar o pedido (CSRF)
        if self.headers.get("X-Requested-With") != "f2b-web" or \
                not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ApiError(403, "requisicao recusada")
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ApiError(413, "corpo muito grande")
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            raise ApiError(400, "JSON invalido")

    def _who(self):
        return "%s@%s" % (self.username, self.client_address[0])

    # -- rotas --------------------------------------------------------------------
    def _dispatch(self, method):
        if not self._authorized():
            return
        url = urlparse(self.path)
        path, query = url.path, parse_qs(url.query)
        try:
            if method == "GET" and path in STATIC_FILES:
                return self._static(*STATIC_FILES[path])
            m = re.match(r"^/api/routers/([0-9a-z_-]+)$", path)
            if method == "GET" and path == "/api/overview":
                return self._json(200, self.panel.overview())
            if method == "GET" and path == "/api/check":
                return self._json(200, self.panel.check(query.get("ip", [""])[0]))
            if method == "GET" and path == "/api/log":
                lines = max(10, min(int(query.get("lines", ["300"])[0] or 300), 5000))
                return self._json(200, self.panel.agent_log_tail(lines))
            if method == "GET" and path == "/api/routers":
                return self._json(200, {"routers": [public_router(r) for r in self.panel.routers()]})
            if method == "POST" and path == "/api/routers":
                return self._json(201, self.panel.create_router(self._body(), self._who()))
            if method == "POST" and path == "/api/routers/test":
                return self._json(200, self.panel.test_router(self._body()))
            if method == "PUT" and m:
                return self._json(200, self.panel.update_router(m.group(1), self._body(), self._who()))
            if method == "DELETE" and m:
                self._body()  # so para validar o cabecalho anti-CSRF
                flush = query.get("flush", ["0"])[0] == "1"
                return self._json(200, self.panel.delete_router(m.group(1), flush, self._who()))
            raise ApiError(404, "nao encontrado")
        except ApiError as e:
            self._json(e.status, {"error": str(e)})
        except Exception as e:
            log.exception("erro em %s %s", method, path)
            self._json(500, {"error": "erro interno: %s" % e})

    def _static(self, name, ctype):
        try:
            with open(os.path.join(STATIC_DIR, name), "rb") as fh:
                body = fh.read()
        except OSError:
            raise ApiError(404, "arquivo %s nao encontrado" % name)
        self._headers(200, ctype, len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")


def main():
    ap = argparse.ArgumentParser(description="Painel web do f2b-mikrotik.")
    ap.add_argument("-c", "--config", default="/etc/f2b-mikrotik/config.ini", help="arquivo de configuracao")
    ap.add_argument("--bind", help="endereco de escuta (padrao: [web] bind)")
    ap.add_argument("--port", type=int, help="porta (padrao: [web] port = 8088)")
    ap.add_argument("-v", "--verbose", action="store_true", help="log detalhado")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    core.log.addHandler(logging.NullHandler())  # avisos do agente aparecem no proprio painel
    core.log.propagate = False

    cfg = core.load_config(args.config)
    web = cfg["web"]
    bind = args.bind or web.get("bind").strip() or "0.0.0.0"
    port = args.port or web.getint("port")
    if not web.get("password", "").strip():
        raise SystemExit("defina [web] password no %s antes de iniciar o painel" % args.config)

    Handler.panel = Panel(cfg)
    Handler.username = web.get("username").strip() or "admin"
    Handler.password = web.get("password").strip()

    try:
        server = ThreadingHTTPServer((bind, port), Handler)
    except OSError as e:
        raise SystemExit("nao foi possivel escutar em %s:%s (%s). Porta em uso? Troque [web] port "
                         "ou use --port." % (bind, port, e))
    server.daemon_threads = True
    scheme = "http"
    cert, key = web.get("tls_cert").strip(), web.get("tls_key").strip()
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key or None)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    log.info("f2b-mikrotik web %s em %s://%s:%s/", core.__version__, scheme, bind, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
