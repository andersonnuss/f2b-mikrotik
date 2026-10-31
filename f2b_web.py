#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
f2b-mikrotik web - painel do f2b-mikrotik.

Consulta o que esta bloqueado (fail2ban, blacklist e cada MikroTik), mostra estatisticas e
permite operar: desbanir, manter blacklist e whitelist, cadastrar roteadores, ajustar as
configuracoes de operacao e gerenciar usuarios. Tudo o que muda fica na trilha de auditoria.

A configuracao editavel fica no banco SQLite (f2b_store.py); o agente percebe as mudancas em
~2 s e replica nos roteadores. Login por sessao (cookie HttpOnly/SameSite=Strict), com papeis:
    leitura   - so consulta
    operador  - + desbanir e blacklist
    admin     - + whitelist, roteadores, configuracoes, usuarios e auditoria

Sem dependencias externas (Python 3.7+).

    python3 f2b_web.py -c /etc/f2b-mikrotik/config.ini [--port 8088]
"""

import argparse
import collections
import csv
import io
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
import f2b_geo  # noqa: E402
import f2b_mikrotik as core  # noqa: E402
import f2b_store  # noqa: E402

STATIC_DIR = os.path.join(HERE, "web")
PUBLIC_FILES = {"/login": ("login.html", "text/html; charset=utf-8"),
                "/login.js": ("login.js", "application/javascript; charset=utf-8"),
                "/app.css": ("app.css", "text/css; charset=utf-8")}
PRIVATE_FILES = {"/": ("index.html", "text/html; charset=utf-8"),
                 "/app.js": ("app.js", "application/javascript; charset=utf-8")}
MAX_BODY = 64 * 1024
QUERY_TIMEOUT = 5.0  # o painel nao espera um roteador fora do ar pelo timeout inteiro do agente
COOKIE = "f2b_session"
SESSION_IDLE = 8 * 3600
ROLE_RANK = {"leitura": 0, "operador": 1, "admin": 2}
EXPIRY_CHOICES = {0, 3600, 6 * 3600, 86400, 7 * 86400, 30 * 86400, 90 * 86400}

log = logging.getLogger("f2b-web")


class ApiError(Exception):
    def __init__(self, status, message, extra=None):
        super().__init__(message)
        self.status = status
        self.extra = extra or {}


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


def public_router(r):
    out = {k: r[k] for k in ("id", "name", "host", "port", "username", "use_ssl", "timeout", "enabled")}
    out["has_password"] = bool(r.get("password"))
    for k in ("created_at", "created_by", "updated_at", "updated_by"):
        out[k] = r.get(k)
    return out


# --------------------------------------------------------------------------- #
# Sessoes e limite de tentativas de login
# --------------------------------------------------------------------------- #
class Sessions:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {}

    def create(self, username):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.data[token] = {"username": username, "seen": time.time()}
        return token

    def get(self, token):
        with self.lock:
            s = self.data.get(token or "")
            if s is None:
                return None
            if time.time() - s["seen"] > SESSION_IDLE:
                del self.data[token]
                return None
            s["seen"] = time.time()
            return s["username"]

    def drop(self, token):
        with self.lock:
            self.data.pop(token or "", None)

    def drop_user(self, username, keep=None):
        with self.lock:
            for t in [t for t, s in self.data.items() if s["username"].lower() == username.lower() and t != keep]:
                del self.data[t]


class LoginLimiter:
    """5 falhas em 15 min a partir do mesmo IP bloqueiam novas tentativas por 15 min."""
    WINDOW, MAX_FAILS = 900, 5

    def __init__(self):
        self.lock = threading.Lock()
        self.fails = collections.defaultdict(collections.deque)

    def blocked_for(self, ip):
        with self.lock:
            q = self.fails[ip]
            while q and time.time() - q[0] > self.WINDOW:
                q.popleft()
            return int(self.WINDOW - (time.time() - q[0])) if len(q) >= self.MAX_FAILS else 0

    def fail(self, ip):
        # um login certo nao zera o contador: senao quem tem uma conta valida intercalaria logins
        # corretos para testar senhas de outros usuarios sem nunca ser bloqueado
        with self.lock:
            self.fails[ip].append(time.time())


# --------------------------------------------------------------------------- #
# Painel
# --------------------------------------------------------------------------- #
class Panel:
    def __init__(self, cfg):
        self.agent = core.Agent(cfg)
        self.store = self.agent.store
        self.agent_log = cfg["agent"].get("logfile").strip()
        self.write_lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=8)
        self.events = self.agent.open_events()  # o agente grava; o painel so consulta
        web = cfg["web"]
        self.geo_file = web.get("geo_file").strip() or f2b_geo.DEFAULT_FILE
        self.ipinfo_url = web.get("ipinfo_url").strip() or None
        self.geo = self.geo_updater = self.ipinfo = None
        self._geo_sig = None
        self.apply_settings()

    # -- configuracao vinda do banco ------------------------------------------------
    def refresh(self, force=False):
        """Rele o banco (mudancas do agente/outro processo, ou forcado apos uma gravacao deste)."""
        if self.agent.reload(force=force):
            self.apply_settings()

    def apply_settings(self):
        s = self.agent.settings
        sig = (s["geoip"], s["geo_provider"], s["ipinfo_token"], s["geo_cache_days"])
        if sig == self._geo_sig:
            return
        self._geo_sig = sig
        if s["geoip"] and self.geo is None:
            self.geo = f2b_geo.GeoDB(self.geo_file)
            self.geo_updater = f2b_geo.GeoUpdater(self.geo)
            self.geo_updater.start()
        self.geo_enabled = bool(s["geoip"])
        if self.ipinfo is not None:
            self.ipinfo.disabled = True  # a thread antiga fica ociosa
            self.ipinfo = None
        if s["geo_provider"] == "ipinfo":
            if not s["ipinfo_token"]:
                log.error("fonte do pais = ipinfo, mas o token esta vazio; usando so as tabelas dos RIRs")
                return
            try:
                self.ipinfo = f2b_geo.IpinfoLite(
                    s["ipinfo_token"], os.path.join(os.path.dirname(self.geo_file) or ".", "geo_cache.db"),
                    ttl_days=int(s["geo_cache_days"]), url=self.ipinfo_url)
                log.info("geo: pais via ipinfo Lite (cache %s dias), com as tabelas dos RIRs como reserva",
                         s["geo_cache_days"])
            except (core.sqlite3.Error, OSError) as e:
                log.error("geo: nao foi possivel abrir o cache do ipinfo: %s; usando so os RIRs", e)

    def routers(self):
        self.refresh()
        return list(self.agent.routers)

    # -- observabilidade ------------------------------------------------------------
    def country_info(self, key):
        """{'cc', 'source', 'asn', 'as_name'} de um IP/rede. cc None = desconhecido.

        Com o ipinfo ligado: usa o cache dele; se o IP ainda nao foi consultado, agenda a consulta
        (em segundo plano) e responde por enquanto com o pais dos RIRs."""
        entry = core.normalize_ip(key) if isinstance(key, str) else key
        info = {"cc": None, "source": None, "asn": "", "as_name": ""}
        if entry is None:
            return info
        if self.geo is not None and self.geo_enabled and self.geo.ready:
            cc = self.geo.lookup(entry)
            if cc:
                info.update(cc=cc, source="rir")
        if self.ipinfo is not None and not core.is_network(entry) and f2b_geo.is_public(entry):
            hit = self.ipinfo.get(str(entry))
            if hit is None:
                self.ipinfo.enqueue(str(entry))
            else:
                info.update(asn=hit["asn"], as_name=hit["as_name"])
                if hit["cc"]:
                    info.update(cc=hit["cc"], source="ipinfo")
        return info

    def country(self, key):
        return self.country_info(key)["cc"]

    def _events(self, sql, args=()):
        if self.events is None:
            return []
        try:
            return self.events.query(sql, args)
        except core.sqlite3.Error as e:
            log.warning("historico indisponivel: %s", e)
            return []

    def block_counts(self):
        """{ip: (vezes bloqueado, ultimo bloqueio)} de todo o historico."""
        rows = self._events("SELECT ip, COUNT(*), MAX(ts) FROM events WHERE kind IN ('ban', 'bl-add') GROUP BY ip")
        return {ip: (n, last) for ip, n, last in rows}

    def meta(self):
        first = self._events("SELECT MIN(ts) FROM events")
        geo_on = self.geo is not None and self.geo_enabled
        return {"events": self.events is not None, "events_since": first[0][0] if first else None,
                "geo": geo_on, "geo_ready": bool(geo_on and self.geo.ready),
                "geo_updated": self.geo.updated_at() if geo_on else None,
                "geo_error": self.geo_updater.last_error if geo_on and self.geo_updater else None,
                "geo_provider": "ipinfo" if self.ipinfo is not None else "rir",
                "ipinfo": self.ipinfo.status() if self.ipinfo is not None else None}

    def stats(self, hours):
        now = int(time.time())
        end = (now // 3600 + 1) * 3600
        start = end - hours * 3600
        buckets = {h: [0, 0] for h in range(start // 3600, end // 3600)}
        for h, blocks, unblocks in self._events(
                "SELECT ts / 3600, SUM(kind IN ('ban', 'bl-add')), SUM(kind IN ('unban', 'bl-del')) "
                "FROM events WHERE ts >= ? GROUP BY ts / 3600", (start,)):
            if h in buckets:
                buckets[h] = [blocks, unblocks]
        series = [{"ts": h * 3600, "blocks": b, "unblocks": u} for h, (b, u) in sorted(buckets.items())]

        def count(kinds, since):
            marks = ",".join("?" * len(kinds))
            row = self._events("SELECT COUNT(*) FROM events WHERE kind IN (%s) AND ts >= ?" % marks,
                               tuple(kinds) + (since,))
            return row[0][0] if row else 0

        blocks = sum(s["blocks"] for s in series)
        unblocks = sum(s["unblocks"] for s in series)
        peak = max(series, key=lambda s: s["blocks"]) if series else None
        totals = {"blocks_1h": count(core.EventStore.BLOCK_KINDS, now - 3600),
                  "unblocks_1h": count(core.EventStore.UNBLOCK_KINDS, now - 3600),
                  "blocks": blocks, "unblocks": unblocks, "avg_per_hour": round(blocks / hours, 1),
                  "peak_ts": peak["ts"] if peak and peak["blocks"] else None,
                  "peak_blocks": peak["blocks"] if peak else 0}

        per_ip = self._events(
            "SELECT ip, COUNT(*), MAX(ts), GROUP_CONCAT(DISTINCT jail) FROM events "
            "WHERE kind IN ('ban', 'bl-add') AND ts >= ? GROUP BY ip", (start,))
        all_time = self.block_counts()
        countries = {}
        for ip, n, _last, _jails in per_ip:
            cc = self.country(ip) or "??"
            c = countries.setdefault(cc, {"country": cc if cc != "??" else None, "blocks": 0, "ips": 0})
            c["blocks"] += n
            c["ips"] += 1
        top_ips = sorted(per_ip, key=lambda r: (-r[1], -r[2]))[:20]
        jails = self._events("SELECT jail, COUNT(*) FROM events WHERE kind IN ('ban', 'bl-add') AND ts >= ? "
                             "GROUP BY jail ORDER BY 2 DESC LIMIT 10", (start,))
        recent = self._events("SELECT ts, kind, ip, jail FROM events WHERE kind != 'restore' "
                              "ORDER BY ts DESC, rowid DESC LIMIT 30")
        return {
            "hours": hours, "series": series, "totals": totals, "unique_ips": len(per_ip),
            "top_ips": [{"ip": ip, "blocks": n, "last": last, "jails": (j or "").split(","),
                         "total": all_time.get(ip, (n, last))[0], "country": self.country(ip)}
                        for ip, n, last, j in top_ips],
            "top_countries": sorted(countries.values(), key=lambda c: -c["blocks"])[:15],
            "top_jails": [{"jail": j, "blocks": n} for j, n in jails],
            "recent": [{"ts": ts, "kind": k, "ip": ip, "jail": j, "country": self.country(ip)}
                       for ts, k, ip, j in recent],
            "meta": self.meta(),
        }

    def history(self, target):
        """Historico de um IP (ou de tudo dentro de uma rede consultada)."""
        if core.is_network(target):
            rows = [r for r in self._events("SELECT ts, kind, ip, jail FROM events ORDER BY ts DESC")
                    if relation(target, core.normalize_ip(r[2])) in ("igual", "contem")]
        else:
            rows = self._events("SELECT ts, kind, ip, jail FROM events WHERE ip = ? ORDER BY ts DESC",
                                (str(target),))
        blocks = [r for r in rows if r[1] in core.EventStore.BLOCK_KINDS]
        return {"blocks": len(blocks), "unblocks": sum(1 for r in rows if r[1] in core.EventStore.UNBLOCK_KINDS),
                "first": blocks[-1][0] if blocks else None, "last": blocks[0][0] if blocks else None,
                "recent": [{"ts": ts, "kind": k, "ip": ip, "jail": j} for ts, k, ip, j in rows[:15]]}

    # -- leitura ------------------------------------------------------------------
    def _skip_reason(self, entry):
        """Por que o agente nao bloqueia esta entrada (ou None se bloqueia)."""
        if entry is None:
            return "invalido"
        if self.agent._whitelisted(entry):
            return "whitelist"
        if entry.version not in self.agent.families:
            return "IPv6 desativado"
        return None

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
        blacklist = a._blacklist()
        items = []
        for row in self.store.blacklist():
            entry = core.normalize_ip(row["entry"])
            items.append(dict(row, ignored=self._skip_reason(entry)))
        bl = {"ok": True, "error": None, "entries": sorted(blacklist, key=sort_key),
              "items": sorted(items, key=lambda i: sort_key(i["entry"]))}
        return f2b, bl, per_jail, blacklist, a._merge(banned, blacklist, a._holds())

    def holds(self):
        """Retencoes ativas no MikroTik, por IP (vazio se a retencao estiver desligada)."""
        if not f2b_store.parse_duration(self.agent.settings["router_hold"]):
            return {}
        return {r["ip"]: r for r in self.store.holds_active()}

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
        self.refresh()
        # fontes no pool e roteadores nesta thread: em paralelo, e nenhuma tarefa do pool espera outra
        sources_future = self.pool.submit(self._sources)
        routers = self._query_routers()
        f2b, bl, per_jail, blacklist, desired = sources_future.result()

        # tudo que esta banido no fail2ban (inclusive o que o agente nao replica), por IP
        f2b_ips = {}
        for jail, ips in per_jail.items():
            for raw in ips:
                ip = core.normalize_ip(raw)
                f2b_ips.setdefault(str(ip) if ip is not None else raw, set()).add(jail)
        bl_networks = [e for e, _ in blacklist.values() if core.is_network(e)]

        holds = self.holds()
        keys = set(desired) | set(f2b_ips) | set(holds)
        for r in routers:
            keys.update(row["key"] for row in r["rows"])
        counts = self.block_counts()
        entries = []
        for key in sorted(keys, key=sort_key):
            jails = sorted(f2b_ips.get(key, ()))
            entry = core.normalize_ip(key)
            hold = holds.get(key)
            geo = self.country_info(entry) if entry is not None else {}  # so le o cache do ipinfo
            item = {"key": key, "jails": jails, "blacklist": key in blacklist, "expected": key in desired,
                    "sources": jails + (["blacklist"] if key in blacklist else []) + (["retencao"] if hold else []),
                    "hold": {"release_at": hold["release_at"], "cycles": hold["cycles"], "jails": hold["jails"]}
                    if hold else None, "note": "",
                    "whitelisted": entry is not None and a._whitelisted(entry), "routers": {},
                    "blocks": counts.get(key, (0, None))[0], "last_block": counts.get(key, (0, None))[1],
                    "country": geo.get("cc"), "asn": geo.get("asn", ""), "as_name": geo.get("as_name", "")}
            if jails and key not in desired:
                cover = next((n for n in bl_networks if entry is not None and entry.version == n.version
                              and entry in n), None)
                if cover is not None:
                    item["note"] = "coberto pela blacklist %s" % cover
                elif self._skip_reason(entry):
                    item["note"] = "não replicado: %s" % self._skip_reason(entry)
                elif a.f2b.jails and not set(jails) & a.f2b.jails:
                    item["note"] = "não replicado: jail fora da lista do agente"
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
                "list_name": a.list_name, "families": a.families, "fail2ban": f2b, "blacklist": bl,
                "whitelist": [str(n) for n in a.whitelist], "desired_count": len(desired),
                "holds_count": len(holds), "router_hold": a.settings["router_hold"],
                "routers": routers, "entries": entries, "agent_service": service_state("f2b-mikrotik"),
                "meta": self.meta()}

    def check(self, text):
        target = core.normalize_ip(text or "")
        if target is None:
            raise ApiError(400, "informe um IP ou rede valido (ex.: 203.0.113.5 ou 198.51.100.0/24)")
        a = self.agent
        self.refresh()
        sources_future = self.pool.submit(self._sources)
        routers = self._query_routers()
        f2b, bl, per_jail, blacklist, desired = sources_future.result()

        result = {"query": str(target), "is_network": core.is_network(target),
                  "whitelist": [], "fail2ban": {"ok": f2b["ok"], "error": f2b["error"], "matches": []},
                  "blacklist": {"ok": bl["ok"], "error": bl["error"], "matches": []},
                  "desired": [], "routers": [], "country_info": self.country_info(target),
                  "history": self.history(target), "meta": self.meta(), "hold": None}
        if not core.is_network(target):
            hold = self.holds().get(str(target))
            if hold:
                result["hold"] = {"release_at": hold["release_at"], "cycles": hold["cycles"], "jails": hold["jails"],
                                  "last_unban": hold["last_unban"]}
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
        bl_rows = {r["entry"]: r for r in self.store.blacklist()}
        for key, (entry, _tags) in sorted(blacklist.items()):
            rel = relation(target, entry)
            if rel:
                row = bl_rows.get(key, {})
                result["blacklist"]["matches"].append({"entry": key, "relation": rel,
                                                       "expires_at": row.get("expires_at"),
                                                       "comment": row.get("comment", "")})
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

    # -- acoes: unban, blacklist e whitelist ----------------------------------------
    def unban(self, data, who, ip):
        try:
            target = ipaddress.ip_address(str(data.get("ip", "")).strip())
        except ValueError:
            raise ApiError(400, "informe um IP valido")
        jail_filter = data.get("jail") or None
        f2b = self.agent.f2b
        try:
            per_jail = f2b.per_jail()
        except core.Fail2banError as e:
            raise ApiError(502, str(e))
        matching = [(jail, raw) for jail, ips in sorted(per_jail.items()) if not jail_filter or jail == jail_filter
                    for raw in ips if core.normalize_ip(raw) == target]
        if matching:
            # desbanir no painel libera de verdade: a liberacao do fail2ban nao gera retencao no MikroTik
            self.store.hold_skip(str(target))
        done = []
        for jail, ips in sorted(per_jail.items()):
            if jail_filter and jail != jail_filter:
                continue
            for raw in ips:
                if core.normalize_ip(raw) == target:
                    try:
                        f2b.unban(raw, jail)
                    except core.Fail2banError as e:
                        self.store.audit(who, "fail2ban.unban_falhou", str(target), {"jail": jail, "erro": str(e)}, ip)
                        raise ApiError(502, "falha ao desbanir de %s: %s" % (jail, e))
                    done.append(jail)
        if not done:
            raise ApiError(404, "%s nao esta banido %s" % (target, "na jail " + jail_filter if jail_filter
                                                              else "no fail2ban"))
        self.store.audit(who, "fail2ban.unban", str(target), {"jails": done}, ip)
        self.store.hold_release(str(target), who, ip, "desbanido no painel")
        self.refresh(force=True)
        in_blacklist = any(relation(target, e) in ("igual", "dentro") for e, _ in self.agent._blacklist().values())
        return {"ip": str(target), "jails": done, "in_blacklist": in_blacklist}

    def release_hold(self, data, who, ip):
        try:
            target = ipaddress.ip_address(str(data.get("ip", "")).strip())
        except ValueError:
            raise ApiError(400, "informe um IP valido")
        if not self.store.hold_release(str(target), who, ip, "liberado no painel"):
            raise ApiError(404, "%s nao esta retido no MikroTik" % target)
        self.refresh(force=True)
        still = [jail for jail, ips in self._safe_per_jail().items() for raw in ips if core.normalize_ip(raw) == target]
        in_blacklist = any(relation(target, e) in ("igual", "dentro") for e, _ in self.agent._blacklist().values())
        return {"ip": str(target), "still_banned": still, "in_blacklist": in_blacklist}

    def _safe_per_jail(self):
        try:
            return self.agent.f2b.per_jail()
        except core.Fail2banError:
            return {}

    def blacklist_add(self, data, who, ip):
        entry = core.normalize_ip(str(data.get("entry", "")).strip())
        if entry is None:
            raise ApiError(400, "informe um IP ou rede valido (ex.: 203.0.113.5 ou 198.51.100.0/24)")
        if core.is_network(entry) and entry.prefixlen < (8 if entry.version == 4 else 32):
            raise ApiError(400, "rede grande demais (/%d): isso cortaria boa parte da internet" % entry.prefixlen)
        reason = self._skip_reason(entry)
        if reason == "whitelist":
            nets = [str(n) for n in self.agent.whitelist if relation(entry, n)]
            raise ApiError(400, "%s esta na whitelist (%s); o agente nao o bloquearia" % (entry, ", ".join(nets)))
        if reason:
            raise ApiError(400, "%s nao seria bloqueado: %s" % (entry, reason))
        try:
            expires = int(data.get("expires") or 0)
        except (TypeError, ValueError):
            expires = -1
        if expires not in EXPIRY_CHOICES:
            raise ApiError(400, "validade invalida")
        with self.write_lock:
            self.store.list_add("blacklist", entry, data.get("comment"), who, ip,
                                expires_at=int(time.time()) + expires if expires else None)
        self.refresh(force=True)
        return {"entry": str(entry)}

    def blacklist_remove(self, data, who, ip):
        entry = core.normalize_ip(str(data.get("entry", "")).strip())
        if entry is None:
            raise ApiError(400, "entrada invalida")
        with self.write_lock:
            self.store.list_remove("blacklist", entry, who, ip)
        self.refresh(force=True)
        return {"entry": str(entry)}

    def whitelist_add(self, data, who, ip):
        entry = core.normalize_ip(str(data.get("entry", "")).strip())
        if entry is None:
            raise ApiError(400, "informe um IP ou rede valido (ex.: 200.200.200.10 ou 10.0.0.0/8)")
        if core.is_network(entry) and entry.prefixlen < (8 if entry.version == 4 else 16):
            raise ApiError(400, "rede grande demais (/%d): o agente deixaria de bloquear boa parte da internet"
                           % entry.prefixlen)
        with self.write_lock:
            self.store.list_add("whitelist", entry, data.get("comment"), who, ip)
        self.refresh(force=True)
        # o que deixa de ser bloqueado por causa da nova entrada
        released = [r["entry"] for r in self.store.blacklist() if relation(core.normalize_ip(r["entry"]), entry)]
        return {"entry": str(entry), "blacklist_ignored": released}

    def whitelist_remove(self, data, who, ip):
        entry = core.normalize_ip(str(data.get("entry", "")).strip())
        if entry is None:
            raise ApiError(400, "entrada invalida")
        client = core.normalize_ip(ip)
        if client is not None and relation(client, entry) in ("igual", "dentro") and not data.get("confirm"):
            raise ApiError(409, "%s inclui o seu IP atual (%s). Sem ela, se o fail2ban banir o seu IP, os "
                                "MikroTiks bloqueiam o seu acesso. Confirme para remover." % (entry, ip),
                           {"needs_confirm": True})
        with self.write_lock:
            self.store.list_remove("whitelist", entry, who, ip)
        self.refresh(force=True)
        return {"entry": str(entry)}

    # -- roteadores -----------------------------------------------------------------
    def _router_or_404(self, rid):
        try:
            return self.store.get_router(rid)
        except f2b_store.StoreError as e:
            raise ApiError(e.status, str(e))

    def create_router(self, data, who, ip):
        with self.write_lock:
            router = self.store.validate_router(data)
            self.store.save_router(router, who, ip, created=True)
        self.refresh(force=True)
        log.info("roteador cadastrado por %s: %s (%s:%s)", who, router["name"], router["host"], router["port"])
        return public_router(router)

    def update_router(self, rid, data, who, ip):
        with self.write_lock:
            router = self.store.validate_router(data, self._router_or_404(rid))
            self.store.save_router(router, who, ip)
        self.refresh(force=True)
        return public_router(router)

    def delete_router(self, rid, flush, who, ip):
        with self.write_lock:
            cur = self._router_or_404(rid)
            removed = 0
            if flush:
                try:
                    with self.agent.api(cur) as api:
                        managed, _ = self.agent._router_entries(api)
                        for _key, (fam, entry_id, _c) in managed.items():
                            api.talk([core.LIST_PATHS[fam] + "/remove", "=.id=" + entry_id])
                            removed += 1
                except (core.RouterOSError, OSError) as e:
                    self.store.audit(who, "roteador.limpeza_falhou", cur["name"], {"erro": str(e)}, ip)
                    raise ApiError(502, "nao foi possivel limpar os bloqueios em %s (%s); o roteador nao foi "
                                        "excluido. Tente de novo ou exclua sem limpar." % (cur["name"], e))
            self.store.delete_router(rid, who, ip, {"bloqueios_removidos": removed, "limpeza": bool(flush)})
        self.refresh(force=True)
        return {"removed_entries": removed}

    def test_router(self, data):
        current = None
        if data.get("id"):
            current = self._router_or_404(data["id"])
        router = self.store.validate_router(dict(data, name=data.get("name") or (current or {}).get("name") or "teste"),
                                            current) if (current is None or len(data) > 1) else current
        out = self._query_router(dict(router, enabled=True))
        out["entries"] = len(out.pop("rows"))
        return out

    # -- configuracoes, usuarios e auditoria ---------------------------------------
    def settings(self):
        return {"values": self.store.public_settings(),
                "schema": {k: {"type": v[0], "min": v[2] if v[0] in ("int", "float") else None,
                               "max": v[3] if v[0] in ("int", "float") else None,
                               "options": list(v[2]) if v[0] == "choice" else None, "label": v[4]}
                           for k, v in f2b_store.SETTINGS.items()},
                "whitelist": self.store.whitelist(),
                "readonly": {"address_list": self.agent.list_name, "comment_prefix": self.agent.prefix,
                             "fail2ban_log": self.agent.f2b_log, "config_db": self.store.path,
                             "events_db": self.agent.events_db}}

    def update_settings(self, data, who, ip):
        with self.write_lock:
            diff = self.store.update_settings(data.get("values") or {}, who, ip)
            released = []
            if "router_hold" in diff and not f2b_store.parse_duration(diff["router_hold"][1]):
                # desligar a retencao libera os retidos (e eles nao voltam se ela for religada)
                released = self.store.end_active_holds(who, ip, "retencao desligada nas configuracoes")
        self.refresh(force=True)
        return {"changed": sorted(diff), "holds_released": released}


def _err(fn, *args, **kwargs):
    """Converte StoreError em ApiError."""
    try:
        return fn(*args, **kwargs)
    except f2b_store.StoreError as e:
        raise ApiError(e.status, str(e))


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "f2b-web"
    sys_version = ""
    panel = None
    sessions = Sessions()
    limiter = LoginLimiter()
    secure_cookie = False

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.client_address[0], fmt % args)

    # -- respostas ----------------------------------------------------------------
    def _headers(self, status, ctype, length, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)

    def _send(self, status, body, ctype, extra=None):
        self._headers(status, ctype, len(body), extra)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, data, extra=None):
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8", extra)

    def _static(self, name, ctype):
        try:
            with open(os.path.join(STATIC_DIR, name), "rb") as fh:
                body = fh.read()
        except OSError:
            raise ApiError(404, "arquivo %s nao encontrado" % name)
        self._send(200, body, ctype)

    def _cookie_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return v
        return None

    def _set_cookie(self, token, clear=False):
        attrs = "Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if self.secure_cookie else "")
        if clear:
            return {"Set-Cookie": "%s=; Max-Age=0; %s" % (COOKIE, attrs)}
        return {"Set-Cookie": "%s=%s; %s" % (COOKIE, token, attrs)}

    def _body(self):
        # exige cabecalho proprio e JSON: um site de terceiros nao consegue forjar o pedido (CSRF)
        if self.headers.get("X-Requested-With") != "f2b-web" or \
                not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ApiError(403, "requisicao recusada")
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ApiError(413, "corpo muito grande")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            raise ApiError(400, "JSON invalido")
        if not isinstance(data, dict):
            raise ApiError(400, "JSON invalido")
        return data

    @property
    def ip(self):
        return self.client_address[0]

    # -- autenticacao -------------------------------------------------------------
    def _current_user(self):
        username = self.sessions.get(self._cookie_token())
        if not username:
            return None
        user = self.panel.store.get_user(username)
        if user is None or not user["enabled"]:
            self.sessions.drop(self._cookie_token())
            return None
        return user

    def _login(self):
        data = self._body()
        wait = self.limiter.blocked_for(self.ip)
        if wait:
            self.panel.store.audit(str(data.get("username", ""))[:40] or "?", "login.bloqueado", "",
                                   {"motivo": "muitas tentativas"}, self.ip)
            raise ApiError(429, "muitas tentativas de login; tente de novo em %d min" % (wait // 60 + 1))
        user = self.panel.store.authenticate(data.get("username"), data.get("password"))
        if user is None:
            self.limiter.fail(self.ip)
            self.panel.store.audit(str(data.get("username", ""))[:40] or "?", "login.falha", "", None, self.ip)
            log.warning("login invalido de %s (usuario %r)", self.ip, data.get("username"))
            time.sleep(1)  # freia forca bruta
            raise ApiError(401, "usuario ou senha incorretos")
        token = self.sessions.create(user["username"])
        self.panel.store.audit(user["username"], "login.ok", "", None, self.ip)
        return self._json(200, self._me(user), self._set_cookie(token))

    @staticmethod
    def _me(user):
        return {"username": user["username"], "name": user["name"], "role": user["role"],
                "role_label": f2b_store.ROLE_LABEL[user["role"]]}

    # -- rotas --------------------------------------------------------------------
    def _dispatch(self):
        url = urlparse(self.path)
        path, query = url.path, parse_qs(url.query)
        method = "GET" if self.command == "HEAD" else self.command
        try:
            if method == "GET" and path in PUBLIC_FILES:
                return self._static(*PUBLIC_FILES[path])
            if method == "POST" and path == "/api/login":
                return self._login()
            user = self._current_user()
            if user is None:
                if method == "GET" and not path.startswith("/api/"):
                    return self._send(302, b"", "text/plain", {"Location": "/login"})
                raise ApiError(401, "sessao expirada; entre novamente")
            if method == "GET" and path in PRIVATE_FILES:
                return self._static(*PRIVATE_FILES[path])
            for m, pattern, role, handler in ROUTES:
                match = re.fullmatch(pattern, path)
                if m == method and match:
                    if ROLE_RANK[user["role"]] < ROLE_RANK[role]:
                        self.panel.store.audit(user["username"], "acesso.negado", "%s %s" % (method, path), None,
                                               self.ip)
                        raise ApiError(403, "seu usuario (%s) nao tem permissao para isso"
                                       % f2b_store.ROLE_LABEL[user["role"]])
                    return handler(self, user, query, *match.groups())
            raise ApiError(404, "nao encontrado")
        except ApiError as e:
            self._json(e.status, dict({"error": str(e)}, **e.extra))
        except f2b_store.StoreError as e:
            self._json(e.status, {"error": str(e)})
        except Exception as e:
            log.exception("erro em %s %s", method, path)
            self._json(500, {"error": "erro interno: %s" % e})

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = _dispatch

    # -- manipuladores (self, user, query, *grupos) ---------------------------------
    def h_logout(self, user, _q):
        self._body()
        self.sessions.drop(self._cookie_token())
        self.panel.store.audit(user["username"], "logout", "", None, self.ip)
        return self._json(200, {"ok": True}, self._set_cookie("", clear=True))

    def h_me(self, user, _q):
        return self._json(200, self._me(user))

    def h_password(self, user, _q):
        data = self._body()
        _err(self.panel.store.change_own_password, user["username"], data.get("current"), data.get("new"), self.ip)
        self.sessions.drop_user(user["username"], keep=self._cookie_token())  # derruba outras sessoes
        return self._json(200, {"ok": True})

    def h_overview(self, _u, _q):
        return self._json(200, self.panel.overview())

    def h_check(self, _u, q):
        return self._json(200, self.panel.check(q.get("ip", [""])[0]))

    def h_stats(self, _u, q):
        try:
            hours = int(q.get("hours", ["24"])[0])
        except ValueError:
            hours = 24
        return self._json(200, self.panel.stats(max(1, min(hours, 24 * 31))))

    def h_log(self, _u, q):
        try:
            lines = int(q.get("lines", ["300"])[0] or 300)
        except ValueError:
            lines = 300
        return self._json(200, self.panel.agent_log_tail(max(10, min(lines, 5000))))

    def h_unban(self, user, _q):
        return self._json(200, self.panel.unban(self._body(), user["username"], self.ip))

    def h_release(self, user, _q):
        return self._json(200, self.panel.release_hold(self._body(), user["username"], self.ip))

    def h_bl_add(self, user, _q):
        return self._json(201, _err(self.panel.blacklist_add, self._body(), user["username"], self.ip))

    def h_bl_del(self, user, _q):
        return self._json(200, _err(self.panel.blacklist_remove, self._body(), user["username"], self.ip))

    def h_wl_add(self, user, _q):
        return self._json(201, _err(self.panel.whitelist_add, self._body(), user["username"], self.ip))

    def h_wl_del(self, user, _q):
        return self._json(200, _err(self.panel.whitelist_remove, self._body(), user["username"], self.ip))

    def h_routers(self, _u, _q):
        return self._json(200, {"routers": [public_router(r) for r in self.panel.routers()]})

    def h_router_add(self, user, _q):
        return self._json(201, _err(self.panel.create_router, self._body(), user["username"], self.ip))

    def h_router_test(self, _u, _q):
        return self._json(200, _err(self.panel.test_router, self._body()))

    def h_router_put(self, user, _q, rid):
        return self._json(200, _err(self.panel.update_router, rid, self._body(), user["username"], self.ip))

    def h_router_del(self, user, q, rid):
        self._body()
        flush = q.get("flush", ["0"])[0] == "1"
        return self._json(200, _err(self.panel.delete_router, rid, flush, user["username"], self.ip))

    def h_settings(self, _u, _q):
        return self._json(200, self.panel.settings())

    def h_settings_put(self, user, _q):
        return self._json(200, _err(self.panel.update_settings, self._body(), user["username"], self.ip))

    def h_users(self, _u, _q):
        return self._json(200, {"users": self.panel.store.users(), "roles": f2b_store.ROLE_LABEL})

    def h_user_add(self, user, _q):
        _err(self.panel.store.create_user, self._body(), user["username"], self.ip)
        return self._json(201, {"ok": True})

    def h_user_put(self, user, _q, username):
        data = self._body()
        diff = _err(self.panel.store.update_user, username, data, user["username"], self.ip)
        if diff and ("ativo" in diff or "papel" in diff or "senha" in diff):
            # perdeu acesso, mudou de papel ou teve a senha redefinida: derruba as sessoes dele
            keep = self._cookie_token() if username.lower() == user["username"].lower() else None
            self.sessions.drop_user(username, keep=keep)
        return self._json(200, {"changed": sorted(diff)})

    def h_user_del(self, user, _q, username):
        self._body()
        _err(self.panel.store.delete_user, username, user["username"], self.ip)
        self.sessions.drop_user(username)
        return self._json(200, {"ok": True})

    def _audit_filters(self, q):
        def first(k):
            return (q.get(k, [""])[0] or "").strip()
        since = until = None
        try:
            if first("since"):
                since = int(first("since"))
            if first("until"):
                until = int(first("until"))
        except ValueError:
            raise ApiError(400, "periodo invalido")
        return dict(actor=first("actor"), action=first("action"), text=first("text"), since=since, until=until)

    def h_audit(self, _u, q):
        limit = 200
        before = q.get("before", [""])[0]
        rows = self.panel.store.audit_query(limit=limit + 1, before_id=int(before) if before.isdigit() else None,
                                            **self._audit_filters(q))
        actors = [r["actor"] for r in self.panel.store.query("SELECT DISTINCT actor FROM audit ORDER BY actor")]
        return self._json(200, {"rows": rows[:limit], "more": len(rows) > limit, "actors": actors})

    def h_audit_csv(self, user, q):
        filters = self._audit_filters(q)
        rows = self.panel.store.audit_query(limit=100000, **filters)
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";")
        w.writerow(["id", "data_hora", "usuario", "ip", "acao", "alvo", "detalhes"])
        for r in rows:
            w.writerow([r["id"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), r["actor"], r["ip"],
                        r["action"], r["target"],
                        json.dumps(r["details"], ensure_ascii=False) if r["details"] else ""])
        self.panel.store.audit(user["username"], "auditoria.exportada", "%d registro(s)" % len(rows),
                               {k: v for k, v in filters.items() if v}, self.ip)
        body = ("\ufeff" + buf.getvalue()).encode("utf-8")  # BOM: o Excel abre os acentos certos
        return self._send(200, body, "text/csv; charset=utf-8",
                          {"Content-Disposition": "attachment; filename=auditoria-%s.csv" % time.strftime("%Y%m%d-%H%M")})


# (metodo, rota, papel minimo, manipulador)
ROUTES = [
    ("POST", r"/api/logout", "leitura", Handler.h_logout),
    ("GET", r"/api/me", "leitura", Handler.h_me),
    ("POST", r"/api/me/password", "leitura", Handler.h_password),
    ("GET", r"/api/overview", "leitura", Handler.h_overview),
    ("GET", r"/api/check", "leitura", Handler.h_check),
    ("GET", r"/api/stats", "leitura", Handler.h_stats),
    ("GET", r"/api/log", "leitura", Handler.h_log),
    ("POST", r"/api/unban", "operador", Handler.h_unban),
    ("POST", r"/api/release", "operador", Handler.h_release),
    ("POST", r"/api/blacklist", "operador", Handler.h_bl_add),
    ("DELETE", r"/api/blacklist", "operador", Handler.h_bl_del),
    ("POST", r"/api/whitelist", "admin", Handler.h_wl_add),
    ("DELETE", r"/api/whitelist", "admin", Handler.h_wl_del),
    ("GET", r"/api/routers", "leitura", Handler.h_routers),
    ("POST", r"/api/routers", "admin", Handler.h_router_add),
    ("POST", r"/api/routers/test", "admin", Handler.h_router_test),
    ("PUT", r"/api/routers/([0-9A-Za-z_-]+)", "admin", Handler.h_router_put),
    ("DELETE", r"/api/routers/([0-9A-Za-z_-]+)", "admin", Handler.h_router_del),
    ("GET", r"/api/settings", "admin", Handler.h_settings),
    ("PUT", r"/api/settings", "admin", Handler.h_settings_put),
    ("GET", r"/api/users", "admin", Handler.h_users),
    ("POST", r"/api/users", "admin", Handler.h_user_add),
    ("PUT", r"/api/users/([A-Za-z0-9._@-]+)", "admin", Handler.h_user_put),
    ("DELETE", r"/api/users/([A-Za-z0-9._@-]+)", "admin", Handler.h_user_del),
    ("GET", r"/api/audit", "admin", Handler.h_audit),
    ("GET", r"/api/audit\.csv", "admin", Handler.h_audit_csv),
]


def main():
    ap = argparse.ArgumentParser(description="Painel web do f2b-mikrotik.")
    ap.add_argument("-c", "--config", default="/etc/f2b-mikrotik/config.ini", help="arquivo de configuracao")
    ap.add_argument("--bind", help="endereco de escuta (padrao: [web] bind)")
    ap.add_argument("--port", type=int, help="porta (padrao: [web] port = 8088)")
    ap.add_argument("-v", "--verbose", action="store_true", help="log detalhado")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    core.log.addHandler(logging.StreamHandler())  # migracao e erros do agente aparecem no journal do painel
    core.log.setLevel(logging.INFO)
    core.log.propagate = False

    cfg = core.load_config(args.config)
    web = cfg["web"]
    bind = args.bind or web.get("bind").strip() or "0.0.0.0"
    port = args.port or web.getint("port")
    Handler.panel = Panel(cfg)

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
        Handler.secure_cookie = True
    Handler.panel.store.audit("sistema", "painel.iniciado", "%s://%s:%s" % (scheme, bind, port), None)
    log.info("f2b-mikrotik web %s em %s://%s:%s/", core.__version__, scheme, bind, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
