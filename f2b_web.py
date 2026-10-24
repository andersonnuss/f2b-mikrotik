#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
f2b-mikrotik web - painel para consultar o que esta bloqueado (fail2ban, blacklist e cada
MikroTik) e cadastrar os roteadores adicionais que recebem os mesmos bloqueios.

Usa o proprio f2b_mikrotik.py para falar com o fail2ban e com os roteadores; nao tem
dependencias externas (Python 3.7+). Bloquear e liberar nos roteadores e trabalho do agente:
o painel desbane no fail2ban e edita a blacklist e o routers.json, e o agente replica em ~2 s.
(A unica escrita direta num roteador e a limpeza opcional ao exclui-lo do cadastro.)

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
import f2b_geo  # noqa: E402
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
        self.events = self.agent.open_events()  # o agente grava; o painel so consulta
        self.geo = self.geo_updater = None
        web = cfg["web"]
        geo_file = web.get("geo_file").strip() or f2b_geo.DEFAULT_FILE
        if web.getboolean("geoip"):
            self.geo = f2b_geo.GeoDB(geo_file)
            self.geo_updater = f2b_geo.GeoUpdater(self.geo)
            self.geo_updater.start()
        self.ipinfo = None
        provider = web.get("geo_provider").strip().lower() or "rir"
        if provider == "ipinfo":
            token = web.get("ipinfo_token").strip()
            if not token:
                log.error("geo_provider = ipinfo, mas ipinfo_token esta vazio; usando so as tabelas dos RIRs")
            else:
                try:
                    self.ipinfo = f2b_geo.IpinfoLite(
                        token, os.path.join(os.path.dirname(geo_file) or ".", "geo_cache.db"),
                        ttl_days=web.getint("geo_cache_days"), url=web.get("ipinfo_url").strip() or None)
                    log.info("geo: pais via ipinfo Lite (cache %d dias), com as tabelas dos RIRs como reserva",
                             web.getint("geo_cache_days"))
                except (core.sqlite3.Error, OSError) as e:
                    log.error("geo: nao foi possivel abrir o cache do ipinfo: %s; usando so os RIRs", e)
        elif provider != "rir":
            log.warning("geo_provider desconhecido: %r (use rir ou ipinfo); usando os RIRs", provider)

    # -- observabilidade ----------------------------------------------------------
    def country_info(self, key):
        """{'cc', 'source', 'asn', 'as_name'} de um IP/rede. cc None = desconhecido.

        Com o ipinfo ligado: usa o cache dele; se o IP ainda nao foi consultado, agenda a consulta
        (em segundo plano) e responde por enquanto com o pais dos RIRs."""
        entry = core.normalize_ip(key) if isinstance(key, str) else key
        info = {"cc": None, "source": None, "asn": "", "as_name": ""}
        if entry is None:
            return info
        if self.geo is not None and self.geo.ready:
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
        """Codigo ISO do pais (ou None = desconhecido)."""
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
        return {"events": self.events is not None, "events_since": first[0][0] if first else None,
                "geo": self.geo is not None, "geo_ready": bool(self.geo and self.geo.ready),
                "geo_updated": self.geo.updated_at() if self.geo else None,
                "geo_error": self.geo_updater.last_error if self.geo_updater else None,
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
        bl = {"ok": True, "error": None, "file": a.blacklist_file, "entries": [], "items": []}
        try:
            blacklist = a._blacklist()
            bl["entries"] = sorted(blacklist, key=sort_key)
            bl["items"] = self.blacklist_items()
        except core.BlacklistError as e:
            bl.update(ok=False, error=str(e))
            blacklist = {}
        return f2b, bl, per_jail, blacklist, a._merge(banned, blacklist)

    def _skip_reason(self, entry):
        """Por que o agente nao bloqueia esta entrada (ou None se bloqueia)."""
        a = self.agent
        if entry is None:
            return "invalido"
        if a._whitelisted(entry):
            return "whitelist"
        if entry.version not in a.families:
            return "IPv6 desativado"
        return None

    def blacklist_items(self):
        """Linhas validas da blacklist com o comentario de cada uma."""
        path = self.agent.blacklist_file
        if not path or not os.path.exists(path):
            return []
        try:
            with open(path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as e:
            raise core.BlacklistError("nao foi possivel ler a blacklist %s: %s" % (path, e))
        items = []
        for n, line in enumerate(lines, 1):
            token, comment = core.parse_blacklist_line(line)
            if not token:
                continue
            entry = core.normalize_ip(token)
            items.append({"entry": str(entry) if entry is not None else token, "comment": comment, "line": n,
                          "ignored": self._skip_reason(entry)})
        return items

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
        f2b, bl, per_jail, blacklist, desired = sources_future.result()

        # tudo que esta banido no fail2ban (inclusive o que o agente nao replica), por IP
        f2b_ips = {}
        for jail, ips in per_jail.items():
            for raw in ips:
                ip = core.normalize_ip(raw)
                f2b_ips.setdefault(str(ip) if ip is not None else raw, set()).add(jail)
        bl_networks = [e for e, _ in blacklist.values() if core.is_network(e)]

        keys = set(desired) | set(f2b_ips)
        for r in routers:
            keys.update(row["key"] for row in r["rows"])
        counts = self.block_counts()
        entries = []
        for key in sorted(keys, key=sort_key):
            jails = sorted(f2b_ips.get(key, ()))
            entry = core.normalize_ip(key)
            item = {"key": key, "jails": jails, "blacklist": key in blacklist, "expected": key in desired,
                    "sources": jails + (["blacklist"] if key in blacklist else []), "note": "",
                    "whitelisted": entry is not None and a._whitelisted(entry), "routers": {},
                    "blocks": counts.get(key, (0, None))[0], "last_block": counts.get(key, (0, None))[1],
                    "country": self.country(entry) if entry is not None else None}
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
                "list_name": a.list_name,
                "families": a.families, "fail2ban": f2b, "blacklist": bl,
                "whitelist": [str(n) for n in a.whitelist], "desired_count": len(desired),
                "routers": routers, "entries": entries, "agent_service": service_state("f2b-mikrotik"),
                "meta": self.meta()}

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
                  "desired": [], "routers": [], "country_info": self.country_info(target),
                  "history": self.history(target), "meta": self.meta()}
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

    # -- acoes: unban e blacklist ---------------------------------------------------
    def unban(self, data, who):
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
        done = []
        for jail, ips in sorted(per_jail.items()):
            if jail_filter and jail != jail_filter:
                continue
            for raw in ips:
                if core.normalize_ip(raw) == target:
                    try:
                        f2b.unban(raw, jail)
                    except core.Fail2banError as e:
                        raise ApiError(502, "falha ao desbanir de %s: %s" % (jail, e))
                    done.append(jail)
        if not done:
            raise ApiError(404, "%s nao esta banido %s" % (target, "na jail " + jail_filter if jail_filter
                                                              else "no fail2ban"))
        log.info("unban por %s: %s (jails: %s)", who, target, ", ".join(done))
        try:
            in_blacklist = any(relation(target, e) in ("igual", "dentro")
                               for e, _ in self.agent._blacklist().values())
        except core.BlacklistError:
            in_blacklist = False
        return {"ip": str(target), "jails": done, "in_blacklist": in_blacklist}

    def _blacklist_path(self):
        path = self.agent.blacklist_file
        if not path:
            raise ApiError(409, "a blacklist esta desativada no config.ini ([blacklist] file)")
        return path

    def _write_blacklist(self, path, lines):
        mode = 0o644
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            pass
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        os.replace(tmp, path)

    def _read_blacklist(self, path):
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.readlines()
        except FileNotFoundError:
            return ["# Blacklist do f2b-mikrotik: um IP ou rede por linha\n"]
        except OSError as e:
            raise ApiError(500, "nao foi possivel ler %s: %s" % (path, e))

    def blacklist_add(self, data, who):
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
        comment = re.sub(r"[\r\n#]+", " ", str(data.get("comment") or "")).strip()[:100]
        stamp = time.strftime("%Y-%m-%d %H:%M")
        note = "%s (%s, %s)" % (comment, who.split("@")[0], stamp) if comment else "%s, %s" % (who.split("@")[0], stamp)
        path = self._blacklist_path()
        with self.write_lock:
            lines = self._read_blacklist(path)
            for line in lines:
                token, _ = core.parse_blacklist_line(line)
                if token and str(core.normalize_ip(token)) == str(entry):
                    raise ApiError(409, "%s ja esta na blacklist" % entry)
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append("%-24s # %s\n" % (entry, note))
            self._write_blacklist(path, lines)
        log.info("blacklist: %s incluido por %s", entry, who)
        return {"entry": str(entry)}

    def blacklist_remove(self, data, who):
        entry = core.normalize_ip(str(data.get("entry", "")).strip())
        if entry is None:
            raise ApiError(400, "entrada invalida")
        path = self._blacklist_path()
        with self.write_lock:
            lines = self._read_blacklist(path)
            keep = [l for l in lines if str(core.normalize_ip(core.parse_blacklist_line(l)[0] or "-")) != str(entry)]
            removed = len(lines) - len(keep)
            if not removed:
                raise ApiError(404, "%s nao esta na blacklist" % entry)
            self._write_blacklist(path, keep)
        log.info("blacklist: %s removido por %s", entry, who)
        return {"entry": str(entry), "removed": removed}

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
            if method == "GET" and path == "/api/stats":
                try:
                    hours = int(query.get("hours", ["24"])[0])
                except ValueError:
                    hours = 24
                return self._json(200, self.panel.stats(max(1, min(hours, 24 * 31))))
            if method == "GET" and path == "/api/log":
                lines = max(10, min(int(query.get("lines", ["300"])[0] or 300), 5000))
                return self._json(200, self.panel.agent_log_tail(lines))
            if method == "GET" and path == "/api/routers":
                return self._json(200, {"routers": [public_router(r) for r in self.panel.routers()]})
            if method == "POST" and path == "/api/routers":
                return self._json(201, self.panel.create_router(self._body(), self._who()))
            if method == "POST" and path == "/api/unban":
                return self._json(200, self.panel.unban(self._body(), self._who()))
            if method == "POST" and path == "/api/blacklist":
                return self._json(201, self.panel.blacklist_add(self._body(), self._who()))
            if method == "DELETE" and path == "/api/blacklist":
                return self._json(200, self.panel.blacklist_remove(self._body(), self._who()))
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
