#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
f2b-mikrotik - replica os bloqueios do fail2ban para um roteador MikroTik (bloqueio na borda).

Funcionamento
  * Acompanha o log do fail2ban (Ban / Unban / Restore Ban) para reagir em poucos segundos.
  * A cada `sync_interval` segundos faz uma reconciliacao completa:
        IPs banidos no fail2ban (fail2ban-client)  x  address-list no MikroTik
    adicionando o que falta e removendo o que foi liberado. Assim nada se perde se o
    roteador estiver fora do ar, se o agente for reiniciado ou se o log rotacionar.
  * So mexe nas entradas da address-list cujo comentario comeca com `comment_prefix`;
    entradas manuais na mesma lista sao preservadas.
  * Se o fail2ban nao responder, nada e removido do roteador (fail-safe).
  * Blacklist: arquivo texto com um IP ou rede por linha, bloqueados independentemente do
    fail2ban. O arquivo e relido sozinho quando alterado; apagar a linha libera no roteador.
  * Varios roteadores: o principal vem do config.ini e os demais do routers.json (editado
    pela interface web, f2b_web.py). Todos recebem os mesmos bloqueios; a falha de um nao
    atrapalha os outros.

Fala com o roteador pela API do RouterOS (porta 8728, ou 8729 com SSL), implementada
aqui mesmo: nenhuma dependencia externa, apenas Python 3.6+.

Modos
  (padrao)   daemon - fica rodando (use com o systemd)
  --once     uma sincronizacao e sai (para usar no cron)
  --test     testa fail2ban e roteador e mostra o que seria feito, sem alterar nada
  --flush    remove do roteador todas as entradas criadas pelo agente
"""

import argparse
import ast
import binascii
import configparser
import glob
import gzip
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import shlex
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time

__version__ = "1.5.0"

log = logging.getLogger("f2b-mikrotik")


# --------------------------------------------------------------------------- #
# Cliente minimo da API do RouterOS
# --------------------------------------------------------------------------- #
class RouterOSError(Exception):
    """Falha de conexao/protocolo com o roteador."""


class RouterOSTrap(RouterOSError):
    """Erro retornado pelo roteador para um comando (!trap). A conexao continua valida."""


class RouterOSApi:
    def __init__(self, host, port, username, password, use_ssl=False, timeout=10.0):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def connect(self):
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                # aceita tambem o api-ssl sem certificado (ADH) do RouterOS
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        self.sock = sock
        try:
            self._login()
        except Exception:
            self.close()
            raise

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _login(self):
        try:
            _, done = self.talk(["/login", "=name=" + self.username, "=password=" + self.password])
            if "ret" in done:
                # RouterOS anterior a 6.43: desafio MD5
                challenge = binascii.unhexlify(done["ret"])
                digest = hashlib.md5(b"\x00" + self.password.encode() + challenge).hexdigest()
                self.talk(["/login", "=name=" + self.username, "=response=00" + digest])
        except RouterOSTrap as e:
            raise RouterOSError("falha no login no MikroTik: %s" % e)

    # -- codificacao de palavras ------------------------------------------------
    @staticmethod
    def _encode_len(n):
        if n < 0x80:
            return bytes([n])
        if n < 0x4000:
            return (n | 0x8000).to_bytes(2, "big")
        if n < 0x200000:
            return (n | 0xC00000).to_bytes(3, "big")
        if n < 0x10000000:
            return (n | 0xE0000000).to_bytes(4, "big")
        return b"\xF0" + n.to_bytes(4, "big")

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise RouterOSError("conexao fechada pelo roteador")
            buf += chunk
        return buf

    def _read_len(self):
        b = self._recv_exact(1)[0]
        if b < 0x80:
            return b
        if b < 0xC0:
            return ((b & 0x3F) << 8) | self._recv_exact(1)[0]
        if b < 0xE0:
            return ((b & 0x1F) << 16) | int.from_bytes(self._recv_exact(2), "big")
        if b < 0xF0:
            return ((b & 0x0F) << 24) | int.from_bytes(self._recv_exact(3), "big")
        return int.from_bytes(self._recv_exact(4), "big")

    def _write_sentence(self, words):
        data = b""
        for w in words:
            raw = w.encode("utf-8")
            data += self._encode_len(len(raw)) + raw
        self.sock.sendall(data + b"\x00")

    def _read_sentence(self):
        words = []
        while True:
            n = self._read_len()
            if n == 0:
                return words
            words.append(self._recv_exact(n).decode("utf-8", "replace"))

    def talk(self, words):
        """Envia um comando. Retorna (lista de respostas !re, atributos do !done)."""
        if self.sock is None:
            raise RouterOSError("nao conectado")
        self._write_sentence(words)
        replies, trap = [], None
        while True:
            sentence = self._read_sentence()
            if not sentence:
                continue
            kind, attrs = sentence[0], {}
            for w in sentence[1:]:
                if w.startswith("="):
                    key, _, value = w[1:].partition("=")
                    attrs[key] = value
            if kind == "!re":
                replies.append(attrs)
            elif kind == "!trap":
                trap = attrs.get("message", str(attrs))
            elif kind == "!fatal":
                self.close()
                raise RouterOSError("erro fatal do roteador: %s" % " ".join(sentence[1:]))
            elif kind == "!done":
                if trap is not None:
                    raise RouterOSTrap(trap)
                return replies, attrs


# --------------------------------------------------------------------------- #
# fail2ban
# --------------------------------------------------------------------------- #
class Fail2banError(Exception):
    pass


class Fail2ban:
    def __init__(self, client, jails, timeout=30):
        self.cmd = shlex.split(client)
        self.jails = set(jails)  # vazio = todas
        self.timeout = timeout

    def _run(self, *args):
        try:
            p = subprocess.run(self.cmd + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise Fail2banError("falha ao executar fail2ban-client: %s" % e)
        if p.returncode != 0:
            msg = (p.stderr.strip() or p.stdout.strip()).splitlines()
            raise Fail2banError("fail2ban-client %s retornou %d: %s"
                                % (" ".join(args), p.returncode, msg[-1] if msg else ""))
        return p.stdout

    def _per_jail(self):
        # fail2ban >= 0.11.2: "fail2ban-client banned" -> [{'sshd': ['1.2.3.4']}, {'nginx': []}]
        try:
            data = ast.literal_eval(self._run("banned").strip())
            per_jail = {}
            for item in data:
                per_jail.update(item)
            return per_jail
        except (Fail2banError, ValueError, SyntaxError, TypeError, AttributeError):
            pass
        # versoes antigas: status de cada jail
        out = self._run("status")
        m = re.search(r"Jail list:[ \t]*(.*)", out)
        jails = [j.strip() for j in m.group(1).split(",") if j.strip()] if m else []
        per_jail = {}
        for jail in jails:
            if self.jails and jail not in self.jails:
                continue
            m = re.search(r"Banned IP list:[ \t]*(.*)", self._run("status", jail))
            per_jail[jail] = m.group(1).split() if m else []
        return per_jail

    def per_jail(self):
        """{jail: [ips]} de todas as jails, como o fail2ban informa."""
        return self._per_jail()

    def unban(self, ip, jail):
        """Libera um IP de uma jail (funciona em todas as versoes do fail2ban)."""
        self._run("set", jail, "unbanip", ip)

    def banned(self, per_jail=None):
        """Retorna {ip: set(jails)} com tudo que esta banido agora (nas jails configuradas)."""
        result = {}
        for jail, ips in (self._per_jail() if per_jail is None else per_jail).items():
            if self.jails and jail not in self.jails:
                continue
            for ip in ips:
                result.setdefault(str(ip), set()).add(jail)
        return result


EVENT_RE = re.compile(r"fail2ban\.actions.*?\[(?P<jail>[^\]]+)\]\s+"
                      r"(?P<action>Restore Ban|Ban|Unban)\s+(?P<ip>[0-9A-Fa-f:.]+)")
LINE_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
EVENT_KINDS = {"Ban": "ban", "Unban": "unban", "Restore Ban": "restore"}


def parse_event_line(line):
    """Linha do fail2ban.log -> (ts, tipo, jail, ip) ou None. Sem data na linha, usa a hora atual."""
    m = EVENT_RE.search(line)
    if not m:
        return None
    ts = None
    t = LINE_TS_RE.match(line)
    if t:
        try:
            ts = int(time.mktime(time.strptime(t.group(1), "%Y-%m-%d %H:%M:%S")))
        except (ValueError, OverflowError):
            ts = None
    return (ts or int(time.time()), EVENT_KINDS[m.group("action")], m.group("jail"), m.group("ip"))


class EventStore:
    """Historico de bloqueios/desbloqueios (SQLite), para contagens e estatisticas.

    tipos: ban / unban / restore (fail2ban) e bl-add / bl-del (blacklist)."""

    BLOCK_KINDS = ("ban", "bl-add")
    UNBLOCK_KINDS = ("unban", "bl-del")

    def __init__(self, path):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (ts INTEGER NOT NULL, kind TEXT NOT NULL, "
                        "ip TEXT NOT NULL, jail TEXT NOT NULL, source TEXT NOT NULL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS events_ts ON events (ts)")
        self.db.execute("CREATE INDEX IF NOT EXISTS events_ip ON events (ip, kind)")
        self.lock = threading.Lock()

    def add_many(self, rows):
        """rows: [(ts, tipo, ip, jail, origem)]"""
        if rows:
            with self.lock:
                # uma transacao so: em autocommit cada linha seria um commit (lento e visivel pela metade)
                self.db.execute("BEGIN")
                try:
                    self.db.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?)", rows)
                    self.db.execute("COMMIT")
                except sqlite3.Error:
                    self.db.execute("ROLLBACK")
                    raise

    def is_empty(self):
        with self.lock:
            return self.db.execute("SELECT 1 FROM events LIMIT 1").fetchone() is None

    def purge(self, days):
        with self.lock:
            return self.db.execute("DELETE FROM events WHERE ts < ?", (int(time.time()) - days * 86400,)).rowcount

    def query(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()


def import_fail2ban_history(store, logfile):
    """Primeira execucao: importa os eventos que ainda estao no fail2ban.log e nos logs rotacionados."""
    paths = sorted(glob.glob(logfile + ".*"), reverse=True) + [logfile]
    rows = []
    for path in paths:
        opener = gzip.open if path.endswith(".gz") else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    ev = parse_event_line(line)
                    if ev:
                        ts, kind, jail, ip = ev
                        key = normalize_ip(ip)
                        rows.append((ts, kind, str(key) if key is not None else ip, jail, "fail2ban"))
        except OSError as e:
            log.warning("historico: nao foi possivel ler %s: %s", path, e)
    store.add_many(rows)
    return len(rows)


class LogWatcher:
    """Acompanha o log do fail2ban (como tail -F), sobrevivendo a rotacao/truncamento."""

    def __init__(self, path):
        self.path = path
        self.fh = None
        self.ino = None
        self.partial = ""
        self.opened_once = False
        self.warned = False
        self._open()

    def _open(self):
        try:
            fh = open(self.path, "r", encoding="utf-8", errors="replace")
        except OSError as e:
            if not self.warned:
                log.warning("nao foi possivel abrir o log do fail2ban (%s); seguindo apenas com "
                            "a sincronizacao periodica", e)
                self.warned = True
            return False
        if not self.opened_once:
            fh.seek(0, os.SEEK_END)  # na partida, so interessa o que vier daqui pra frente
        self.fh, self.ino = fh, os.fstat(fh.fileno()).st_ino
        self.opened_once = True
        self.warned = False
        return True

    def _read(self):
        data = self.fh.read()
        if not data:
            return []
        parts = (self.partial + data).split("\n")
        self.partial = parts.pop()
        return parts

    def poll(self):
        if self.fh is None and not self._open():
            return []
        lines = self._read()
        try:
            st = os.stat(self.path)
        except OSError:
            st = None
        if st is None or st.st_ino != self.ino:
            log.debug("log do fail2ban rotacionado, reabrindo")
            self.fh.close()
            self.fh, self.partial = None, ""
            if st is not None and self._open():
                lines += self._read()
        elif st.st_size < self.fh.tell():
            log.debug("log do fail2ban truncado, relendo do inicio")
            self.fh.seek(0)
            self.partial = ""
            lines += self._read()
        return [ev for ev in map(parse_event_line, lines) if ev]


# --------------------------------------------------------------------------- #
# Agente
# --------------------------------------------------------------------------- #
LIST_PATHS = {4: "/ip/firewall/address-list", 6: "/ipv6/firewall/address-list"}
BLACKLIST_TAG = "blacklist"


class BlacklistError(Exception):
    pass


def is_network(entry):
    return isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network))


def normalize_ip(text):
    """'1.2.3.4', '1.2.3.4/32', '2001:db8::1/128' -> endereco; prefixos -> rede; invalido -> None."""
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None
    return net.network_address if net.num_addresses == 1 else net


def parse_blacklist_line(line):
    """'198.51.100.0/24   # scanner' -> ('198.51.100.0/24', 'scanner'); linha vazia/comentario -> ('', ...)."""
    text, _, comment = line.partition("#")
    tokens = text.split()
    return (tokens[0] if tokens else ""), comment.strip()


def parse_list(value):
    return [v.strip() for v in re.split(r"[,\s]+", value or "") if v.strip()]


class RoutersFileError(Exception):
    pass


PRIMARY_ID = "principal"
ROUTER_FIELDS = ("id", "name", "host", "port", "username", "password", "use_ssl", "timeout", "enabled")


def file_signature(path):
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def read_routers_file(path):
    """Roteadores adicionais (cadastrados pela interface web). Arquivo ausente = nenhum."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as e:
        raise RoutersFileError("nao foi possivel ler %s: %s" % (path, e))
    if not isinstance(data, dict) or not isinstance(data.get("routers", []), list):
        raise RoutersFileError("formato invalido em %s" % path)
    routers = []
    for r in data.get("routers", []):
        try:
            routers.append(dict(id=str(r["id"]), name=str(r.get("name") or r["host"]), host=str(r["host"]),
                                port=int(r.get("port", 8728)), username=str(r["username"]),
                                password=str(r.get("password", "")), use_ssl=bool(r.get("use_ssl", False)),
                                timeout=float(r.get("timeout", 10)), enabled=bool(r.get("enabled", True)),
                                primary=False))
        except (KeyError, TypeError, ValueError, AttributeError):
            raise RoutersFileError("roteador invalido em %s: %r" % (path, r))
    return routers


def write_routers_file(path, routers):
    """Grava os roteadores adicionais de forma atomica e com permissao 600 (contem senhas)."""
    data = {"routers": [{k: r[k] for k in ROUTER_FIELDS} for r in routers if not r.get("primary")]}
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


class Agent:
    def __init__(self, cfg, dry_run=False):
        mk, f2b, ag = cfg["mikrotik"], cfg["fail2ban"], cfg["agent"]
        self.primary = dict(id=PRIMARY_ID, name=mk.get("name").strip() or PRIMARY_ID, host=mk.get("host"),
                            port=mk.getint("port"), username=mk.get("username"), password=mk.get("password"),
                            use_ssl=mk.getboolean("use_ssl"), timeout=mk.getfloat("timeout"),
                            enabled=True, primary=True)
        self.list_name = mk.get("address_list")
        self.prefix = mk.get("comment_prefix")
        self.entry_timeout = mk.get("entry_timeout").strip()
        self.families = [4, 6] if mk.getboolean("ipv6") else [4]
        self.f2b = Fail2ban(f2b.get("client"), parse_list(f2b.get("jails")))
        self.f2b_log = f2b.get("logfile").strip()
        self.whitelist = [ipaddress.ip_network(n, strict=False) for n in parse_list(f2b.get("whitelist"))]
        self.blacklist_file = cfg["blacklist"].get("file").strip()
        self.routers_file = ag.get("routers_file").strip()
        self.events_db = ag.get("events_db").strip()
        self.events_retention = ag.getint("events_retention_days")
        self.events = None
        self._last_f2b = None
        self.sync_interval = ag.getfloat("sync_interval")
        self.debounce = ag.getfloat("debounce")
        self.retry_delay = ag.getfloat("retry_delay")
        self.dry_run = dry_run
        self.routers = [self.primary]
        self._routers_sig = None
        self._routers_loaded = False
        self._ignored_logged = set()
        self._errors = {}
        self._stop = False
        self.reload_routers()

    # -- roteadores ---------------------------------------------------------------
    def reload_routers(self):
        """Rele o routers.json se ele mudou. Retorna True se a lista mudou.
        Se o arquivo estiver invalido, mantem a lista anterior."""
        if not self.routers_file:
            return False
        sig = file_signature(self.routers_file)
        if sig == self._routers_sig:
            return False
        self._routers_sig = sig
        try:
            extra = read_routers_file(self.routers_file)
        except RoutersFileError as e:
            log.error("%s; mantendo a lista anterior de roteadores", e)
            return False
        routers, ids = [self.primary], {PRIMARY_ID}
        for r in extra:
            if r["id"] in ids:
                log.warning("roteador com id repetido em %s ignorado: %s", self.routers_file, r["id"])
                continue
            ids.add(r["id"])
            routers.append(r)
        self.routers = routers
        if self._routers_loaded:
            log.info("lista de roteadores atualizada: %s", self.describe_routers())
        self._routers_loaded = True
        return True

    # -- historico de eventos -------------------------------------------------------
    def open_events(self, import_history=False):
        """Abre o historico (SQLite). Na primeira vez importa o que ainda esta no log do fail2ban."""
        if not self.events_db:
            return None
        try:
            self.events = EventStore(self.events_db)
            if import_history and self.f2b_log and self.events.is_empty():
                n = import_fail2ban_history(self.events, self.f2b_log)
                log.info("historico: %d evento(s) importados de %s*", n, self.f2b_log)
            if import_history and self.events_retention > 0:
                purged = self.events.purge(self.events_retention)
                if purged:
                    log.info("historico: %d evento(s) com mais de %d dias removidos", purged, self.events_retention)
        except (sqlite3.Error, OSError) as e:
            log.error("historico desativado: nao foi possivel abrir %s: %s", self.events_db, e)
            self.events = None
        return self.events

    def record(self, rows):
        """Grava eventos [(ts, tipo, ip, jail, origem)] sem nunca derrubar o agente."""
        if self.events is None or not rows:
            return
        try:
            self.events.add_many(rows)
        except sqlite3.Error as e:
            self._report_error("eventos", "falha ao gravar o historico em %s: %s" % (self.events_db, e))

    def _record_diff(self, before, after, add_kind, del_kind, source, now=None):
        """Registra o que entrou e saiu entre dois estados {ip: jails}."""
        now = now or int(time.time())
        rows = [(now, add_kind, k, ",".join(sorted(after[k])) or source, source) for k in after if k not in before]
        rows += [(now, del_kind, k, ",".join(sorted(before[k])) or source, source) for k in before if k not in after]
        self.record(rows)

    def describe_routers(self):
        return ", ".join("%s (%s:%s%s)" % (r["name"], r["host"], r["port"], "" if r["enabled"] else ", desabilitado")
                         for r in self.routers)

    def api(self, router):
        return RouterOSApi(host=router["host"], port=router["port"], username=router["username"],
                           password=router["password"], use_ssl=router["use_ssl"], timeout=router["timeout"])

    # -- auxiliares -------------------------------------------------------------
    def _whitelisted(self, entry):
        for net in self.whitelist:
            if entry.version == net.version and (entry.overlaps(net) if is_network(entry) else entry in net):
                return True
        return False

    def _blacklist(self):
        """Le a blacklist: {chave: (ip_ou_rede, {"blacklist"})}. Arquivo ausente = vazia."""
        result = {}
        if not self.blacklist_file:
            return result
        try:
            with open(self.blacklist_file, encoding="utf-8") as fh:
                lines = fh.readlines()
        except FileNotFoundError:
            return result
        except OSError as e:
            raise BlacklistError("nao foi possivel ler a blacklist %s: %s" % (self.blacklist_file, e))
        for n, line in enumerate(lines, 1):
            text, _comment = parse_blacklist_line(line)
            if not text:
                continue
            entry = normalize_ip(text)
            if entry is None:
                self._log_ignored(text, "linha %d da blacklist invalida" % n)
            elif self._whitelisted(entry):
                self._log_ignored(str(entry), "esta na blacklist, mas tambem na whitelist")
            elif entry.version not in self.families:
                self._log_ignored(str(entry), "IPv6 desabilitado na configuracao")
            else:
                result[str(entry)] = (entry, {BLACKLIST_TAG})
        return result

    @staticmethod
    def _merge(banned, blacklist):
        desired = {k: (entry, set(tags)) for k, (entry, tags) in blacklist.items()}
        networks = [entry for entry, _ in blacklist.values() if is_network(entry)]
        for key, (ip, jails) in banned.items():
            if key in desired:
                desired[key][1].update(jails)
            elif not any(ip.version == net.version and ip in net for net in networks):
                desired[key] = (ip, jails)  # IP dentro de uma rede da blacklist ja esta bloqueado
        return desired

    def _desired(self):
        """O que deve estar bloqueado nos roteadores: ({chave: (ip_ou_rede, origens)}, fail2ban_ok).

        Se o fail2ban estiver fora do ar, aplica so a blacklist e sinaliza para nada ser removido."""
        blacklist = self._blacklist()
        try:
            banned = self._from_fail2ban()
        except Fail2banError as e:
            if not blacklist:
                raise
            self._report_error("fontes", "fail2ban indisponivel; aplicando apenas a blacklist, "
                                         "nada sera removido: %s" % e)
            return blacklist, False
        return self._merge(banned, blacklist), True

    def _from_fail2ban(self, per_jail=None):
        """IPs banidos no fail2ban: {ip_str: (ip, jails)}."""
        desired = {}
        for raw, jails in self.f2b.banned(per_jail).items():
            ip = normalize_ip(raw)
            if ip is None or not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                self._log_ignored(raw, "endereco invalido")
                continue
            if self._whitelisted(ip):
                self._log_ignored(raw, "esta na whitelist")
                continue
            if ip.version not in self.families:
                self._log_ignored(raw, "IPv6 desabilitado na configuracao")
                continue
            desired[str(ip)] = (ip, jails)
        self._last_f2b = {k: jails for k, (_ip, jails) in desired.items()}
        return desired

    def _log_ignored(self, ip, why):
        if ip not in self._ignored_logged:
            log.warning("IGNORADO %s (%s) - nao sera bloqueado no MikroTik", ip, why)
            self._ignored_logged.add(ip)

    def router_rows(self, api):
        """Todas as entradas da address-list no roteador."""
        rows = []
        for fam in self.families:
            res, _ = api.talk([LIST_PATHS[fam] + "/print", "=.proplist=.id,address,comment,timeout,disabled",
                               "?list=" + self.list_name])
            for r in res:
                addr = r.get("address", "")
                ip = normalize_ip(addr)
                comment = r.get("comment", "")
                rows.append(dict(key=str(ip) if ip is not None else addr, entry=ip, family=fam, id=r.get(".id"),
                                 comment=comment, managed=comment.startswith(self.prefix),
                                 timeout=r.get("timeout", ""), disabled=r.get("disabled") == "true"))
        return rows

    def _router_entries(self, api):
        """Retorna (gerenciadas {ip_str: (familia, .id, comentario)}, demais enderecos da lista)."""
        managed, others = {}, set()
        for r in self.router_rows(api):
            if r["managed"]:
                managed[r["key"]] = (r["family"], r["id"], r["comment"])
            else:
                others.add(r["key"])
        return managed, others

    # -- operacoes ----------------------------------------------------------------
    def sync(self, reason="periodica"):
        """Reconciliacao completa com todos os roteadores. Retorna True se nao houve erros."""
        # se fail2ban e blacklist falharem, levanta excecao antes de tocar nos roteadores
        desired, f2b_ok = self._desired()
        if f2b_ok:
            self._clear_error("fontes", "fail2ban respondendo novamente")
        self.reload_routers()
        ok = f2b_ok
        for router in self.routers:
            if not router["enabled"]:
                continue
            try:
                errors = self._sync_router(router, desired, f2b_ok, reason)
                self._clear_error(router["id"], "comunicacao com o MikroTik [%s] restabelecida" % router["name"])
                ok = ok and errors == 0
            except (RouterOSError, OSError) as e:
                ok = False
                self._report_error(router["id"], "falha ao comunicar com o MikroTik [%s] %s:%s: %s"
                                   % (router["name"], router["host"], router["port"], e))
        return ok

    def _sync_router(self, router, desired, f2b_ok, reason):
        name = router["name"]
        added = removed = errors = 0
        with self.api(router) as api:
            managed, others = self._router_entries(api)
            to_add = sorted(k for k in desired if k not in managed and k not in others)
            to_remove = sorted(k for k in managed if k not in desired) if f2b_ok else []
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")

            for key in to_add:
                ip, jails = desired[key]
                jail_txt = ",".join(sorted(jails))
                words = [LIST_PATHS[ip.version] + "/add", "=list=" + self.list_name, "=address=" + key,
                         "=comment=%s [%s] %s" % (self.prefix, jail_txt, stamp)]
                if self.entry_timeout:
                    words.append("=timeout=" + self.entry_timeout)
                if self.dry_run:
                    log.info("[dry-run] BLOQUEARIA no MikroTik [%s]: %s (jail: %s)", name, key, jail_txt)
                    continue
                try:
                    api.talk(words)
                    added += 1
                    log.info("BLOQUEADO no MikroTik [%s]: %s (jail: %s)", name, key, jail_txt)
                except RouterOSTrap as e:
                    errors += 1
                    log.error("erro ao bloquear %s no MikroTik [%s]: %s", key, name, e)

            for key in to_remove:
                fam, rid, comment = managed[key]
                if self.dry_run:
                    log.info("[dry-run] LIBERARIA no MikroTik [%s]: %s", name, key)
                    continue
                try:
                    api.talk([LIST_PATHS[fam] + "/remove", "=.id=" + rid])
                    removed += 1
                    log.info("LIBERADO no MikroTik [%s]: %s (%s)", name, key, comment)
                except RouterOSTrap as e:
                    errors += 1
                    log.error("erro ao liberar %s no MikroTik [%s]: %s", key, name, e)

        level = logging.INFO if (to_add or to_remove or errors) else logging.DEBUG
        log.log(level, "sincronizacao %s [%s]: %d a bloquear (fail2ban + blacklist), %d no roteador | "
                       "+%d -%d, %d erro(s)", reason, name, len(desired), len(managed) + added - removed,
                added, removed, errors)
        return errors

    def flush(self):
        for router in self.routers:
            if not router["enabled"]:
                continue
            try:
                with self.api(router) as api:
                    managed, _ = self._router_entries(api)
                    for key, (fam, rid, _comment) in sorted(managed.items()):
                        if self.dry_run:
                            log.info("[dry-run] REMOVERIA do MikroTik [%s]: %s", router["name"], key)
                            continue
                        api.talk([LIST_PATHS[fam] + "/remove", "=.id=" + rid])
                        log.info("REMOVIDO do MikroTik [%s]: %s", router["name"], key)
                log.info("flush [%s] concluido: %d entrada(s) do agente %s", router["name"], len(managed),
                         "seriam removidas" if self.dry_run else "removidas")
            except (RouterOSError, OSError) as e:
                log.error("flush [%s] falhou: %s", router["name"], e)

    def test(self):
        ok = True
        desired = None
        print("blacklist ...", end=" ", flush=True)
        try:
            blacklist = self._blacklist()
            if not self.blacklist_file:
                print("desativada")
            elif not os.path.exists(self.blacklist_file):
                print("OK - %s nao existe (vazia)" % self.blacklist_file)
            else:
                print("OK - %d entrada(s) em %s" % (len(blacklist), self.blacklist_file))
        except BlacklistError as e:
            print("FALHOU: %s" % e)
            blacklist, ok = {}, False
        print("fail2ban ...", end=" ", flush=True)
        try:
            banned = self._from_fail2ban()
            print("OK - %d IP(s) banido(s) a replicar" % len(banned))
            if ok:
                desired = self._merge(banned, blacklist)
        except Fail2banError as e:
            print("FALHOU: %s" % e)
            ok = False
        for router in self.routers:
            print("MikroTik [%s] %s:%s ..." % (router["name"], router["host"], router["port"]), end=" ", flush=True)
            if not router["enabled"]:
                print("desabilitado")
                continue
            try:
                with self.api(router) as api:
                    res, _ = api.talk(["/system/resource/print"])
                    info = res[0] if res else {}
                    managed, others = self._router_entries(api)
                print("OK - %s RouterOS %s" % (info.get("board-name", "?"), info.get("version", "?")))
                print("  lista '%s': %d entrada(s) do agente, %d outra(s)"
                      % (self.list_name, len(managed), len(others)))
                if desired is not None:
                    print("  a adicionar: %d   a remover: %d" % (
                        len([k for k in desired if k not in managed and k not in others]),
                        len([k for k in managed if k not in desired])))
            except (RouterOSError, OSError) as e:
                print("FALHOU: %s" % e)
                ok = False
        return ok

    def safe_sync(self, reason):
        try:
            return self.sync(reason)
        except Fail2banError as e:
            self._report_error("fontes", "fail2ban indisponivel, nada foi alterado nos roteadores: %s" % e)
        except BlacklistError as e:
            self._report_error("fontes", "%s; nada foi alterado nos roteadores" % e)
        except Exception:
            log.exception("erro inesperado na sincronizacao")
        return False

    def _report_error(self, key, msg):
        # evita encher o log com o mesmo erro a cada tentativa: repete no maximo a cada 5 min
        last_msg, last_time = self._errors.get(key, (None, 0.0))
        now = time.monotonic()
        if msg != last_msg or now - last_time >= 300:
            log.error("%s (nova tentativa em %ds)", msg, self.retry_delay)
            self._errors[key] = (msg, now)

    def _clear_error(self, key, msg):
        if self._errors.pop(key, None) is not None:
            log.info(msg)

    def run_forever(self):
        def on_signal(signum, _frame):
            log.info("sinal %d recebido, encerrando", signum)
            self._stop = True

        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)

        # o log passa a ser acompanhado antes da importacao do historico: nada escrito durante ela se perde
        watcher = LogWatcher(self.f2b_log) if self.f2b_log else None
        self.open_events(import_history=True)
        bl_sig = file_signature(self.blacklist_file) if self.blacklist_file else None
        bl_snapshot = self._blacklist_snapshot()
        f2b_snapshot = None  # so usado sem log do fail2ban: eventos deduzidos entre sincronizacoes
        next_sync = 0.0
        pending_since = last_event = None
        labels = {"ban": "Ban", "unban": "Unban", "restore": "Restore Ban"}

        while not self._stop:
            now = time.monotonic()
            changed = False
            if watcher is not None:
                rows = []
                for ts, kind, jail, ip in watcher.poll():
                    log.info("fail2ban: [%s] %s %s", jail, labels[kind], ip)
                    key = normalize_ip(ip)
                    rows.append((ts, kind, str(key) if key is not None else ip, jail, "fail2ban"))
                    changed = True
                self.record(rows)
            if self.blacklist_file:
                sig = file_signature(self.blacklist_file)
                if sig != bl_sig:
                    log.info("blacklist %s alterada", self.blacklist_file)
                    bl_sig, changed = sig, True
                    snapshot = self._blacklist_snapshot()
                    if snapshot is not None and bl_snapshot is not None:
                        self._record_diff(bl_snapshot, snapshot, "bl-add", "bl-del", BLACKLIST_TAG)
                    if snapshot is not None:
                        bl_snapshot = snapshot
            if self.reload_routers():
                changed = True
            if changed:
                last_event = now
                if pending_since is None:
                    pending_since = now

            due_event = pending_since is not None and (
                now - last_event >= self.debounce or now - pending_since >= 10)
            if due_event or now >= next_sync:
                reason = "por evento" if due_event else "periodica"
                pending_since = last_event = None
                ok = self.safe_sync(reason)
                next_sync = time.monotonic() + (self.sync_interval if ok else self.retry_delay)
                if watcher is None and self._last_f2b is not None:
                    if f2b_snapshot is not None:
                        self._record_diff(f2b_snapshot, self._last_f2b, "ban", "unban", "fail2ban")
                    f2b_snapshot = self._last_f2b

            time.sleep(0.5)
        log.info("agente finalizado")

    def _blacklist_snapshot(self):
        if not self.blacklist_file:
            return {}
        try:
            return {k: set() for k in self._blacklist()}
        except BlacklistError:
            return None


# --------------------------------------------------------------------------- #
# Configuracao, log e entrada
# --------------------------------------------------------------------------- #
DEFAULTS = {
    "mikrotik": {"name": PRIMARY_ID, "port": "8728", "use_ssl": "no", "timeout": "10", "address_list": "fail2ban",
                 "comment_prefix": "f2b-agent", "entry_timeout": "", "ipv6": "no"},
    "fail2ban": {"client": "/usr/bin/fail2ban-client", "logfile": "/var/log/fail2ban.log", "jails": "",
                 "whitelist": "127.0.0.0/8, ::1"},
    "blacklist": {"file": "/etc/f2b-mikrotik/blacklist.txt"},
    "agent": {"sync_interval": "60", "debounce": "2", "retry_delay": "15",
              "logfile": "/var/log/f2b-mikrotik.log", "log_level": "INFO",
              "log_max_bytes": "10485760", "log_backups": "5", "lockfile": "/run/f2b-mikrotik.lock",
              "routers_file": "/etc/f2b-mikrotik/routers.json",
              "events_db": "/var/lib/f2b-mikrotik/events.db", "events_retention_days": "365"},
    "web": {"bind": "0.0.0.0", "port": "8088", "username": "admin", "password": "",
            "tls_cert": "", "tls_key": "", "geoip": "yes", "geo_file": "/var/lib/f2b-mikrotik/geo.tsv.gz",
            "geo_provider": "rir", "ipinfo_token": "", "geo_cache_days": "30", "ipinfo_url": ""},
}


def load_config(path):
    cfg = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";",))
    cfg.read_dict(DEFAULTS)
    if not cfg.read(path, encoding="utf-8"):
        raise SystemExit("arquivo de configuracao nao encontrado: %s" % path)
    for key in ("host", "username", "password"):
        if not cfg["mikrotik"].get(key, "").strip():
            raise SystemExit("configuracao: [mikrotik] %s e obrigatorio" % key)
    return cfg


def setup_logging(cfg, verbose):
    ag = cfg["agent"]
    level = logging.DEBUG if verbose else getattr(logging, ag.get("log_level").upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    log.setLevel(level)
    logfile = ag.get("logfile").strip()
    if logfile:
        fh = logging.handlers.RotatingFileHandler(logfile, maxBytes=ag.getint("log_max_bytes"),
                                                  backupCount=ag.getint("log_backups"), encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
    if verbose or sys.stderr.isatty() or not logfile:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        log.addHandler(sh)


def acquire_lock(path):
    try:
        import fcntl
    except ImportError:  # sem fcntl (ex.: Windows) - segue sem trava
        return None
    fh = open(path, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit("outra instancia ja esta em execucao (trava %s)" % path)
    fh.write(str(os.getpid()))
    fh.flush()
    return fh


def main():
    ap = argparse.ArgumentParser(description="Replica os bloqueios do fail2ban para um roteador MikroTik.")
    ap.add_argument("-c", "--config", default="/etc/f2b-mikrotik/config.ini", help="arquivo de configuracao")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="faz uma sincronizacao e sai (modo cron)")
    mode.add_argument("--test", action="store_true", help="testa fail2ban e roteador sem alterar nada")
    mode.add_argument("--flush", action="store_true", help="remove do roteador todas as entradas do agente")
    ap.add_argument("--dry-run", action="store_true", help="mostra o que faria, sem alterar o roteador")
    ap.add_argument("-v", "--verbose", action="store_true", help="log em DEBUG e tambem no terminal")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args()

    cfg = load_config(args.config)
    agent = Agent(cfg, dry_run=args.dry_run or args.test)

    if args.test:
        sys.exit(0 if agent.test() else 1)

    setup_logging(cfg, args.verbose)
    lock = acquire_lock(cfg["agent"].get("lockfile"))  # noqa: F841 (mantem a trava ate o fim)

    if args.flush:
        agent.flush()
    elif args.once:
        sys.exit(0 if agent.safe_sync("cron") else 1)
    else:
        log.info("f2b-mikrotik %s iniciado: lista=%s jails=%s%s", __version__, agent.list_name,
                 ",".join(sorted(agent.f2b.jails)) or "todas", " [DRY-RUN]" if agent.dry_run else "")
        log.info("roteadores: %s", agent.describe_routers())
        agent.run_forever()


if __name__ == "__main__":
    main()
