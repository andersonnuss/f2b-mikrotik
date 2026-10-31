#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
f2b-mikrotik store - configuracao em SQLite, editada pelo painel.

Guarda roteadores, blacklist, whitelist, configuracoes de operacao, usuarios do painel e a
trilha de auditoria. O config.ini fica so com o que nao pode ser editado pela web (caminhos de
comandos e arquivos, porta/TLS do painel): o agente e o painel rodam como root, e deixar um
caminho de comando editavel pela web daria a quem tem uma senha do painel o controle do servidor.

Na primeira abertura importa a configuracao antiga (config.ini, routers.json, blacklist.txt).
"""

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time

ROLES = ("leitura", "operador", "admin")
ROLE_LABEL = {"leitura": "somente leitura", "operador": "operador", "admin": "administrador"}
PBKDF2_ITER = 200000
MIN_PASSWORD = 8

# chave: (tipo, padrao, minimo/opcoes, maximo, descricao)
SETTINGS = {
    "sync_interval": ("int", 60, 10, 3600, "reconciliacao completa a cada (segundos)"),
    "debounce": ("float", 2.0, 0, 60, "espera apos um evento antes de sincronizar (segundos)"),
    "retry_delay": ("int", 15, 5, 3600, "nova tentativa apos falha (segundos)"),
    "entry_timeout": ("duration", "", None, None, "validade da entrada no roteador (ex.: 7d; vazio = permanente)"),
    "ipv6": ("bool", False, None, None, "replicar tambem IPv6"),
    "jails": ("list", "", None, None, "jails replicadas (vazio = todas)"),
    "events_retention_days": ("int", 365, 0, 3650, "dias de historico de eventos (0 = sem limite)"),
    "audit_retention_days": ("int", 365, 0, 3650, "dias de auditoria (0 = sem limite)"),
    "geoip": ("bool", True, None, None, "pais pelas tabelas dos RIRs"),
    "geo_provider": ("choice", "rir", ("rir", "ipinfo"), None, "fonte do pais"),
    "ipinfo_token": ("secret", "", None, None, "token do ipinfo Lite"),
    "geo_cache_days": ("int", 180, 1, 365, "dias de cache do ipinfo"),
    "router_hold": ("duration", "", None, None,
                    "retencao no MikroTik depois que o fail2ban libera (ex.: 7d; vazio = segue o fail2ban)"),
    "router_hold_increment": ("bool", False, None, None, "dobrar a retencao a cada reincidencia (em 30 dias)"),
    "router_hold_max": ("duration", "90d", None, None, "retencao maxima com reincidencia"),
}
HOLD_WINDOW = 30 * 86400  # reincidencia: nova liberacao ate 30 dias depois da anterior
DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text):
    """'7d', '1d12h', '90m' -> segundos; vazio/'0' -> 0."""
    text = str(text or "").strip().lower()
    if not text or text == "0":
        return 0
    if not DURATION_RE.match(text):
        raise ValueError("duracao invalida: %r" % text)
    return sum(int(n) * DURATION_UNITS[u] for n, u in re.findall(r"(\d+)([smhdw])", text))
SECRET_MASK = "********"
DURATION_RE = re.compile(r"^(\d+[smhdw])+$")
HOST_RE = re.compile(r"^[A-Za-z0-9.:\-\[\]]{1,253}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{2,40}$")


class StoreError(Exception):
    """Erro de validacao/regra; a mensagem vai para o usuario."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def now():
    return int(time.time())


def normalize_entry(text):
    """'1.2.3.4', '1.2.3.0/24' -> objeto ipaddress (endereco ou rede); invalido -> None."""
    try:
        net = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None
    return net.network_address if net.num_addresses == 1 else net


def hash_password(password, salt=None, iterations=PBKDF2_ITER):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt.hex(), digest.hex())


def check_password(password, stored):
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(calc.hex(), digest)
    except (ValueError, AttributeError):
        return False


def mask(key, value):
    return SECRET_MASK if SETTINGS.get(key, ("",))[0] == "secret" and value else value


class ConfigStore:
    def __init__(self, path):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.path = path
        fresh = not os.path.exists(path)
        self.db = sqlite3.connect(path, timeout=15, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        if fresh:
            try:
                os.chmod(path, 0o600)  # contem senhas de roteadores e hashes de usuarios
            except OSError:
                pass
        self.lock = threading.RLock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,
                updated_at INTEGER, updated_by TEXT);
            CREATE TABLE IF NOT EXISTS routers (id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
                port INTEGER NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL, use_ssl INTEGER NOT NULL,
                timeout REAL NOT NULL, enabled INTEGER NOT NULL, created_at INTEGER, created_by TEXT,
                updated_at INTEGER, updated_by TEXT);
            CREATE TABLE IF NOT EXISTS blacklist (entry TEXT PRIMARY KEY, comment TEXT NOT NULL DEFAULT '',
                created_at INTEGER, created_by TEXT, expires_at INTEGER);
            CREATE TABLE IF NOT EXISTS whitelist (entry TEXT PRIMARY KEY, comment TEXT NOT NULL DEFAULT '',
                created_at INTEGER, created_by TEXT);
            CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY COLLATE NOCASE, name TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL, password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER, created_by TEXT, updated_at INTEGER, updated_by TEXT, last_login INTEGER);
            CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
                actor TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', action TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
            CREATE INDEX IF NOT EXISTS audit_actor ON audit (actor);
            CREATE TABLE IF NOT EXISTS holds (ip TEXT PRIMARY KEY, jails TEXT NOT NULL DEFAULT '',
                first_at INTEGER, last_unban INTEGER, cycles INTEGER NOT NULL DEFAULT 0, release_at INTEGER,
                ended INTEGER NOT NULL DEFAULT 1, released_by TEXT, released_at INTEGER, skip_until INTEGER);
            CREATE INDEX IF NOT EXISTS holds_release ON holds (ended, release_at);
        """)

    # -- infraestrutura -------------------------------------------------------------
    def query(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def _tx(self, immediate=False):
        return _Transaction(self, immediate)

    def data_version(self):
        """Muda quando OUTRO processo grava no banco (o agente usa para perceber edicoes do painel)."""
        with self.lock:
            return self.db.execute("PRAGMA data_version").fetchone()[0]

    def get_meta(self, key, default=None):
        rows = self.query("SELECT value FROM meta WHERE key = ?", (key,))
        return rows[0]["value"] if rows else default

    # -- auditoria ------------------------------------------------------------------
    def audit(self, actor, action, target="", details=None, ip=""):
        """Registra uma acao. Nunca levanta excecao: auditoria falhar nao pode derrubar a operacao."""
        try:
            with self.lock:
                self.db.execute("INSERT INTO audit (ts, actor, ip, action, target, details) VALUES (?, ?, ?, ?, ?, ?)",
                                (now(), actor or "?", ip or "", action, str(target or ""),
                                 json.dumps(details, ensure_ascii=False, sort_keys=True) if details else ""))
        except sqlite3.Error:
            pass

    def audit_query(self, actor="", action="", text="", since=None, until=None, limit=200, before_id=None):
        sql, args = "SELECT * FROM audit WHERE 1=1", []
        if actor:
            sql += " AND actor = ?"
            args.append(actor)
        if action:
            sql += " AND action LIKE ?"
            args.append(action + "%")
        if text:
            sql += " AND (target LIKE ? OR details LIKE ? OR ip LIKE ?)"
            args += ["%" + text + "%"] * 3
        if since:
            sql += " AND ts >= ?"
            args.append(int(since))
        if until:
            sql += " AND ts < ?"
            args.append(int(until))
        if before_id:
            sql += " AND id < ?"
            args.append(int(before_id))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        rows = self.query(sql, args)
        for r in rows:
            try:
                r["details"] = json.loads(r["details"]) if r["details"] else None
            except ValueError:
                pass
        return rows

    def audit_purge(self, days):
        if days <= 0:
            return 0
        with self.lock:
            return self.db.execute("DELETE FROM audit WHERE ts < ?", (now() - days * 86400,)).rowcount

    # -- configuracoes --------------------------------------------------------------
    def settings(self):
        values = {k: spec[1] for k, spec in SETTINGS.items()}
        for row in self.query("SELECT key, value FROM settings"):
            if row["key"] in SETTINGS:
                try:
                    values[row["key"]] = json.loads(row["value"])
                except ValueError:
                    pass
        return values

    def public_settings(self):
        return {k: (bool(v) if SETTINGS[k][0] == "secret" else v) for k, v in self.settings().items()}

    @staticmethod
    def validate_setting(key, value):
        if key not in SETTINGS:
            raise StoreError("configuracao desconhecida: %s" % key)
        kind, _default, lo, hi, label = SETTINGS[key]
        try:
            if kind == "int":
                value = int(value)
            elif kind == "float":
                value = float(value)
            elif kind == "bool":
                value = value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "sim", "on")
            elif kind == "list":
                items = value if isinstance(value, list) else re.split(r"[,\s]+", str(value or ""))
                value = ",".join(sorted({str(i).strip() for i in items if str(i).strip()}))
                if value and not re.match(r"^[A-Za-z0-9_.,-]+$", value):
                    raise ValueError
            elif kind == "duration":
                value = str(value or "").strip()
                if value and not DURATION_RE.match(value):
                    raise ValueError
            elif kind == "choice":
                value = str(value)
                if value not in lo:
                    raise ValueError
            else:
                value = str(value or "").strip()
        except (TypeError, ValueError):
            raise StoreError("valor invalido para %s (%s)" % (key, label))
        if kind in ("int", "float") and not lo <= value <= hi:
            raise StoreError("%s deve estar entre %s e %s" % (key, lo, hi))
        return value

    def update_settings(self, changes, actor, ip=""):
        current = self.settings()
        diff = {}
        for key, value in changes.items():
            if SETTINGS.get(key, ("",))[0] == "secret" and value in (SECRET_MASK, None):
                continue  # campo de segredo nao reenviado: mantem o atual
            value = self.validate_setting(key, value)
            if value != current[key]:
                diff[key] = [mask(key, current[key]), mask(key, value)]
                current[key] = value
        if not diff:
            return {}
        with self._tx() as db:
            for key in diff:
                db.execute("INSERT OR REPLACE INTO settings VALUES (?, ?, ?, ?)",
                           (key, json.dumps(current[key]), now(), actor))
        self.audit(actor, "config.alterada", ", ".join(sorted(diff)), diff, ip)
        return diff

    # -- roteadores -----------------------------------------------------------------
    def routers(self):
        return [dict(r, use_ssl=bool(r["use_ssl"]), enabled=bool(r["enabled"]))
                for r in self.query("SELECT * FROM routers ORDER BY created_at, name")]

    def get_router(self, rid):
        for r in self.routers():
            if r["id"] == rid:
                return r
        raise StoreError("roteador nao encontrado", 404)

    @staticmethod
    def validate_router(data, current=None):
        if not isinstance(data, dict):
            raise StoreError("dados invalidos")

        def text(field, limit):
            value = data.get(field, current.get(field) if current else "")
            value = "" if value is None else str(value).strip()
            if not value:
                raise StoreError("campo obrigatorio: %s" % field)
            if len(value) > limit:
                raise StoreError("campo muito longo: %s" % field)
            return value

        use_ssl = bool(data.get("use_ssl", current["use_ssl"] if current else False))
        host = text("host", 253)
        if not HOST_RE.match(host):
            raise StoreError("host invalido")
        try:
            port = int(data.get("port") or (current["port"] if current else (8729 if use_ssl else 8728)))
            timeout = float(data.get("timeout") or (current["timeout"] if current else 10))
        except (TypeError, ValueError):
            raise StoreError("porta ou timeout invalido")
        if not 1 <= port <= 65535 or not 1 <= timeout <= 60:
            raise StoreError("porta (1-65535) ou timeout (1-60 s) fora do intervalo")
        password = data.get("password") or (current["password"] if current else "")
        if not password:
            raise StoreError("campo obrigatorio: password")
        return dict(id=current["id"] if current else secrets.token_hex(4), name=text("name", 40), host=host,
                    port=port, username=text("username", 64), password=str(password), use_ssl=use_ssl,
                    timeout=timeout, enabled=bool(data.get("enabled", current["enabled"] if current else True)))

    def save_router(self, router, actor, ip="", created=False):
        before = None if created else self.get_router(router["id"])
        with self._tx() as db:
            if created:
                db.execute("INSERT INTO routers (id, name, host, port, username, password, use_ssl, timeout, "
                           "enabled, created_at, created_by, updated_at, updated_by) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (router["id"], router["name"], router["host"], router["port"], router["username"],
                            router["password"], int(router["use_ssl"]), router["timeout"], int(router["enabled"]),
                            now(), actor, now(), actor))
            else:
                db.execute("UPDATE routers SET name=?, host=?, port=?, username=?, password=?, use_ssl=?, timeout=?, "
                           "enabled=?, updated_at=?, updated_by=? WHERE id=?",
                           (router["name"], router["host"], router["port"], router["username"], router["password"],
                            int(router["use_ssl"]), router["timeout"], int(router["enabled"]), now(), actor,
                            router["id"]))
        if created:
            self.audit(actor, "roteador.criado", router["name"],
                       {k: router[k] for k in ("host", "port", "username", "use_ssl", "enabled")}, ip)
        else:
            diff = {k: [before[k], router[k]] for k in ("name", "host", "port", "username", "use_ssl", "timeout",
                                                         "enabled") if before[k] != router[k]}
            if before["password"] != router["password"]:
                diff["password"] = [SECRET_MASK, "(alterada)"]
            self.audit(actor, "roteador.alterado", router["name"], diff, ip)
        return router

    def delete_router(self, rid, actor, ip="", details=None):
        router = self.get_router(rid)
        with self._tx() as db:
            db.execute("DELETE FROM routers WHERE id = ?", (rid,))
        self.audit(actor, "roteador.removido", router["name"], dict(details or {}, host=router["host"]), ip)
        return router

    # -- blacklist e whitelist ------------------------------------------------------
    def blacklist(self, include_expired=False):
        sql = "SELECT * FROM blacklist"
        if not include_expired:
            sql += " WHERE expires_at IS NULL OR expires_at > %d" % now()
        return self.query(sql + " ORDER BY created_at")

    def whitelist(self):
        return self.query("SELECT * FROM whitelist ORDER BY created_at")

    def list_add(self, table, entry, comment, actor, ip="", expires_at=None):
        assert table in ("blacklist", "whitelist")
        key = str(entry)
        comment = re.sub(r"[\r\n]+", " ", str(comment or "")).strip()[:120]
        with self._tx() as db:
            if db.execute("SELECT 1 FROM %s WHERE entry = ?" % table, (key,)).fetchone():
                raise StoreError("%s ja esta na %s" % (key, table), 409)
            if table == "blacklist":
                db.execute("INSERT INTO blacklist VALUES (?, ?, ?, ?, ?)", (key, comment, now(), actor, expires_at))
            else:
                db.execute("INSERT INTO whitelist VALUES (?, ?, ?, ?)", (key, comment, now(), actor))
        details = {"comentario": comment} if comment else {}
        if expires_at:
            details["expira_em"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(expires_at))
        self.audit(actor, "%s.incluido" % table, key, details or None, ip)

    def list_remove(self, table, entry, actor, ip="", action=None):
        assert table in ("blacklist", "whitelist")
        key = str(entry)
        with self._tx() as db:
            row = db.execute("SELECT * FROM %s WHERE entry = ?" % table, (key,)).fetchone()
            if row is None:
                raise StoreError("%s nao esta na %s" % (key, table), 404)
            db.execute("DELETE FROM %s WHERE entry = ?" % table, (key,))
        self.audit(actor, action or "%s.removido" % table, key,
                   {"comentario": row["comment"]} if row["comment"] else None, ip)

    def expire_blacklist(self, actor="agente"):
        """Remove as entradas vencidas da blacklist. Retorna as removidas."""
        expired = self.query("SELECT * FROM blacklist WHERE expires_at IS NOT NULL AND expires_at <= ?", (now(),))
        for row in expired:
            try:
                self.list_remove("blacklist", row["entry"], actor, action="blacklist.expirado")
            except StoreError:
                pass
        return expired

    # -- retencao no MikroTik depois do unban do fail2ban ------------------------------
    @staticmethod
    def hold_duration(settings, cycles):
        base = parse_duration(settings.get("router_hold"))
        if not base:
            return 0
        if not settings.get("router_hold_increment"):
            return base
        cap = parse_duration(settings.get("router_hold_max")) or base
        return min(base * (2 ** max(0, cycles - 1)), max(cap, base))

    def hold_unbanned(self, ip, jails, ts, settings):
        """O fail2ban liberou `ip` em `ts`: retem no MikroTik. Retorna a linha da retencao, ou None se
        nao houve retencao (desativada, liberacao pedida no painel ou evento repetido)."""
        if not parse_duration(settings.get("router_hold")):
            return None
        with self._tx() as db:
            row = db.execute("SELECT * FROM holds WHERE ip = ?", (ip,)).fetchone()
            if row is not None and row["skip_until"] and row["skip_until"] >= ts:
                db.execute("UPDATE holds SET skip_until = NULL WHERE ip = ?", (ip,))
                return None  # desbanido no painel: libera tudo, sem retencao
            recent = row is not None and row["last_unban"] and ts - row["last_unban"] <= HOLD_WINDOW
            cycles = (row["cycles"] + 1) if recent else 1
            release = ts + self.hold_duration(settings, cycles)
            if row is not None and not row["ended"] and row["release_at"] and row["release_at"] > release:
                release = row["release_at"]  # nunca encurta uma retencao em andamento
            names = sorted(set(filter(None, (row["jails"].split(",") if row else []) + str(jails or "").split(","))))
            if row is None:
                db.execute("INSERT INTO holds (ip, jails, first_at, last_unban, cycles, release_at, ended) "
                           "VALUES (?, ?, ?, ?, ?, ?, 0)", (ip, ",".join(names), ts, ts, cycles, release))
            else:
                db.execute("UPDATE holds SET jails=?, last_unban=?, cycles=?, release_at=?, ended=0, "
                           "released_by=NULL, released_at=NULL WHERE ip=?",
                           (",".join(names), ts, cycles, release, ip))
        self.audit("agente", "retencao.iniciada", ip,
                   {"jails": ",".join(names), "ate": time.strftime("%Y-%m-%d %H:%M", time.localtime(release)),
                    "reincidencia": cycles})
        return {"ip": ip, "release_at": release, "cycles": cycles, "jails": ",".join(names)}

    def holds_active(self):
        return self.query("SELECT * FROM holds WHERE ended = 0 AND release_at > ? ORDER BY release_at", (now(),))

    def hold_skip(self, ip, seconds=180):
        """O painel vai desbanir `ip`: a proxima liberacao do fail2ban nao gera retencao."""
        with self._tx() as db:  # sem ON CONFLICT: funciona tambem com SQLite antigo (< 3.24)
            if db.execute("SELECT 1 FROM holds WHERE ip = ?", (ip,)).fetchone():
                db.execute("UPDATE holds SET skip_until = ? WHERE ip = ?", (now() + seconds, ip))
            else:
                db.execute("INSERT INTO holds (ip, skip_until) VALUES (?, ?)", (ip, now() + seconds))

    def hold_release(self, ip, actor, ip_addr="", reason=None):
        """Libera agora uma retencao em andamento. Retorna True se havia uma."""
        with self._tx() as db:
            row = db.execute("SELECT * FROM holds WHERE ip = ? AND ended = 0 AND release_at > ?", (ip, now())).fetchone()
            if row is None:
                return False
            db.execute("UPDATE holds SET ended=1, released_by=?, released_at=? WHERE ip=?", (actor, now(), ip))
        self.audit(actor, "retencao.liberada", ip,
                   dict({"previsto": time.strftime("%Y-%m-%d %H:%M", time.localtime(row["release_at"]))},
                        **({"motivo": reason} if reason else {})), ip_addr)
        return True

    def end_active_holds(self, actor, ip_addr="", reason=""):
        """Encerra todas as retencoes em andamento (ex.: retencao desligada). Retorna os IPs."""
        rows = self.query("SELECT ip FROM holds WHERE ended = 0")
        if not rows:
            return []
        for r in rows:
            self.hold_release(r["ip"], actor, ip_addr, reason)
        with self._tx() as db:  # inclui as que ja tinham vencido e ainda nao foram marcadas
            db.execute("UPDATE holds SET ended = 1 WHERE ended = 0")
        return [r["ip"] for r in rows]

    def expire_holds(self, actor="agente"):
        """Marca como encerradas as retencoes vencidas. Retorna as encerradas."""
        rows = self.query("SELECT * FROM holds WHERE ended = 0 AND release_at <= ?", (now(),))
        for r in rows:
            with self._tx() as db:
                db.execute("UPDATE holds SET ended=1, released_by=?, released_at=? WHERE ip=? AND ended=0",
                           (actor, now(), r["ip"]))
            self.audit(actor, "retencao.expirada", r["ip"], {"jails": r["jails"], "reincidencia": r["cycles"]})
        return rows

    def next_hold_release(self):
        rows = self.query("SELECT MIN(release_at) AS t FROM holds WHERE ended = 0 AND release_at > ?", (now(),))
        return rows[0]["t"] if rows else None

    # -- usuarios -------------------------------------------------------------------
    def users(self):
        return self.query("SELECT username, name, role, enabled, created_at, created_by, updated_at, updated_by, "
                          "last_login FROM users ORDER BY username")

    def get_user(self, username):
        rows = self.query("SELECT * FROM users WHERE username = ?", (username,))
        return rows[0] if rows else None

    def _admins(self, exclude=None):
        return [u for u in self.query("SELECT username FROM users WHERE role = 'admin' AND enabled = 1")
                if u["username"].lower() != (exclude or "").lower()]

    @staticmethod
    def validate_password(password):
        if not isinstance(password, str) or len(password) < MIN_PASSWORD:
            raise StoreError("a senha precisa ter pelo menos %d caracteres" % MIN_PASSWORD)
        return password

    def create_user(self, data, actor, ip=""):
        username = str(data.get("username") or "").strip()
        if not USERNAME_RE.match(username):
            raise StoreError("usuario invalido: use 2 a 40 letras, numeros ou . _ @ -")
        role = data.get("role") or "leitura"
        if role not in ROLES:
            raise StoreError("papel invalido")
        password = self.validate_password(data.get("password"))
        name = str(data.get("name") or "").strip()[:80]
        enabled = bool(data.get("enabled", True))
        with self._tx() as db:
            if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise StoreError("o usuario %s ja existe" % username, 409)
            db.execute("INSERT INTO users (username, name, role, password_hash, enabled, created_at, created_by, "
                       "updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (username, name, role, hash_password(password), int(enabled), now(), actor, now(), actor))
        self.audit(actor, "usuario.criado", username, {"nome": name, "papel": role, "ativo": enabled}, ip)

    def update_user(self, username, data, actor, ip=""):
        user = self.get_user(username)
        if user is None:
            raise StoreError("usuario nao encontrado", 404)
        role = data.get("role", user["role"])
        if role not in ROLES:
            raise StoreError("papel invalido")
        enabled = bool(data.get("enabled", user["enabled"]))
        name = str(data.get("name", user["name"]) or "").strip()[:80]
        if user["role"] == "admin" and user["enabled"] and (role != "admin" or not enabled) \
                and not self._admins(exclude=user["username"]):
            raise StoreError("nao e possivel: este e o ultimo administrador ativo", 409)
        diff = {}
        if role != user["role"]:
            diff["papel"] = [user["role"], role]
        if enabled != bool(user["enabled"]):
            diff["ativo"] = [bool(user["enabled"]), enabled]
        if name != user["name"]:
            diff["nome"] = [user["name"], name]
        new_hash = user["password_hash"]
        if data.get("password"):
            new_hash = hash_password(self.validate_password(data["password"]))
            diff["senha"] = "redefinida"
        if not diff:
            return {}
        with self._tx() as db:
            db.execute("UPDATE users SET name=?, role=?, enabled=?, password_hash=?, updated_at=?, updated_by=? "
                       "WHERE username=?", (name, role, int(enabled), new_hash, now(), actor, user["username"]))
        self.audit(actor, "usuario.alterado", user["username"], diff, ip)
        return diff

    def delete_user(self, username, actor, ip=""):
        user = self.get_user(username)
        if user is None:
            raise StoreError("usuario nao encontrado", 404)
        if user["username"].lower() == (actor or "").lower():
            raise StoreError("voce nao pode excluir o proprio usuario", 409)
        if user["role"] == "admin" and user["enabled"] and not self._admins(exclude=user["username"]):
            raise StoreError("nao e possivel: este e o ultimo administrador ativo", 409)
        with self._tx() as db:
            db.execute("DELETE FROM users WHERE username = ?", (user["username"],))
        self.audit(actor, "usuario.removido", user["username"], {"papel": user["role"]}, ip)

    def change_own_password(self, username, current, new, ip=""):
        user = self.get_user(username)
        if user is None or not check_password(current or "", user["password_hash"]):
            self.audit(username, "senha.falha", username, {"motivo": "senha atual incorreta"}, ip)
            raise StoreError("senha atual incorreta", 403)
        self.validate_password(new)
        with self._tx() as db:
            db.execute("UPDATE users SET password_hash=?, updated_at=?, updated_by=? WHERE username=?",
                       (hash_password(new), now(), username, user["username"]))
        self.audit(username, "senha.alterada", username, None, ip)

    def authenticate(self, username, password):
        """Retorna o usuario (dict) ou None. Nao audita: quem chama sabe o IP e o contexto."""
        user = self.get_user(str(username or "").strip())
        if user is None:
            check_password(password or "", hash_password("x"))  # tempo parecido com usuario existente
            return None
        if not user["enabled"] or not check_password(password or "", user["password_hash"]):
            return None
        with self.lock:
            self.db.execute("UPDATE users SET last_login = ? WHERE username = ?", (now(), user["username"]))
        return user

    def reset_password(self, username, password, actor="terminal"):
        """Recuperacao pelo terminal: redefine (ou cria como admin) e reativa o usuario."""
        self.validate_password(password)
        user = self.get_user(username)
        with self._tx() as db:
            if user is None:
                db.execute("INSERT INTO users (username, name, role, password_hash, enabled, created_at, created_by, "
                           "updated_at, updated_by) VALUES (?, '', 'admin', ?, 1, ?, ?, ?, ?)",
                           (username, hash_password(password), now(), actor, now(), actor))
            else:
                db.execute("UPDATE users SET password_hash=?, enabled=1, updated_at=?, updated_by=? WHERE username=?",
                           (hash_password(password), now(), actor, user["username"]))
        self.audit(actor, "usuario.senha_redefinida" if user else "usuario.criado", username,
                   {"via": "terminal", "papel": user["role"] if user else "admin"})

    # -- migracao da configuracao antiga ---------------------------------------------
    def migrate(self, legacy):
        """Importa a configuracao antiga uma unica vez. legacy: dict montado pelo agente a partir dos arquivos."""
        with self._tx(immediate=True) as db:
            if db.execute("SELECT 1 FROM meta WHERE key = 'migrated'").fetchone():
                return None
            summary = {}
            for key, value in legacy.get("settings", {}).items():
                try:
                    value = self.validate_setting(key, value)
                except StoreError:
                    continue
                db.execute("INSERT OR REPLACE INTO settings VALUES (?, ?, ?, ?)",
                           (key, json.dumps(value), now(), "migracao"))
            routers = legacy.get("routers", [])
            for r in routers:
                db.execute("INSERT OR IGNORE INTO routers (id, name, host, port, username, password, use_ssl, timeout, "
                           "enabled, created_at, created_by, updated_at, updated_by) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'migracao', ?, 'migracao')",
                           (r["id"], r["name"], r["host"], r["port"], r["username"], r["password"],
                            int(r["use_ssl"]), r["timeout"], int(r["enabled"]), now(), now()))
            for table in ("blacklist", "whitelist"):
                for entry, comment in legacy.get(table, []):
                    if table == "blacklist":
                        db.execute("INSERT OR IGNORE INTO blacklist VALUES (?, ?, ?, 'migracao', NULL)",
                                   (entry, comment, now()))
                    else:
                        db.execute("INSERT OR IGNORE INTO whitelist VALUES (?, ?, ?, 'migracao')",
                                   (entry, comment, now()))
            admin_password = legacy.get("admin_password") or ""
            generated = None
            if not db.execute("SELECT 1 FROM users").fetchone():
                if len(admin_password) < MIN_PASSWORD:
                    generated = admin_password = secrets.token_urlsafe(12)
                db.execute("INSERT INTO users (username, name, role, password_hash, enabled, created_at, created_by, "
                           "updated_at, updated_by) VALUES ('admin', 'Administrador', 'admin', ?, 1, ?, 'migracao', "
                           "?, 'migracao')", (hash_password(admin_password), now(), now()))
            db.execute("INSERT INTO meta VALUES ('migrated', ?)", (str(now()),))
            summary = {"roteadores": len(routers), "blacklist": len(legacy.get("blacklist", [])),
                       "whitelist": len(legacy.get("whitelist", [])),
                       "configuracoes": sorted(legacy.get("settings", {}))}
        self.audit("sistema", "sistema.migracao", "config.ini/routers.json/blacklist.txt", summary)
        return {"summary": summary, "generated_admin_password": generated}


class _Transaction:
    def __init__(self, store, immediate=False):
        self.store = store
        self.immediate = immediate

    def __enter__(self):
        self.store.lock.acquire()
        self.store.db.execute("BEGIN IMMEDIATE" if self.immediate else "BEGIN")
        return self.store.db

    def __exit__(self, exc_type, exc, tb):
        try:
            self.store.db.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self.store.lock.release()
        return False
