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
import hashlib
import ipaddress
import logging
import logging.handlers
import os
import re
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import time

__version__ = "1.0.0"

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

    def banned(self):
        """Retorna {ip: set(jails)} com tudo que esta banido agora."""
        result = {}
        for jail, ips in self._per_jail().items():
            if self.jails and jail not in self.jails:
                continue
            for ip in ips:
                result.setdefault(str(ip), set()).add(jail)
        return result


EVENT_RE = re.compile(r"fail2ban\.actions.*?\[(?P<jail>[^\]]+)\]\s+"
                      r"(?P<action>Restore Ban|Ban|Unban)\s+(?P<ip>[0-9A-Fa-f:.]+)")


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
        events = []
        for line in lines:
            m = EVENT_RE.search(line)
            if m:
                events.append((m.group("action"), m.group("jail"), m.group("ip")))
        return events


# --------------------------------------------------------------------------- #
# Agente
# --------------------------------------------------------------------------- #
LIST_PATHS = {4: "/ip/firewall/address-list", 6: "/ipv6/firewall/address-list"}


def normalize_ip(text):
    """'1.2.3.4', '1.2.3.4/32', '2001:db8::1/128' -> endereco; prefixos -> rede; invalido -> None."""
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None
    return net.network_address if net.num_addresses == 1 else net


def parse_list(value):
    return [v.strip() for v in re.split(r"[,\s]+", value or "") if v.strip()]


class Agent:
    def __init__(self, cfg, dry_run=False):
        mk, f2b, ag = cfg["mikrotik"], cfg["fail2ban"], cfg["agent"]
        self.router = dict(host=mk.get("host"), port=mk.getint("port"), username=mk.get("username"),
                           password=mk.get("password"), use_ssl=mk.getboolean("use_ssl"),
                           timeout=mk.getfloat("timeout"))
        self.list_name = mk.get("address_list")
        self.prefix = mk.get("comment_prefix")
        self.entry_timeout = mk.get("entry_timeout").strip()
        self.families = [4, 6] if mk.getboolean("ipv6") else [4]
        self.f2b = Fail2ban(f2b.get("client"), parse_list(f2b.get("jails")))
        self.f2b_log = f2b.get("logfile").strip()
        self.whitelist = [ipaddress.ip_network(n, strict=False) for n in parse_list(f2b.get("whitelist"))]
        self.sync_interval = ag.getfloat("sync_interval")
        self.debounce = ag.getfloat("debounce")
        self.retry_delay = ag.getfloat("retry_delay")
        self.dry_run = dry_run
        self._ignored_logged = set()
        self._last_error = (None, 0.0)
        self._stop = False

    # -- auxiliares -------------------------------------------------------------
    def _api(self):
        return RouterOSApi(**self.router)

    def _whitelisted(self, ip):
        return any(ip.version == net.version and ip in net for net in self.whitelist)

    def _desired(self):
        """IPs que devem estar bloqueados no roteador: {ip_str: (ip, jails)}."""
        desired = {}
        for raw, jails in self.f2b.banned().items():
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
        return desired

    def _log_ignored(self, ip, why):
        if ip not in self._ignored_logged:
            log.warning("IGNORADO %s (%s) - nao sera bloqueado no MikroTik", ip, why)
            self._ignored_logged.add(ip)

    def _router_entries(self, api):
        """Retorna (gerenciadas {ip_str: (familia, .id, comentario)}, demais enderecos da lista)."""
        managed, others = {}, set()
        for fam in self.families:
            rows, _ = api.talk([LIST_PATHS[fam] + "/print", "=.proplist=.id,address,comment",
                                "?list=" + self.list_name])
            for r in rows:
                addr = r.get("address", "")
                ip = normalize_ip(addr)
                key = str(ip) if ip is not None else addr
                comment = r.get("comment", "")
                if comment.startswith(self.prefix):
                    managed[key] = (fam, r.get(".id"), comment)
                else:
                    others.add(key)
        return managed, others

    # -- operacoes ----------------------------------------------------------------
    def sync(self, reason="periodica"):
        """Reconciliacao completa. Retorna True se nao houve erros."""
        desired = self._desired()  # se o fail2ban falhar, levanta excecao antes de tocar no roteador
        added = removed = errors = 0
        with self._api() as api:
            managed, others = self._router_entries(api)
            to_add = sorted(k for k in desired if k not in managed and k not in others)
            to_remove = sorted(k for k in managed if k not in desired)
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")

            for key in to_add:
                ip, jails = desired[key]
                jail_txt = ",".join(sorted(jails))
                words = [LIST_PATHS[ip.version] + "/add", "=list=" + self.list_name, "=address=" + key,
                         "=comment=%s [%s] %s" % (self.prefix, jail_txt, stamp)]
                if self.entry_timeout:
                    words.append("=timeout=" + self.entry_timeout)
                if self.dry_run:
                    log.info("[dry-run] BLOQUEARIA no MikroTik: %s (jail: %s)", key, jail_txt)
                    continue
                try:
                    api.talk(words)
                    added += 1
                    log.info("BLOQUEADO no MikroTik: %s (jail: %s)", key, jail_txt)
                except RouterOSTrap as e:
                    errors += 1
                    log.error("erro ao bloquear %s no MikroTik: %s", key, e)

            for key in to_remove:
                fam, rid, comment = managed[key]
                if self.dry_run:
                    log.info("[dry-run] LIBERARIA no MikroTik: %s", key)
                    continue
                try:
                    api.talk([LIST_PATHS[fam] + "/remove", "=.id=" + rid])
                    removed += 1
                    log.info("LIBERADO no MikroTik: %s (%s)", key, comment)
                except RouterOSTrap as e:
                    errors += 1
                    log.error("erro ao liberar %s no MikroTik: %s", key, e)

        level = logging.INFO if (to_add or to_remove or errors) else logging.DEBUG
        log.log(level, "sincronizacao %s: %d banidos no fail2ban, %d no roteador | +%d -%d, %d erro(s)",
                reason, len(desired), len(managed) + added - removed, added, removed, errors)
        return errors == 0

    def flush(self):
        with self._api() as api:
            managed, _ = self._router_entries(api)
            for key, (fam, rid, _comment) in sorted(managed.items()):
                if self.dry_run:
                    log.info("[dry-run] REMOVERIA do MikroTik: %s", key)
                    continue
                api.talk([LIST_PATHS[fam] + "/remove", "=.id=" + rid])
                log.info("REMOVIDO do MikroTik: %s", key)
        log.info("flush concluido: %d entrada(s) do agente %s", len(managed),
                 "seriam removidas" if self.dry_run else "removidas")

    def test(self):
        ok = True
        print("fail2ban ...", end=" ", flush=True)
        try:
            desired = self._desired()
            print("OK - %d IP(s) banido(s) a replicar" % len(desired))
        except Fail2banError as e:
            print("FALHOU: %s" % e)
            desired, ok = None, False
        print("MikroTik %s:%s ..." % (self.router["host"], self.router["port"]), end=" ", flush=True)
        try:
            with self._api() as api:
                res, _ = api.talk(["/system/resource/print"])
                info = res[0] if res else {}
                managed, others = self._router_entries(api)
            print("OK - %s RouterOS %s" % (info.get("board-name", "?"), info.get("version", "?")))
            print("  lista '%s': %d entrada(s) do agente, %d outra(s)" % (self.list_name, len(managed), len(others)))
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
            ok = self.sync(reason)
            if self._last_error[0] is not None:
                log.info("comunicacao restabelecida")
                self._last_error = (None, 0.0)
            return ok
        except Fail2banError as e:
            self._report_error("fail2ban indisponivel, nada foi alterado no roteador: %s" % e)
        except (RouterOSError, OSError) as e:
            self._report_error("falha ao comunicar com o MikroTik %s:%s: %s"
                               % (self.router["host"], self.router["port"], e))
        except Exception:
            log.exception("erro inesperado na sincronizacao")
        return False

    def _report_error(self, msg):
        # evita encher o log com o mesmo erro a cada tentativa: repete no maximo a cada 5 min
        last_msg, last_time = self._last_error
        now = time.monotonic()
        if msg != last_msg or now - last_time >= 300:
            log.error("%s (nova tentativa em %ds)", msg, self.retry_delay)
            self._last_error = (msg, now)

    def run_forever(self):
        def on_signal(signum, _frame):
            log.info("sinal %d recebido, encerrando", signum)
            self._stop = True

        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)

        watcher = LogWatcher(self.f2b_log) if self.f2b_log else None
        next_sync = 0.0
        pending_since = last_event = None

        while not self._stop:
            now = time.monotonic()
            if watcher is not None:
                for action, jail, ip in watcher.poll():
                    log.info("fail2ban: [%s] %s %s", jail, action, ip)
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

            time.sleep(0.5)
        log.info("agente finalizado")


# --------------------------------------------------------------------------- #
# Configuracao, log e entrada
# --------------------------------------------------------------------------- #
DEFAULTS = {
    "mikrotik": {"port": "8728", "use_ssl": "no", "timeout": "10", "address_list": "fail2ban",
                 "comment_prefix": "f2b-agent", "entry_timeout": "", "ipv6": "no"},
    "fail2ban": {"client": "/usr/bin/fail2ban-client", "logfile": "/var/log/fail2ban.log", "jails": "",
                 "whitelist": "127.0.0.0/8, ::1"},
    "agent": {"sync_interval": "60", "debounce": "2", "retry_delay": "15",
              "logfile": "/var/log/f2b-mikrotik.log", "log_level": "INFO",
              "log_max_bytes": "10485760", "log_backups": "5", "lockfile": "/run/f2b-mikrotik.lock"},
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
        log.info("f2b-mikrotik %s iniciado: roteador=%s:%s lista=%s jails=%s%s", __version__,
                 agent.router["host"], agent.router["port"], agent.list_name,
                 ",".join(sorted(agent.f2b.jails)) or "todas", " [DRY-RUN]" if agent.dry_run else "")
        agent.run_forever()


if __name__ == "__main__":
    main()
