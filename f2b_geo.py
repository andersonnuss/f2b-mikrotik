#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
f2b-mikrotik geo - pais de origem de um IP, sem servico externo nem conta.

Usa as tabelas publicas de alocacao ("delegated-extended") dos cinco registros regionais
(ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC): cada bloco de IPs tem o pais da organizacao
para a qual foi alocado. E o pais de registro, nao uma geolocalizacao fina, mas e
gratuito, oficial e funciona offline: nenhum IP consultado sai do servidor.

    python3 f2b_geo.py --update [arquivo]    baixa as tabelas e gera o arquivo compacto
    python3 f2b_geo.py 203.0.113.5           consulta um IP
"""

import argparse
import bisect
import gzip
import ipaddress
import logging
import os
import threading
import time
import urllib.request

RIR_URLS = (
    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
)
DEFAULT_FILE = "/var/lib/f2b-mikrotik/geo.tsv.gz"
MAX_AGE = 7 * 86400  # as tabelas mudam pouco; atualiza uma vez por semana

log = logging.getLogger("f2b-geo")


def _parse_rir(lines):
    """Linhas 'registro|CC|ipv4|inicio|qtde|data|status' -> (versao, inicio, fim, CC)."""
    for raw in lines:
        line = raw.decode("ascii", "replace") if isinstance(raw, bytes) else raw
        if not line or line[0] in "#\n" or line[0].isdigit():
            continue  # comentario ou cabecalho de versao
        parts = line.strip().split("|")
        if len(parts) < 7 or parts[1] in ("*", "", "ZZ") or parts[2] not in ("ipv4", "ipv6"):
            continue  # linhas de resumo e blocos sem pais
        if parts[6] not in ("allocated", "assigned"):
            continue
        try:
            if parts[2] == "ipv4":
                start = int(ipaddress.IPv4Address(parts[3]))
                yield 4, start, start + int(parts[4]) - 1, parts[1].upper()
            else:
                start = int(ipaddress.IPv6Address(parts[3]))
                yield 6, start, start + (1 << (128 - int(parts[4]))) - 1, parts[1].upper()
        except ValueError:
            continue


def build(dest=DEFAULT_FILE, urls=RIR_URLS, timeout=120):
    """Baixa as tabelas de todos os RIRs e grava o arquivo compacto. Retorna a quantidade de faixas.
    So substitui o arquivo existente se todos os downloads derem certo."""
    ranges = []
    for url in urls:
        req = urllib.request.Request(url, headers={"User-Agent": "f2b-mikrotik-geo"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ranges.extend(_parse_rir(resp))
        log.info("geo: %s lido", url.rsplit("/", 1)[-1])
    if not ranges:
        raise ValueError("nenhuma faixa de IP encontrada nas tabelas dos RIRs")
    ranges.sort()
    merged = []
    for fam, start, end, cc in ranges:
        last = merged[-1] if merged else None
        if last and last[0] == fam and last[3] == cc and start <= last[2] + 1:
            last[2] = max(last[2], end)  # faixas vizinhas do mesmo pais viram uma so
        else:
            merged.append([fam, start, end, cc])
    directory = os.path.dirname(dest)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = dest + ".tmp"
    with gzip.open(tmp, "wt", encoding="ascii") as fh:
        fh.write("# f2b-mikrotik geo: versao\tinicio\tfim\tpais (fonte: RIRs, %s)\n" % time.strftime("%Y-%m-%d"))
        for fam, start, end, cc in merged:
            fh.write("%d\t%x\t%x\t%s\n" % (fam, start, end, cc))
    os.replace(tmp, dest)
    return len(merged)


class GeoDB:
    """Consulta de pais em memoria. Recarrega sozinha quando o arquivo muda."""

    def __init__(self, path=DEFAULT_FILE):
        self.path = path
        self.lock = threading.Lock()
        self.tables = {4: ([], [], []), 6: ([], [], [])}
        self.loaded_mtime = None

    def load(self):
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            return False
        if mtime == self.loaded_mtime:
            return True
        tables = {4: ([], [], []), 6: ([], [], [])}
        with gzip.open(self.path, "rt", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                fam, start, end, cc = line.rstrip("\n").split("\t")
                starts, ends, ccs = tables[int(fam)]
                starts.append(int(start, 16))
                ends.append(int(end, 16))
                ccs.append(cc)
        with self.lock:
            self.tables, self.loaded_mtime = tables, mtime
        return True

    @property
    def ready(self):
        return self.loaded_mtime is not None

    def updated_at(self):
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(self.loaded_mtime)) if self.ready else None

    def lookup(self, value):
        """IP ou rede (texto ou objeto ipaddress) -> codigo ISO do pais, ou None se desconhecido."""
        try:
            if isinstance(value, str):
                value = ipaddress.ip_network(value.strip(), strict=False)
            addr = value.network_address if hasattr(value, "network_address") else value
        except ValueError:
            return None
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return None
        with self.lock:
            starts, ends, ccs = self.tables[addr.version]
        x = int(addr)
        i = bisect.bisect_right(starts, x) - 1
        if i >= 0 and x <= ends[i]:
            return ccs[i]
        return None


class GeoUpdater(threading.Thread):
    """Mantem o arquivo atualizado em segundo plano (baixa se faltar ou tiver mais de 7 dias)."""

    def __init__(self, geo, interval=6 * 3600):
        super().__init__(daemon=True, name="geo-updater")
        self.geo = geo
        self.interval = interval
        self.last_error = None

    def run(self):
        while True:
            try:
                age = time.time() - os.stat(self.geo.path).st_mtime
            except OSError:
                age = None
            if age is None or age > MAX_AGE:
                try:
                    n = build(self.geo.path)
                    log.info("geo: tabela de paises atualizada (%d faixas)", n)
                    self.last_error = None
                except Exception as e:  # rede fora, RIR fora do ar...: tenta de novo depois
                    self.last_error = str(e)
                    log.warning("geo: nao foi possivel atualizar a tabela de paises: %s", e)
            try:
                self.geo.load()
            except (OSError, ValueError) as e:
                self.last_error = str(e)
                log.warning("geo: arquivo %s invalido: %s", self.geo.path, e)
            time.sleep(self.interval)


def main():
    ap = argparse.ArgumentParser(description="Pais de origem de IPs a partir das tabelas dos RIRs.")
    ap.add_argument("--update", action="store_true", help="baixa as tabelas e gera o arquivo")
    ap.add_argument("--file", default=DEFAULT_FILE, help="arquivo compacto (padrao: %(default)s)")
    ap.add_argument("ips", nargs="*", help="IPs a consultar")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if args.update:
        print("%d faixas gravadas em %s" % (build(args.file), args.file))
    if args.ips:
        geo = GeoDB(args.file)
        if not geo.load():
            raise SystemExit("arquivo %s nao encontrado; rode com --update" % args.file)
        for ip in args.ips:
            print("%s\t%s" % (ip, geo.lookup(ip) or "desconhecido"))


if __name__ == "__main__":
    main()
