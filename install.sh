#!/bin/sh
# Instala/atualiza o f2b-mikrotik (agente + painel web) como servicos systemd
set -e

[ "$(id -u)" -eq 0 ] || { echo "Execute como root (sudo $0)"; exit 1; }
command -v python3 >/dev/null || { echo "python3 nao encontrado"; exit 1; }

SRC=$(cd "$(dirname "$0")" && pwd)
DEST=/opt/f2b-mikrotik
CFG=/etc/f2b-mikrotik/config.ini
DATA=/var/lib/f2b-mikrotik

install -d -m 755 "$DEST"
# se o repositorio foi clonado direto em /opt/f2b-mikrotik, os arquivos ja estao no lugar
if [ "$SRC" != "$DEST" ]; then
    for f in f2b_mikrotik.py f2b_web.py f2b_geo.py f2b_store.py; do
        install -m 755 "$SRC/$f" "$DEST/$f"
    done
    install -d -m 755 "$DEST/web"
    install -m 644 "$SRC"/web/* "$DEST/web/"
fi

install -d -m 700 /etc/f2b-mikrotik
# banco da configuracao (senhas dos roteadores e hashes dos usuarios), historico e tabela de paises
install -d -m 700 "$DATA"
chmod 700 "$DATA"

if [ -f "$CFG" ]; then
    echo "Mantido o $CFG existente"
else
    install -m 600 "$SRC/config.ini.example" "$CFG"
    echo "Criado $CFG"
fi

# primeira instalacao (ainda sem banco): define a senha inicial do usuario admin
if [ ! -f "$DATA/config.db" ]; then
    grep -q '^\[web\]' "$CFG" || printf '\n[web]\nbind = 0.0.0.0\nport = 8088\npassword =\n' >> "$CFG"
    if awk '/^\[/{w=($0=="[web]")} w && /^password[ \t]*=[ \t]*$/{f=1} END{exit !f}' "$CFG"; then
        WEBPASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
        awk -v p="$WEBPASS" '/^\[/{w=($0=="[web]")} w && /^password[ \t]*=[ \t]*$/{$0="password = " p} {print}' \
            "$CFG" > "$CFG.new"
        cat "$CFG.new" > "$CFG" && rm -f "$CFG.new"
        echo "Senha inicial do painel (usuario admin): $WEBPASS"
    fi
    echo "Na primeira subida a configuracao atual (config.ini, routers.json, blacklist.txt) e"
    echo "importada para $DATA/config.db; depois disso tudo e editado no painel."
fi

install -m 644 "$SRC/f2b-mikrotik.service" /etc/systemd/system/f2b-mikrotik.service
install -m 644 "$SRC/f2b-mikrotik-web.service" /etc/systemd/system/f2b-mikrotik-web.service
systemctl daemon-reload

cat <<'EOF'

Proximos passos:
  1. Prepare cada MikroTik com o mikrotik-setup.rsc
  2. Inicie:   systemctl enable --now f2b-mikrotik f2b-mikrotik-web
  3. Painel:   http://IP-DO-SERVIDOR:8088/  (usuario admin) -> cadastre os roteadores
               na aba Roteadores e ajuste whitelist/configuracoes na aba Configuracoes
  4. Teste:    python3 /opt/f2b-mikrotik/f2b_mikrotik.py --test
  5. Log:      tail -f /var/log/f2b-mikrotik.log
Atualizacao:   systemctl restart f2b-mikrotik f2b-mikrotik-web
Senha perdida: python3 /opt/f2b-mikrotik/f2b_mikrotik.py --reset-password admin
EOF
