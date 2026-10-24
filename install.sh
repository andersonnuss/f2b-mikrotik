#!/bin/sh
# Instala o f2b-mikrotik (agente + painel web) como servicos systemd
set -e

[ "$(id -u)" -eq 0 ] || { echo "Execute como root (sudo $0)"; exit 1; }
command -v python3 >/dev/null || { echo "python3 nao encontrado"; exit 1; }

SRC=$(cd "$(dirname "$0")" && pwd)
DEST=/opt/f2b-mikrotik

install -d -m 755 "$DEST"
# se o repositorio foi clonado direto em /opt/f2b-mikrotik, o script ja esta no lugar
if [ "$SRC" != "$DEST" ]; then
    install -m 755 "$SRC/f2b_mikrotik.py" "$DEST/f2b_mikrotik.py"
    install -m 755 "$SRC/f2b_web.py" "$DEST/f2b_web.py"
    install -m 755 "$SRC/f2b_geo.py" "$DEST/f2b_geo.py"
    install -d -m 755 "$DEST/web"
    install -m 644 "$SRC"/web/* "$DEST/web/"
fi

install -d -m 700 /etc/f2b-mikrotik
install -d -m 750 /var/lib/f2b-mikrotik   # historico de eventos e tabela de paises
if [ -f /etc/f2b-mikrotik/config.ini ]; then
    echo "Mantido o /etc/f2b-mikrotik/config.ini existente"
    grep -q '^\[blacklist\]' /etc/f2b-mikrotik/config.ini ||
        echo "  (sem secao [blacklist]: sera usado /etc/f2b-mikrotik/blacklist.txt)"
else
    install -m 600 "$SRC/config.ini.example" /etc/f2b-mikrotik/config.ini
    echo "Criado /etc/f2b-mikrotik/config.ini - EDITE antes de iniciar"
fi
# config de versoes anteriores: acrescenta a secao do painel com uma senha aleatoria
CFG=/etc/f2b-mikrotik/config.ini
if ! grep -q '^\[web\]' "$CFG"; then
    printf '\n[web]\nbind = 0.0.0.0\nport = 8088\nusername = admin\npassword =\ntls_cert =\ntls_key =\n' >> "$CFG"
    echo "Acrescentada a secao [web] ao config.ini"
fi
# senha do painel vazia -> gera uma aleatoria (o painel nao inicia sem senha)
if awk '/^\[/{w=($0=="[web]")} w && /^password[ \t]*=[ \t]*$/{f=1} END{exit !f}' "$CFG"; then
    WEBPASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
    awk -v p="$WEBPASS" '/^\[/{w=($0=="[web]")} w && /^password[ \t]*=[ \t]*$/{$0="password = " p} {print}' \
        "$CFG" > "$CFG.new"
    cat "$CFG.new" > "$CFG" && rm -f "$CFG.new"
    echo "Senha do painel web (usuario admin): $WEBPASS   (pode trocar em [web] password)"
fi
if [ ! -f /etc/f2b-mikrotik/blacklist.txt ]; then
    install -m 644 "$SRC/blacklist.txt.example" /etc/f2b-mikrotik/blacklist.txt
    echo "Criado /etc/f2b-mikrotik/blacklist.txt"
fi

install -m 644 "$SRC/f2b-mikrotik.service" /etc/systemd/system/f2b-mikrotik.service
install -m 644 "$SRC/f2b-mikrotik-web.service" /etc/systemd/system/f2b-mikrotik-web.service
systemctl daemon-reload

cat <<'EOF'

Proximos passos:
  1. Prepare o MikroTik com o mikrotik-setup.rsc
  2. Edite /etc/f2b-mikrotik/config.ini
  3. Teste:   python3 /opt/f2b-mikrotik/f2b_mikrotik.py --test
  4. Inicie:  systemctl enable --now f2b-mikrotik
  5. Log:     tail -f /var/log/f2b-mikrotik.log
  6. Painel:  systemctl enable --now f2b-mikrotik-web   ->  http://IP-DO-SERVIDOR:8088/
     (atualizacao: systemctl restart f2b-mikrotik f2b-mikrotik-web)
EOF
