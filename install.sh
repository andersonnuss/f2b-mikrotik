#!/bin/sh
# Instala o f2b-mikrotik como servico systemd
set -e

[ "$(id -u)" -eq 0 ] || { echo "Execute como root (sudo $0)"; exit 1; }
command -v python3 >/dev/null || { echo "python3 nao encontrado"; exit 1; }

SRC=$(cd "$(dirname "$0")" && pwd)

install -d -m 755 /opt/f2b-mikrotik
install -m 755 "$SRC/f2b_mikrotik.py" /opt/f2b-mikrotik/f2b_mikrotik.py

install -d -m 700 /etc/f2b-mikrotik
if [ -f /etc/f2b-mikrotik/config.ini ]; then
    echo "Mantido o /etc/f2b-mikrotik/config.ini existente"
else
    install -m 600 "$SRC/config.ini.example" /etc/f2b-mikrotik/config.ini
    echo "Criado /etc/f2b-mikrotik/config.ini - EDITE antes de iniciar"
fi

install -m 644 "$SRC/f2b-mikrotik.service" /etc/systemd/system/f2b-mikrotik.service
systemctl daemon-reload

cat <<'EOF'

Proximos passos:
  1. Prepare o MikroTik com o mikrotik-setup.rsc
  2. Edite /etc/f2b-mikrotik/config.ini
  3. Teste:   python3 /opt/f2b-mikrotik/f2b_mikrotik.py --test
  4. Inicie:  systemctl enable --now f2b-mikrotik
  5. Log:     tail -f /var/log/f2b-mikrotik.log
EOF
