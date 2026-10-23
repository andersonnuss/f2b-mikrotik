# =====================================================================
#  Preparacao do MikroTik (RB750) para o agente f2b-mikrotik
#  Antes de colar no terminal (Winbox > New Terminal), troque:
#    192.168.88.10       -> IP do servidor Linux onde roda o agente
#    TROQUE-ESTA-SENHA   -> mesma senha do config.ini
#    WAN                 -> interface list da WAN (padrao da config de fabrica).
#                           Se nao existir, use in-interface=ether1
# =====================================================================

# 1) Grupo com o minimo de permissao: somente API + leitura/escrita
/user group add name=f2b-api policy=api,read,write comment="f2b-mikrotik"

# 2) Usuario do agente, aceito apenas a partir do servidor Linux
/user add name=f2b-agent group=f2b-api address=192.168.88.10/32 password="TROQUE-ESTA-SENHA" comment="f2b-mikrotik"

# 3) Libera a API somente para o servidor (nunca exponha a API para a internet)
/ip service set api disabled=no address=192.168.88.10/32
#    Opcional, API criptografada (porta 8729, use_ssl = yes no config.ini):
# /certificate add name=api-cert common-name=api-cert days-valid=3650
# /certificate sign api-cert
# /ip service set api-ssl disabled=no address=192.168.88.10/32 certificate=api-cert

# 4) Descarte na borda. A tabela RAW age antes do connection tracking e do NAT:
#    menos CPU no RB750 e vale tambem para portas redirecionadas (dst-nat).
#    Se ja houver regras em /ip firewall raw, mova esta para o topo.
/ip firewall raw add chain=prerouting in-interface-list=WAN src-address-list=fail2ban action=drop comment="f2b-mikrotik: descarta IPs banidos pelo fail2ban"

# 5) (Opcional) IPv6 - somente se ipv6 = yes no config.ini
# /ipv6 firewall raw add chain=prerouting in-interface-list=WAN src-address-list=fail2ban action=drop comment="f2b-mikrotik: descarta IPs banidos pelo fail2ban"

# Conferir:
#   /ip firewall address-list print where list=fail2ban
#   /ip firewall raw print stats
