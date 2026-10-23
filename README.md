# f2b-mikrotik

Replica no MikroTik (RB750) os IPs banidos e liberados pelo fail2ban, para que o bloqueio aconteça **na borda**.

```
 fail2ban (servidor Linux)                      MikroTik RB750
 ┌──────────────────────────┐   API 8728/8729   ┌────────────────────────────────────┐
 │ /var/log/fail2ban.log ───┼─► f2b_mikrotik ──►│ /ip firewall address-list fail2ban │
 │ fail2ban-client banned ──┘   (daemon)        │ /ip firewall raw  drop src-list    │
 └──────────────────────────┘                   └────────────────────────────────────┘
```

## Por que daemon (e não cron)

| | Daemon (systemd) | Cron |
|---|---|---|
| Tempo até bloquear na borda | ~2 s (lê o log em tempo real) | até 1 min (menor intervalo do cron) |
| Recuperação de falhas | automática, re-tenta a cada 15 s | só na próxima execução |
| Supervisão | `systemctl status`, reinicia sozinho | nenhuma |

O agente faz as duas coisas:

1. **Eventos**: acompanha o `fail2ban.log` (`Ban`, `Unban`, `Restore Ban`) e sincroniza ~2 s depois.
2. **Reconciliação**: a cada 60 s compara o que está banido no fail2ban (`fail2ban-client`) com a address-list do roteador e corrige diferenças. Por isso nada se perde se o roteador cair, o agente reiniciar ou o log rotacionar.

O modo cron continua disponível (`--once`), se preferir.

### Garantias de segurança

- Só altera entradas cujo comentário começa com `f2b-agent`. **Entradas manuais na mesma lista ficam intactas.**
- Se o `fail2ban-client` falhar (serviço parado/reiniciando), **nada é removido** do roteador.
- `whitelist` impede que redes internas/gerência sejam bloqueadas na borda.
- IP banido em mais de uma jail só sai do roteador quando for liberado em todas.
- O usuário no MikroTik tem só a permissão `api,read,write` e só aceita login a partir do IP do servidor.

## Instalação

### 1. MikroTik

Edite os valores em [mikrotik-setup.rsc](mikrotik-setup.rsc) (IP do servidor, senha, interface WAN) e cole no terminal do Winbox. Ele cria:
- grupo `f2b-api` e usuário `f2b-agent` (login só a partir do servidor);
- API liberada apenas para o servidor;
- regra `/ip firewall raw` que descarta `src-address-list=fail2ban` vindo da WAN. A tabela RAW age antes do conntrack e do NAT: gasta menos CPU no RB750 e vale também para portas redirecionadas (dst-nat).

### 2. Servidor Linux

Requisitos: Python 3.6+ (sem bibliotecas extras) e fail2ban. Rodar como root, pois o `fail2ban-client` precisa disso.

```bash
sudo sh install.sh
```

```bash
sudo nano /etc/f2b-mikrotik/config.ini
```

```bash
sudo python3 /opt/f2b-mikrotik/f2b_mikrotik.py --test
```

O `--test` não altera nada. Deve mostrar algo assim:

```
fail2ban ... OK - 37 IP(s) banido(s) a replicar
MikroTik 192.168.88.1:8728 ... OK - RB750Gr3 RouterOS 7.16 (stable)
  lista 'fail2ban': 0 entrada(s) do agente, 0 outra(s)
  a adicionar: 37   a remover: 0
```

Opcional, para ver o que seria feito sem alterar o roteador:

```bash
sudo python3 /opt/f2b-mikrotik/f2b_mikrotik.py --once --dry-run -v
```

Ativar o serviço:

```bash
sudo systemctl enable --now f2b-mikrotik
```

## Acompanhando o log

```bash
tail -f /var/log/f2b-mikrotik.log
```

```
2026-10-23 19:23:34 [INFO] f2b-mikrotik 1.0.0 iniciado: roteador=192.168.88.1:8728 lista=fail2ban jails=todas
2026-10-23 19:23:36 [INFO] fail2ban: [sshd] Ban 203.0.113.77
2026-10-23 19:23:37 [INFO] BLOQUEADO no MikroTik: 203.0.113.77 (jail: sshd)
2026-10-23 19:23:37 [INFO] sincronizacao por evento: 2 banidos no fail2ban, 2 no roteador | +1 -0, 0 erro(s)
2026-10-23 20:23:37 [INFO] fail2ban: [sshd] Unban 203.0.113.77
2026-10-23 20:23:39 [INFO] LIBERADO no MikroTik: 203.0.113.77 (f2b-agent [sshd] 2026-10-23 19:23:37)
2026-10-23 20:25:10 [WARNING] IGNORADO 192.168.1.50 (esta na whitelist) - nao sera bloqueado no MikroTik
2026-10-23 20:40:00 [ERROR] falha ao comunicar com o MikroTik 192.168.88.1:8728: timed out (nova tentativa em 15s)
2026-10-23 20:41:15 [INFO] comunicacao restabelecida
```

- O arquivo rotaciona sozinho (10 MB x 5 arquivos, configurável).
- Sincronizações sem alteração só aparecem com `log_level = DEBUG`.
- Erros repetidos são registrados no máximo a cada 5 minutos, para não encher o log.
- Erros de partida (configuração, Python) aparecem em `journalctl -u f2b-mikrotik`.

No roteador:

```
/ip firewall address-list print where list=fail2ban
/ip firewall raw print stats
```

## Alternativa: cron

Em vez do serviço, rode a cada minuto (`crontab -e` do root):

```
* * * * * /usr/bin/python3 /opt/f2b-mikrotik/f2b_mikrotik.py --once
```

Uma trava (`/run/f2b-mikrotik.lock`) impede duas execuções simultâneas.

## Opções úteis do config.ini

| Opção | Para que serve |
|---|---|
| `jails` | replicar só algumas jails (ex.: `sshd, postfix`) |
| `whitelist` | redes que nunca vão para o roteador |
| `entry_timeout` | ex.: `7d`. As entradas expiram sozinhas no roteador se o agente for desinstalado ou parar; enquanto o IP seguir banido, o agente o recoloca |
| `ipv6` | replica também para `/ipv6 firewall address-list` |
| `use_ssl` / `port` | usar `api-ssl` (8729) |

## Remover tudo

```bash
sudo systemctl disable --now f2b-mikrotik
```

```bash
sudo python3 /opt/f2b-mikrotik/f2b_mikrotik.py --flush
```

O `--flush` remove do roteador só as entradas criadas pelo agente.

## Observações

- Ao **parar** o fail2ban, ele libera todos os IPs. O agente então os remove do roteador. Quando o fail2ban volta, os bans persistentes (`Restore Ban`) são recolocados.
- Compatível com RouterOS v6 (inclusive anterior à 6.43) e v7. Testa automaticamente o comando `fail2ban-client banned` (0.11.2+) e recorre ao `status` em versões antigas.
