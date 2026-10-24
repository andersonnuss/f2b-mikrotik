# f2b-mikrotik

Replica no MikroTik (RB750) os IPs banidos e liberados pelo fail2ban, para que o bloqueio aconteça **na borda**.
Pode replicar para vários MikroTiks e tem um **painel web** para consultar o que está bloqueado e cadastrar roteadores.

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
- Com vários roteadores, um fora do ar não atrapalha os outros: ele recebe tudo quando voltar.

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
2026-10-23 19:23:37 [INFO] BLOQUEADO no MikroTik [principal]: 203.0.113.77 (jail: sshd)
2026-10-23 19:23:37 [INFO] sincronizacao por evento [principal]: 2 a bloquear (fail2ban + blacklist), 2 no roteador | +1 -0, 0 erro(s)
2026-10-23 20:23:37 [INFO] fail2ban: [sshd] Unban 203.0.113.77
2026-10-23 20:23:39 [INFO] LIBERADO no MikroTik [principal]: 203.0.113.77 (f2b-agent [sshd] 2026-10-23 19:23:37)
2026-10-23 20:25:10 [WARNING] IGNORADO 192.168.1.50 (esta na whitelist) - nao sera bloqueado no MikroTik
2026-10-23 20:40:00 [ERROR] falha ao comunicar com o MikroTik [filial] 10.0.0.1:8728: timed out (nova tentativa em 15s)
2026-10-23 20:41:15 [INFO] comunicacao com o MikroTik [filial] restabelecida
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

## Painel web

Painel para conferir o que está bloqueado e cadastrar outros MikroTiks. Usa o próprio Python, sem Node e sem dependências, e roda na **porta 8088**.

```bash
sudo systemctl enable --now f2b-mikrotik-web
```

Abra `http://IP-DO-SERVIDOR:8088/` e entre com o usuário `admin` e a senha da seção `[web]` do `/etc/f2b-mikrotik/config.ini`. O `install.sh` gera essa senha e a mostra na tela; ela pode ser trocada no arquivo.

O que o painel mostra:

- **Este IP está bloqueado?** Digite um IP ou uma rede. A resposta diz em quais roteadores está bloqueado, por quê (jail do fail2ban, blacklist, ou dentro de uma rede bloqueada) e avisa quando o IP deveria estar bloqueado e ainda não está, ou quando está na whitelist.
- **Visão geral:** estado de cada roteador (modelo, versão, identity, uptime), jails do fail2ban com os IPs banidos, blacklist e whitelist. Clique num IP para consultá-lo.
- **Bloqueios:** uma tabela com todos os IPs e uma coluna por roteador (bloqueado, manual, faltando, a remover). O filtro "só divergências" mostra o que o agente ainda não sincronizou.
- **Roteadores:** cadastrar, editar, testar a conexão e excluir MikroTiks.
- **Log do agente:** as últimas linhas do `/var/log/f2b-mikrotik.log`, com filtro.

O painel só **lê** o fail2ban e os roteadores. Quem bloqueia e libera é o agente.

Configuração (`[web]` no `config.ini`):

| Opção | Padrão | |
|---|---|---|
| `port` | `8088` | troque se a porta estiver em uso (a 3000 não é usada) |
| `bind` | `0.0.0.0` | `127.0.0.1` aceita só acessos do próprio servidor |
| `username` / `password` | `admin` / *(gerada)* | o painel não inicia sem senha |
| `tls_cert` / `tls_key` | *(vazio)* | caminhos do certificado e da chave para usar HTTPS |

Segurança: o painel exige senha e recusa pedidos forjados por outros sites. As senhas dos roteadores nunca são enviadas ao navegador. Sem `tls_cert`, porém, o tráfego é HTTP puro: use o painel só na rede interna, ou configure o HTTPS.

## Vários MikroTiks

O roteador do `config.ini` (seção `[mikrotik]`) é o **principal**. Os demais são cadastrados no painel, na aba **Roteadores**, e ficam em `/etc/f2b-mikrotik/routers.json` (permissão 600, porque contém as senhas).

- **Recebem tudo:** todos os roteadores recebem os mesmos bloqueios, do fail2ban e da blacklist.
- **Novo roteador:** o agente percebe o cadastro em cerca de 2 s e envia para ele tudo o que já está bloqueado. Não precisa reiniciar o serviço.
- **Desabilitar:** o roteador para de receber bloqueios, mas os que já estão nele ficam lá.
- **Excluir:** por padrão, também remove do roteador os bloqueios criados pelo agente.
- **Preparação:** cada roteador precisa ser preparado com o [mikrotik-setup.rsc](mikrotik-setup.rsc), como o principal. Ele precisa do usuário, da API liberada para o IP do servidor e da regra raw.

```
/ip firewall address-list print where list=fail2ban
```

## Blacklist: bloqueios manuais

Para bloquear no MikroTik IPs ou redes que o fail2ban não pegou, edite o arquivo:

```bash
sudo nano /etc/f2b-mikrotik/blacklist.txt
```

Use um IP ou uma rede por linha. O texto depois de `#` é comentário:

```
203.0.113.45              # scanner insistente
198.51.100.0/24           # rede inteira
```

- Ao salvar, o agente percebe a mudança em cerca de 2 segundos e atualiza o roteador. Não precisa reiniciar o serviço.
- Apagar ou comentar a linha libera o IP no roteador.
- No MikroTik, essas entradas aparecem com o comentário `f2b-agent [blacklist] ...`.
- Se uma entrada cair na `whitelist`, ela é ignorada e o motivo fica registrado no log.
- Um IP banido pelo fail2ban que já está dentro de uma rede da blacklist não é duplicado no roteador.
- Se o fail2ban estiver fora do ar, a blacklist continua sendo aplicada, mas nada é removido do roteador.

```
2026-10-23 21:02:10 [INFO] blacklist /etc/f2b-mikrotik/blacklist.txt alterada
2026-10-23 21:02:12 [INFO] BLOQUEADO no MikroTik: 198.51.100.0/24 (jail: blacklist)
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
| `[blacklist] file` | arquivo de bloqueios manuais (vazio desativa) |
| `[mikrotik] name` | nome do roteador principal no log e no painel |
| `[agent] routers_file` | arquivo dos roteadores cadastrados pelo painel |
| `entry_timeout` | ex.: `7d`. As entradas expiram sozinhas no roteador se o agente for desinstalado ou parar; enquanto o IP seguir banido, o agente o recoloca |
| `ipv6` | replica também para `/ipv6 firewall address-list` |
| `use_ssl` / `port` | usar `api-ssl` (8729) |

## Remover tudo

```bash
sudo systemctl disable --now f2b-mikrotik f2b-mikrotik-web
```

```bash
sudo python3 /opt/f2b-mikrotik/f2b_mikrotik.py --flush
```

O `--flush` remove de todos os roteadores só as entradas criadas pelo agente.

## Observações

- Ao **parar** o fail2ban, ele libera todos os IPs. O agente então os remove do roteador. Quando o fail2ban volta, os bans persistentes (`Restore Ban`) são recolocados.
- Compatível com RouterOS v6 (inclusive anterior à 6.43) e v7. Testa automaticamente o comando `fail2ban-client banned` (0.11.2+) e recorre ao `status` em versões antigas.
