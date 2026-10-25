# f2b-mikrotik

Replica nos MikroTiks os IPs banidos e liberados pelo fail2ban, para que o bloqueio aconteça **na borda**. Tem um **painel web**, com usuários, papéis e auditoria, para consultar o que está bloqueado, desbanir IPs e manter roteadores, blacklist, whitelist e configurações.

```
 fail2ban (servidor Linux)                         MikroTiks
 ┌──────────────────────────┐   API 8728/8729   ┌────────────────────────────────────┐
 │ /var/log/fail2ban.log ───┼─► f2b_mikrotik ──►│ /ip firewall address-list fail2ban │
 │ fail2ban-client banned ──┘   (daemon)   ▲    │ /ip firewall raw  drop src-list    │
 └──────────────────────────┘              │    └────────────────────────────────────┘
          painel web (f2b_web.py) ──► config.db (SQLite): roteadores, blacklist, whitelist,
                                      configurações, usuários e auditoria
```

## Como funciona

O agente roda como daemon (systemd) e faz duas coisas:

1. **Eventos:** acompanha o `fail2ban.log` (`Ban`, `Unban`, `Restore Ban`) e sincroniza ~2 s depois. Faz o mesmo quando algo muda no painel.
2. **Reconciliação:** a cada 60 s (configurável), compara o que deveria estar bloqueado (fail2ban + blacklist + retenções − whitelist) com a address-list de **cada** roteador e corrige as diferenças. Por isso nada se perde se um roteador cair, o agente reiniciar ou o log rotacionar.

## Retenção no MikroTik (bloqueio maior que o do fail2ban)

A liberação nos MikroTiks tem um controle próprio, paralelo ao do fail2ban: quando o fail2ban **libera** um IP, seja porque o ban venceu, seja por um `unban`, o MikroTik continua bloqueando esse IP por mais um tempo, que você define. Assim o servidor pode usar bans curtos, que perdoam rápido um usuário legítimo, enquanto a borda segura o atacante por mais tempo.

Configure em **Configurações → Retenção no MikroTik**:

| Opção | Exemplo | Efeito |
|---|---|---|
| Manter bloqueado por mais | `7d` | depois que o fail2ban libera, o IP fica mais 7 dias bloqueado nos MikroTiks. Vazio desliga a retenção. |
| Dobrar a cada reincidência | ✓ | se o mesmo IP for liberado de novo em até 30 dias, a retenção dobra: 7d, 14d, 28d… |
| Retenção máxima | `90d` | limite da retenção dobrada |

As durações usam `s`, `m`, `h`, `d` e `w`, e podem ser combinadas: `1d12h`, `2w`.

Como a retenção funciona:
- **Contagem:** começa no momento em que o fail2ban libera o IP, e não no ban. Por isso é sempre um bloqueio **a mais**, qualquer que seja o `bantime` do fail2ban.
- **Detecção:** a liberação é percebida pelo log do fail2ban ou, sem ele, comparando duas sincronizações. Em ambos os casos o IP é retido antes de sincronizar, então ele **nunca sai do roteador**, nem por um instante.
- **Na tela:** a tabela da visão geral mostra **"retido até dd/mm hh:mm"**. O filtro "retido no MikroTik" lista só esses IPs, e a consulta de IP informa quando o fail2ban liberou e até quando dura a retenção.
- **Liberação manual:** o botão **Liberar no MikroTik** (operador ou administrador) encerra a retenção na hora.
- **Desbanir pelo painel:** libera de verdade. Tira o IP do fail2ban e dos MikroTiks **sem** aplicar retenção.
- **Vencimento:** quando a retenção termina, o agente libera o IP nos roteadores sozinho.
- **Desligar:** apagar o tempo de retenção encerra todas as retenções em andamento. Elas não voltam se a retenção for religada.
- **Whitelist e reinício do fail2ban:** IPs da whitelist nunca são retidos. Ao **parar** o fail2ban, ele libera todos os IPs, e com a retenção ligada todos ficam retidos, o que evita uma janela sem bloqueio durante o reinício.
- **Auditoria:** registra `retencao.iniciada`, `retencao.liberada` (com usuário e motivo) e `retencao.expirada`.

### Garantias de segurança

- **Entradas manuais preservadas:** o agente só altera entradas cujo comentário começa com `f2b-agent`. As demais entradas da mesma lista ficam intactas.
- **Fail2ban fora do ar:** se o `fail2ban-client` falhar, **nada é removido** dos roteadores.
- **Vários roteadores:** um roteador fora do ar não atrapalha os outros, e recebe tudo quando voltar.
- **Configuração sensível fica no servidor:** o que pode dar controle do servidor (caminhos de comandos e arquivos usados como root, porta e TLS do painel) **não** é editável pela web. Fica no `config.ini`.
- **Senhas protegidas:** as senhas dos roteadores nunca vão para o navegador, e as dos usuários são guardadas com hash PBKDF2.
- **Auditoria completa:** toda ação, de pessoas e do agente, fica registrada.

## Instalação

### 1. MikroTik

Edite [mikrotik-setup.rsc](mikrotik-setup.rsc) (IP do servidor, senha, interface WAN) e cole no terminal de cada roteador. Ele cria:
- o usuário `f2b-agent`, com permissão só de API, e que só aceita login a partir do servidor;
- a liberação da API para o servidor;
- a regra `/ip firewall raw` que descarta `src-address-list=fail2ban` vinda da WAN.

### 2. Servidor Linux

Requisitos: Python 3.7+ (sem bibliotecas extras) e fail2ban. Tudo roda como root, porque o `fail2ban-client` exige.

```bash
sudo sh install.sh
```

```bash
sudo systemctl enable --now f2b-mikrotik f2b-mikrotik-web
```

Abra `http://IP-DO-SERVIDOR:8088/` e entre com o usuário **admin** e a senha que o `install.sh` mostrou. Depois:
1. Na aba **Roteadores**, cadastre os MikroTiks e use **Testar conexão**.
2. Na aba **Configurações**, revise a whitelist: ela já vem com as redes privadas.
3. Na aba **Usuários**, crie um usuário para cada pessoa e troque a senha do admin.

Para conferir, sem alterar nada:

```bash
sudo python3 /opt/f2b-mikrotik/f2b_mikrotik.py --test
```

### Atualização a partir da 1.x

```bash
cd /opt/f2b-mikrotik && git pull && sh install.sh && systemctl restart f2b-mikrotik f2b-mikrotik-web
```

Na primeira subida da 2.0, a configuração atual é **importada automaticamente** para `/var/lib/f2b-mikrotik/config.db`:
- o roteador do `[mikrotik]` e os do `routers.json`;
- a blacklist do `blacklist.txt`;
- a whitelist, os intervalos, as jails, o país e o token do ipinfo do `config.ini`;
- o usuário **admin**, com a senha atual de `[web] password`.

A importação é registrada na auditoria e no log. Depois dela, `routers.json`, `blacklist.txt` e essas opções do `config.ini` **deixam de ser usados**; tudo passa a ser editado no painel. Os arquivos antigos não são apagados.

## Painel web

Roda na porta **8088**, sem Node e sem dependências. O login é por sessão: o cookie é `HttpOnly` e `SameSite=Strict`, a sessão expira após 8 h sem uso, e há o botão **Sair**. Depois de 5 senhas erradas em 15 minutos, o IP fica bloqueado por 15 minutos.

### Papéis

| | leitura | operador | administrador |
|---|:-:|:-:|:-:|
| Visão geral, consulta de IP, estatísticas, log do agente | ✓ | ✓ | ✓ |
| Desbanir IP no fail2ban, liberar retenção no MikroTik | | ✓ | ✓ |
| Incluir e remover da blacklist | | ✓ | ✓ |
| Whitelist, roteadores, configurações | | | ✓ |
| Usuários e auditoria | | | ✓ |

Cada usuário pode **trocar a própria senha**, e ao trocá-la suas outras sessões são encerradas. Desativar um usuário, mudar seu papel ou redefinir sua senha também derruba as sessões dele na hora. O sistema não deixa excluir, desativar ou rebaixar o **último administrador**.

### Abas

- **Este IP está bloqueado?** Diz em quais roteadores o IP está bloqueado e por quê: jail, blacklist (com a validade) ou dentro de uma rede bloqueada. Mostra também país, provedor e histórico. Avisa quando o IP deveria estar bloqueado e não está, ou quando está na whitelist, e traz botões para desbanir e para incluir na blacklist ou tirar dela.
- **Visão geral:** o estado de cada roteador e a tabela única de bloqueios, com fail2ban, blacklist e cada MikroTik, mais país e quantidade de bloqueios. Tem também a blacklist, com o formulário para incluir.
- **Estatísticas:** bloqueios e desbloqueios por hora, IPs mais bloqueados, bloqueios por país e por jail, e os últimos eventos.
- **Roteadores:** cadastrar, editar, testar a conexão e excluir MikroTiks. Todos recebem os mesmos bloqueios.
- **Configurações:** intervalos, validade da entrada no roteador, jails replicadas, IPv6, **retenção no MikroTik**, retenção do histórico e da auditoria, fonte do país (RIRs ou ipinfo) e token do ipinfo. Também a **whitelist**, com inclusão e remoção.
- **Usuários:** cadastrar, editar (papel, nome, ativo, nova senha) e excluir usuários.
- **Auditoria:** a trilha completa, com filtros por usuário, tipo de ação, texto e período, e exportação em **CSV**.
- **Log do agente:** as últimas linhas do `/var/log/f2b-mikrotik.log`.

### Blacklist

Bloqueia IPs ou redes que o fail2ban não pegou, em todos os MikroTiks, em ~2 s.
- **Validade:** cada inclusão pode ter validade de 1 hora, 6 horas, 1 dia, 7 dias, 30 dias ou 90 dias, ou ser **permanente**. Quando vence, o agente remove a entrada sozinho e registra na auditoria.
- **Recusas:** o painel recusa entradas que estão na whitelist e redes maiores que /8.
- **Rede da blacklist:** um IP banido pelo fail2ban que já está dentro de uma rede da blacklist não é duplicado no roteador.

### Whitelist

São IPs e redes que o agente **nunca** bloqueia, nem pelo fail2ban nem pela blacklist.
- **Ao incluir:** o painel avisa quais entradas da blacklist deixam de valer.
- **Ao remover:** se a entrada contém o seu próprio IP, o painel pede uma confirmação extra.
- **Recusas:** redes maiores que /8 (IPv4) são recusadas, porque fariam o agente parar de bloquear boa parte da internet.

### Auditoria

Tudo fica registrado com data e hora, usuário, IP de origem, ação, alvo e detalhes:

| Grupo | Ações |
|---|---|
| Acesso | `login.ok`, `login.falha`, `login.bloqueado`, `logout`, `acesso.negado` |
| Usuários | `usuario.criado` / `alterado` / `removido` / `senha_redefinida`, `senha.alterada` / `falha` |
| Configuração | `config.alterada` (valor antigo → novo; o token aparece como `********`) |
| Roteadores | `roteador.criado` / `alterado` / `removido` / `limpeza_falhou` |
| Listas | `blacklist.incluido` / `removido` / `expirado`, `whitelist.incluido` / `removido` |
| Operação | `fail2ban.unban`, `retencao.iniciada` / `liberada` / `expirada`, `auditoria.exportada` |
| Agente | `agente.bloqueio` / `liberacao` (por roteador), `agente.erro`, `agente.iniciado` / `encerrado` |
| Sistema | `sistema.migracao`, `painel.iniciado` |

Os registros são guardados por 365 dias, valor que dá para mudar em Configurações.

### Recuperar o acesso

Se você perder a senha do admin, rode no servidor:

```bash
sudo python3 /opt/f2b-mikrotik/f2b_mikrotik.py --reset-password admin
```

O comando pede a nova senha. Se o usuário não existir, ele é criado como administrador. A ação é registrada na auditoria como feita pelo `terminal`.

### HTTPS

Sem certificado, o tráfego é HTTP puro, incluindo o login. Fora da rede interna, configure o HTTPS em `[web] tls_cert` / `tls_key` no `config.ini`.

## O que fica no config.ini

Só o que não pode ser alterado pela web:

| Seção | Opções |
|---|---|
| `[mikrotik]` | `address_list`, `comment_prefix` |
| `[fail2ban]` | `client` (comando executado como root), `logfile` |
| `[agent]` | `config_db`, `events_db`, `logfile`, `log_level`, `lockfile` |
| `[web]` | `bind`, `port` (padrão 8088), `tls_cert`, `tls_key`, `geo_file` e `password` (senha **inicial** do admin, usada só na primeira subida) |

## Observabilidade

O agente grava num histórico (`events.db`) cada bloqueio e desbloqueio, tanto do fail2ban quanto da blacklist. Na primeira execução, importa o que ainda estiver no `fail2ban.log` e nos logs rotacionados. A partir disso, o painel mostra quantas vezes cada IP foi bloqueado, o país de origem e os bloqueios e desbloqueios por hora.

**País de origem:**
- **Padrão (tabelas dos RIRs):** tabelas públicas de alocação dos cinco registros regionais (ARIN, RIPE, LACNIC, APNIC, AFRINIC). São baixadas uma vez por semana e consultadas localmente, então nenhum IP sai do servidor. O servidor precisa de acesso HTTPS a `ftp.arin.net`, `ftp.ripe.net`, `ftp.lacnic.net`, `ftp.apnic.net` e `ftp.afrinic.net`.
- **Opcional (ipinfo Lite):** em Configurações, escolha **ipinfo Lite** e informe o token gratuito de https://ipinfo.io/signup. Dá a geolocalização, mais precisa para nuvens, e o provedor (ASN). Cada IP público é consultado uma vez e fica em cache. Se a API falhar, vale o país dos RIRs. Com essa opção, os IPs bloqueados são enviados ao ipinfo.io.
- **Desconhecido:** IP privado ou reservado, ou não encontrado.

## Acompanhando o log

```bash
tail -f /var/log/f2b-mikrotik.log
```

```
2026-10-24 17:58:13 [INFO] f2b-mikrotik 2.0.0 iniciado: lista=fail2ban jails=todas
2026-10-24 17:58:13 [INFO] roteadores: sede (192.168.1.254:8728), filial (10.0.0.1:8728)
2026-10-24 17:58:15 [INFO] fail2ban: [sshd] Ban 203.0.113.77
2026-10-24 17:58:16 [INFO] BLOQUEADO no MikroTik [sede]: 203.0.113.77 (jail: sshd)
2026-10-24 17:58:16 [INFO] BLOQUEADO no MikroTik [filial]: 203.0.113.77 (jail: sshd)
2026-10-24 18:58:15 [INFO] fail2ban: [sshd] Unban 203.0.113.77
2026-10-24 18:58:15 [INFO] RETIDO no MikroTik: 203.0.113.77 ate 2026-10-31 18:58 (o fail2ban liberou; reincidencia 1)
2026-10-24 18:02:40 [INFO] configuracao atualizada pelo painel; roteadores: sede (...), filial (...), loja (...)
2026-10-24 18:40:00 [ERROR] falha ao comunicar com o MikroTik [filial] 10.0.0.1:8728: timed out (nova tentativa em 15s)
```

Erros de partida e a migração também aparecem em `journalctl -u f2b-mikrotik` e `journalctl -u f2b-mikrotik-web`.

## Outros modos do agente

| Comando | Para quê |
|---|---|
| `--test` | testa banco, fail2ban e roteadores, sem alterar nada |
| `--once` | uma sincronização e sai (modo cron, sem histórico de eventos) |
| `--dry-run -v` | mostra o que faria, sem alterar os roteadores |
| `--flush` | remove de todos os roteadores as entradas criadas pelo agente |
| `--reset-password USUARIO` | recupera o acesso ao painel |

## Remover tudo

```bash
sudo systemctl disable --now f2b-mikrotik f2b-mikrotik-web
```

```bash
sudo python3 /opt/f2b-mikrotik/f2b_mikrotik.py --flush
```

## Observações

- **Parar o fail2ban libera tudo:** ao parar, o fail2ban libera todos os IPs, e o agente os remove dos roteadores. Quando o fail2ban volta, os bans persistentes (`Restore Ban`) são recolocados.
- **Compatibilidade:** funciona com RouterOS v6 (inclusive anterior à 6.43) e v7, e com fail2ban 0.10 ou mais novo.
