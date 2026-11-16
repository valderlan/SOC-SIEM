# Relatório Completo da Sessão e da Etapa 4 — Open SOC Lab (`SOC-SIEM`)

**Projeto:** `SOC-SIEM` (`open-soc-lab`)  
**Branch de trabalho:** `etapa4` (baseada no commit `08728a8` — *Add Stage 3 SOAR response pipeline*)  
**Data:** 16 de novembro de 2026  
**Documento de referência:** `docs/especifica_o_do_projeto_soc_siem_open_source.md`

---

## 1. Resumo Executivo

Nesta sessão, o ambiente **Open SOC Lab** foi diagnosticado desde o bootstrap inicial no Windows 11 + WSL2 + Docker Desktop, auditado contra a especificação oficial do projeto e evoluído até a conclusão completa da **Etapa 4**, fechando o ciclo operacional de **1-clique** e ponta a ponta:

```text
[kali-attacker (172.28.0.200)]
        │  Reconhecimento (ICMP/Nmap) / Web SQLi / SSH Brute-Force / Path Traversal
        ▼
[linux-target (172.28.0.20)] ─── Ubuntu 24.04 + Nginx (:80 / :8081) + OpenSSH (:22 / :2222)
   ├── Suricata 7.0.3 NIDS (eth0 -> /var/log/suricata/eve.json, SIDs 910001-910006)
   └── Wazuh Agent 4.14.8 (auth.log, nginx, eve.json, FIM /etc/soclab-protected, audit.jsonl)
        │
        ▼ (rede Docker soclab-net)
[Wazuh SIEM (wazuh.manager + wazuh.indexer + wazuh.dashboard :443, :55000, :9200)]
   ├── local_rules.xml (regras 100101-100151)
   └── <integration> shuffle (level >= 6, json)
        │
        ▼ Webhook HTTP
[Shuffle SOAR (shuffle-frontend :3001, shuffle-backend :5001, shuffle-orborus, opensearch)]
   ├── Ação 1: POST http://soclab:8080/api/v1/alerts (header X-SOCLAB-TOKEN)
   └── Branch condicional (action == BLOCK_IP ou NOTIFY):
         ├── E-mail SMTP -> Mailpit (:1025 / Webmail http://127.0.0.1:8025)
         └── Webhook de Chat opcional (SOCLAB_CHAT_WEBHOOK_URL)
        │
        ▼
[SOC Lab SOAR API (:8080, network_mode: "service:linux-target")]
   ├── ResponsePolicy + Guarda de Redes Protegidas (172.28.0.0/25 protegido; .200 bloqueável)
   ├── Bloqueio real isolado via nftables no linux-target (Windows físico mantido em dry-run)
   ├── Coleta forense JSON em logs/evidence/ para alertas HIGH e CRITICAL
   └── Auditoria JSONL em logs/audit.jsonl -> reingerida no Wazuh (100150/100151) -> Dashboard
```

### Decisões arquiteturais definidas durante a sessão
1. **Topologia portátil em containers:** toda a arquitetura operacional (alvo Linux com serviços Web/SSH + Suricata + Wazuh Agent, SIEM Wazuh, SOAR Shuffle, servidor SMTP/Webmail Mailpit e atacante Kali Linux) foi encapsulada em Docker, mantendo o script `scripts/windows/install_wazuh_agent.ps1` disponível caso se deseje adicionar um endpoint Windows físico na demonstração final.
2. **Bloqueio real seguro por isolamento:** a resposta ativa `BLOCK_IP` executa bloqueio real via `nftables` exclusivamente dentro do namespace de rede compartilhado entre `soclab` e `linux-target` (`network_mode: "service:linux-target"`, `SOCLAB_RESPONSE_DRY_RUN=false` no container), preservando o `.env` local em `SOCLAB_RESPONSE_DRY_RUN=true` para não alterar o firewall do Windows físico.
3. **Notificações locais e extensíveis:** o workflow do Shuffle envia notificações SMTP reais para o container **Mailpit** (com Webmail em `http://127.0.0.1:8025`) e oferece suporte opcional a webhook externo de chat (Discord/Slack) via `SOCLAB_CHAT_WEBHOOK_URL`.

---

## 2. Linha do Tempo do Diagnóstico Inicial e Levantamento de Gaps

1. **Validação inicial da CLI e serviços locais:**
   - Identificado por que `http://localhost:1514/` e `http://localhost:9200/` não respondiam antes do bootstrap dos containers e esclarecido que a porta `1514` é TCP binária de comunicação dos agentes Wazuh (não HTTP) enquanto a `9200` usa HTTPS interno do OpenSearch/Wazuh Indexer.
   - Removida a pasta vazia `infra/wazuh-docker` (gitlink sem conteúdo) e inicializado o stack oficial `wazuh/wazuh-docker` `v4.14.8` (`wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`) via `.\scripts\bootstrap_wazuh.ps1` com ajuste de `vm.max_map_count=262144` no WSL2 (`Ubuntu-24.04`).
   - Explicada a tela inicial do Wazuh Dashboard (`Overview` exibindo apenas eventos internos do próprio manager antes da conexão de agentes externos) e o funcionamento do teste de geração de eventos SSH (`rule.id: 5710`).
   - Criado e populado o arquivo `.env` local a partir do `.env.example` com `SOCLAB_WAZUH_PASSWORD` e `SOCLAB_WEBHOOK_TOKEN`.
2. **Diagnóstico da Etapa 3 no Docker:**
   - Subida da stack inicial com `docker compose --profile full up -d`, validação live do endpoint `POST /api/v1/alerts` (`HTTP 401` sem `X-SOCLAB-TOKEN` e `HTTP 200` com `action=BLOCK_IP` em `dry-run`).
   - Identificada a causa do crash em loop do `shuffle-frontend` (`invalid port in upstream "shuffle-backend:5001:5001"` no Nginx por receber `:5001` em `BACKEND_HOSTNAME`).
3. **Análise de lacunas contra a especificação oficial:**
   - Produzido o levantamento técnico completo em `docs/relatorio_estado_atual_do_projeto.md`, detalhando os gaps entre as Etapas 1–3 e os requisitos da Etapa 4 (elo automático `Wazuh -> Shuffle`, coleta de evidências, notificações, dashboards e Threat Hunting, cenários reais de ataque com Kali Linux e automação 1-clique).

---

## 3. Tudo o Que Foi Criado e Modificado

### 3.1. Infraestrutura Docker e Scripts de Automação

| Arquivo | Tipo | O que foi feito |
|---|---|---|
| `compose.yaml` | Modificado | Configurada rede `soclab-net` (`172.28.0.0/24`); corrigido `shuffle-frontend` (`BACKEND_HOSTNAME: shuffle-backend`, porta `3001:80`); ajustado `shuffle-backend` (`SHUFFLE_DEFAULT_APIKEY` em formato UUID de 36 caracteres); adicionado `shuffle-orborus` em modo standalone (`SHUFFLE_SWARM_CONFIG: ""`, `container_name: shuffle-orborus`); adicionados os serviços `mailpit` (`172.28.0.14`, portas `8025` e `1025`), `linux-target` (`172.28.0.20`, portas `8080`, `8081:80`, `2222:22`) e `kali-attacker` (`172.28.0.200`); acoplado `soclab` via `network_mode: "service:linux-target"` com `CAP_NET_ADMIN`, `SOCLAB_PROTECTED_NETWORKS` protegendo `172.28.0.0/25` e `SOCLAB_RESPONSE_DRY_RUN=false` isolado no container. |
| `Dockerfile` | Modificado | Instalado o pacote `nftables` na imagem `soclab` (`python3.12-bookworm-slim` + `uv`) para permitir aplicação e remoção real de regras no namespace isolado. |
| `.env.example` / `.env` | Modificados | Adicionadas as variáveis `SOCLAB_EVIDENCE_DIR`, `SHUFFLE_DEFAULT_USERNAME`, `SHUFFLE_DEFAULT_PASSWORD`, `SHUFFLE_DEFAULT_APIKEY` e `SOCLAB_CHAT_WEBHOOK_URL`; `.env` local configurado para o laboratório. |
| `.gitattributes` | Modificado | Definida normalização LF para scripts shell (`*.sh text eol=lf`) evitando falhas de execução em containers Linux criados a partir do Windows. |
| `infra/linux-target/Dockerfile` | Criado | Imagem Ubuntu 24.04 com `nginx`, `openssh-server`, `suricata`, `nftables`, `wazuh-agent=4.14.8-1`, usuário de teste `soclab-user` e arquivo semente em `/etc/soclab-protected/sensitive.conf` para FIM. |
| `infra/linux-target/local.rules` | Criado | 6 assinaturas Suricata determinísticas (`SIDs 910001–910006`) cobrindo `priority` 4 (`LOW`), 3 (`MEDIUM`), 2 (`HIGH`) e 1 (`CRITICAL`): ICMP ping, `/admin`, scanner HTTP Nmap, SQLi `UNION SELECT`, threshold de brute-force SSH e Path Traversal `/etc/passwd`. |
| `infra/linux-target/ossec.conf.tmpl` | Criado | Configuração do Wazuh Agent conectando em `wazuh.manager:1514`, com `syscheck` em tempo real para `/etc/soclab-protected` e `localfile` para `/var/log/auth.log`, `/var/log/nginx/access.log`, `/var/log/nginx/error.log`, `/var/log/suricata/eve.json` e `/var/log/soclab/audit.jsonl`. |
| `infra/linux-target/entrypoint.sh` | Criado | Inicialização de `inet filter` / `input` no `nftables`, start de `sshd -E /var/log/auth.log`, `nginx`, `suricata -i eth0 -k none -S /etc/suricata/rules/local.rules -D`, auto-registro do agente via `agent-auth` e `wazuh-control start`. |
| `infra/linux-target/index.html` | Criado | Página Web alvo servida pelo Nginx em `linux-target:80` (exposta no host em `http://127.0.0.1:8081`). |
| `infra/kali-attacker/Dockerfile` e `simulate_attacks.sh` | Criados | Container `kalilinux/kali-rolling` com `nmap`, `curl`, `hydra`, `sshpass`, `ping` e `nc` + script de simulação com modos `recon`, `web`, `ssh`, `all` e `check`. |
| `infra/wazuh-custom/local_rules.xml` | Criado | Regras customizadas `100101–100151`: elevação Suricata (`100101` nível `13`, `100102` nível `10`, `100103` nível `6`), correlação SSH brute-force (`100110`/`100111` nível `12` com `frequency="5"` em `60s`), ataques Web (`100120` nível `10`, `100121` nível `13`), FIM em `/etc/soclab-protected` (`100130` nível `10`) e indexação do `logs/audit.jsonl` (`100150` nível `4` e `100151` nível `5`, mantidas abaixo do nível `6` da integração Shuffle para evitar loops). |
| `infra/shuffle/soclab_workflow.json` | Criado | Exportação sanitizada do workflow provisionado do Shuffle (`__SOCLAB_WEBHOOK_TOKEN__`). |
| `infra/wazuh-dashboard/soclab-dashboard.ndjson` | Criado | Pacote NDJSON com 8 objetos OpenSearch Dashboards: 6 visualizações (`Total de Alertas`, `Alertas por Severidade`, `Eventos por Host/Agente`, `Tendência Temporal`, `Anomalias de Rede Suricata`, `Respostas Automatizadas do SOAR`), 1 busca salva de Threat Hunting (`search-soclab-threat-hunting`) e o dashboard **`Open SOC Lab - SOC Overview`** (`dashboard-soclab-overview`). |
| `scripts/up.ps1`, `scripts/up.sh` e `scripts/down.ps1` | Criados | Scripts 1-clique de subida, verificação HTTP, provisionamento e encerramento para Windows PowerShell (5.1 e 7+) e Linux/WSL2. |

### 3.2. Código Python (`src/soclab`) e Testes (`tests/unit`)

| Arquivo | Tipo | Alterações implementadas |
|---|---|---|
| `src/soclab/config.py` | Modificado | Adicionados `evidence_dir: Path = Path("logs/evidence")` (`SOCLAB_EVIDENCE_DIR`) e `chat_webhook_url: str = ""` (`SOCLAB_CHAT_WEBHOOK_URL`) em `Settings`. |
| `src/soclab/services/evidence.py` | Criado | Classe `EvidenceCollector` que grava snapshots forenses em JSON (`alert` completo + decisão de resposta) para incidentes `HIGH` e `CRITICAL`, com sanitização de nomes de arquivo. |
| `src/soclab/adapters/firewall.py` | Modificado | Adicionados `unblock_ip()`, `build_unblock_command()`, `find_nft_rule_handles()`, criação idempotente da tabela/chain `inet filter input` (`_ensure_chain()`) e verificação prévia para evitar regras duplicadas no `LinuxFirewallAdapter`. |
| `src/soclab/services/response.py` | Modificado | Integração do `EvidenceCollector` em `ResponseService.handle()` preenchendo `ResponseOutcome.evidence_path`, além do método auditado `ResponseService.unblock(ip)`. |
| `src/soclab/normalizers/shuffle.py` | Modificado | Suporte em `_unwrap()` ao envelope nativo `all_fields` emitido pelo `/var/ossec/integrations/shuffle.py` do Wazuh (descartando o `severity` comprimido externo `1/2/3` para respeitar `rule.level` 0–15) e lookup em campos aninhados `data.*` (`src_ip`, `dst_ip`, `alert.signature`). |
| `src/soclab/api/app.py` | Modificado | Campo `evidence_path` em `AlertDecisionResponse` e novo endpoint autenticado `POST /api/v1/unblock` (`UnblockRequest` / `UnblockResponse`). |
| `src/soclab/services/provision.py` | Criado | Serviço idempotente `LabProvisionService` (com `upsert_shuffle_integration()` e `build_shuffle_workflow_definition()`): conecta `single-node-wazuh.manager-1` à rede `soclab-net`, cria/atualiza o workflow no Shuffle com trigger webhook + API `soclab` + Mailpit + chat opcional, sincroniza `local_rules.xml` e `<integration>` no Wazuh Manager (validando com `wazuh-analysisd -t` antes de reiniciar) e importa `soclab-dashboard.ndjson` no Wazuh Dashboard. |
| `src/soclab/services/stage3_verification.py` | Modificado | Diretório de evidências (`evidence_dir`) isolado no diretório temporário da verificação para não poluir `logs/evidence/` durante `soclab stage3 verify`. |
| `src/soclab/services/stage4_verification.py` | Criado | Serviço `Stage4VerificationService` executando 6 blocos de validação: containers do Compose (`REQUIRED_SERVICES`), agentes inscritos e integração Shuffle no Wazuh, telemetria Suricata em `runtime/suricata/eve.json`, API `soclab /ready` + Shuffle UI/Workflow + Mailpit Webmail, presença do dashboard `dashboard-soclab-overview` e checagens de qualidade (`pytest`, `ruff`, `mypy`). |
| `src/soclab/cli.py` | Modificado | Novos comandos e subcomandos: `soclab unblock <ip>`, `soclab lab provision`, `soclab stage4 verify` (`--quick/--verbose/--no-color`) e `soclab attack [recon|web|ssh|all|check]`. |
| `tests/unit/test_provision.py` e `tests/unit/test_stage4_verification.py` | Criados | Testes unitários cobrindo `upsert_shuffle_integration`, `build_shuffle_workflow_definition` (com e sem chat webhook) e `Stage4VerificationService`. |
| `tests/unit/test_api.py`, `test_cli.py`, `test_response_service.py`, `test_shuffle_mapper.py`, `test_stage3_verification.py` | Modificados | Ampliação da suíte de 81 para **91 testes unitários** cobrindo `unblock`, evidências, `all_fields` do Wazuh/Shuffle, CLI da Etapa 4 e isolamento de arquivos temporários nos testes. |

### 3.3. Documentação Criada / Atualizada

- `docs/relatorio_estado_atual_do_projeto.md`: análise completa de aderência e gaps antes da implementação da Etapa 4.
- `docs/dashboards-and-threat-hunting.md`: descrição das visualizações do dashboard `Open SOC Lab - SOC Overview` e 8 consultas DQL prontas de Threat Hunting.
- `docs/attack-simulation-guide.md`: guia passo a passo dos cenários de ataque (`recon`, `web`, `ssh`) e validação de bloqueio/auditoria/desbloqueio.
- `Relatorio_Etapa_4.md` e `README.md`: resumo técnico da Etapa 4 e guia de inicialização 1-clique na raiz do repositório.
- `docs/relatorio4.md`: este relatório detalhado.

---

## 4. Problemas Reais Encontrados e Corrigidos Durante a Validação

1. **Nginx do `shuffle-frontend` em loop de reinício:** `BACKEND_HOSTNAME=shuffle-backend:5001` fazia o `/entrypoint.sh` do frontend gerar `shuffle-backend:5001:5001`. Corrigido definindo `BACKEND_HOSTNAME: shuffle-backend`.
2. **Chave padrão do Shuffle Backend:** `SHUFFLE_DEFAULT_APIKEY` exige string UUID válida de 36 caracteres para inicializar corretamente no bootstrap (`7f8e9d0c-1a2b-4c3d-8e9f-0a1b2c3d4e5f`).
3. **Execução de apps do Shuffle sem Docker Swarm:** adicionado `shuffle-orborus` com `container_name: shuffle-orborus` e `SHUFFLE_SWARM_CONFIG: ""` para modo Docker Compose standalone.
4. **Envelope nativo `all_fields` do Wazuh:** a integração padrão `shuffle.py` do Wazuh comprime severidade no nível raiz em `1/2/3` enquanto mantém o `rule.level` original (`0–15`) dentro de `all_fields`, além de aninhar campos Suricata em `data.*`. O normalizador `src/soclab/normalizers/shuffle.py` foi atualizado para desembrulhar corretamente sem rebaixar alertas críticos.
5. **Sintaxe OSRegex no Wazuh e prevenção de loop:** em `infra/wazuh-custom/local_rules.xml`, ajustado `<field>` para `\.+` (em vez de `.+`), usado `<match>"action": "BLOCK_IP"</match>` na regra `100151`, e mantidas as regras de reingestão do `audit.jsonl` nos níveis `4` e `5` (abaixo do `<level>6</level>` configurado na integração do Shuffle).
6. **Compatibilidade Windows PowerShell 5.1 no `scripts/up.ps1`:** a flag `Invoke-WebRequest -SkipCertificateCheck` (disponível apenas no PowerShell 7+) falhava no Windows PowerShell 5.1 nativo; substituída por probe via `httpx` do `.venv` (`Wait-HttpReady`).
7. **Endpoint de health check do Shuffle Backend:** `/api/v1/getenvironments` retorna HTTP `401` sem sessão autenticada, causando timeout nos probes com `raise_for_status()` / `curl -f`. Alterado em `scripts/up.ps1` e `scripts/up.sh` para `http://127.0.0.1:5001/api/v1/health` (HTTP `200`) e `http://127.0.0.1:3001` (HTTP `200`).

---

## 5. Resultados das Verificações Executadas Após a Última Edição

Todos os comandos abaixo foram executados após as últimas edições nos scripts de startup (`scripts/up.ps1` e `scripts/up.sh`):

| Comando | Resultado observado |
|---|---|
| `.\scripts\up.ps1 -SkipBuild` | **Código de saída `0` (`STAGE 4 STATUS: READY`)** — inicializou Wazuh + 8 serviços do Compose, aguardou `/health`, HTTPS `:443`, Shuffle Backend `:5001/api/v1/health` e Shuffle UI `:3001`, executou `lab provision` (workflow `d9d45cc2-7daa-4d30-9c82-260c615729a7`, `Dashboard objects imported: 8`) e concluiu `stage4 verify --quick`. |
| `.\.venv\Scripts\pytest.exe --basetemp .\.pytest_tmp` | **`91 passed, 1 warning in 2.19s`** (o único aviso é `StarletteDeprecationWarning` em `fastapi/testclient.py`). |
| `.\.venv\Scripts\ruff.exe check .` | **`All checks passed!`** |
| `.\.venv\Scripts\mypy.exe src` | **`Success: no issues found in 35 source files`** |
| `.\.venv\Scripts\soclab.exe stage1 verify --quick --no-color` | Docker CLI/Engine/Compose, `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`, configuração, API `4.14.8`, `1` agente ativo (`Ubuntu`) e `logtest` (`sshd`, regra `5710`, nível `5`) todos em `PASS` (`Stage 1: WARN` apenas porque `Real event test`, `Pytest`, `Ruff` e `Mypy` são pulados com `--quick`). |
| `.\.venv\Scripts\soclab.exe stage3 verify --quick --demo --no-color` | **`Stage 3 ...................... PASS`** (`Warnings: none`, `Failures: none`; checagens de qualidade puladas com `--quick`). |
| `.\.venv\Scripts\soclab.exe stage4 verify --no-color` | **`STAGE 4 STATUS: READY` (`4.8s`)** — todos os 6 blocos em `PASS`: 8 serviços Docker rodando, `linux-target(001)` ativo no Wazuh, `local_rules.xml` e `<integration>` ativos, `eve.json` ao vivo (`lines=477, alerts=9`), `soclab /ready` (`adapter=linux-nftables, dry_run=False`), Shuffle UI `200` e workflow ativo, Mailpit HTTP `200`, dashboard `Open SOC Lab - SOC Overview` importado, e `Pytest`/`Ruff`/`Mypy` aprovados. |
| `.\.venv\Scripts\soclab.exe attack check` | **`ACCESS: OPEN (HTTP 200 reachable from attacker)`** — atacante `172.28.0.200` desbloqueado e pronto para demonstração ao vivo. |

---

## 6. Guia Rápido de Operação e Demonstração

### URLs e Credenciais do Laboratório Ativo
- **Wazuh Dashboard:** https://localhost (`admin` / `SecretPassword`) $\rightarrow$ *Explore* $\rightarrow$ *Dashboards* $\rightarrow$ **`Open SOC Lab - SOC Overview`**
- **Shuffle SOAR UI:** http://localhost:3001 (`admin` / `soclab-shuffle-admin`)
- **Mailpit Webmail:** http://127.0.0.1:8025
- **SOC Lab SOAR API Docs:** http://127.0.0.1:8080/docs
- **Alvo Web Linux (Nginx):** http://127.0.0.1:8081

### Sequência de Demonstração ao Vivo
```powershell
# 1. Subir e provisionar todo o ambiente com 1 clique (quando estiver parado)
.\scripts\up.ps1

# 2. Confirmar que o atacante Kali (172.28.0.200) alcança o alvo
.\.venv\Scripts\soclab.exe attack check

# 3. Executar ataques controlados (ICMP/Nmap recon, SQLi Web e Brute-force SSH + /etc/passwd)
.\.venv\Scripts\soclab.exe attack all

# 4. Aguardar ~10-20s para o pipeline Wazuh -> Shuffle -> soclab atuar e comprovar o bloqueio real
.\.venv\Scripts\soclab.exe attack check

# 5. Inspecionar regra aplicada no nftables, evidências forenses e auditoria JSONL
docker compose --profile full exec linux-target nft list ruleset
Get-ChildItem .\logs\evidence\
Get-Content .\logs\audit.jsonl -Tail 5

# 6. Desbloquear o IP atacante após a demonstração
docker compose --profile full exec soclab soclab unblock 172.28.0.200

# 7. Encerrar todo o laboratório (Stack Stage 4 + Wazuh single-node)
.\scripts\down.ps1
```

### Observações Importantes
- Caso deseje demonstrar também um endpoint Windows no Wazuh Dashboard, utilize `scripts/windows/install_wazuh_agent.ps1`.
- O arquivo `.env` local contém credenciais/tokens de laboratório (`SOCLAB_WAZUH_PASSWORD` e `SOCLAB_WEBHOOK_TOKEN`) e aparece modificado no Git (`M .env`) porque já existia no histórico inicial; evite incluir segredos locais em commits públicos.
