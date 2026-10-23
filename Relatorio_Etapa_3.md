# Relatorio - Etapa 3 (SOAR + Resposta Ativa)

Projeto: **SOC-SIEM-Open-Source** (`open-soc-lab`)
Escopo: Etapa 3 - o sistema deixa de apenas detectar e passa a **decidir e
responder** a incidentes, com Modo Seguro (`dry-run`) como padrao.

Pipeline implementado:

```
Suricata / Wazuh  ->  Shuffle (orquestra)  ->  POST /api/v1/alerts  ->  SOC Lab (decide)  ->  Firewall Adapter (responde)
      detecta                                     webhook            policy + dedup + audit         dry-run / real
```

As Etapas 1 (Wazuh HIDS) e 2 (Suricata NIDS) foram preservadas: nenhum contrato
existente foi alterado, apenas estendido. `uv run pytest` continua cobrindo as
tres etapas (81 testes).

---

## 1. Arquivos criados

| Arquivo | Responsabilidade |
|---|---|
| `src/soclab/api/__init__.py` | Exporta `create_app`. |
| `src/soclab/api/app.py` | FastAPI: `GET /health`, `GET /ready`, `POST /api/v1/alerts`; validacao do header `X-SOCLAB-TOKEN` com `secrets.compare_digest()`; modelos de resposta (`HealthResponse`, `AlertDecisionResponse`). |
| `src/soclab/adapters/__init__.py` | Exporta adapters e a factory. |
| `src/soclab/adapters/firewall.py` | `FirewallAdapter` (interface ABC), `DryRunFirewallAdapter` (padrao), `WindowsFirewallAdapter` (PowerShell/`New-NetFirewallRule`), `LinuxFirewallAdapter` (nftables), `create_firewall_adapter()` e `build_block_command()`. |
| `src/soclab/domain/networks.py` | `DEFAULT_PROTECTED_NETWORKS`, `parse_network_list()`, `is_protected()` (comparacao por versao IPv4/IPv6, falha fechada). |
| `src/soclab/normalizers/shuffle.py` | `map_shuffle_alert()`: Mapper tolerante (payload canonico, JSON do Wazuh, envelope `{"alert": {...}}` do Shuffle) -> `SecurityAlert`. Nunca rebaixa severidade em silencio. |
| `src/soclab/services/policy.py` | `ResponseAction` (NONE/LOG/NOTIFY/BLOCK_IP), `SEVERITY_ACTIONS`, `ResponseDecision`, `ResponsePolicy` (politica + guarda de IP). |
| `src/soclab/services/dedup.py` | `AlertDeduplicator`: tabela `processed_alerts` em SQLite (stdlib), `is_duplicate()`, `count()`, `is_writable()`. |
| `src/soclab/services/audit.py` | `AuditLogger`: escrita JSONL append-only em `logs/audit.jsonl`, com lock (linhas nunca intercaladas). |
| `src/soclab/services/response.py` | `ResponseService` (policy -> dedup -> adapter -> audit), `ResponseOutcome`, `build_response_service(settings)`. |
| `src/soclab/services/api_smoke.py` | Smoke test in-process da API (`/health`, `/ready`, 401 sem/with token errado, 200 com token, duplicata) reutilizado por `verify`, `demo`. |
| `src/soclab/services/demo.py` | `run_demo()`: 6 caminhos de decisao + round-trip do webhook; `build_shuffle_payload()`, `build_demo_expectations()`. |
| `src/soclab/services/stage3_verification.py` | `Stage3VerificationService` + `Stage3VerificationReport`, reutilizando `CheckResult`/`CheckStatus`/`CommandResult` da Etapa 1. |
| `tests/unit/test_response_policy.py` | Matriz de severidade, IPs protegidos, ausencia de `src_ip`, redes customizadas. |
| `tests/unit/test_response_service.py` | Dry-run nunca executa, IP protegido nao chama adapter, dedup, auditoria sem segredos, factory. |
| `tests/unit/test_shuffle_mapper.py` | Payload canonico, wrapper Wazuh/Shuffle, niveis 0-15, epoch ms, payload invalido. |
| `tests/unit/test_api.py` | `health`, `ready` (200/503), 401 sem/with token errado, 200 CRITICAL, duplicata, protegido, 400. |
| `tests/unit/test_stage3_verification.py` | `verify --quick --demo` READY, falha de configuracao, demo cobre todos os caminhos. |
| `compose.yaml` | Profile `full`: `soclab` (API) + `shuffle-backend`, `shuffle-frontend`, `shuffle-opensearch`. |
| `Dockerfile` | Imagem Python 3.12 (uv) rodando `soclab run` em `0.0.0.0:8080`. |
| `docs/shuffle-workflow.md` | Fluxo, configuracao do webhook no Shuffle, payload aceito, tabela de decisao, codigos HTTP. |
| `Relatorio_Etapa_3.md` | Este documento. |

## 2. Arquivos modificados

| Arquivo | Alteracao |
|---|---|
| `pyproject.toml` | Dependencias `fastapi` e `uvicorn` (nenhuma outra adicionada). |
| `src/soclab/config.py` | Novos campos `Settings`: `webhook_token` (`SecretStr`), `api_host`, `api_port`, `response_dry_run=True`, `protected_networks`, `audit_log_path`, `state_db_path`; validador de CIDR na carga. Retrocompativel (todos com default). |
| `src/soclab/exceptions.py` | `AlertMappingError` e `ResponseError` (subclasses de `SocLabError`, para o CLI tratar sem traceback). |
| `src/soclab/cli.py` | Comandos `run`, `status`, `stage3 verify` (`--quick/--watch/--demo/--verbose/--interval/--no-color`), `demo final`; `config` agora mostra modo de resposta, audit log e token mascarado. Nada existente foi removido. |
| `README.md` | Secao "Etapa 3 - SOAR" com os comandos principais e as salvaguardas. |
| `.env.example` | Variaveis da Etapa 3 (`SOCLAB_WEBHOOK_TOKEN`, `SOCLAB_API_HOST/PORT`, `SOCLAB_RESPONSE_DRY_RUN`, `SOCLAB_PROTECTED_NETWORKS`, `SOCLAB_AUDIT_LOG_PATH`, `SOCLAB_STATE_DB_PATH`). |
| `.gitignore` | `logs/`, `runtime/`, `.pytest_tmp/` (estado local do laboratorio). |

---

## 3. Motivacao arquitetural

### 3.1 Separacao detectar -> orquestrar -> decidir -> responder
O SOC Lab **nao** escuta o firewall nem o Suricata: ele expoe um webhook. O
Shuffle orquestra (quem notifica, quem escala, quem abre ticket) e o SOC Lab
decide de forma deterministica. Vantagens:

- a politica de resposta fica em **um** lugar, testavel sem rede e sem firewall;
- trocar o orquestrador (Shuffle -> n8n) nao muda o nucleo;
- o nucleo continua funcionando offline (Etapas 1 e 2 intactas).

### 3.2 Mapper em vez de poluir o dominio
`SecurityAlert` (`src/soclab/domain/alert.py`) continua sendo o contrato
canonico. O Shuffle manda o que o workflow montar, entao a traducao vive em
`normalizers/shuffle.py` (mesmo pacote do normalizador Suricata da Etapa 2). O
dominio nao conhece `rule.level`, `srcip` ou envelopes de workflow.
Consequencias positivas:

- severidade ausente gera `AlertMappingError` -> HTTP 400, em vez de virar
  `LOW` silenciosamente (falha segura: um alerta sem severidade nao pode ser
  tratado como ruido);
- sem `alert_id`, o mapper deriva um hash SHA-256 estavel do payload, o que
  mantem a deduplicacao funcionando em reentregas.

### 3.3 `dry-run` como padrao obrigatorio
`SOCLAB_RESPONSE_DRY_RUN=true` e o default e `create_firewall_adapter()`
devolve `DryRunFirewallAdapter` em qualquer duvida (inclusive quando a
plataforma nao e Windows/Linux). O adapter de dry-run **gera o comando real**
(`nft add rule ... drop` / `New-NetFirewallRule ...`) mas nao o executa: a demo
mostra exatamente o que aconteceria em modo live, sem tocar no host. Para
ativar bloqueio real e preciso mudar explicitamente a variavel de ambiente -
nenhum comando do projeto (nem teste, nem `verify`, nem `demo`) ativa isso.
Alem disso, `stage3 verify` **forca** dry-run e estado temporario
(`settings.model_copy`), entao verificar nunca altera firewall nem a base de
producao.

### 3.4 Politica de severidade explicita e conservadora
| Severidade | Acao |
|---|---|
| LOW / MEDIUM | `LOG` |
| HIGH | `NOTIFY` |
| CRITICAL | `BLOCK_IP` |

`LOG`/`NOTIFY` nao executam nada no host: viram evento de auditoria (o envio de
notificacao e responsabilidade do Shuffle, que ja tem integracao de e-mail,
Slack, Teams etc.). Isso evita adicionar dependencias e credenciais ao nucleo.

### 3.5 Guarda de IP (fail closed)
Antes de qualquer bloqueio: sem `src_ip` -> `NOTIFY`; IP em
`SOCLAB_PROTECTED_NETWORKS` -> `NOTIFY` com `protected=true`. O default protege
loopback, link-local, ULA e todas as faixas RFC1918 (Wazuh manager, VLAN
administrativa, o proprio lab). Enderecos nao parseaveis sao tratados como
protegidos - o erro cai para o lado seguro. A comparacao respeita a versao
IPv4/IPv6 (sem `TypeError`).

### 3.6 Deduplicacao com SQLite da stdlib
O Shuffle reexecuta workflows, entao o mesmo alerta chega varias vezes. Um
`INSERT OR IGNORE` em `alert_id TEXT PRIMARY KEY` da deduplicacao atomica,
persistente entre reinicios, sem Redis/Kafka e sem dependencia nova. A falha e
resiliente: cada chamada abre/fecha a conexao, o que e seguro no threadpool do
FastAPI (`def` sync -> roda em worker thread). O unico limite conhecido esta
anotado no codigo: linhas nao expiram (`shortcut: ... add a TTL purge`).

### 3.7 Auditoria em JSONL
`logs/audit.jsonl` (uma linha JSON por alerta) e o formato que ferramentas de
SIEM e o proprio Wazuh consomem sem conversao. O registro contem
`alert_id/severity/action/requested_action/target_ip/executed/dry_run/duplicate/protected/adapter/reason`.
Escrita append com `threading.Lock` para nao intercalar linhas sob concorrencia.
O log e a prova de que a decisao aconteceu - inclusive a decisao de *nao*
bloquear.

### 3.8 Token do webhook
Header `X-SOCLAB-TOKEN`, comparado com `secrets.compare_digest()` sobre bytes
UTF-8 (evita `TypeError` com header nao-ASCII e mantem comparacao em tempo
constante). Ausente/errado -> **401**. Servidor sem `SOCLAB_WEBHOOK_TOKEN`
configurado -> **503** (nunca aceita token vazio). O token e `SecretStr`, nunca
aparece em log, `repr`, resposta HTTP, auditoria ou tabela do CLI (o `config`
mostra `********`, o `status`/`run` mostram apenas "configured/NOT CONFIGURED"),
e os testes verificam explicitamente que ele nao vaza no corpo das respostas.

### 3.9 API como camada fina
`create_app(settings=..., response_service=...)` permite injetar servico e
settings. Com isso o mesmo objeto FastAPI e usado em producao (`soclab run`),
nos testes (`TestClient`) e na verificacao in-process, sem subir porta e sem
duplicar regra de negocio. Os endpoints sao `def` (sync) porque toda a decisao
e I/O local rapido: o FastAPI os executa no threadpool e a thread do event loop
nao bloqueia.

### 3.10 Reuso das Etapas 1 e 2
`Stage3VerificationService` reutiliza `CheckResult`, `CheckStatus`,
`CommandResult`, `find_project_root` e os checks de qualidade (pytest/ruff/mypy)
de `Stage1VerificationService`, e usa o mesmo estilo de relatorio/`--watch`.
Nao existe um segundo framework de verificacao no projeto.

### 3.11 Empacotamento
`compose.yaml` usa **profile `full`**: `docker compose up` do dia a dia nao
sobe nada de Shuffle. O `Dockerfile` e multi-stage com `uv` (sem compilar
nada), roda `soclab run` e escreve em volumes `./logs` e `./runtime`, em
`dry-run` por padrao. Bloqueio real em container exigiria `cap_add: NET_ADMIN`
e, de proposito, nao esta habilitado.

---

## 4. Output esperado de `uv run soclab demo final`

```
Open SOC Lab - Stage 3 demo
                     Alert -> policy -> adapter (dry-run)
+-----------------------------------------------------------------------------+
| STEP      | SEVERITY | SRC IP        | REQUESTED | ACTION   | EXEC | RESULT |
|-----------+----------+---------------+-----------+----------+------+--------|
| low       | LOW      | 198.51.100.11 | LOG       | LOG      | no   | PASS   |
| medium    | MEDIUM   | 198.51.100.12 | LOG       | LOG      | no   | PASS   |
| high      | HIGH     | 203.0.113.7   | NOTIFY    | NOTIFY   | no   | PASS   |
| critical  | CRITICAL | 203.0.113.99  | BLOCK_IP  | BLOCK_IP | no   | PASS   |
| duplicate | CRITICAL | 203.0.113.99  | BLOCK_IP  | NONE     | no   | PASS   |
| protected | CRITICAL | 127.0.0.1     | BLOCK_IP  | NOTIFY   | no   | PASS   |
+-----------------------------------------------------------------------------+
                          Webhook API (in-process)
+--------------------------------------------------------------------------+
| CHECK                                | STATUS | DETAIL                   |
|--------------------------------------+--------+--------------------------|
| GET /health                          | PASS   | 200                      |
| GET /ready                           | PASS   | 200                      |
| POST /api/v1/alerts without token    | PASS   | HTTP 401                 |
| POST /api/v1/alerts with wrong token | PASS   | HTTP 401                 |
| POST /api/v1/alerts with token       | PASS   | HTTP 200 action=BLOCK_IP |
| duplicate webhook delivery           | PASS   | HTTP 200 duplicate=True  |
+--------------------------------------------------------------------------+
Run id ........................ 124a31be
Dry-run mode .................. YES
Audit log ..................... logs\audit.jsonl
Demo result ................... PASS
```

Codigo de saida: `0` (PASS). O `Run id` muda a cada execucao para que os
`alert_id` da demo nunca colidam com execucoes anteriores na base de dedup.
Cada passo grava uma linha em `logs/audit.jsonl`; o `dry-run mode YES` e o
`EXEC = no` em todas as linhas sao a prova de que nada foi aplicado no
firewall real.

Exemplo de linha de auditoria gerada:

```json
{"timestamp": "2026-10-23T20:03:16.309962+00:00", "alert_id": "demo-05a907d4-medium", "severity": "MEDIUM", "action": "LOG", "requested_action": "LOG", "target_ip": "198.51.100.12", "executed": false, "dry_run": true, "duplicate": false, "protected": false, "adapter": "dry-run", "reason": "MEDIUM severity requires LOG"}
```

---

## 5. Validacao executada

| Comando | Resultado |
|---|---|
| `uv sync` | OK (38 pacotes, `fastapi`/`uvicorn` adicionados) |
| `uv run pytest` | **81 passed** (1 warning de deprecacao do `starlette.testclient`, apenas nos testes) |
| `uv run ruff check .` | **All checks passed!** |
| `uv run mypy src` | **Success: no issues found in 32 source files** (strict) |
| `uv run soclab stage3 verify --demo` | PASS em configuracao/politica/protecao/dedup/audit/dry-run/API/demo/pytest/ruff/mypy; aviso esperado porque `SOCLAB_WEBHOOK_TOKEN` nao esta no `.env` local |
| `uv run soclab status` | Tabela com modo dry-run, adapter, redes protegidas, estado do SQLite |
| `uv run soclab run` + `curl` | `GET /health` 200, `GET /ready` 200, `POST /api/v1/alerts` 401 sem token e 200 com token, reenvio `duplicate=true` |
| `docker compose --profile full config` | OK (YAML valido) |

Nao executado: `docker build`. O Docker Desktop estava instalado mas com o
daemon parado (`npipe:////./pipe/dockerDesktopLinuxEngine` indisponivel), entao
a imagem nao pode ser construida neste ambiente.

### Riscos e limites conhecidos

1. `SOCLAB_RESPONSE_DRY_RUN=false` aplica bloqueio real e nao ha comando de
   rollback no CLI (os adapters nao removem regras). Em Windows/Linux o
   processo precisa de privilegio administrativo; sem ele o adapter retorna
   `executed=false` e o motivo fica na auditoria.
2. A regra nftables assume a tabela `inet filter` e a chain `input` existentes.
3. A base de dedup cresce indefinidamente (marcado com `shortcut:` em
   `services/dedup.py`).
4. `NOTIFY` nao envia nada por conta propria: a notificacao e do Shuffle.
5. Aviso de deprecacao do Starlette sobre `httpx` no `TestClient` nao afeta
   producao (a API usa uvicorn); pode ser resolvido quando `httpx2` for padrao.
