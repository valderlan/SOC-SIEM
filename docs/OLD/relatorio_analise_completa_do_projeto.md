# Relatório de Auditoria Minuciosa do Repositório — Open SOC Lab (`SOC-SIEM`)

**Data da Auditoria:** 16 de novembro de 2026  
**Repositório:** `SOC-SIEM` (`open-soc-lab` v0.1.0, branch `etapa4`)  
**Documentos de Referência Analisados:**
- Especificação Oficial: [especifica_o_do_projeto_soc_siem_open_source.md](especifica_o_do_projeto_soc_siem_open_source.md)
- Registro das alterações da Etapa 4: [relatorio4.md](relatorio4.md)

---

## 1. O Que Já Foi Feito

O projeto **Open SOC Lab** implementa as **4 etapas evolutivas** planejadas (HIDS/SIEM $\rightarrow$ NIDS $\rightarrow$ SOAR/Resposta Ativa $\rightarrow$ Integração Ponta a Ponta, Dashboards e Automação 1-Clique), cobrindo **todas as 5 camadas tecnológicas obrigatórias** e **todos os 6 fluxos ponta a ponta** definidos em [especifica_o_do_projeto_soc_siem_open_source.md](especifica_o_do_projeto_soc_siem_open_source.md).

### 1.1. Mapeamento contra as 5 Camadas Obrigatórias (Seção 2 da Especificação)

| Camada da Especificação | Ferramenta Homologada Utilizada | Status | Implementação Concreta no Repositório |
|---|---|---|---|
| **1. HIDS** (Coleta de OS e integridade de host) | **Wazuh Agent** (`v4.14.8`) | **Implementado e Ativo** | • Container alvo [infra/linux-target/Dockerfile](../../infra/linux-target/Dockerfile) e [ossec.conf.tmpl](../../infra/linux-target/ossec.conf.tmpl) com `wazuh-agent=4.14.8-1` monitorando `/var/log/auth.log`, `/var/log/nginx/access.log`, `/var/log/nginx/error.log`, `/var/log/suricata/eve.json`, `/var/log/soclab/audit.jsonl` e integridade em tempo real (**FIM/syscheck**) em `/etc/soclab-protected`.<br>• Scripts para máquinas dedicadas/VMs em [install_wazuh_agent.ps1](../../scripts/windows/install_wazuh_agent.ps1) (Windows) e [install_wazuh_agent_debian.sh](../../scripts/linux/install_wazuh_agent_debian.sh) (Linux), além de auto-instalação via `soclab stage1 verify --ensure-agent`. |
| **2. NIDS / NSM** (Inspeção de tráfego e detecção em rede) | **Suricata** (`7.0.3` / `EVE JSON`) | **Implementado e Ativo** | • Sensor Suricata rodando em tempo real na interface `eth0` do `linux-target` ([entrypoint.sh](../../infra/linux-target/entrypoint.sh)), exportando eventos em `runtime/suricata/eve.json` e encaminhando-os ao Wazuh.<br>• 6 assinaturas customizadas determinísticas (`SIDs 910001–910006`) em [local.rules](../../infra/linux-target/local.rules) cobrindo severidades `LOW`, `MEDIUM`, `HIGH` e `CRITICAL`.<br>• Coletor em streaming tolerante a falhas ([collectors/suricata.py](../../src/soclab/collectors/suricata.py)), normalizador ([normalizers/suricata.py](../../src/soclab/normalizers/suricata.py)) e serviço de filtragem/validação ([services/nids.py](../../src/soclab/services/nids.py)).<br>• Scripts para instalação nativa em Linux: [install_suricata.sh](../../scripts/linux/install_suricata.sh) e [configure_suricata_wazuh.sh](../../scripts/linux/configure_suricata_wazuh.sh). |
| **3. SIEM** (Centralização, normalização, indexação e correlação) | **Wazuh** (`Manager` + `Indexer` + `Dashboard` `v4.14.8`) | **Implementado e Ativo** | • Stack single-node oficial em `infra/wazuh-docker/single-node` inicializada por [bootstrap_wazuh.ps1](../../scripts/bootstrap_wazuh.ps1) / [bootstrap_wazuh.sh](../../scripts/bootstrap_wazuh.sh).<br>• Cliente REST síncrono com JWT Bearer e retry em GET ([clients/wazuh.py](../../src/soclab/clients/wazuh.py)) suportando `api_info()`, `agents()`, `logtest()` e `send_event()`.<br>• Regras customizadas `100101–100151` em [local_rules.xml](../../infra/wazuh-custom/local_rules.xml) para elevação de alertas Suricata, correlação de brute-force SSH (`frequency="5"` em `60s`), SQLi/Path Traversal, FIM e reingestão do `audit.jsonl` do SOAR.<br>• Integração automática `<integration><name>shuffle</name>` (`level >= 6`) provisionada em `/var/ossec/etc/ossec.conf`. |
| **4. SOAR** (Orquestração de workflows e resposta ativa) | **Shuffle SOAR** + **SOC Lab FastAPI** + **Mailpit** | **Implementado e Ativo** | • Stack completa em [compose.yaml](../../compose.yaml): `shuffle-frontend` (`:3001`), `shuffle-backend` (`:5001`), `shuffle-orborus`, `shuffle-opensearch`, `mailpit` (`:8025` / `:1025`) e `soclab` (`:8080`).<br>• Workflow `SOC Lab - Wazuh Automated Response` provisionado via API ([services/provision.py](../../src/soclab/services/provision.py)) e exportado em [soclab_workflow.json](../../infra/shuffle/soclab_workflow.json).<br>• API FastAPI ([api/app.py](../../src/soclab/api/app.py)) com `GET /health`, `GET /ready`, `POST /api/v1/alerts` e `POST /api/v1/unblock`, protegida por `X-SOCLAB-TOKEN` (`secrets.compare_digest`).<br>• Normalizador polimórfico ([normalizers/shuffle.py](../../src/soclab/normalizers/shuffle.py)) compatível com o envelope `all_fields` nativo do Wazuh.<br>• Motor de decisão ([services/policy.py](../../src/soclab/services/policy.py), [services/response.py](../../src/soclab/services/response.py)), proteção *fail-closed* de redes ([domain/networks.py](../../src/soclab/domain/networks.py)), deduplicação SQLite ([services/dedup.py](../../src/soclab/services/dedup.py)), auditoria JSONL ([services/audit.py](../../src/soclab/services/audit.py)), captura de evidências ([services/evidence.py](../../src/soclab/services/evidence.py)) e adapters de firewall Windows/Linux/Dry-Run ([adapters/firewall.py](../../src/soclab/adapters/firewall.py)). |
| **5. Dashboards** (Visualização operacional e Threat Hunting) | **Wazuh Dashboard** (OpenSearch Dashboards) | **Implementado e Ativo** | • Pacote NDJSON [soclab-dashboard.ndjson](../../infra/wazuh-dashboard/soclab-dashboard.ndjson) importado automaticamente com 8 *Saved Objects*: painel **`Open SOC Lab - SOC Overview`** (`dashboard-soclab-overview`), 6 visualizações (Total de Alertas, Severidade, Eventos por Host/OS, Série Temporal, Anomalias de Rede Suricata, Respostas do SOAR) e 1 busca salva de Threat Hunting.<br>• Guia de investigação e queries DQL em [dashboards-and-threat-hunting.md](dashboards-and-threat-hunting.md). |

### 1.2. Cobertura das 5 Ações Práticas de Resposta (Seção 3.6 da Especificação)

1. **Bloqueio de IP (Firewall):** executado de forma real e isolada via `nftables` (`nft add rule inet filter input ip saddr <ip> drop`) dentro do namespace de rede do container `linux-target`, com suporte a rollback via `soclab unblock <ip>` / `POST /api/v1/unblock`, mantendo o host físico Windows protegido em `dry-run`.
2. **Execução de Scripts / Comandos:** invocação segura de subprocessos (`shell=False`, timeout e validação canônica de IP via `ip_address()`) nos adapters de firewall e automação de ataques/verificação via CLI.
3. **Notificações (E-mail / Chat):** envio automático de e-mails enriquecidos via SMTP para o **Mailpit** (`http://127.0.0.1:8025`) em decisões `NOTIFY` e `BLOCK_IP`, além de nó condicional para Webhook de Chat externo (Discord/Slack via `SOCLAB_CHAT_WEBHOOK_URL`).
4. **Registro da Ação (Auditoria):** gravação append-only thread-safe em `logs/audit.jsonl` e reingestão automática pelo Wazuh Agent (`regras 100150/100151`) para exibição no Dashboard.
5. **Coleta de Evidências:** geração automática de arquivos forenses em `logs/evidence/<alert_id>.json` para todo incidente `HIGH` ou `CRITICAL`, contendo o alerta normalizado, o payload bruto e os metadados da decisão do SOAR.

### 1.3. Cobertura da Topologia de Referência (VM01 a VM06 — Seção 4 da Especificação)

| Papel na Especificação | Implementação no Repositório |
|---|---|
| **VM01 — Wazuh Server** | Containers `single-node-wazuh.manager-1`, `single-node-wazuh.indexer-1` e `single-node-wazuh.dashboard-1` conectados à rede `soclab-net`. |
| **VM02 — Suricata (NIDS)** | Sensor Suricata integrado ao `linux-target` inspecionando a interface `eth0` da sub-rede `172.28.0.0/24` (e scripts `scripts/linux/*` para VM dedicada). |
| **VM03 — Shuffle SOAR** | Containers `shuffle-frontend`, `shuffle-backend`, `shuffle-orborus`, `shuffle-opensearch`, `mailpit` e `soclab`. |
| **VM04 — Endpoint Linux + Serviços** | Container `linux-target` (`172.28.0.20`) rodando Ubuntu 24.04, Nginx Web Server, OpenSSH, diretório FIM `/etc/soclab-protected` e Wazuh Agent `001`. |
| **VM05 — Endpoint Windows** | Script automatizado [install_wazuh_agent.ps1](../../scripts/windows/install_wazuh_agent.ps1) e suporte via `soclab stage1 verify --ensure-agent` para o host Windows físico ou VM Windows. |
| **VM06 — Kali Linux (Ataques)** | Container `kali-attacker` (`172.28.0.200`) com `nmap`, `curl`, `hydra`, `sshpass` e script [simulate_attacks.sh](../../infra/kali-attacker/simulate_attacks.sh) acionável via `soclab attack`. |

---

## 2. O Que Falta

Contrastando minuciosamente o estado atual do repositório com [especifica_o_do_projeto_soc_siem_open_source.md](especifica_o_do_projeto_soc_siem_open_source.md), **não resta nenhuma lacuna nos componentes obrigatórios de software ou integração**. Os pontos abaixo referem-se apenas a **(a)** ativação opcional do agente Windows para a apresentação, **(b)** itens explicitamente marcados como opcionais na especificação e **(c)** finalização do fluxo Git:

### 2.1. Ativação do Endpoint Windows (VM05) durante a Demonstração (Opcional / Sob Demanda)
- **Situação atual:** Por decisão arquitetural para manter o laboratório 100% contido em Docker no dia a dia, apenas o agente Linux (`linux-target`, ID `001`, Ubuntu) está conectado neste instante (`Registered: 1, Active: 1`).
- **O que fazer caso queira exibir eventos Windows + Linux simultaneamente na apresentação:** executar em PowerShell como Administrador o script já pronto [install_wazuh_agent.ps1](../../scripts/windows/install_wazuh_agent.ps1) (`.\scripts\windows\install_wazuh_agent.ps1 -Manager 127.0.0.1 -AgentName windows-host`) ou `soclab stage1 verify --ensure-agent --agent-manager 127.0.0.1`. O painel `SOC Lab - Eventos por Host / Agente (Linux vs Windows)` no Wazuh Dashboard já está configurado para agrupar automaticamente ambos os sistemas operacionais (`agent.os.name`).

### 2.2. Componentes Marcados como Opcionais na Especificação (Não Incluídos por Escopo)
1. **Zeek (NSM — Seção 3.2):** listado na especificação como *"Opcional/Complementar"*. A inspeção de rede foi atendida integralmente com o **Suricata**.
2. **Grafana (Seção 3.4):** listado como *"Opcional"*. Os painéis operacionais foram construídos nativamente no **Wazuh Dashboard** (`Open SOC Lab - SOC Overview`).
3. **Suricata em modo IPS inline (Seção 3.2):** listado como *"opcional"*. O bloqueio ativo foi implementado na camada SOAR via `nftables`.
4. **Servidores de Banco de Dados (DB Server) e Arquivos (File Server) dedicados (Seção 3.1):** a especificação cita *"tais como Web Server, DB Server e File Server"*. O laboratório implementa **Web Server (Nginx)**, **SSH Server (OpenSSH)**, ** ataque de SQL Injection via HTTP** (`SID 910004` / regra `100120`) e **monitoramento de integridade de arquivos críticos (FIM)** em `/etc/soclab-protected/sensitive.conf` (regra `100130`), sem necessidade de subir containers extras de MySQL/Samba.

### 2.3. Consolidação no Git (Commit e Merge das Branches)
- As alterações da Etapa 4 encontram-se na árvore de trabalho da branch `etapa4` (ainda não comitadas).
- As branches locais `develop` e `main` ainda apontam para o commit da Etapa 2 (`1306490`), portanto após o commit na `etapa4` será necessário abrir Pull Request / fazer merge para `develop` e `main`.

---

## 3. Erros Encontrados, Pontos de Atenção e Oportunidades de Melhoria

Durante a inspeção minuciosa do código-fonte, configurações e histórico Git, foram identificados os seguintes pontos técnicos — divididos entre **higiene do repositório Git** e **melhorias técnicas de código/configuração**:

### 3.1. Higiene do Repositório Git e Segurança de Configuração (Recomendado corrigir antes do `git commit`)

1. **Arquivo `.env` rastreado pelo Git contendo senhas/tokens locais:**
   - **Problema:** O arquivo [.env](../../.env) foi comitado originalmente na Etapa 1 (commit `6cc2029`) e não está listado no [.gitignore](../../.gitignore). Como ele foi preenchido com `SOCLAB_WAZUH_PASSWORD=MyS3cr37P450r.*-` e `SOCLAB_WEBHOOK_TOKEN=soclab-dev-token`, um `git commit -a` enviaria essas credenciais ao repositório.
   - **Correção recomendada:** remover `.env` do índice do Git mantendo o arquivo local (`git rm --cached .env`) e incluir `.env` no [.gitignore](../../.gitignore).
2. **Artefatos de teste (`.coverage` e resíduos de `.pytest_tmp/`) e gitlink órfão `infra/wazuh-docker` no índice Git:**
   - **Problema:** Na raiz existe um arquivo `.coverage` não ignorado pelo [.gitignore](../../.gitignore). Além disso, o commit `6cc2029` (Etapa 1) registrou arquivos temporários dentro de `.pytest_tmp/` e um *gitlink* (`160000`) em `infra/wazuh-docker` sem `.gitmodules`.
   - **Correção recomendada:** adicionar `.coverage` e `infra/wazuh-docker/` ao [.gitignore](../../.gitignore) e limpar entradas residuais do índice com `git rm -r --cached .pytest_tmp infra/wazuh-docker`.
3. **Arquivo `main.py` sem função na raiz do projeto:**
   - **Problema:** [main.py](../../main.py) contém apenas `print("Hello from soc-siem-open-source!")` gerado na criação inicial do projeto pelo `uv`, enquanto o ponto de entrada real configurado em [pyproject.toml](../../pyproject.toml#L17-L18) é `soclab = "soclab.cli:app"`.
   - **Melhoria:** remover `main.py` ou fazê-lo delegar para `soclab.cli:app()`.

### 3.2. Melhorias Técnicas de Código e Operação

1. **Caminho `SOCLAB_SURICATA_EVE_PATH` quando a CLI roda diretamente no host Windows:**
   - **Observação:** Em [.env.example](../../.env.example#L16), `SOCLAB_SURICATA_EVE_PATH=/var/log/suricata/eve.json`. Dentro dos containers (`linux-target` e `soclab`), esse caminho existe e funciona. Porém, quando o usuário executa `soclab nids status` ou `soclab stage2 verify` diretamente no Windows, o caminho é resolvido como `\var\log\suricata\eve.json` (inexistente no Windows), fazendo `soclab nids alerts` usar a fixture de demonstração (`tests/fixtures/suricata/eve.json`) em vez de ler o arquivo ao vivo que o container `linux-target` já expõe no host em `runtime/suricata/eve.json`.
   - **Melhoria sugerida:** em [cli.py](../../src/soclab/cli.py#L389-L397) / [nids.py](../../src/soclab/services/nids.py), verificar automaticamente se `runtime/suricata/eve.json` existe no projeto antes de recorrer à fixture de demo no Windows (ou definir `SOCLAB_SURICATA_EVE_PATH=runtime/suricata/eve.json` no `.env` do host, já que o `compose.yaml` sobrescreve `SOCLAB_SURICATA_EVE_PATH=/var/log/suricata/eve.json` dentro do container `soclab`).
2. **Tabela de deduplicação SQLite (`AlertDeduplicator`) sem expiração (TTL) ou limpeza no `unblock`:**
   - **Observação:** Em [dedup.py](../../src/soclab/services/dedup.py#L28), os `alert_id` processados ficam gravados permanentemente em `runtime/soclab_state.db`. Para alertas reais do Wazuh/Suricata isso não impede novos bloqueios porque cada novo evento possui `id`/`timestamp` distinto; contudo, se um operador desbloquear um IP (`soclab unblock <ip>`) e reenviar manualmente exatamente o mesmo JSON de teste com `alert_id` fixo, ele será ignorado como `duplicate=True`.
   - **Melhoria sugerida:** adicionar um subcomando opcional `soclab dedup clear` ou parâmetro `--TTL` para ambientes de longa duração.
3. **Verificação TLS (`verify=False`) hardcoded no provisionamento e verificador da Etapa 4:**
   - **Observação:** Enquanto [clients/wazuh.py](../../src/soclab/clients/wazuh.py#L47) utiliza `verify=settings.httpx_verify` (permitindo habilitar TLS estrito via `SOCLAB_WAZUH_VERIFY_TLS` e `SOCLAB_WAZUH_CA_BUNDLE`), as chamadas ao Wazuh Dashboard em [provision.py](../../src/soclab/services/provision.py#L590) e [stage4_verification.py](../../src/soclab/services/stage4_verification.py#L408) passam `verify=False` diretamente.
   - **Melhoria sugerida:** reutilizar `self._settings.httpx_verify` também nas chamadas ao Wazuh Dashboard.
4. **Acoplamento de formatação JSON na regra `100151` do Wazuh:**
   - **Observação:** Em [local_rules.xml](../../infra/wazuh-custom/local_rules.xml#L71-L76), a regra `100151` usa `<match>"action": "BLOCK_IP"</match>`. Ela funciona perfeitamente com `AuditLogger.record()` porque `json.dumps` insere espaço após `:`, mas caso outro produtor grave `"action":"BLOCK_IP"` sem espaço, apenas a regra pai `100150` dispararia.
5. **Pequenos detalhes cosméticos de metadados e documentação prévia:**
   - O arquivo [relatorio_estado_atual_do_projeto.md](relatorio_estado_atual_do_projeto.md) foi escrito *antes* da implementação da Etapa 4 (como diagnóstico inicial) e por isso descreve como pendentes itens que já foram implementados e documentados em [relatorio4.md](relatorio4.md).
   - Em [api/app.py](../../src/soclab/api/app.py#L104), o endpoint `GET /health` retorna `stage=3` (mantido por compatibilidade com os testes unitários da Etapa 3 em [test_api.py](../../tests/unit/test_api.py)).
   - Na execução do `pytest`, a biblioteca `starlette.testclient` emite 1 `StarletteDeprecationWarning` sobre `httpx` (originado internamente pelo FastAPI/Starlette, sem impacto em execução real).

---

## 4. Testes Executados

Todos os testes unitários, checagens estáticas de código, scripts de provisionamento e verificadores das **Etapas 1, 2, 3 e 4** foram executados diretamente no ambiente e seus resultados reais estão registrados abaixo:

### 4.1. Resumo Consolidado das Execuções

| Suíte / Comando Executado | Status | Tempo | Resultado Observado |
|---|---|---|---|
| `.\.venv\Scripts\pytest.exe --basetemp .\.pytest_tmp` | **PASS** | `2.19s` | **`91 passed, 1 warning`** (100% dos 91 testes aprovados em 15 arquivos de teste). |
| `.\.venv\Scripts\ruff.exe check .` | **PASS** | `<1s` | **`All checks passed!`** (0 erros de lint/formatação). |
| `.\.venv\Scripts\mypy.exe src` | **PASS** | `<2s` | **`Success: no issues found in 35 source files`** (tipagem estrita `strict = true`). |
| `.\scripts\up.ps1 -SkipBuild` | **PASS** | `~49s` | **Código de saída `0`** — subiu Wazuh + 8 containers do Compose, validou endpoints HTTP/HTTPS, provisionou regras/Shuffle/Dashboard e aprovou `stage4 verify --quick`. |
| `.\.venv\Scripts\soclab.exe stage1 verify --quick --no-color` | **PASS / WARN** | `0.9s` | Docker CLI/Engine/Compose `PASS`, containers Wazuh `PASS`, API `4.14.8` `PASS`, `1` agente ativo (`Ubuntu`) `PASS`, `Wazuh Logtest` (`sshd`, regra `5710`, nível `5`) `PASS`. Status geral `WARN` apenas porque `Real event test`, `Pytest`, `Ruff` e `Mypy` são `SKIP` no modo `--quick`. |
| `.\.venv\Scripts\soclab.exe stage2 verify --quick --demo --no-color` | **PASS** | `1.1s` | **`STAGE 2 STATUS: READY FOR DEMO`** — API e containers Wazuh `PASS`, parsing tolerante de `tests/fixtures/suricata/eve.json` (`10` linhas, `9` válidas, `1` JSON inválido tratado sem abortar, `5` alertas normalizados) `PASS`. |
| `.\.venv\Scripts\soclab.exe stage3 verify --quick --demo --no-color` | **PASS** | `0.1s` | **`Stage 3 ...................... PASS`** — configuração, matriz de política (`LOW/MEDIUM -> LOG`, `HIGH -> NOTIFY`, `CRITICAL -> BLOCK_IP`), guarda de IPs protegidos, deduplicação SQLite, auditoria JSONL, adapter `dry-run`, API Webhook (`401`/`200`/`duplicate`) e demo ponta a ponta em `PASS` (`Warnings: none`, `Failures: none`). |
| `.\.venv\Scripts\soclab.exe demo final` | **PASS** | `<1s` | **`Demo result ................... PASS`** (`Run id: 1df5b29e`) — validou os 6 cenários de decisão (`low`, `medium`, `high`, `critical`, `duplicate`, `protected`) e os 6 checks in-process da API Webhook. |
| `.\.venv\Scripts\soclab.exe stage4 verify --no-color` | **PASS** | `4.8s` | **`STAGE 4 STATUS: READY`** — todos os 6 grupos de verificação em `PASS` (incluindo `Pytest`, `Ruff` e `Mypy`). |
| `.\.venv\Scripts\soclab.exe attack check` | **PASS** | `<2s` | **`ACCESS: OPEN (HTTP 200 reachable from attacker)`** — conectividade inicial entre `kali-attacker` (`172.28.0.200`) e `linux-target` validada; em execução anterior de `soclab attack all`, comprovou-se o bloqueio automático (`ACCESS: BLOCKED`), geração de 11 arquivos de evidência em `logs/evidence/` e desbloqueio via `soclab unblock 172.28.0.200`. |

### 4.2. Detalhamento dos 91 Testes Unitários (`pytest`)

A suíte automatizada em `tests/unit/` cobre todas as camadas da aplicação:
- [test_api.py](../../tests/unit/test_api.py) (**10 testes**): `/health`, `/ready` (`200` e `503`), autenticação `X-SOCLAB-TOKEN` (`401` sem token ou token inválido), decisão `CRITICAL -> BLOCK_IP` com `evidence_path`, duplicidade, IP protegido, erro `400` em payload inválido e endpoint `POST /api/v1/unblock`.
- [test_cli.py](../../tests/unit/test_cli.py) (**9 testes**): comandos de CLI das Etapas 1 a 4 (`config`, `health`, `agents`, `nids`, `unblock`, `attack`).
- [test_config.py](../../tests/unit/test_config.py) (**4 testes**): carregamento de `Settings`, obrigatoriedade de `SOCLAB_WAZUH_PASSWORD` no modo estrito e modo opcional.
- [test_health.py](../../tests/unit/test_health.py) (**1 teste**) e [test_models.py](../../tests/unit/test_models.py) (**1 teste**): modelos e agregação de saúde do Wazuh.
- [test_nids.py](../../tests/unit/test_nids.py) (**7 testes**): coleta `SuricataEveCollector`, tolerância a JSON corrompido, normalização de severidades Suricata e filtragem por severidade/IP.
- [test_provision.py](../../tests/unit/test_provision.py) (**2 testes**): idempotência de `upsert_shuffle_integration()` e geração do workflow do Shuffle (`build_shuffle_workflow_definition()`) com Mailpit e com/sem webhook de chat.
- [test_response_policy.py](../../tests/unit/test_response_policy.py) (**12 testes**): matriz de severidade, rebaixamento seguro para `NOTIFY` em IPs protegidos (loopback, RFC1918, IPv6) ou sem `src_ip`.
- [test_response_service.py](../../tests/unit/test_response_service.py) (**11 testes**): garantia de que `dry-run` nunca executa bloqueio real, deduplicação SQLite, gravação de auditoria sem vazar segredos, captura de evidências em `HIGH`/`CRITICAL`, `unblock_ip` e detecção de handles `nftables` (`find_nft_rule_handles`).
- [test_shuffle_mapper.py](../../tests/unit/test_shuffle_mapper.py) (**12 testes**): mapeamento de payloads canônicos, alertas brutos do Wazuh, envelopes `{"alert": ...}` e `{"all_fields": ...}` com campos aninhados `data.*`.
- [test_stage1_verification.py](../../tests/unit/test_stage1_verification.py) (**10 testes**), [test_stage2_verification.py](../../tests/unit/test_stage2_verification.py) (**3 testes**), [test_stage3_verification.py](../../tests/unit/test_stage3_verification.py) (**3 testes**) e [test_stage4_verification.py](../../tests/unit/test_stage4_verification.py) (**1 teste**): serviços de verificação das 4 etapas.
- [test_wazuh_client.py](../../tests/unit/test_wazuh_client.py) (**5 testes**): autenticação JWT, renovação automática após `401`, retry de transporte em `GET`, `logtest` e `send_event`.

### 4.3. Saída Real do Verificador Ponta a Ponta (`soclab stage4 verify --no-color`)

```text
─────────────── Open SOC Lab - Stage 4 End-to-End Verification ────────────────

[1/6] Checking containerized lab stack
  Docker Compose stack.............. PASS All 8 lab services are running.

[2/6] Checking Wazuh endpoints & Shuffle integration
  Wazuh enrolled endpoints.......... PASS Active endpoints: linux-target(001)
  Wazuh -> Shuffle integration...... PASS local_rules.xml and Shuffle <integration> block are active.

[3/6] Checking live Suricata NIDS telemetry
  Live Suricata EVE log............. PASS Live EVE OK: lines=477, alerts=9

[4/6] Checking Shuffle, SOC Lab API & Mailpit
  SOC Lab API (/ready).............. PASS ready (adapter=linux-nftables, dry_run=False)
  Shuffle UI & Workflow............. PASS UI 200 and workflow 'SOC Lab - Wazuh Automated Response' active.
  Mailpit local email UI............ PASS HTTP 200 (http://127.0.0.1:8025)

[5/6] Checking Wazuh Dashboard visualizations
  Wazuh SOC Overview Dashboard...... PASS Custom dashboard 'Open SOC Lab - SOC Overview' imported.

[6/6] Running quality checks
  Pytest............................ PASS Check passed.
  Ruff.............................. PASS Check passed.
  Mypy.............................. PASS Check passed.
──────────────────────────────── FINAL RESULT ─────────────────────────────────
STAGE 4 STATUS: READY
Total time: 4.8s
```
