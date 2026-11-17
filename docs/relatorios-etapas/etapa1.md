# Relatório da Etapa 1 — HIDS e SIEM com Wazuh

**Projeto:** `SOC-SIEM` (`open-soc-lab`)  
**Escopo da Etapa 1:** Implantação do núcleo SIEM (**Wazuh Manager + Wazuh Indexer + Wazuh Dashboard**), coleta de host (**HIDS** via Wazuh Agent para Linux e Windows), cliente Python autenticado via JWT para a API REST do Wazuh e ferramenta de linha de comando (`soclab`) com verificação automatizada de prontidão.

---

## 1. Objetivos Alcançados na Etapa 1

1. **Infraestrutura SIEM reproduzível via Docker Compose:**
   - Automação do download da tag oficial `v4.14.8` do repositório `wazuh/wazuh-docker` (`single-node`), geração de certificados TLS do Indexer e subida dos containers `wazuh.manager` (portas `1514`, `1515`, `514/udp`, `55000`), `wazuh.indexer` (`9200`) e `wazuh.dashboard` (`443`).
   - Ajuste automático do parâmetro de kernel `vm.max_map_count=262144` no Linux e no WSL2 (Windows) exigido pelo OpenSearch/Wazuh Indexer.
2. **Coleta de Host (HIDS) multiplataforma:**
   - Scripts automatizados para instalação e registro do **Wazuh Agent (`4.14.8`)** em endpoints Debian/Ubuntu e Windows, além de suporte a auto-instalação via CLI (`--ensure-agent`).
3. **Integração Python com a API do Wazuh (`https://127.0.0.1:55000`):**
   - Autenticação via HTTP Basic em `/security/user/authenticate?raw=true` para obtenção de token JWT Bearer, renovação automática em caso de expiração (`HTTP 401`) e *retry* com *backoff* em chamadas `GET` idempotentes.
   - Consulta de metadados da API (`GET /`), listagem e classificação de agentes (`GET /agents`), teste seguro de regras/decoders sem gerar alerta real (`PUT /logtest`) e injeção controlada de eventos (`POST /events`).
4. **Verificador completo da Etapa 1 (`soclab stage1 verify`):**
   - Diagnóstico em 8 etapas cobrindo Docker CLI/Engine/Compose, containers do Wazuh, configuração `.env`, autenticação na API, agentes ativos (diferenciando o agente interno `000` de endpoints reais), `logtest` (regra SSH `5710`), envio opcional de evento real (`--send-event`) e checagens de qualidade (`pytest`, `ruff`, `mypy`).

---

## 2. Arquivos Criados na Etapa 1

| Arquivo (relativo à raiz do repositório) | Responsabilidade Técnica |
|---|---|
| [`pyproject.toml`](../../pyproject.toml) | Configuração do pacote `open-soc-lab`, entrypoint `soclab = "soclab.cli:app"`, dependências (`httpx`, `pydantic`, `pydantic-settings`, `rich`, `typer`) e configuração estrita do `ruff`, `mypy` (`strict = true`) e `pytest`. |
| [`.env.example`](../../.env.example) | Modelo de variáveis de ambiente (`SOCLAB_WAZUH_URL`, `SOCLAB_WAZUH_USERNAME`, `SOCLAB_WAZUH_PASSWORD`, `SOCLAB_WAZUH_VERIFY_TLS`, `SOCLAB_HTTP_TIMEOUT_SECONDS`, `SOCLAB_MAX_AGENTS`). |
| [`src/soclab/config.py`](../../src/soclab/config.py) | Classe `Settings` (`BaseSettings` com prefixo `SOCLAB_`), armazenamento seguro de `wazuh_password` como `SecretStr`, validação de CA bundle e carregadores `get_settings()` (estrito) e `get_settings_optional()`. |
| [`src/soclab/exceptions.py`](../../src/soclab/exceptions.py) | Hierarquia de exceções de domínio: `SocLabError`, `ConfigurationError`, `WazuhError`, `WazuhAuthenticationError` e `WazuhRequestError`. |
| [`src/soclab/models.py`](../../src/soclab/models.py) | Modelos Pydantic `AgentOS`, `Agent`, `RuleMatch` e `HealthReport`. |
| [`src/soclab/clients/wazuh.py`](../../src/soclab/clients/wazuh.py) | Cliente síncrono `WazuhClient` com suporte a context manager, autenticação JWT, `api_info()`, `agents()`, `logtest()` e `send_event()`. |
| [`src/soclab/services/health.py`](../../src/soclab/services/health.py) | `build_health_report(client)`: agrega versão da API, hostname do manager e contagem de agentes (`total`, `active`, `disconnected`, `never_connected`). |
| [`src/soclab/services/events.py`](../../src/soclab/services/events.py) | `sample_failed_ssh_event()`: gera evento syslog padronizado de falha SSH (`Failed password for invalid user soclab-demo from 198.51.100.23`) para acionar o decoder `sshd` e a regra `5710` (nível `5`). |
| [`src/soclab/services/stage1_verification.py`](../../src/soclab/services/stage1_verification.py) | `Stage1VerificationService`, `VerificationReport`, `CheckResult`, `CheckStatus`, `CommandResult` e `find_project_root()`. |
| [`src/soclab/cli.py`](../../src/soclab/cli.py) | Comandos `soclab version`, `soclab config`, `soclab health`, `soclab agents`, `soclab event test`, `soclab event send` e `soclab stage1 verify`. |
| [`scripts/bootstrap_wazuh.ps1`](../../scripts/bootstrap_wazuh.ps1) e [`scripts/bootstrap_wazuh.sh`](../../scripts/bootstrap_wazuh.sh) | Automação do clone de `wazuh/wazuh-docker` (`v4.14.8`), geração de certificados via `generate-indexer-certs.yml` e inicialização do stack `single-node`. |
| [`scripts/wazuh_status.ps1`](../../scripts/wazuh_status.ps1) e [`scripts/wazuh_stop.ps1`](../../scripts/wazuh_stop.ps1) | Utilitários PowerShell para consultar o status e parar os containers do Wazuh. |
| [`scripts/linux/install_wazuh_agent_debian.sh`](../../scripts/linux/install_wazuh_agent_debian.sh) e [`scripts/windows/install_wazuh_agent.ps1`](../../scripts/windows/install_wazuh_agent.ps1) | Instaladores automatizados do Wazuh Agent para endpoints Linux (APT) e Windows (MSI). |
| `tests/unit/test_config.py`, `test_models.py`, `test_health.py`, `test_wazuh_client.py`, `test_stage1_verification.py`, `test_cli.py` | Suíte de testes unitários cobrindo configuração, modelos, cliente REST (com `MockTransport`), CLI e fluxo de verificação da Etapa 1. |

---

## 3. Fluxo de Funcionamento da Etapa 1

```text
[Endpoints Linux / Windows (Wazuh Agent)]
                 │
                 ▼ (TCP :1514 / :1515)
        [Wazuh Manager (:55000)] ◄──── REST API (JWT) ────► [CLI Python: soclab]
                 │                                            ├── soclab health / agents
                 ▼ (HTTPS :9200)                              ├── soclab event test (/logtest)
        [Wazuh Indexer (OpenSearch)]                          ├── soclab event send (/events)
                 │                                            └── soclab stage1 verify
                 ▼ (HTTPS :443)
        [Wazuh Dashboard (https://localhost)]
```

---

## 4. Comandos de Validação da Etapa 1

```powershell
# Exibir configuração efetiva (mascarando senhas)
soclab config

# Verificar saúde da API do Wazuh e resumo de agentes
soclab health

# Listar agentes registrados (Manager 000 + endpoints)
soclab agents

# Testar regra SSH no sandbox logtest do Wazuh (esperado: regra 5710, nível 5, decoder sshd)
soclab event test

# Executar o verificador completo da Etapa 1
soclab stage1 verify --quick
```
