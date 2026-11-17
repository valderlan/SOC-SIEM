# Relatório da Etapa 3 — SOAR e Resposta Ativa com Shuffle e FastAPI

**Projeto:** `SOC-SIEM` (`open-soc-lab`)  
**Escopo da Etapa 3:** Evolução do laboratório da detecção passiva para **decisão e resposta automatizada a incidentes (SOAR)** por meio da integração entre **Shuffle SOAR** e uma **API Webhook em FastAPI (`soclab`)**, com política determinística por severidade, guarda *fail-closed* de redes protegidas, deduplicação persistente em SQLite, trilha de auditoria JSONL e adapters de firewall multiplataforma com modo seguro (`dry-run`) por padrão.

---

## 1. Objetivos Alcançados na Etapa 3

1. **API Webhook Segura em FastAPI ([`src/soclab/api/app.py`](../../src/soclab/api/app.py)):**
   - Endpoints `GET /health`, `GET /ready` e `POST /api/v1/alerts` (estendido na Etapa 4 com `POST /api/v1/unblock`).
   - Autenticação obrigatória via header `X-SOCLAB-TOKEN` validada em tempo constante com `secrets.compare_digest()` sobre bytes UTF-8: retorna `HTTP 503` se o servidor não tiver token configurado e `HTTP 401` se o token enviado estiver ausente ou incorreto.
2. **Normalizador Polimórfico de Alertas ([`src/soclab/normalizers/shuffle.py`](../../src/soclab/normalizers/shuffle.py)):**
   - Converte tanto o formato canônico `SecurityAlert` quanto alertas brutos do Wazuh e envelopes do Shuffle (`{"alert": {...}}`, `{"data": {...}}`, `{"all_fields": {...}}`).
   - Mapeia a escala numérica do Wazuh (`0–15`) para `AlertSeverity`: `0–3 -> LOW`, `4–7 -> MEDIUM`, `8–11 -> HIGH`, `12–15 -> CRITICAL`.
   - Nunca rebaixa severidade silenciosamente: payloads sem severidade ou com timestamp inválido lançam `AlertMappingError` (`HTTP 400`).
3. **Motor Determinístico de Política e Guarda de Redes Protegidas (`policy.py` e `networks.py`):**
   - Matriz de decisão:
     - `LOW` / `MEDIUM` $\rightarrow$ `LOG`
     - `HIGH` $\rightarrow$ `NOTIFY`
     - `CRITICAL` $\rightarrow$ `BLOCK_IP`
   - Salvaguarda *fail-closed*: se um alerta `CRITICAL` não possuir `src_ip` ou se o `src_ip` pertencer a `SOCLAB_PROTECTED_NETWORKS` (loopback `127.0.0.0/8`, `::1/128`, link-local e redes privadas RFC1918 por padrão), a ação é rebaixada com segurança para `NOTIFY` (`protected=True`).
4. **Deduplicação em SQLite (`dedup.py`) e Auditoria Append-Only (`audit.py`):**
   - `AlertDeduplicator` usa `INSERT OR IGNORE INTO processed_alerts` em `runtime/soclab_state.db` (com suporte opcional a expiração por `SOCLAB_DEDUP_TTL_SECONDS` e limpeza via `soclab dedup clear`), ignorando reentregas do mesmo `alert_id` pelo Shuffle (`duplicate=True`, `action=NONE`).
   - `AuditLogger` grava cada decisão em `logs/audit.jsonl` protegido por `threading.Lock`, sem jamais registrar tokens ou segredos.
5. **Adapters de Firewall com Modo `dry-run` Padrão (`adapters/firewall.py`):**
   - `DryRunFirewallAdapter` (padrão no host): constrói o comando real de bloqueio/desbloqueio mas nunca toca no firewall do sistema operacional (`executed=False`, `dry_run=True`).
   - `LinuxFirewallAdapter` (`nftables`) e `WindowsFirewallAdapter` (`New-NetFirewallRule` / `Remove-NetFirewallRule`): validam canonicamente o IP com `ip_address()` e executam `subprocess.run(..., shell=False)` com timeout de 15s (prevenindo *command injection*).

---

## 2. Arquivos Criados e Modificados na Etapa 3

| Arquivo (relativo à raiz do repositório) | Responsabilidade Técnica |
|---|---|
| [`src/soclab/api/app.py`](../../src/soclab/api/app.py) | Aplicação FastAPI (`create_app`), validação `X-SOCLAB-TOKEN` e modelos `HealthResponse`, `AlertDecisionResponse`, `UnblockRequest` e `UnblockResponse`. |
| [`src/soclab/adapters/firewall.py`](../../src/soclab/adapters/firewall.py) | `FirewallAdapter`, `DryRunFirewallAdapter`, `WindowsFirewallAdapter`, `LinuxFirewallAdapter`, `create_firewall_adapter()`, `build_block_command()`, `build_unblock_command()` e `find_nft_rule_handles()`. |
| [`src/soclab/domain/networks.py`](../../src/soclab/domain/networks.py) | `DEFAULT_PROTECTED_NETWORKS`, `parse_network_list()` e `is_protected()`. |
| [`src/soclab/normalizers/shuffle.py`](../../src/soclab/normalizers/shuffle.py) | `map_shuffle_alert()` e funções de desembrulhamento/extração tolerante. |
| [`src/soclab/services/policy.py`](../../src/soclab/services/policy.py) | `ResponseAction`, `SEVERITY_ACTIONS`, `ResponseDecision` e `ResponsePolicy`. |
| [`src/soclab/services/dedup.py`](../../src/soclab/services/dedup.py) | `AlertDeduplicator` (SQLite `processed_alerts`, `is_duplicate()`, `purge_older_than()`, `clear()`, `count()`). |
| [`src/soclab/services/audit.py`](../../src/soclab/services/audit.py) | `AuditLogger` (`logs/audit.jsonl`). |
| [`src/soclab/services/response.py`](../../src/soclab/services/response.py) | `ResponseService` (`handle()`, `unblock()`), `ResponseOutcome` e factory `build_response_service()`. |
| [`src/soclab/services/api_smoke.py`](../../src/soclab/services/api_smoke.py) e [`src/soclab/services/demo.py`](../../src/soclab/services/demo.py) | Smoke test in-process da API e execução automatizada dos 6 caminhos de decisão (`run_demo()`). |
| [`src/soclab/services/stage3_verification.py`](../../src/soclab/services/stage3_verification.py) | `Stage3VerificationService` (sempre isolado em diretório temporário e forçando `dry-run`). |
| [`Dockerfile`](../../Dockerfile) e [`compose.yaml`](../../compose.yaml) | Empacotamento da API `soclab` e orquestração com Shuffle SOAR. |
| `tests/unit/test_response_policy.py`, `test_response_service.py`, `test_shuffle_mapper.py`, `test_api.py`, `test_stage3_verification.py` | Testes unitários cobrindo política, deduplicação, auditoria, API FastAPI, mapper e verificador da Etapa 3. |

---

## 3. Fluxo de Funcionamento da Etapa 3

```text
[Alerta Wazuh / Suricata]
           │
           ▼
    [Shuffle SOAR]
           │  POST /api/v1/alerts (Header: X-SOCLAB-TOKEN)
           ▼
  [API FastAPI: soclab]
     ├── 1. Valida Token (401 / 503)
     ├── 2. Normaliza Payload -> SecurityAlert (400 se inválido)
     ├── 3. Avalia ResponsePolicy + Guarda de Redes Protegidas
     ├── 4. Checa SQLite AlertDeduplicator (ignora repetidos)
     ├── 5. Aciona FirewallAdapter (dry-run no host / nftables no container)
     └── 6. Grava AuditLogger (logs/audit.jsonl) e retorna JSON de decisão
```

---

## 4. Comandos de Validação da Etapa 3

```powershell
# Exibir status da camada SOAR (bind, modo dry-run/LIVE, adapter, dedup, auditoria)
soclab status

# Executar a demonstração completa in-process (6 caminhos de política + 6 checks da API)
soclab demo final

# Executar o verificador da Etapa 3 (sempre em dry-run e estado temporário isolado)
soclab stage3 verify --quick --demo

# Inspecionar ou limpar a tabela de deduplicação SQLite
soclab dedup status
soclab dedup clear
```
