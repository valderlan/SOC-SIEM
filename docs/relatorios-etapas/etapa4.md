# Relatório da Etapa 4 — Integração Ponta a Ponta, Containerização 1-Clique e Dashboards

**Projeto:** `SOC-SIEM` (`open-soc-lab`)  
**Escopo da Etapa 4:** Fechamento completo e automatizado (**1-clique**) de todos os 6 fluxos operacionais da especificação: **Atacante Kali Linux (`kali-attacker`) $\rightarrow$ Servidor Alvo Linux com Nginx, OpenSSH, Suricata NIDS, Wazuh Agent e `nftables` (`linux-target`) $\rightarrow$ Wazuh SIEM (`local_rules.xml` + `<integration>` automática) $\rightarrow$ Shuffle SOAR (`workflow` + `orborus`) $\rightarrow$ API `soclab` (bloqueio real isolado + coleta de evidências + auditoria JSONL) $\rightarrow$ Notificações Mailpit SMTP/Webmail $\rightarrow$ Reingestão SIEM e Dashboard `Open SOC Lab - SOC Overview`**.

---

## 1. Objetivos Alcançados na Etapa 4

1. **Laboratório 100% Containerizado com Bloqueio Real Isolado:**
   - Criação da rede bridge `soclab-net` (`172.28.0.0/24`) interligando `linux-target` (`172.28.0.20`), `kali-attacker` (`172.28.0.200`), `shuffle-opensearch` (`.10`), `shuffle-backend` (`.11`), `shuffle-frontend` (`.12`), `shuffle-orborus` (`.13`), `mailpit` (`.14`) e `single-node-wazuh.manager-1` (`wazuh.manager`).
   - O container `soclab` compartilha o namespace de rede do `linux-target` (`network_mode: "service:linux-target"`, `cap_add: [NET_ADMIN]`) com `SOCLAB_RESPONSE_DRY_RUN=false` e `SOCLAB_PROTECTED_NETWORKS` protegendo `172.28.0.0/25`. Assim, **o bloqueio via `nftables` acontece de verdade contra o container Kali (`172.28.0.200`) dentro do `linux-target`, enquanto o firewall do Windows físico permanece intocado (`dry-run`)**.
2. **Servidor Alvo Realista (`linux-target`) e Simulador de Ataques (`kali-attacker`):**
   - `linux-target`: Ubuntu 24.04 rodando **Nginx** (`:80` $\rightarrow$ `http://127.0.0.1:8081`), **OpenSSH** (`:22` $\rightarrow$ `127.0.0.1:2222`), **Suricata 7.0.3** na interface `eth0` com 6 regras determinísticas (`SIDs 910001–910006` cobrindo `LOW`, `MEDIUM`, `HIGH` e `CRITICAL`), diretório monitorado por **FIM** (`/etc/soclab-protected`) e **Wazuh Agent `4.14.8`**.
   - `kali-attacker`: Kali Linux Rolling com script `/usr/local/bin/simulate_attacks.sh` acionável via `soclab attack [recon|web|ssh|all|check]`.
3. **Correlação no Wazuh SIEM e Integração Automática com o Shuffle:**
   - Regras customizadas `100101–100151` ([`infra/wazuh-custom/local_rules.xml`](../../infra/wazuh-custom/local_rules.xml)) elevando alertas Suricata (`13`/`10`/`6`), correlacionando brute-force SSH (`100110`/`100111`, 5 falhas em 60s $\rightarrow$ nível `12`), detectando SQLi/Path Traversal (`100120`/`100121`), FIM (`100130`) e indexando as decisões do `logs/audit.jsonl` (`100150` nível `4` e `100151` nível `5` — abaixo do limiar `<level>6</level>` do Shuffle para impedir loops).
   - Serviço `LabProvisionService` (`soclab lab provision`) que injeta o bloco `<integration><name>shuffle</name>` no `ossec.conf` do Wazuh Manager, cria o workflow no Shuffle e importa os painéis no Wazuh Dashboard sem passos manuais.
4. **Coleta Forense de Evidências, Notificações Mailpit e Rollback de Firewall:**
   - `EvidenceCollector` ([`src/soclab/services/evidence.py`](../../src/soclab/services/evidence.py)) salva automaticamente `logs/evidence/<alert_id>.json` para todo incidente `HIGH` ou `CRITICAL`.
   - Workflow do Shuffle ([`infra/shuffle/soclab_workflow.json`](../../infra/shuffle/soclab_workflow.json)) envia e-mail SMTP para o **Mailpit** (`http://127.0.0.1:8025`) quando a decisão é `NOTIFY` ou `BLOCK_IP` (e opcionalmente para Discord/Slack via `SOCLAB_CHAT_WEBHOOK_URL`).
   - Desbloqueio auditado via `soclab unblock <ip>` e `POST /api/v1/unblock`.
5. **Camada de Visualização (`Open SOC Lab - SOC Overview`) e Scripts 1-Clique:**
   - 8 objetos OpenSearch Dashboards em [`infra/wazuh-dashboard/soclab-dashboard.ndjson`](../../infra/wazuh-dashboard/soclab-dashboard.ndjson) (6 visualizações + busca salva de Threat Hunting + dashboard principal).
   - Scripts 1-clique [`scripts/up.ps1`](../../scripts/up.ps1), [`scripts/up.sh`](../../scripts/up.sh) e [`scripts/down.ps1`](../../scripts/down.ps1).

---

## 2. Arquivos Criados e Modificados na Etapa 4

| Arquivo (relativo à raiz do repositório) | Responsabilidade Técnica |
|---|---|
| [`compose.yaml`](../../compose.yaml) e [`Dockerfile`](../../Dockerfile) | Stack completa de 8 serviços na rede `soclab-net` + pacote `nftables` na imagem `soclab`. |
| [`infra/linux-target/Dockerfile`](../../infra/linux-target/Dockerfile), [`entrypoint.sh`](../../infra/linux-target/entrypoint.sh), [`local.rules`](../../infra/linux-target/local.rules), [`ossec.conf.tmpl`](../../infra/linux-target/ossec.conf.tmpl), [`index.html`](../../infra/linux-target/index.html) | Container servidor alvo Ubuntu com Nginx, OpenSSH, Suricata NIDS, Wazuh Agent e `nftables`. |
| [`infra/kali-attacker/Dockerfile`](../../infra/kali-attacker/Dockerfile) e [`simulate_attacks.sh`](../../infra/kali-attacker/simulate_attacks.sh) | Container atacante Kali Linux com modos `recon`, `web`, `ssh`, `all` e `check`. |
| [`infra/wazuh-custom/local_rules.xml`](../../infra/wazuh-custom/local_rules.xml) | Regras customizadas `100101–100151` do Wazuh Manager. |
| [`infra/shuffle/soclab_workflow.json`](../../infra/shuffle/soclab_workflow.json) | Definição exportada do workflow `SOC Lab - Wazuh Automated Response`. |
| [`infra/wazuh-dashboard/soclab-dashboard.ndjson`](../../infra/wazuh-dashboard/soclab-dashboard.ndjson) | Dashboard `Open SOC Lab - SOC Overview`, 6 visualizações e busca salva de Threat Hunting. |
| [`src/soclab/services/evidence.py`](../../src/soclab/services/evidence.py) | `EvidenceCollector` (`logs/evidence/<alert_id>.json`). |
| [`src/soclab/services/provision.py`](../../src/soclab/services/provision.py) | `LabProvisionService`, `upsert_shuffle_integration()` e `build_shuffle_workflow_definition()`. |
| [`src/soclab/services/stage4_verification.py`](../../src/soclab/services/stage4_verification.py) | `Stage4VerificationService` (`soclab stage4 verify`). |
| [`scripts/up.ps1`](../../scripts/up.ps1), [`scripts/up.sh`](../../scripts/up.sh), [`scripts/down.ps1`](../../scripts/down.ps1) | Inicialização, provisionamento e desligamento 1-clique do laboratório. |
| `tests/unit/test_provision.py` e `tests/unit/test_stage4_verification.py` (+ ampliação para **97 testes unitários**) | Testes unitários do provisionador, verificador da Etapa 4, `unblock`, evidências, `all_fields` e TTL de deduplicação. |

---

## 3. Comandos de Validação da Etapa 4

```powershell
# Subir e provisionar todo o laboratório com 1 clique
.\scripts\up.ps1

# Reaplicar provisionamento (regras Wazuh, integração Shuffle e Dashboard)
soclab lab provision

# Executar a verificação ponta a ponta da Etapa 4 (incluindo pytest, ruff e mypy)
soclab stage4 verify

# Testar ataques controlados por estágio de gravidade e comprovar o bloqueio real
soclab attack check
soclab attack recon
soclab attack web
soclab attack ssh
soclab attack check

# Desbloquear o IP do atacante após a demonstração
docker compose --profile full exec soclab soclab unblock 172.28.0.200
```
