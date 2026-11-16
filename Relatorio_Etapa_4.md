# Relatorio - Etapa 4 (Integracao Ponta a Ponta, Containerizacao 1-Clique e Dashboards)

Projeto: **SOC-SIEM-Open-Source** (`open-soc-lab`)
Escopo: Etapa 4 — fechamento do ciclo completo **HIDS + NIDS + SIEM + SOAR + Notificacoes + Coleta de Evidencias + Dashboards + Threat Hunting** de forma portatil e automatizada com **1-clique**.

---

## 1. Arquitetura Implementada na Etapa 4

```text
[kali-attacker (172.28.0.200)]
        │  Nmap / SQLi / SSH Brute-Force / Path Traversal
        ▼
[linux-target (172.28.0.20)] ─── Nginx (:80 / :8081), OpenSSH (:22 / :2222)
   ├── Suricata NIDS (eth0 -> /var/log/suricata/eve.json)
   └── Wazuh Agent 4.14.8 (auth.log, nginx, eve.json, FIM, audit.jsonl)
        │
        ▼ (rede soclab-net)
[wazuh.manager + wazuh.indexer + wazuh.dashboard] (:443, :55000, :9200)
   ├── local_rules.xml (100101-100151: eleva Suricata/SSH/Web/FIM + indexa SOAR)
   └── <integration> shuffle (level >= 6)
        │
        ▼ Webhook HTTP
[Shuffle SOAR (shuffle-frontend :3001, shuffle-backend :5001, shuffle-orborus, opensearch)]
   ├── Node 1: POST http://soclab:8080/api/v1/alerts (X-SOCLAB-TOKEN)
   └── Branch (BLOCK_IP / NOTIFY):
         ├── Email SMTP -> Mailpit (:1025 / Webmail :8025)
         └── Chat Webhook opcional (SOCLAB_CHAT_WEBHOOK_URL)
        │
        ▼
[soclab API (:8080, network_mode: service:linux-target)]
   ├── Policy + Protected Networks (172.28.0.0/25 protegido; .200 bloqueavel)
   ├── Bloqueio real isolado via nftables no linux-target (Windows host fica em dry-run)
   ├── Coleta de evidencias (logs/evidence/<alert_id>.json) em HIGH/CRITICAL
   └── Auditoria JSONL (logs/audit.jsonl) -> reingerida pelo Wazuh Agent -> Dashboard
```

---

## 2. Arquivos Criados e Modificados

### Infraestrutura e Scripts 1-Clique
| Arquivo | Descricao |
|---|---|
| `compose.yaml` | Corrige `shuffle-frontend` (`BACKEND_HOSTNAME: shuffle-backend`), adiciona `shuffle-orborus`, `mailpit`, `linux-target`, `kali-attacker`, rede `soclab-net` (`172.28.0.0/24`) e isola `soclab` no namespace de rede do `linux-target`. |
| `Dockerfile` | Adiciona `nftables` na imagem `soclab` para bloqueio/desbloqueio real dentro do namespace isolado. |
| `infra/linux-target/*` | Container Ubuntu 24.04 com Nginx, OpenSSH, Suricata (`local.rules` SIDs `910001–910006`), Wazuh Agent `4.14.8` e `nftables`. |
| `infra/kali-attacker/*` | Container Kali Linux (`nmap`, `curl`, `hydra`, `sshpass`) com `simulate_attacks.sh`. |
| `infra/wazuh-custom/local_rules.xml` | Regras customizadas (`100101–100151`) para Suricata, SSH brute-force, Web attacks, FIM e reingestao do `audit.jsonl` (niveis `4`/`5`, evitando loops com o Shuffle). |
| `infra/shuffle/soclab_workflow.json` | Workflow exportado do Shuffle (Webhook Wazuh -> `POST /api/v1/alerts` -> Email SMTP Mailpit / Chat opcional). |
| `infra/wazuh-dashboard/soclab-dashboard.ndjson` | Dashboard `Open SOC Lab - SOC Overview` (6 visualizacoes + busca de Threat Hunting) para o Wazuh Dashboard. |
| `scripts/up.ps1`, `scripts/down.ps1`, `scripts/up.sh` | Scripts 1-clique para subir, provisionar e encerrar todo o laboratorio (Windows/WSL2 e Linux). |

### Codigo Python e Testes (`src/soclab` / `tests/unit`)
| Arquivo | Descricao |
|---|---|
| `src/soclab/normalizers/shuffle.py` | Suporte ao envelope nativo `all_fields` do `/var/ossec/integrations/shuffle.py` do Wazuh e campos aninhados `data.*`. |
| `src/soclab/adapters/firewall.py` | Inicializacao idempotente da chain `inet filter input` no `nftables`, deteccao de duplicidade e `unblock_ip()` (Windows e Linux). |
| `src/soclab/services/evidence.py` | Coleta forense automatica em JSON (`logs/evidence/`) para alertas `HIGH` e `CRITICAL`. |
| `src/soclab/services/response.py` | Integracao com `EvidenceCollector` e `unblock()` auditado. |
| `src/soclab/services/provision.py` | Provisionamento automatizado (`LabProvisionService`): rede Docker, regras Wazuh, integracao `<integration>`, workflow Shuffle e importacao do Dashboard. |
| `src/soclab/services/stage4_verification.py` | Verificador completo `Stage4VerificationService` (`soclab stage4 verify`). |
| `src/soclab/api/app.py`, `src/soclab/cli.py`, `src/soclab/config.py` | `POST /api/v1/unblock`, `evidence_path`, `SOCLAB_EVIDENCE_DIR`, `SOCLAB_CHAT_WEBHOOK_URL`, comandos `soclab lab provision`, `soclab stage4 verify`, `soclab attack` e `soclab unblock`. |

### Documentacao
- `docs/dashboards-and-threat-hunting.md`
- `docs/attack-simulation-guide.md`
- `README.md` atualizado com secao 1-clique e Etapa 4.

---

## 3. Como Usar (Resumo)

```powershell
# Subir e provisionar tudo com 1 clique
.\scripts\up.ps1

# Verificar ponta a ponta
.\.venv\Scripts\soclab.exe stage4 verify

# Testar ataques controlados do Kali e comprovar bloqueio
.\.venv\Scripts\soclab.exe attack check
.\.venv\Scripts\soclab.exe attack all
.\.venv\Scripts\soclab.exe attack check

# Desbloquear atacante apos demonstracao
docker compose --profile full exec soclab soclab unblock 172.28.0.200
```
