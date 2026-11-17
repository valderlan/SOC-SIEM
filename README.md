# Open SOC Lab — Ambiente Integrado de SOC/SIEM Open-Source (`HIDS + NIDS + SIEM + SOAR + Dashboards`)

Projeto acadêmico e prático de **Security Operations Center (SOC)** e **SIEM** construído 100% com ferramentas **Open-Source** e automação em Python/Docker, cobrindo todo o ciclo de defesa cibernética: **coleta de host (HIDS), inspeção de tráfego de rede (NIDS), centralização e correlação (SIEM), orquestração e resposta ativa automatizada (SOAR + Firewall + Evidências + Notificações) e visualização operacional (*Dashboards & Threat Hunting*)**.

---

## 1. Arquitetura Ponta a Ponta

```text
[kali-attacker (172.28.0.200)]
        │  Reconhecimento (ICMP/Nmap) / Web SQLi / SSH Brute-Force / Path Traversal
        ▼
[linux-target (172.28.0.20)] ─── Ubuntu 24.04 + Nginx (:80 / :8081) + OpenSSH (:22 / :2222)
   ├── Suricata 7.0.3 NIDS (eth0 -> /var/log/suricata/eve.json, SIDs 910001-910006)
   └── Wazuh Agent 4.14.8 (auth.log, nginx, eve.json, FIM /etc/soclab-protected, audit.jsonl)
        │
        ▼ (rede Docker soclab-net)
[Wazuh SIEM v4.14.8 (wazuh.manager + wazuh.indexer + wazuh.dashboard :443, :55000, :9200)]
   ├── local_rules.xml (regras 100101-100151)
   └── <integration> shuffle (level >= 6, json)
        │
        ▼ Webhook HTTP
[Shuffle SOAR (shuffle-frontend :3001, shuffle-backend :5001, shuffle-orborus, opensearch)]
   ├── Nó 1: POST http://soclab:8080/api/v1/alerts (header X-SOCLAB-TOKEN)
   └── Condição (action == BLOCK_IP ou NOTIFY):
         ├── E-mail SMTP -> Mailpit (:1025 / Webmail http://127.0.0.1:8025)
         └── Webhook de Chat opcional (SOCLAB_CHAT_WEBHOOK_URL)
        │
        ▼
[SOC Lab SOAR API (:8080, network_mode: "service:linux-target")]
   ├── Política Determinística (LOW/MEDIUM -> LOG, HIGH -> NOTIFY, CRITICAL -> BLOCK_IP)
   ├── Guarda Fail-Closed de Redes Protegidas (172.28.0.0/25 protegido; .200 bloqueável)
   ├── Bloqueio real isolado via nftables no linux-target (Windows físico mantido em dry-run)
   ├── Coleta forense JSON em logs/evidence/ para alertas HIGH e CRITICAL
   └── Auditoria JSONL em logs/audit.jsonl -> reingerida no Wazuh (100150/100151) -> Dashboard
```

### Evolução das 4 Etapas do Projeto

| Etapa | Foco Principal | Tecnologias | Relatório Detalhado |
| :---: | :--- | :--- | :--- |
| **Etapa 1** | Monitoramento de Endpoints e Centralização SIEM | Wazuh (`Manager`, `Indexer`, `Dashboard`, `Agent`) + CLI Python | [docs/relatorios-etapas/etapa1.md](docs/relatorios-etapas/etapa1.md) |
| **Etapa 2** | Monitoramento e Inspeção de Rede (NIDS) | Suricata (`EVE JSON`) + Streaming Parser/Normalizer | [docs/relatorios-etapas/etapa2.md](docs/relatorios-etapas/etapa2.md) |
| **Etapa 3** | Orquestração SOAR, Política e Motor de Resposta | Shuffle SOAR + FastAPI + SQLite Dedup + Firewall Adapters | [docs/relatorios-etapas/etapa3.md](docs/relatorios-etapas/etapa3.md) |
| **Etapa 4** | Integração Ponta a Ponta, Containerização 1-Clique e Dashboards | Kali + Alvo Linux + Mailpit + Evidências + Dashboard `SOC Overview` | [docs/relatorios-etapas/etapa4.md](docs/relatorios-etapas/etapa4.md) |

---

## 2. Subir Todo o Ambiente com 1 Clique

### Pré-requisitos
- **Windows 10/11:** Docker Desktop (com backend WSL2 ativo), distribuição Linux no WSL2 (`Ubuntu-24.04` / `Ubuntu`), Python 3.12+, `uv` e Git.
- **Linux (Ubuntu/Debian):** Docker Engine + Docker Compose v2, Python 3.12+, `uv`, `curl` e Git.

### Inicialização Automatizada
No **Windows (PowerShell)**, a partir da raiz do repositório:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\scripts\up.ps1
```
*(Use `.\scripts\up.ps1 -SkipBuild` nas próximas vezes para subir ainda mais rápido sem reconstruir imagens.)*

No **Linux / WSL2 (Bash)**:
```bash
chmod +x ./scripts/up.sh ./scripts/bootstrap_wazuh.sh
./scripts/up.sh
```

Para **desligar todos os containers** ao finalizar:
```powershell
.\scripts\down.ps1
```

---

## 3. URLs e Credenciais dos Serviços

| Serviço | URL | Usuário | Senha / Token |
|---|---|---|---|
| **Wazuh Dashboard** (Painel `Open SOC Lab - SOC Overview`) | `https://localhost` | `admin` | `SecretPassword` |
| **Shuffle SOAR UI** (Workflow `SOC Lab - Wazuh Automated Response`) | `http://localhost:3001` | `admin` | `soclab-shuffle-admin` |
| **Mailpit Webmail** (Caixa de entrada de notificações do SOC) | `http://127.0.0.1:8025` | *(sem login)* | *(sem senha)* |
| **SOC Lab SOAR API** (Swagger / OpenAPI) | `http://127.0.0.1:8080/docs` | `X-SOCLAB-TOKEN` | `soclab-dev-token` |
| **Servidor Web Alvo** (Nginx monitorado no `linux-target`) | `http://127.0.0.1:8081` | *(público)* | *(sem senha)* |
| **Wazuh REST API** | `https://127.0.0.1:55000` | `wazuh-wui` | `MyS3cr37P450r.*-` |

---

## 4. Demonstração Rápida em 5 Comandos

Com o ambiente no ar e o `.venv` ativo (`.\.venv\Scripts\Activate.ps1`):

```powershell
# 1. Confirmar que os 8 containers, integrações, Suricata e Dashboard estão prontos
soclab stage4 verify --quick

# 2. Confirmar que o atacante Kali (172.28.0.200) começa com acesso livre ao servidor alvo
soclab attack check

# 3. Disparar os 3 estágios de ataque (Recon LOW/MEDIUM -> Web SQLi HIGH -> SSH Brute-Force CRITICAL)
soclab attack all

# 4. Aguardar ~10s e comprovar que o firewall nftables bloqueou o Kali automaticamente
Start-Sleep -Seconds 10
soclab attack check
docker compose --profile full exec linux-target nft list chain inet filter input

# 5. Desbloquear o atacante após a demonstração
docker compose --profile full exec soclab soclab unblock 172.28.0.200
soclab attack check
```

---

## 5. Principais Comandos da CLI (`soclab`)

```powershell
# Configuração e Etapa 1 (Wazuh HIDS/SIEM)
soclab config
soclab health
soclab agents
soclab event test
soclab stage1 verify --quick

# Etapa 2 (Suricata NIDS)
soclab nids status
soclab nids alerts --limit 10
soclab nids alerts --severity high
soclab stage2 verify --quick

# Etapa 3 (SOAR + Política + Deduplicação + Firewall)
soclab status
soclab demo final
soclab dedup status
soclab dedup clear
soclab stage3 verify --quick --demo

# Etapa 4 (Provisionamento, Simulação de Ataques e Verificação Completa)
soclab lab provision
soclab attack [recon|web|ssh|all|check]
soclab stage4 verify

# Qualidade de Código e Testes Unitários (97 testes)
pytest --basetemp .\.pytest_tmp
ruff check .
mypy src
```

---

## 6. Mapa Completo da Documentação (`docs/`)

Toda a documentação técnica, guias operacionais, relatórios por etapa e roteiro de apresentação estão organizados na pasta [`docs/`](docs/):

### Guias Principais de Operação, Arquitetura e Apresentação
- **[Guia de Uso, Operação e Comandos](docs/guia_de_uso_e_operacao.md):** pré-requisitos, como subir do zero, como reiniciar após reboot, todos os comandos da CLI e troubleshooting.
- **[Arquitetura e Detalhes Técnicos](docs/arquitetura_e_detalhes_tecnicos.md):** explicação minuciosa dos containers, rede `soclab-net`, namespace compartilhado `nftables`, regras Suricata (`910001–910006`) e Wazuh (`100101–100151`), estrutura do código Python e prevenção de loops.
- **[Roteiro Sugerido de Apresentação e Experimento](docs/roteiro_apresentacao_e_experimento.md):** passo a passo cronometrado para apresentar o trabalho à banca, com o que falar, o que mostrar em cada aba e o resultado esperado de cada comando.

### Relatórios por Etapa (`docs/relatorios-etapas/`)
- **[Índice dos Relatórios por Etapa](docs/relatorios-etapas/README.md):**
  - [Relatório da Etapa 1 — HIDS e SIEM com Wazuh](docs/relatorios-etapas/etapa1.md)
  - [Relatório da Etapa 2 — NIDS com Suricata](docs/relatorios-etapas/etapa2.md)
  - [Relatório da Etapa 3 — SOAR e Resposta Ativa](docs/relatorios-etapas/etapa3.md)
  - [Relatório da Etapa 4 — Integração Ponta a Ponta, Containerização e Dashboards](docs/relatorios-etapas/etapa4.md)
