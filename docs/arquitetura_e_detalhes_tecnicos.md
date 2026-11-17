# Arquitetura e Detalhes Técnicos — Open SOC Lab (`SOC-SIEM`)

Este documento descreve em profundidade a engenharia de software, a arquitetura de rede, os containers, os arquivos de configuração, as regras de detecção/correlação e o fluxo interno de dados do **Open SOC Lab**.

---

## 1. Visão Geral da Arquitetura e Topologia de Rede

O ambiente integra cinco camadas tecnológicas open-source (**HIDS**, **NIDS**, **SIEM**, **SOAR + API de Resposta** e **Dashboards**) distribuídas em dois stacks Docker Compose interconectados pela rede bridge **`soclab-net` (`172.28.0.0/24`)**, além da máquina hospedeira Windows/Linux.

```text
+---------------------------------------------------------------------------------------------------+
|                           HOST FÍSICO (Windows 11 + WSL2 / Linux)                                 |
|  - CLI Python (soclab) em modo dry-run seguro no host                                             |
|  - Volumes compartilhados: ./logs (audit.jsonl, evidence/*.json) e ./runtime (eve.json, state.db) |
|  - Portas locais: :443 (Dashboard), :55000 (Wazuh API), :3001 (Shuffle), :8025 (Mailpit),         |
|                   :8080 (SOC Lab FastAPI), :8081 (Nginx Alvo), :2222 (SSH Alvo)                   |
+---------------------------------------------------------------------------------------------------+
                                                 │
                 ┌───────────────────────────────┴───────────────────────────────┐
                 ▼                                                               ▼
+----------------------------------------+      +---------------------------------------------------+
|   Stack 1: WAZUH SIEM (single-node)    |      |         Stack 2: SOCLAB (rede soclab-net)         |
|                                        |      |                  172.28.0.0/24                    |
|  - wazuh.manager (:1514, :1515, :55000)|◄────►|  - shuffle-opensearch (172.28.0.10:9200)          |
|    (conectado também à soclab-net)     |      |  - shuffle-backend    (172.28.0.11:5001)          |
|  - wazuh.indexer (:9200 OpenSearch)    |      |  - shuffle-frontend   (172.28.0.12:80 -> :3001)   |
|  - wazuh.dashboard (:5601 -> :443)     |      |  - shuffle-orborus    (172.28.0.13 worker)        |
+----------------------------------------+      |  - mailpit            (172.28.0.14:1025 / :8025)  |
                                                |                                                   |
                                                |  +---------------------------------------------+  |
                                                |  | Namespace de Rede Compartilhado (172.28.0.20)| |
                                                |  |  • linux-target (Nginx :80, SSH :22,        |  |
                                                |  |    Suricata eth0, Wazuh Agent 001, nftables)|  |
                                                |  |  • soclab (FastAPI :8080, CAP_NET_ADMIN,    |  |
                                                |  |    dry_run=False isolado no container)      |  |
                                                |  +---------------------------------------------+  |
                                                |                         ▲                         |
                                                |                         │ Ataques controlados     |
                                                |  - kali-attacker      (172.28.0.200)              |
                                                +---------------------------------------------------+
```

### 1.1. Tabela Técnica de Containers, Endereços IP e Portas

| Container | Imagem | IP (`soclab-net`) | Portas (Host $\rightarrow$ Container) | Papel Técnico |
|---|---|---|---|---|
| `single-node-wazuh.manager-1` | `wazuh/wazuh-manager:4.14.8` | Dinâmico (alias `wazuh.manager`) | `1514:1514/tcp`, `1515:1515/tcp`, `514:514/udp`, `55000:55000/tcp` | Motor de decodificação, correlação (`local_rules.xml`), API REST (`:55000`) e disparo de webhooks (`shuffle`). |
| `single-node-wazuh.indexer-1` | `wazuh/wazuh-indexer:4.14.8` | Rede `single-node` | `9200:9200/tcp` | Motor OpenSearch que indexa alertas em `wazuh-alerts-*`. |
| `single-node-wazuh.dashboard-1` | `wazuh/wazuh-dashboard:4.14.8` | Rede `single-node` | `443:5601/tcp` | Interface web OpenSearch Dashboards + plugin Wazuh. |
| `soclab-shuffle-opensearch-1` | `opensearchproject/opensearch:2.11.1` | `172.28.0.10` | *(interno `:9200`)* | Persistência interna do Shuffle (workflows, apps, execuções). |
| `soclab-shuffle-backend-1` | `ghcr.io/shuffle/shuffle-backend:latest` | `172.28.0.11` | `127.0.0.1:5001:5001` | API do SOAR Shuffle e receptor de webhooks do Wazuh. |
| `soclab-shuffle-frontend-1` | `ghcr.io/shuffle/shuffle-frontend:latest` | `172.28.0.12` | `127.0.0.1:3001:80` | Interface gráfica web do Shuffle SOAR (`BACKEND_HOSTNAME=shuffle-backend`). |
| `shuffle-orborus` | `ghcr.io/shuffle/shuffle-orborus:latest` | `172.28.0.13` | *(interno)* | Worker em modo standalone (`SHUFFLE_SWARM_CONFIG=""`) que executa os nós do workflow. |
| `soclab-mailpit-1` | `axllent/mailpit:latest` | `172.28.0.14` | `127.0.0.1:1025:1025`, `127.0.0.1:8025:8025` | Servidor SMTP local (`:1025`) e interface Webmail (`:8025`) para notificações do SOC. |
| `soclab-linux-target-1` | `soclab:linux-target` | `172.28.0.20` (aliases `linux-target`, `soclab`) | `127.0.0.1:8080:8080`, `127.0.0.1:8081:80`, `127.0.0.1:2222:22` | Endpoint Ubuntu 24.04 monitorado com Nginx, OpenSSH, Suricata NIDS, Wazuh Agent e `nftables`. |
| `soclab-soclab-1` | `soclab:stage4` | Compartilha `172.28.0.20` (`service:linux-target`) | Exposta via `linux-target` (`:8080`) | API FastAPI de decisão SOAR, bloqueio `nftables`, captura de evidências e auditoria JSONL. |
| `soclab-kali-attacker-1` | `soclab:kali-attacker` | `172.28.0.200` | *(interno)* | Container Kali Linux para simulação controlada de ataques. |

---

## 2. Isolamento de Rede e Mecanismo de Bloqueio Real (`network_mode: "service:linux-target"`)

Um dos principais diferenciais arquiteturais do projeto está definido em [`compose.yaml`](../compose.yaml):

1. **Compartilhamento de Network Namespace:**
   - O container `soclab` utiliza `network_mode: "service:linux-target"` e `cap_add: [NET_ADMIN]`.
   - No kernel Linux, isso faz com que `soclab` e `linux-target` possuam processos e sistemas de arquivos independentes, mas **compartilhem exatamente a mesma interface `eth0` (`172.28.0.20`), a mesma pilha TCP/IP e a mesma tabela `nftables`**.
   - Quando o `LinuxFirewallAdapter` ([`src/soclab/adapters/firewall.py`](../src/soclab/adapters/firewall.py)) dentro do container `soclab` executa:
     ```bash
     nft add rule inet filter input ip saddr 172.28.0.200 drop
     ```
     o bloqueio passa a vigorar imediatamente na entrada do servidor `linux-target`, cortando o acesso do `kali-attacker` (`172.28.0.200`) às portas `:80` (Nginx) e `:22` (SSH) sem precisar de SSH, agentes extras ou alterações no firewall do Windows físico.

2. **Particionamento CIDR da Sub-rede (`SOCLAB_PROTECTED_NETWORKS`):**
   - A sub-rede Docker é `172.28.0.0/24` (`172.28.0.1` a `172.28.0.254`).
   - No `compose.yaml`, `SOCLAB_PROTECTED_NETWORKS` protege `172.28.0.0/25` (`172.28.0.0` a `172.28.0.127`), onde residem o gateway Docker e todos os serviços de infraestrutura do SOC (`.10` a `.20`).
   - O container `kali-attacker` é alocado em `172.28.0.200` (na metade superior `.128–.254`), permitindo que a política bloqueie o atacante enquanto protege de forma *fail-closed* todos os servidores internos do laboratório.

---

## 3. Detalhamento das Regras de Detecção e Correlação

### 3.1. Assinaturas Suricata NIDS ([`infra/linux-target/local.rules`](../infra/linux-target/local.rules))

No Suricata, o atributo `priority` determina o campo `alert.severity` gravado no `eve.json`:

| SID | Priority (`alert.severity`) | Severidade Interna | Condição da Assinatura | Gatilho no Simulador Kali |
| :---: | :---: | :---: | :--- | :--- |
| `910001` | `4` | `LOW` | Pacote ICMP Echo Request (`itype:8`) | `soclab attack recon` (`ping`) |
| `910002` | `3` | `MEDIUM` | URI HTTP contendo `/admin` (`nocase`) | `soclab attack recon` (`curl /admin`) |
| `910003` | `3` | `MEDIUM` | Header `User-Agent` contendo `Nmap` | `soclab attack recon` (`curl -A "Nmap..."`) |
| `910004` | `2` | `HIGH` | URI HTTP contendo `UNION` e `SELECT` (`nocase`) | `soclab attack web` (SQL Injection) |
| `910005` | `1` | `CRITICAL` | Pacotes TCP SYN na porta `22` com `threshold: count 4, seconds 30` por IP de origem | `soclab attack ssh` (Brute-force SSH) |
| `910006` | `1` | `CRITICAL` | URI HTTP contendo `/etc/passwd` (`nocase`) | `soclab attack ssh` (Path Traversal) |

### 3.2. Regras Customizadas do Wazuh Manager ([`infra/wazuh-custom/local_rules.xml`](../infra/wazuh-custom/local_rules.xml))

Por padrão, a regra nativa `86601` do Wazuh para alertas JSON do Suricata possui nível `3` (`LOW`). O arquivo `local_rules.xml` implementa a elevação de severidade, correlação de host e indexação da auditoria SOAR:

| Rule ID | Regra Pai / Condição | Level Wazuh | Severidade `soclab` | Ação Esperada no SOAR | Descrição Técnica |
| :---: | :--- | :---: | :---: | :---: | :--- |
| `100101` | `if_sid: 86601` + `alert.severity == 1` | `13` | `CRITICAL` | `BLOCK_IP` | Eleva alertas Suricata de prioridade 1 para nível crítico. |
| `100102` | `if_sid: 86601` + `alert.severity == 2` | `10` | `HIGH` | `NOTIFY` | Eleva alertas Suricata de prioridade 2 para nível alto. |
| `100103` | `if_sid: 86601` + `alert.severity == 3` | `6` | `MEDIUM` | `LOG` | Eleva alertas Suricata de prioridade 3 para nível médio. |
| `100110` | `if_matched_sid: 5760` (`frequency=5`, `60s`, `same_source_ip`) | `12` | `CRITICAL` | `BLOCK_IP` | Correlação HIDS: 5 falhas de senha SSH do mesmo IP em 60 segundos. |
| `100111` | `if_matched_sid: 5710` (`frequency=5`, `60s`, `same_source_ip`) | `12` | `CRITICAL` | `BLOCK_IP` | Correlação HIDS: 5 tentativas SSH com usuário inválido do mesmo IP em 60s. |
| `100120` | `if_sid: 31103` (Nginx access log SQLi) | `10` | `HIGH` | `NOTIFY` | Detecção HIDS de tentativa de SQL Injection nos logs do servidor Web. |
| `100121` | `if_sid: 31104` (Nginx access log exploit) | `13` | `CRITICAL` | `BLOCK_IP` | Detecção HIDS de tentativa crítica de Path Traversal / exploit Web. |
| `100130` | `if_sid: 550,553,554` + `/etc/soclab-protected` | `10` | `HIGH` | `NOTIFY` | Monitoramento de Integridade de Arquivos (FIM/syscheck) no diretório protegido. |
| `100150` | `decoded_as: json` + campos `adapter` e `requested_action` | `4` | *(Auditoria)* | *(Não aciona Shuffle)* | Reingere cada linha de decisão do `logs/audit.jsonl` no Wazuh Indexer. |
| `100151` | `if_sid: 100150` + `<action>BLOCK_IP</action>` | `5` | *(Auditoria)* | *(Não aciona Shuffle)* | Destaca eventos de bloqueio de firewall do SOAR no Dashboard. |

> **Prevenção de Loop Infinito SIEM $\leftrightarrow$ SOAR:** O bloco `<integration><name>shuffle</name>` em `/var/ossec/etc/ossec.conf` está configurado com `<level>6</level>`. Como as regras de auditoria `100150` e `100151` possuem níveis `4` e `5`, elas são indexadas normalmente no Wazuh Dashboard, mas **nunca** disparam um novo webhook para o Shuffle.

---

## 4. Arquitetura Interna do Pacote Python (`src/soclab`)

A aplicação foi estruturada seguindo separação estrita de responsabilidades e injeção de dependências:

```text
src/soclab/
├── config.py                  # Settings (pydantic-settings, SecretStr, validação de CIDRs e TLS)
├── exceptions.py              # Hierarquia SocLabError (Configuration, Wazuh, AlertMapping, Response)
├── models.py                  # Modelos da Etapa 1 (Agent, AgentOS, RuleMatch, HealthReport)
├── cli.py                     # CLI Typer (comandos das Etapas 1, 2, 3 e 4)
├── domain/
│   ├── alert.py               # Enum AlertSeverity e modelo canônico SecurityAlert
│   └── networks.py            # DEFAULT_PROTECTED_NETWORKS, parse_network_list(), is_protected()
├── clients/
│   └── wazuh.py               # WazuhClient (JWT auth, auto-reauth em 401, retry GET, logtest, events)
├── collectors/
│   └── suricata.py            # SuricataEveCollector (streaming iter_records e tail follow_records)
├── normalizers/
│   ├── suricata.py            # normalize_suricata_alert() e normalize_suricata_severity()
│   └── shuffle.py             # map_shuffle_alert() (suporta formato canônico, Wazuh e all_fields)
├── adapters/
│   └── firewall.py            # DryRunFirewallAdapter, LinuxFirewallAdapter (nft), WindowsFirewallAdapter
├── api/
│   └── app.py                 # FastAPI (/health, /ready, /api/v1/alerts, /api/v1/unblock)
└── services/
    ├── health.py              # Agregação de saúde da API e agentes Wazuh
    ├── events.py              # Gerador de evento syslog SSH controlado
    ├── nids.py                # NidsService, validação EVE, filtros e resolve_eve_path()
    ├── policy.py              # ResponsePolicy (matriz severidade -> ação + guarda de IP protegido)
    ├── dedup.py               # AlertDeduplicator (SQLite processed_alerts + TTL e purge/clear)
    ├── audit.py               # AuditLogger (escrita JSONL thread-safe com threading.Lock)
    ├── evidence.py            # EvidenceCollector (snapshots forenses JSON em HIGH/CRITICAL)
    ├── response.py            # ResponseService (orquestra policy -> dedup -> adapter -> evidence -> audit)
    ├── api_smoke.py           # Testes in-process da API FastAPI via Starlette TestClient
    ├── demo.py                # Execução automatizada dos 6 caminhos de decisão (soclab demo final)
    ├── provision.py           # LabProvisionService (rede Docker, Shuffle workflow, regras Wazuh, NDJSON)
    ├── stage1_verification.py # Verificador de prontidão da Etapa 1
    ├── stage2_verification.py # Verificador de prontidão da Etapa 2
    ├── stage3_verification.py # Verificador de prontidão da Etapa 3
    └── stage4_verification.py # Verificador ponta a ponta da Etapa 4
```

### Tratamento do Envelope `all_fields` do Wazuh ([`src/soclab/normalizers/shuffle.py`](../src/soclab/normalizers/shuffle.py))
Quando o script oficial `/var/ossec/integrations/shuffle.py` do Wazuh envia um alerta ao Shuffle, ele constrói um JSON contendo `"severity": 1|2|3` no nível externo e coloca o objeto original do Wazuh dentro de `"all_fields"` (onde está `"rule": {"level": 13, ...}` e `"data": {"src_ip": ...}`).  
A função `_unwrap()` em `shuffle.py` descarta especificamente o campo `"severity"` comprimido externo quando `"all_fields"` possui `"rule"`, preservando o `rule.level` real (`0–15`) e extraindo `src_ip`/`dst_ip` tanto do nível raiz quanto de `data.*`.

---

## 5. Estrutura do Workflow no Shuffle SOAR ([`infra/shuffle/soclab_workflow.json`](../infra/shuffle/soclab_workflow.json))

O workflow **`SOC Lab - Wazuh Automated Response`** (`ID: d9d45cc2-7daa-4d30-9c82-260c615729a7`) é composto por:

1. **Trigger (`Wazuh Alerts Webhook`):**
   - Escuta em `http://shuffle-backend:5001/api/v1/hooks/webhook_<trigger_id>` e repassa o corpo recebido (`$exec`) ao nó inicial.
2. **Nó Inicial (`soclab_decision` — App `http`, ação `POST`):**
   - **URL:** `http://soclab:8080/api/v1/alerts`
   - **Headers:** `Content-Type: application/json` e `X-SOCLAB-TOKEN: <token>`
   - **Body:** `$exec`
3. **Condições de Ramificação (`branches`):**
   - Avalia `$soclab_decision.body.action`:
     - Se igual a `"BLOCK_IP"` **ou** `"NOTIFY"` $\rightarrow$ avança para o nó `notify_mailpit` (e para `notify_chat`, se `SOCLAB_CHAT_WEBHOOK_URL` estiver definido).
     - Se igual a `"LOG"` ou `"NONE"` $\rightarrow$ encerra a execução silenciosamente.
4. **Nó de Notificação (`notify_mailpit` — App `email`, ação `send_email_smtp`):**
   - Conecta em `mailpit:1025` e envia e-mail para `analysts@soclab.local` com assunto `[SOC Lab] $soclab_decision.body.severity - $soclab_decision.body.action ($soclab_decision.body.target_ip)` e corpo detalhando `Alert ID`, `Severity`, `Action`, `Target IP`, `Executed`, `Adapter`, `Evidence` e `Reason`.

---

## 6. Objetos do Wazuh Dashboard ([`infra/wazuh-dashboard/soclab-dashboard.ndjson`](../infra/wazuh-dashboard/soclab-dashboard.ndjson))

Importados via `POST https://127.0.0.1/api/saved_objects/_import?overwrite=true` com header `osd-xsrf: true`:

1. `vis-soclab-total-alerts`: métrica de contagem total no índice `wazuh-alerts-*`.
2. `vis-soclab-severity`: gráfico donut por faixas de `rule.level` (`0–4`, `4–8`, `8–12`, `12–17`).
3. `vis-soclab-hosts`: barras horizontais empilhadas por `agent.name` e `decoder.name`.
4. `vis-soclab-timeline`: série temporal (`date_histogram` sobre `timestamp`) dividida por faixas de `rule.level`.
5. `vis-soclab-suricata`: tabela filtrada por `rule.groups: "suricata"` agregando `data.alert.signature`, `data.src_ip` e `data.dest_ip`.
6. `vis-soclab-soar-actions`: tabela filtrada por `rule.groups: "soclab_soar"` agregando `data.action`, `data.target_ip` e `data.executed`.
7. `search-soclab-threat-hunting`: busca salva filtrando `rule.level >= 8 OR rule.groups: "soclab_soar"`.
8. `dashboard-soclab-overview`: painel consolidado **`Open SOC Lab - SOC Overview`** organizando os 7 objetos acima.
