> **Nota Histórica:** Este documento registra o diagnóstico inicial realizado **antes** da implementação da Etapa 4. Todos os gaps obrigatórios listados aqui já foram implementados e validados; consulte [relatorio4.md](file:///C:/Users/esdn6/Documents/SOC-SIEM/docs/relatorio4.md) e [relatorio_analise_completa_do_projeto.md](file:///C:/Users/esdn6/Documents/SOC-SIEM/docs/relatorio_analise_completa_do_projeto.md) para o estado atual do projeto.

# Relatório Detalhado: Estado Atual do Projeto e Pendências para Finalização (Open SOC Lab)

**Data da Análise:** 16 de novembro de 2026  
**Repositório:** `SOC-SIEM` (`open-soc-lab` v0.1.0)  
**Branch Atual:** `etapa4` (posicionada no commit `08728a8` — *Add Stage 3 SOAR response pipeline*)  
**Documento de Referência:** `docs/especifica_o_do_projeto_soc_siem_open_source.md`

---

## 1. Sumário Executivo

O projeto **Open SOC Lab** encontra-se em um **estágio avançado de desenvolvimento e maturidade de engenharia de software**, tendo concluído com sucesso a implementação de código, testes automatizados e ferramentas de linha de comando (CLI) das **Etapas 1, 2 e 3**:

1. **Etapa 1 (HIDS + SIEM — Wazuh):** Stack oficial do Wazuh (`v4.14.8` single-node via Docker), cliente Python REST (`WazuhClient`) com autenticação JWT, listagem e verificação de agentes (Linux e Windows), avaliação segura de regras via `logtest`, injeção controlada de eventos (`POST /events`), scripts de instalação automatizada de agentes e comando de verificação (`soclab stage1 verify`).
2. **Etapa 2 (NIDS — Suricata):** Coleta em streaming e validação tolerante a falhas de arquivos `EVE JSON` (`SuricataEveCollector`), normalização para um modelo de domínio canônico (`SecurityAlert`), filtragem por severidade/IP e acompanhamento em tempo real (`--follow`), scripts para instalação do Suricata no Linux e integração automática com o Wazuh Agent via `ossec.conf`, além de modo demonstração offline (`soclab stage2 verify --demo`).
3. **Etapa 3 (SOAR + Resposta Ativa — Shuffle + FastAPI):** API Webhook em FastAPI (`POST /api/v1/alerts`) protegida por token em tempo constante (`X-SOCLAB-TOKEN`), normalizador polimórfico de payloads (`map_shuffle_alert`), motor determinístico de política de resposta (`LOW/MEDIUM -> LOG`, `HIGH -> NOTIFY`, `CRITICAL -> BLOCK_IP`), proteção *fail-closed* para redes administrativas/RFC1918/loopback, deduplicação persistente em SQLite (`AlertDeduplicator`), trilha de auditoria append-only (`logs/audit.jsonl`), adapters de firewall para Windows (`New-NetFirewallRule`) e Linux (`nftables`) com modo seguro (`dry-run`) por padrão, e orquestração via Docker Compose (`profile: full`) com Shuffle Frontend, Backend e OpenSearch.

A base de código Python possui **excelente qualidade técnica**: conta com **81 testes unitários passando (`pytest`)**, checagem estrita de tipos (`mypy --strict` em 32 arquivos) e linting padronizado (`ruff`).

### O que falta em alto nível para finalizar o projeto?
Para atingir **100% de conformidade com a Especificação Oficial (`especifica_o_do_projeto_soc_siem_open_source.md`)** e concluir a **Etapa 4 (Integração Ponta a Ponta, Visualização e Entrega Final)**, o trabalho restante concentra-se em **quatro frentes principais**:
1. **Conectar o elo automático SIEM -> SOAR (Wazuh Manager -> Shuffle):** Configurar o Wazuh Manager para enviar alertas relevantes automaticamente ao Webhook do Shuffle (atualmente o projeto documenta e implementa `Shuffle -> SOC Lab API`, mas não automatiza o envio `Wazuh -> Shuffle`).
2. **Camada de Visualização e *Threat Hunting* (Seção 3.4 da Especificação):** Estruturar, documentar e/ou exportar os painéis exigidos no **Wazuh Dashboard** (e opcionalmente Grafana): *SOC Overview*, alertas por severidade, eventos por host (Windows/Linux), anomalias de rede, séries temporais e consultas de *Threat Hunting*, além de ingerir o `logs/audit.jsonl` no SIEM para visualizar as respostas do SOAR no Dashboard.
3. **Cenários Reais de Ataque/Simulação e Regras de Correlação (Seções 3.1, 3.2 e 3.3):** Criar scripts ou roteiros práticos a partir da máquina de testes (Kali Linux / gerador de tráfego) contra serviços simulados (Web/DB/File/SSH) e garantir regras no Suricata/Wazuh que disparem alertas de diferentes severidades (incluindo nível $\ge 12$ / `CRITICAL`) para acionar todo o pipeline ponta a ponta ao vivo.
4. **Consolidação do Ambiente, Workflow do Shuffle e Documentação Unificada:** Exportar o workflow JSON do Shuffle para o repositório, adicionar ação prática de notificação (Chat/Email) no workflow, atualizar o `.env` e o `README.md` principal (que ainda possui título da Etapa 1) e unificar o roteiro de demonstração final.

---

## 2. Matriz de Aderência à Especificação Oficial

A tabela abaixo cruza os **Componentes Obrigatórios da Arquitetura (Seção 2)** e os **Domínios Operacionais (Seção 3)** da especificação com o que já existe no repositório:

| Camada / Domínio | Ferramenta Escolhida | Status no Repositório | O que está pronto (Arquivos / Módulos) | O que falta para finalizar |
| :--- | :--- | :---: | :--- | :--- |
| **1. HIDS** (Coleta de Host Linux e Windows) | **Wazuh Agent** (`v4.14.8`) | **90% Concluído** | Scripts `scripts/windows/install_wazuh_agent.ps1` e `scripts/linux/install_wazuh_agent_debian.sh`; auto-instalação via `soclab stage1 verify --ensure-agent`; listagem via `soclab agents`. | Validar ambos os agentes (Linux **e** Windows) ativos simultaneamente no ambiente final de apresentação e monitorando diretórios críticos (FIM/syscheck) ou serviços (Web/DB/File). |
| **2. NIDS / NSM** (Inspeção de Rede) | **Suricata** (EVE JSON) *(Zeek é opcional)* | **85% Concluído** | Script `scripts/linux/install_suricata.sh`; integração com Wazuh Agent em `scripts/linux/configure_suricata_wazuh.sh`; coletor/normalizador Python (`collectors/suricata.py`, `normalizers/suricata.py`, `services/nids.py`); fixture `tests/fixtures/suricata/eve.json`. | Adicionar regras customizadas de laboratório (`/etc/suricata/rules/local.rules`) para garantir geração determinística de alertas `LOW`, `MEDIUM`, `HIGH` e `CRITICAL` durante os testes de rede ao vivo. *(Zeek é opcional e não foi incluído).* |
| **3. SIEM** (Centralização, Normalização e Correlação) | **Wazuh** (Manager + Indexer + Dashboard) | **80% Concluído** | Bootstrap automatizado em `scripts/bootstrap_wazuh.ps1` e `.sh`; cliente API completo em `src/soclab/clients/wazuh.py`; `logtest` e envio de eventos em `services/events.py`. | 1) Configurar `<integration>` no `ossec.conf` do **Wazuh Manager** para encaminhar alertas automaticamente ao Shuffle.<br>2) Ingerir `logs/audit.jsonl` no Wazuh para fechar o ciclo de auditoria.<br>3) Regras customizadas (`local_rules.xml`) se necessário para correlação host+rede. |
| **4. SOAR** (Orquestração e Automação de Resposta) | **Shuffle** + **SOC Lab FastAPI** | **85% Concluído** | Stack em `compose.yaml` (`shuffle-frontend`, `shuffle-backend`, `shuffle-opensearch`, `soclab`); API FastAPI (`src/soclab/api/app.py`); mapper (`normalizers/shuffle.py`); política (`services/policy.py`), dedup SQLite (`services/dedup.py`), auditoria (`services/audit.jsonl`) e firewall adapters (`adapters/firewall.py`). | 1) Exportar e versionar o arquivo JSON do Workflow do Shuffle no repositório.<br>2) Configurar no Shuffle o gatilho vindo do Wazuh Manager e um nó real de Notificação (Email/Slack/Discord/Telegram) para alertas `HIGH`/`CRITICAL`. |
| **5. Dashboards** (Visualização e *Threat Hunting*) | **Wazuh Dashboard** *(Grafana opcional)* | **35% Concluído** | Container `wazuh.dashboard` sobe via Docker Compose (`https://localhost`); instruções básicas de busca no índice `wazuh-alerts-*` no `README.md`. | **Principal lacuna para a Etapa 4:** Criar/exportar os dashboards/visualizações exigidos na Seção 3.4 (*SOC Overview*, severidade, eventos Windows/Linux, rede/Suricata, séries temporais e guia/queries de *Threat Hunting*). |
| **6. Fontes de Eventos e Testes de Ataque** | Endpoints + Serviços + **Kali Linux** | **50% Concluído** | Evento sintético SSH (`sample_failed_ssh_event`), fixture Suricata (`eve.json`) e payloads de demo da Etapa 3 (`services/demo.py`). | Roteiro/scripts de simulação de ataques controlados (ex: Nmap, Hydra/SSH brute force, Nikto/SQLi/curl malicioso, alteração de arquivo monitorado) simulando a VM06 (Kali) contra serviços Web/DB/File. |

---

## 3. Diagnóstico Técnico Detalhado do Repositório Atual

### 3.1. Estrutura e Arquitetura do Código Python (`src/soclab`)

A aplicação `soclab` foi desenhada de forma modular e limpa, dividida em subpacotes bem definidos:

* **`src/soclab/config.py`:** Gerenciamento centralizado via `pydantic-settings` (`Settings`), lendo variáveis com prefixo `SOCLAB_` do arquivo `.env`. Possui carregamento estrito (`get_settings()`, que exige `SOCLAB_WAZUH_PASSWORD`) e opcional (`get_settings_optional()`, usado pelas Etapas 2 e 3 quando executadas de forma independente da API do Wazuh). Protege segredos (`wazuh_password` e `webhook_token`) usando `SecretStr`.
* **`src/soclab/domain/`:**
  * `alert.py`: Define `AlertSeverity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) e o contrato canônico `SecurityAlert` (agnóstico à fonte, com validação de IPs via `IPvAnyAddress` e timestamps *timezone-aware*).
  * `networks.py`: Define as faixas protegidas padrão (`DEFAULT_PROTECTED_NETWORKS`: loopback `127.0.0.0/8`, `::1/128`, link-local e todas as redes privadas RFC1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`). Possui lógica *fail-closed* (`is_protected()` retorna `True` caso o endereço IP seja inválido/não-parseável).
* **`src/soclab/clients/wazuh.py`:** Cliente síncrono `WazuhClient` baseado em `httpx`. Realiza autenticação Basic em `/security/user/authenticate?raw=true` para obter JWT Bearer token, renova automaticamente o token em caso de `HTTP 401`, possui *retry* com *backoff* apenas para requisições idempotentes (`GET`), e implementa `api_info()`, `agents()`, `logtest()` e `send_event()`.
* **`src/soclab/collectors/suricata.py` e `normalizers/suricata.py`:**
  * `SuricataEveCollector` lê arquivos `eve.json` linha a linha em streaming (sem carregar tudo na memória) e suporta modo *tail/follow* (`follow_records()`). Linhas com JSON corrompido ou schema inválido são contabilizadas sem interromper o processamento.
  * `normalize_suricata_alert()` filtra eventos com `event_type == "alert"`, gera ID determinístico (`suricata-<sha1>`) e mapeia a severidade numérica do Suricata (`1 -> CRITICAL`, `2 -> HIGH`, `3 -> MEDIUM`, `>=4 -> LOW`).
* **`src/soclab/normalizers/shuffle.py`:**
  * `map_shuffle_alert()` aceita tanto o formato canônico do `soclab`, quanto o JSON nativo de alerta do Wazuh ou envelopes do Shuffle (`{"alert": {...}}`, `{"data": {...}}`).
  * Converte níveis numéricos do Wazuh (escala 0 a 15) para `AlertSeverity`: `0–3 -> LOW`, `4–7 -> MEDIUM`, `8–11 -> HIGH`, `12–15 -> CRITICAL`.
  * Caso o payload não possua severidade/level, lança `AlertMappingError` (retornando HTTP 400 na API) para nunca rebaixar silenciosamente um alerta crítico.
* **`src/soclab/services/`:**
  * `policy.py`: `ResponsePolicy` avalia um `SecurityAlert` segundo a matriz `LOW/MEDIUM -> LOG`, `HIGH -> NOTIFY`, `CRITICAL -> BLOCK_IP`. Se a ação for `BLOCK_IP`, mas o alerta não tiver `src_ip` ou o `src_ip` pertencer a `protected_networks`, a ação é rebaixada com segurança para `NOTIFY` (`protected=True`).
  * `dedup.py`: `AlertDeduplicator` usa `sqlite3` da biblioteca padrão (`runtime/soclab_state.db`) com `INSERT OR IGNORE INTO processed_alerts` para garantir idempotência em reentregas de webhook pelo Shuffle.
  * `audit.py`: `AuditLogger` grava cada decisão em formato JSON Lines (`logs/audit.jsonl`) protegido por `threading.Lock`.
  * `response.py`: `ResponseService` orquestra o fluxo `policy -> dedup -> adapter -> audit`.
  * `stage1_verification.py`, `stage2_verification.py`, `stage3_verification.py`: Serviços completos de diagnóstico automatizado e auto-verificação do ambiente e da qualidade do código (`pytest`, `ruff`, `mypy`).
* **`src/soclab/adapters/firewall.py`:**
  * Implementa `DryRunFirewallAdapter` (padrão), `WindowsFirewallAdapter` (`New-NetFirewallRule -DisplayName 'SOCLab-Block-<ip>' -Direction Inbound -Action Block -RemoteAddress <ip>`) e `LinuxFirewallAdapter` (`nft add rule inet filter input ip/ip6 saddr <ip> drop`).
  * Valida o IP canonicamente antes de construir a lista de argumentos e executa `subprocess.run(..., shell=False)` com timeout de 15s (prevenindo *command injection*).
* **`src/soclab/api/app.py`:**
  * Aplicação FastAPI expondo `GET /health`, `GET /ready` e `POST /api/v1/alerts`.
  * Valida o header `X-SOCLAB-TOKEN` usando `secrets.compare_digest()`. Retorna `503` se o token não estiver configurado no servidor e `401` se o token enviado for inválido ou ausente.

### 3.2. Estado Atual do Ambiente Local (Arquivos de Runtime e Configuração)

Durante a inspeção do diretório de trabalho (`C:\Users\esdn6\Documents\SOC-SIEM`), foram constatados os seguintes detalhes sobre o estado local:

1. **Arquivo `.env` incompleto:**
   * O arquivo `.env` local contém apenas as 6 variáveis da Etapa 1 e **`SOCLAB_WAZUH_PASSWORD=` está vazio**.
   * As variáveis adicionadas nas Etapas 2 e 3 (presentes no `.env.example`, como `SOCLAB_SURICATA_ENABLED`, `SOCLAB_WEBHOOK_TOKEN`, `SOCLAB_RESPONSE_DRY_RUN`, `SOCLAB_PROTECTED_NETWORKS`, etc.) ainda não foram copiadas para o `.env` local. Como consequência, `SOCLAB_WEBHOOK_TOKEN` assume string vazia por padrão e o endpoint `/ready` ou `/api/v1/alerts` retorna `HTTP 503` em execução real até que `SOCLAB_WEBHOOK_TOKEN` seja definido no `.env`.
2. **Diretório `infra/wazuh-docker` vazio:**
   * A pasta `infra/wazuh-docker` existe, mas está vazia no momento (não contém o clone do repositório oficial `wazuh/wazuh-docker` na tag `v4.14.8`). Para subir o SIEM localmente, é necessário executar `.\scripts\bootstrap_wazuh.ps1` (Windows) ou `./scripts/bootstrap_wazuh.sh infra/wazuh-docker` (Linux) com o Docker Engine ativo.
3. **Evidências de execução da Etapa 3 presentes:**
   * O arquivo `logs/audit.jsonl` (com 26 registros de auditoria gerados pelas execuções de demo/teste) e o banco SQLite `runtime/soclab_state.db` já existem e demonstram o funcionamento correto do motor de resposta em modo `dry-run`.
4. **Estado das Branches Git:**
   * A branch atual é `etapa4`, criada no mesmo commit da `etapa3` (`08728a8`).
   * As branches `develop` e `main` ainda apontam para o merge da Etapa 2 (`1306490` e `5e094cf`), ou seja, a Etapa 3 ainda não foi mesclada em `develop`/`main`.
   * O arquivo `docs/especifica_o_do_projeto_soc_siem_open_source.md` aparece como *untracked* (`??`) no Git.

---

## 4. O Que Falta Para Finalizar o Projeto (Análise de Gaps)

Abaixo estão detalhadas todas as pendências que separam o estado atual do repositório da entrega final completa exigida na especificação do projeto.

### 4.1. Gap 1: Integração Automática Wazuh SIEM $\rightarrow$ Shuffle SOAR (Fluxo 5 da Especificação)

* **O que a especificação pede (Seções 3.5 e 5.5):** *"Quando o SIEM identifica incidentes relevantes, ele encaminha os dados através de Alertas / Webhook / API para a plataforma Shuffle SOAR"* (`Wazuh Manager -> Shuffle -> SOC Lab API`).
* **O que existe hoje:** A documentação em `docs/shuffle-workflow.md` mostra como configurar o Shuffle para chamar `POST /api/v1/alerts` da API do SOC Lab, e como testar via `curl`. Porém, **não há script ou configuração automatizada para fazer o Wazuh Manager enviar os alertas para o Webhook do Shuffle**.
* **O que precisa ser feito:**
  1. Criar um script ou configuração para adicionar o bloco `<integration>` no `/var/ossec/etc/ossec.conf` do **Wazuh Manager** (dentro do container `wazuh.manager` ou mapeado via volume no `docker-compose.yml` do Wazuh):
     ```xml
     <integration>
       <name>shuffle</name>
       <hook_url>http://<IP-DO-SHUFFLE>:5001/api/v1/hooks/<WEBHOOK_ID></hook_url>
       <level>3</level>
       <alert_format>json</alert_format>
     </integration>
     ```
  2. Alternativamente, caso o Shuffle esteja na mesma máquina/rede Docker, documentar e automatizar a injeção dessa configuração no container `wazuh.manager` para que qualquer alerta gerado no Wazuh acione o Shuffle sem intervenção manual.

### 4.2. Gap 2: Exportação do Workflow do Shuffle e Ações Complementares de Resposta (Seções 3.5 e 3.6)

* **O que a especificação pede (Seção 3.6):** O SOAR deve orquestrar workflows capazes de acionar respostas práticas como:
  1. Bloqueio de IP (Firewall)
  2. Execução de Scripts
  3. Notificações (Email / Chat)
  4. Registro Formal da Ação (Auditoria)
  5. Coleta de Evidências
* **O que existe hoje:**
  * O **Bloqueio de IP** (`WindowsFirewallAdapter` / `LinuxFirewallAdapter`) e o **Registro da Ação** (`logs/audit.jsonl` + SQLite) estão 100% implementados na API do SOC Lab.
  * Para **Notificações**, o `Relatorio_Etapa_3.md` define que a ação `NOTIFY` registra a decisão e delega o envio de mensagem (Email/Slack/Discord/Teams) ao workflow do Shuffle. Entretanto, o workflow do Shuffle ainda não está exportado como arquivo JSON no repositório.
* **O que precisa ser feito:**
  1. **Construir e exportar o Workflow do Shuffle** (ex: salvar em `infra/shuffle/soclab_workflow.json`) contendo:
     * **Trigger:** Webhook recebendo o alerta do Wazuh Manager.
     * **Node 1 (HTTP):** Chamada `POST http://soclab:8080/api/v1/alerts` com header `X-SOCLAB-TOKEN`.
     * **Node 2 (Condicional / Branching ou Notificação):** Quando a resposta da API indicar `action == "NOTIFY"` ou `action == "BLOCK_IP"`, disparar uma notificação enriquecida (para Discord, Telegram, Slack, Email ou canal de chat da equipe) contendo ID do alerta, severidade, IP atacante, assinatura e se o IP foi bloqueado.
  2. **Coleta de Evidências (Seção 3.6 item 5):** Incluir no workflow do Shuffle ou na própria resposta do `soclab` o salvamento do payload bruto completo do incidente / contexto forense básico (timestamp, processo/regra, IPs, portas, payload original) em um diretório de evidências (ex: `logs/evidence/<alert_id>.json`) quando a severidade for `HIGH` ou `CRITICAL`. Isso cumpre explicitamente o item 5 da Seção 3.6 com mínimo esforço de código.

### 4.3. Gap 3: Camada de Visualização e *Threat Hunting* (Seção 3.4 e Fluxo 4 da Especificação)

* **O que a especificação pede (Seção 3.4):** Painéis gráficos alimentados pelos dados indexados no SIEM cobrindo:
  1. Visão geral do SOC (*SOC Overview*)
  2. Classificação e contagem de alertas por severidade
  3. Monitoramento de eventos por host (Windows / Linux)
  4. Monitoramento de eventos e anomalias de rede (Suricata)
  5. Análise de tendências temporais (séries históricas de ataques/eventos)
  6. Suporte a atividades de *Threat Hunting*
  7. *(Opcional)* Grafana conectado à base do SIEM.
* **O que existe hoje:** O Wazuh Dashboard é iniciado na Etapa 1, mas não há painéis customizados exportados, nem documentação detalhada das visualizações ou queries de *Threat Hunting*, e os logs de decisão do SOAR (`logs/audit.jsonl`) ficam apenas em disco local sem voltar para o Wazuh Indexer.
* **O que precisa ser feito:**
  1. **Ingerir `logs/audit.jsonl` no Wazuh:** Configurar o Wazuh Agent (ou volume no Wazuh Manager) para ler `logs/audit.jsonl` (`<log_format>json</log_format>`) e criar uma regra simples no Wazuh para indexar os eventos do SOAR (`adapter`, `action`, `target_ip`, `protected`, `duplicate`). Assim, as ações do SOAR também aparecem no Wazuh Dashboard!
  2. **Criar e exportar o Dashboard Customizado no Wazuh Dashboard (OpenSearch Dashboards):**
     * Montar um painel consolidado **"Open SOC Lab - SOC Overview"** contendo os gráficos exigidos na Seção 3.4 (pizza/barras de severidade, tabela/contagem por host Windows vs. Linux, eventos de rede do Suricata `data.event_type: alert`, linha do tempo de ataques e tabela de respostas do SOAR).
     * Exportar o painel em `infra/wazuh-dashboard/soclab-dashboard.ndjson` (via *Stack Management -> Saved Objects -> Export*) para que qualquer membro da equipe possa importar rapidamente.
  3. **Documentar Guia de *Threat Hunting* e Visualização (`docs/dashboards-and-threat-hunting.md`):**
     * Documentar as queries DQL/KQL prontas para caça a ameaças no `Explore > Discover` (ex: busca por brute-force SSH, varreduras de porta do Suricata, tentativas de login falhas no Windows EventChannel, alertas críticos bloqueados pelo SOAR) com capturas de tela ou instruções passo a passo para a banca.

### 4.4. Gap 4: Simulação de Ataques (Kali Linux), Serviços Monitorados e Regras de Detecção (Seções 3.1, 3.2 e 4)

* **O que a especificação pede (Seções 3.1 e 4):**
  * Topologia de referência com Endpoints Linux (VM04) e Windows (VM05), serviços simulados (*Web Server, DB Server, File Server*) e máquina de ataques **Kali Linux (VM06)** gerando tráfego malicioso controlado (varreduras, tentativas de exploração, força bruta) capturado pelo Suricata e pelos agentes Wazuh.
* **O que existe hoje:**
  * Existe apenas 1 evento sintético de falha de SSH (`sample_failed_ssh_event()` em `src/soclab/services/events.py`, que gera regra nível 5 no Wazuh — ou seja, `MEDIUM`, que não aciona `BLOCK_IP`) e 1 fixture estática do Suricata (`tests/fixtures/suricata/eve.json`).
  * A proteção de IPs padrão (`DEFAULT_PROTECTED_NETWORKS`) inclui todas as redes privadas RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). **Atenção crítica:** Em um laboratório local onde a VM Kali Linux (VM06) possui um IP privado (ex: `192.168.56.106` ou `10.0.0.6`), qualquer ataque vindo da Kali será classificado como `protected=True` e **rebaixado de `BLOCK_IP` para `NOTIFY`**, a menos que `SOCLAB_PROTECTED_NETWORKS` seja ajustado no `.env` para proteger apenas os IPs dos servidores do SOC/gateways e permitir o bloqueio da sub-rede ou IP da máquina atacante (Kali)!
* **O que precisa ser feito:**
  1. **Regras de Detecção para o Laboratório:**
     * Adicionar regras locais no Suricata (ex: `scripts/linux/suricata_local.rules` instalado pelo script) ou usar assinaturas *Emerging Threats* que detectem Nmap scan (`HIGH`), SQL Injection / Web attack (`CRITICAL`), e brute-force SSH (`CRITICAL`).
     * Garantir pelo menos um cenário no Wazuh que gere alerta de nível $\ge 12$ (`CRITICAL`) ou configurar a política/regras customizadas (`local_rules.xml`) para que o ataque demonstrado pela Kali acione `BLOCK_IP`.
  2. **Ajuste de `SOCLAB_PROTECTED_NETWORKS` para o Cenário com Kali Linux:**
     * Documentar claramente quais redes devem ficar em `SOCLAB_PROTECTED_NETWORKS` durante o teste real entre VMs (ex: proteger o IP do Wazuh Server, Shuffle e Gateway, mas **não** colocar o IP da VM06 Kali Linux na lista de protegidos, permitindo demonstrar o `BLOCK_IP` real ou dry-run contra a Kali).
  3. **Script/Roteiro de Simulação de Ataques (`docs/attack-simulation-guide.md` ou comando CLI):**
     * Documentar os comandos exatos a serem executados a partir da Kali Linux (VM06) contra os alvos Linux (VM04 - ex: Nginx/Apache, SSH, MySQL/PostgreSQL, Samba/File Server) e Windows (VM05 - ex: SMB/RDP/WinRM/IIS) para validar os 6 fluxos ponta a ponta da Seção 5.

### 4.5. Gap 5: Refinamentos Técnicos e Consolidação da Etapa 4 no CLI/Documentação

1. **Atualização do `README.md` e Documentação Final:**
   * O `README.md` ainda inicia com `# Open SOC Lab - Etapa 1`. Deve ser atualizado para apresentar a arquitetura completa das 4 etapas, a topologia do laboratório (VM01 a VM06 / containers), o fluxo ponta a ponta e os comandos de todas as etapas.
2. **Sincronização do `.env`:**
   * Atualizar o `.env` local com base no `.env.example`, preenchendo `SOCLAB_WAZUH_PASSWORD` e `SOCLAB_WEBHOOK_TOKEN`.
3. **Comando de Desbloqueio / Rollback de Firewall (Opcional, mas altamente recomendado):**
   * Conforme apontado nos riscos do `Relatorio_Etapa_3.md`, quando `SOCLAB_RESPONSE_DRY_RUN=false`, o adapter cria a regra de bloqueio no Windows Firewall ou `nftables`, mas não há um comando CLI (ex: `uv run soclab unblock <ip>`) para remover a regra após a demonstração ao vivo.
4. **Verificador Final / Etapa 4 (`soclab stage4 verify` ou `soclab verify all` - Opcional):**
   * Como a equipe criou a branch `etapa4`, pode-se adicionar um comando consolidado que verifique o pipeline completo (Stage 1 + Stage 2 + Stage 3 + conectividade com Shuffle/Dashboard) ou um relatório final da Etapa 4 (`Relatorio_Etapa_4.md`).

---

## 5. Avaliações dos 6 Fluxos Ponta a Ponta (Seção 5 da Especificação)

Para facilitar a visualização do que já funciona e do que falta no fluxo integrado exigido pela especificação:

```
[VM06: Kali Linux] ──(1. Tráfego de Ataque)──> [Rede / SPAN] ──> [VM02: Suricata NIDS]
        │                                                                 │
        ▼                                                          (2b. eve.json)
[VM04/VM05: Linux & Windows]                                              │
        │                                                                 ▼
   (2a. Logs OS) ─────────────────────────────────────────────> [VM01: Wazuh Server]
                                                                 (Manager + Indexer)
                                                                    │           │
                                                     (4. Consultas) │           │ (5. Webhook Alerta)
                                                                    ▼           ▼
                                                           [Wazuh Dashboard] [VM03: Shuffle SOAR]
                                                                                │
                                                                    (6a. POST /api/v1/alerts)
                                                                                ▼
                                                                       [SOC Lab FastAPI]
                                                                                │
                                                       ┌────────────────────────┼────────────────────────┐
                                                       ▼                        ▼                        ▼
                                              [Firewall Block IP]      [logs/audit.jsonl]     [Coleta Evidências]
```

* **Fluxo 1 (Tráfego de Rede $\rightarrow$ Suricata):** **Pronto no sensor**, falta apenas padronizar o roteiro de comandos de ataque da VM06 (Kali) e regras locais do Suricata.
* **Fluxo 2 (Eventos e Logs $\rightarrow$ Wazuh Manager):** **100% Pronto** (scripts de agentes Windows/Linux e script `configure_suricata_wazuh.sh` para enviar `eve.json` ao Wazuh).
* **Fluxo 3 (Correlação e Indexação no Wazuh):** **Pronto** na stack Docker do Wazuh; recomenda-se apenas adicionar regras customizadas (`local_rules.xml`) para garantir alertas de nível $\ge 12$ nos cenários de demonstração.
* **Fluxo 4 (Visualização no Wazuh Dashboard):** **Pendente de construção/exportação dos painéis** específicos exigidos na Seção 3.4 e guia de *Threat Hunting*.
* **Fluxo 5 (Alerta do Wazuh $\rightarrow$ Shuffle SOAR):** **Pendente de configuração automatizada** do bloco `<integration>` no `ossec.conf` do Wazuh Manager apontando para o Webhook do Shuffle.
* **Fluxo 6 (Ação de Resposta do Shuffle $\rightarrow$ Firewall / Notificação / Auditoria / Evidências):** **85% Pronto** (API FastAPI, política, deduplicação, auditoria JSONL e bloqueio de IP em Windows/Linux prontos; falta exportar o workflow do Shuffle com nó de notificação e eventual gravação de evidência forense).

---

## 6. Checklist Recomendado para Finalização (Plano de Trabalho da Etapa 4)

Abaixo está a lista ordenada de tarefas sugeridas para concluir o projeto sem pendências perante a especificação:

### Prioridade 1 — Integração Ponta a Ponta (Fechamento do Ciclo SIEM $\leftrightarrow$ SOAR)
- [ ] **Configurar integração Wazuh Manager $\rightarrow$ Shuffle:** Criar script ou configuração automatizada que insira o bloco `<integration>` para o Shuffle no `ossec.conf` do Wazuh Manager e reinicie o serviço.
- [ ] **Exportar Workflow do Shuffle:** Criar o workflow completo na interface do Shuffle (Webhook Wazuh $\rightarrow$ `POST /api/v1/alerts` no SOC Lab $\rightarrow$ Notificação Email/Chat) e exportar o JSON para o repositório (ex: `infra/shuffle/workflow-soclab.json`).
- [ ] **Ingerir `logs/audit.jsonl` no Wazuh:** Configurar leitura do `logs/audit.jsonl` pelo Wazuh para que as ações de resposta do SOAR sejam indexadas no `wazuh-alerts-*`.
- [ ] **Adicionar Coleta de Evidências (Seção 3.6.5):** Persistir um snapshot de evidências do incidente (ex: `logs/evidence/<alert_id>.json`) nos alertas `HIGH`/`CRITICAL` ou documentar a coleta via script de resposta.

### Prioridade 2 — Visualização e *Threat Hunting* (Seção 3.4 da Especificação)
- [ ] **Construir e Exportar Dashboards no Wazuh Dashboard:** Criar as visualizações para:
  - *SOC Overview* (visão executiva e operacional);
  - Contagem e classificação de alertas por severidade;
  - Eventos por host (comparativo Windows vs. Linux);
  - Monitoramento de eventos e anomalias de rede (alertas do Suricata);
  - Séries históricas (tendências temporais de eventos/ataques);
  - Painel de ações de resposta executadas pelo SOAR.
- [ ] **Documentar Consultas de *Threat Hunting*:** Criar documento em `docs/` com filtros KQL/DQL e roteiro de investigação no índice `wazuh-alerts-*`.

### Prioridade 3 — Cenários de Ataque, Topologia e Regras (Seções 3.1, 3.2 e 4)
- [ ] **Regras Customizadas (Suricata / Wazuh):** Incluir arquivo de regras locais do Suricata (`local.rules`) e/ou regras do Wazuh (`local_rules.xml`) que garantam o disparo de alertas `LOW`, `MEDIUM`, `HIGH` e `CRITICAL` (nível $\ge 12$) para os testes controlados.
- [ ] **Ajustar `SOCLAB_PROTECTED_NETWORKS` para o Lab de VMs:** Documentar a configuração de redes protegidas de forma que o IP da máquina atacante (VM06 Kali Linux) **não** seja filtrado como IP administrativo protegido, permitindo demonstrar a ação `BLOCK_IP` contra ela.
- [ ] **Documentar Roteiro de Testes com Kali Linux e Serviços Alvo:** Criar guia passo a passo dos ataques controlados (Nmap, força bruta SSH/Web, modificação de arquivo FIM) contra os endpoints Linux/Windows.

### Prioridade 4 — Polimento, Ambiente Local e Documentação Final
- [ ] **Atualizar `.env` local e subir `wazuh-docker`:** Executar `bootstrap_wazuh.ps1` / `.sh` para popular `infra/wazuh-docker` e sincronizar o `.env` com todas as variáveis do `.env.example`.
- [ ] **Adicionar comando de Rollback/Unblock (Opcional):** Implementar `soclab unblock <ip>` nos adapters de firewall para facilitar múltiplos testes em modo live (`SOCLAB_RESPONSE_DRY_RUN=false`).
- [ ] **Atualizar `README.md` e Mesclar Branches:** Atualizar o `README.md` principal contemplando toda a arquitetura (Etapas 1 a 4) e realizar o merge das branches (`etapa3` / `etapa4`) para `develop` e `main`.
