# Dashboards e Guia de Threat Hunting (Open SOC Lab)

Este documento descreve a camada de visualização operacional (Seção 3.4 da especificação) construída sobre o **Wazuh Dashboard** (`https://localhost`) e o guia prático de **Threat Hunting** no índice `wazuh-alerts-*`.

---

## 1. Dashboard Customizado: `Open SOC Lab - SOC Overview`

O arquivo [soclab-dashboard.ndjson](file:///C:/Users/esdn6/Documents/SOC-SIEM/infra/wazuh-dashboard/soclab-dashboard.ndjson) é importado automaticamente pelo provisionamento (`soclab lab provision` / `.\scripts\up.ps1`) via API de *Saved Objects* do OpenSearch Dashboards.

### Como abrir no navegador:
1. Acesse **`https://localhost`** (`admin` / `SecretPassword`).
2. Abra o menu lateral (`≡`) $\rightarrow$ **Explore $\rightarrow$ Dashboards**.
3. Clique em **`Open SOC Lab - SOC Overview`**.

### Painéis incluídos:
| Painel | Tipo | O que exibe |
|---|---|---|
| `SOC Lab - Total de Alertas` | Métrica | Volume total de eventos indexados no SIEM no intervalo selecionado. |
| `SOC Lab - Alertas por Severidade (Rule Level)` | Gráfico de Pizza/Donut | Distribuição por faixas de nível: `0–3` (Low), `4–7` (Medium), `8–11` (High), `12+` (Critical). |
| `SOC Lab - Eventos por Host / Agente e Origem` | Barras Horizontais | Comparativo de alertas por endpoint (`linux-target`, `wazuh.manager`, endpoint Windows quando conectado) agrupado por `decoder.name` (`json`, `web-accesslog`, `sshd`, `syscheck`). |
| `SOC Lab - Tendencia Temporal de Alertas` | Série Histórica (Linha) | Evolução temporal de ataques e alertas agrupada por nível de severidade. |
| `SOC Lab - Anomalias de Rede (Suricata NIDS)` | Tabela | Assinaturas Suricata (`data.alert.signature`), IP de origem e destino filtrados por `rule.groups: "suricata"`. |
| `SOC Lab - Respostas Automatizadas do SOAR` | Tabela | Decisões do Shuffle + API `soclab` (`data.action`, `data.target_ip`, `data.executed`) reingeridas via `logs/audit.jsonl` (regras `100150` / `100151`). |
| `SOC Lab - Threat Hunting (Eventos High/Critical & SOAR)` | Busca Salva | Lista cronológica filtrando incidentes críticos (`rule.level >= 8`) e ações de resposta do SOAR. |

---

## 2. Guia de Threat Hunting (`Explore > Discover` ou `Threat Hunting`)

Na barra de busca do Wazuh Dashboard, certifique-se de que a linguagem está em **DQL** (padrão) e selecione o intervalo de tempo adequado (ex.: `Last 1 hour` ou `Last 24 hours`).

### Consultas prontas para investigação:

1. **Caçar todos os ataques críticos e de alta severidade:**
   ```text
   rule.level >= 8
   ```
2. **Investigar alertas de rede gerados pelo Suricata NIDS:**
   ```text
   rule.groups: "suricata"
   ```
3. **Investigar apenas o IP atacante do container Kali (`172.28.0.200`):**
   ```text
   data.src_ip: "172.28.0.200" OR data.srcip: "172.28.0.200"
   ```
4. **Rastrear tentativas de força bruta SSH:**
   ```text
   rule.groups: "sshd" and rule.level >= 5
   ```
5. **Rastrear ataques Web contra o Nginx (SQLi / Path Traversal):**
   ```text
   rule.groups: "web" or data.alert.signature_id: (910004 or 910006)
   ```
6. **Auditar alterações de integridade de arquivos (FIM) no diretório protegido:**
   ```text
   rule.groups: "syscheck" and syscheck.path: "/etc/soclab-protected*"
   ```
7. **Auditar todas as decisões e bloqueios executados pelo SOAR:**
   ```text
   rule.groups: "soclab_soar"
   ```
8. **Separar eventos por endpoint (`agent.name`) ou plataforma (quando houver Windows e Linux ativos):**
   ```text
   agent.name: "linux-target"
   ```
   ```text
   data.os.platform: "windows" OR agent.name: *win*
   ```
