# Especificação do Projeto: Ambiente SOC/SIEM Open-Source (Open SOC Lab)

## 1. Objetivo Geral do Trabalho

O objetivo deste projeto acadêmico é projetar, implementar e integrar um ambiente funcional de **SOC (Security Operations Center)** e **SIEM (Security Information and Event Management)** utilizando exclusivamente ferramentas **Open-Source**.

O trabalho deve ser desenvolvido por equipes integradas de até **4 alunos**, cobrindo todo o ciclo de vida de monitoramento e defesa cibernética: coleta de telemetria de host e rede, detecção de ameaças, centralização e correlação de logs, visualização operacional e resposta automatizada a incidentes.

## 2. Componentes Obrigatórios da Arquitetura

A especificação do projeto exige que a solução contemple cinco camadas tecnológicas fundamentais, permitindo à equipe escolher entre as ferramentas homologadas abaixo:

| Camada | Função Principal | Ferramentas Permitidas na Especificação |
| :--- | :--- | :--- |
| **HIDS** | Coleta de logs de Sistema Operacional e monitoramento de integridade de host | Wazuh, Auditd, OSSEC ou Velociraptor |
| **NIDS / NSM** | Inspeção de pacotes, análise de tráfego e detecção de intrusão em rede | Suricata, Zeek ou Snort |
| **SIEM** | Gestão centralizada, normalização, indexação e correlação de eventos de host e rede | Wazuh ou Graylog |
| **SOAR** | Recebimento de alertas do SIEM, orquestração de workflows e execução de ações de resposta | Shuffle |
| **Dashboards** | Exibição gráfica de eventos, métricas operacionais e painéis de monitoramento | Wazuh Dashboard, Grafana ou Kibana |

## 3. Detalhamento da Arquitetura da Solução (Open SOC Lab)

A arquitetura de referência do laboratório (**HIDS + NSM/NIDS + SIEM + SOAR + Visualização**) organiza o ambiente em seis grandes domínios operacionais interconectados:

### 3.1. Fontes de Eventos
Representam os ativos monitorados e os geradores de tráfego e telemetria dentro do laboratório:
* **Endpoints Monitorados (Linux e Windows):** Estações de trabalho ou servidores contendo o agente de monitoramento instalado (ex: *Wazuh Agent*) para coleta contínua de logs de sistema operacional, autenticação, processos e integridade de arquivos.
* **Servidores e Aplicações:** Serviços de infraestrutura crítica simulados no ambiente, tais como *Web Server*, *DB Server* (Banco de Dados) e *File Server* (Servidor de Arquivos).
* **Máquina de Ataques e Testes (Kali Linux):** Estação dedicada à simulação de ameaças, varreduras de rede, tentativas de exploração e geração de tráfego malicioso controlado para validar as regras de detecção do SOC.
* **Fontes Adicionais (Opcional):** Integração complementar de telemetria oriunda de *Logs de Sistemas*, *Firewall*, *Proxy* e outras fontes de rede.

### 3.2. Monitoramento e Inspeção de Rede (NIDS / NSM)
O tráfego que circula pela **Rede** dos ativos monitorados é espelhado (via **SPAN / TAP**) para os sensores de análise de rede:
* **NIDS - Suricata:**
  * Responsável pela detecção baseada em assinaturas.
  * Capacidade de atuação como IPS (Prevenção de Intrusão - opcional).
  * Geração de alertas de segurança em tempo real.
  * Saída padronizada de eventos e alertas no formato **EVE JSON**, encaminhada ao SIEM.
* **NSM - Zeek (Opcional/Complementar):**
  * Focado em análise comportamental e metadados de tráfego de rede.
  * Registro detalhado de conexões e protocolos (*DNS, HTTP, SSL/TLS, SSH*, etc.).
  * Saída estruturada em logs nos formatos **JSON / TSV**, encaminhada ao SIEM.

### 3.3. Centralização e Correlação (SIEM - Wazuh)
Atua como o núcleo analítico da arquitetura, recebendo tanto os logs diretos dos agentes de endpoint quanto os arquivos JSON gerados pelos sensores de rede (Suricata / Zeek):
* **Wazuh Manager:**
  * Coleta e normalização dos eventos recebidos de múltiplas fontes (decoders).
  * Aplicação de regras de detecção e avaliação de níveis de severidade.
  * Correlação de eventos entre host e rede.
  * Geração e disparo de alertas consolidados.
* **Wazuh Indexer:**
  * Indexação de alta performance dos eventos processados.
  * Armazenamento estruturado e retenção de dados.
  * Motor de pesquisa para consultas rápidas e investigação.
* **Wazuh Dashboard (Componente Nativo):**
  * Interface de visualização nativa integrada ao Indexer para operação de painéis operacionais.

### 3.4. Camada de Visualização
Fornece consciência situacional para os analistas do SOC por meio de painéis gráficos alimentados pelos dados indexados no SIEM:
* **Wazuh Dashboard:**
  * Visão geral do SOC (*SOC Overview*).
  * Classificação e contagem de alertas por severidade.
  * Monitoramento de eventos por host (Windows / Linux).
  * Monitoramento de eventos e anomalias de rede.
  * Análise de tendências temporais (séries históricas de ataques/eventos).
  * Suporte a atividades de *Threat Hunting* (caça a ameaças).
* **Grafana (Opcional):**
  * Construção de dashboards personalizados adicionais conectados à base de dados do SIEM.

### 3.5. Orquestração e Automação de Resposta (SOAR - Shuffle)
Quando o SIEM identifica incidentes relevantes, ele encaminha os dados através de **Alertas / Webhook / API** para a plataforma **Shuffle SOAR**:
* **Papel do Shuffle:**
  * Receber alertas em tempo real gerados pelo SIEM.
  * Orquestrar *workflows* (fluxos de trabalho automatizados) de resposta a incidentes.
  * Automatizar tomadas de decisão e respostas operacionais.
  * Integrar-se com APIs externas, sistemas de mensageria, firewalls e scripts personalizados.

### 3.6. Ações de Resposta (Exemplos Práticos)
A partir dos *workflows* executados pelo Shuffle SOAR, o ambiente deve ser capaz de acionar respostas práticas para conter ou documentar o incidente, tais como:
1. **Bloqueio de IP (Firewall):** Criação automática de regras de bloqueio no firewall contra o endereço IP de origem do ataque.
2. **Execução de Scripts:** Disparo de scripts de contenção, isolamento ou remediação nos hosts.
3. **Notificações (Email / Chat):** Envio de alertas enriquecidos para canais de comunicação da equipe de segurança.
4. **Registro da Ação:** Documentação e auditoria formal da resposta executada pelo SOAR.
5. **Coleta de Evidências:** Captura automatizada de dados forenses ou estado do sistema no momento do incidente.

## 4. Topologia de Infraestrutura do Laboratório (Referência)

A especificação apresenta uma topologia de referência composta por **6 Máquinas Virtuais (VM01 a VM06)** para distribuição das funções do laboratório:

```
+---------------------------------------------------+---------------------------------------+
|             NÚCLEO DO SOC (SERVIDORES)            |      AMBIENTE MONITORADO E TESTES     |
+----------------+-----------------+----------------+------------+-------------+------------+
|      VM01      |       VM02      |      VM03      |    VM04    |     VM05    |    VM06    |
|  Wazuh Server  | Suricata + Zeek |  Shuffle SOAR  |   Linux    |   Windows   | Kali Linux |
|   (Manager +   |  (Sensores de   | (Orquestração  | (Endpoint  |  (Endpoint  | (Máquina   |
|   Indexer +    |   Rede NIDS e   |  e Automação   | Monitorado |  Monitorado | de Ataques |
|   Dashboard)   |      NSM)       |  de Resposta)  | com Agent) |  com Agent) | e Testes)  |
+----------------+-----------------+----------------+------------+-------------+------------+
```

* **VM01 - Wazuh Server:** Hospeda a stack central do SIEM (*Wazuh Manager + Wazuh Indexer + Wazuh Dashboard*).
* **VM02 - Suricata + Zeek:** Hospeda os sensores de monitoramento e inspeção de tráfego de rede.
* **VM03 - Shuffle SOAR:** Hospeda a plataforma de orquestração e resposta a incidentes.
* **VM04 - Linux:** Endpoint cliente/servidor Linux monitorado pelo agente HIDS.
* **VM05 - Windows:** Endpoint cliente/servidor Windows monitorado pelo agente HIDS.
* **VM06 - Kali Linux (Testes):** Máquina dedicada à execução de testes de invasão e geração de eventos para validação do pipeline completo.

## 5. Fluxo Ponta a Ponta de Funcionamento

O funcionamento integrado do laboratório segue seis fluxos principais de dados:

1. **Fluxo de Tráfego de Rede:** As comunicações entre os endpoints (VM04, VM05), servidores e a máquina de testes (VM06) passam pela rede e são capturadas via SPAN/TAP pelos sensores **Suricata / Zeek** (VM02).
2. **Fluxo de Eventos e Logs:**
   * Os agentes instalados nos endpoints **Linux e Windows** coletam logs do sistema operacional e os enviam diretamente ao **Wazuh Manager** (VM01).
   * O **Suricata** e o **Zeek** processam o tráfego de rede, geram alertas/logs em formato **JSON** (`EVE JSON` / `JSON/TSV`) e os encaminham ao **Wazuh Manager**.
3. **Fluxo de Correlação e Indexação:** O **Wazuh Manager** decodifica os logs, aplica as regras de detecção e envia os alertas gerados para o **Wazuh Indexer**, onde são armazenados e indexados.
4. **Fluxo de Visualização:** O **Wazuh Dashboard** (e opcionalmente o **Grafana**) consulta os dados do Indexer para exibir painéis de severidade, eventos por host, eventos de rede, tendências temporais e *Threat Hunting*.
5. **Fluxo de Alerta e Automação:** Diante de um alerta relevante, o **Wazuh** aciona o **Shuffle SOAR** (VM03) via Webhook/API.
6. **Fluxo de Ação de Resposta:** O **Shuffle SOAR** processa o *workflow* correspondente e dispara as ações de resposta (bloqueio de IP no firewall, execução de scripts, envio de notificações por email/chat, registro da ação e coleta de evidências).