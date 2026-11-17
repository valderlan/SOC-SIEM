# Guia de Uso, Operação e Comandos — Open SOC Lab (`SOC-SIEM`)

Este guia reúne todas as instruções práticas para preparar, subir, operar, reiniciar, desligar e depurar o laboratório **Open SOC Lab** no **Windows (PowerShell + WSL2 + Docker Desktop)** e no **Linux (Ubuntu/Debian)**.

---

## 1. Pré-requisitos do Ambiente

### No Windows 10 / 11
1. **Docker Desktop** instalado e em execução (com backend **WSL2** habilitado).
2. **WSL2** com uma distribuição Linux instalada (ex.: `Ubuntu-24.04` ou `Ubuntu`).
3. **Python 3.12+** e gerenciador **`uv`** (ou o ambiente virtual `.venv` já sincronizado na raiz do projeto).
4. **Git** instalado.
5. **PowerShell** (compatível tanto com Windows PowerShell 5.1 nativo quanto com PowerShell 7+).

### No Linux (Ubuntu 22.04+ / 24.04+ ou Debian)
1. **Docker Engine** e **Docker Compose v2** (`sudo apt install -y docker.io docker-compose-v2`).
2. Usuário adicionado ao grupo `docker` (`sudo usermod -aG docker $USER`).
3. **Python 3.12+**, **`uv`**, **`git`** e **`curl`**.

---

## 2. Como Subir o Ambiente do Zero (1-Clique)

### Opção A — Windows (PowerShell)
Abra o PowerShell na raiz do repositório (`SOC-SIEM`) e execute:

```powershell
# Liberar execução de scripts apenas para a sessão atual do PowerShell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# Subir e provisionar todo o laboratório com 1 clique
.\scripts\up.ps1
```

> **Dica:** se as imagens Docker já foram construídas anteriormente e você quiser subir mais rápido sem refazer `docker build`, use:
> ```powershell
> .\scripts\up.ps1 -SkipBuild
> ```

**O que o `.\scripts\up.ps1` faz sozinho (6 passos):**
1. Garante que o arquivo `.env` existe (copiando de `.env.example` se necessário e preenchendo as senhas/tokens padrão de laboratório).
2. Configura `vm.max_map_count=262144` no WSL2, clona `wazuh/wazuh-docker` (`v4.14.8`) em `infra/wazuh-docker` (se ainda não existir), gera certificados TLS e sobe o SIEM (`wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`).
3. Cria as pastas locais `runtime/suricata`, `runtime/shuffle-apps`, `runtime/shuffle-files` e `logs/evidence`.
4. Constrói e sobe os 8 serviços da Etapa 4 (`linux-target`, `soclab`, `mailpit`, `shuffle-opensearch`, `shuffle-backend`, `shuffle-frontend`, `shuffle-orborus`, `kali-attacker`).
5. Aguarda os serviços responderem nos health checks (`SOC Lab API :8080`, `Wazuh Dashboard :443`, `Shuffle Backend :5001` e `Shuffle UI :3001`).
6. Executa `soclab lab provision` (conecta `wazuh.manager` à rede `soclab-net`, aplica `local_rules.xml`, configura `<integration>` com o Shuffle, cria o workflow no Shuffle e importa os 8 objetos do Dashboard) e roda `soclab stage4 verify --quick`.

### Opção B — Linux / WSL2 (Bash)
```bash
chmod +x ./scripts/up.sh ./scripts/bootstrap_wazuh.sh
./scripts/up.sh
```

---

## 3. Como Ativar o Ambiente Python (`.venv`) no Terminal

Sempre que abrir uma nova janela do PowerShell na raiz do repositório (`SOC-SIEM`) para rodar comandos `soclab`, ative o ambiente virtual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```
*(O prompt mudará para exibir o prefixo `(open-soc-lab)` antes do `PS`.)*

Caso não queira ativar o `.venv`, você pode chamar o executável diretamente a partir da raiz do repositório:
```powershell
.\.venv\Scripts\soclab.exe <comando>
```

---

## 4. Como Reiniciar, Reprovisionar ou Desligar o Ambiente

### Cenário 1 — Você reiniciou o Windows / abriu o PC no dia seguinte
Como os containers possuem `restart: unless-stopped`, assim que o Docker Desktop iniciar eles voltam a subir sozinhos. Na raiz do repositório, ative o `.venv` e verifique:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1

# Verifica se todos os containers, integrações e dashboards estão prontos
soclab stage4 verify --quick
```
Se algum container estiver parado ou desconectado após o reboot, basta rodar:
```powershell
.\scripts\up.ps1 -SkipBuild
```

### Cenário 2 — Desbloquear o Kali e limpar o estado para uma nova bateria de testes
```powershell
# 1. Remove qualquer bloqueio de IP ativo no firewall nftables do alvo
docker compose --profile full exec soclab soclab unblock 172.28.0.200

# 2. (Opcional) Limpa o banco SQLite de deduplicação caso queira reenviar IDs manuais idênticos
soclab dedup clear

# 3. Confirma que o Kali voltou a ter acesso livre ao servidor alvo
soclab attack check
```

### Cenário 3 — Reiniciar apenas um serviço específico
```powershell
# Reiniciar apenas a API soclab e o alvo Linux
docker compose --profile full restart linux-target soclab

# Reiniciar apenas os containers do Shuffle SOAR
docker compose --profile full restart shuffle-backend shuffle-frontend shuffle-orborus

# Reaplicar regras do Wazuh, workflow do Shuffle e Dashboard
soclab lab provision
```

### Cenário 4 — Desligar todo o laboratório (liberar memória RAM e CPU)
```powershell
.\scripts\down.ps1
```
*(Encerra os 8 containers da Etapa 4, remove o container auxiliar `tenzir-node` e para os 3 containers do Wazuh single-node.)*

---

## 5. URLs, Portas e Credenciais de Acesso

| Serviço | URL de Acesso no Navegador | Usuário | Senha / Token |
|---|---|---|---|
| **Wazuh Dashboard** (SIEM + `Open SOC Lab - SOC Overview`) | `https://localhost` | `admin` | `SecretPassword` |
| **Wazuh REST API** (consumida pelo Python CLI) | `https://127.0.0.1:55000` | `wazuh-wui` | `MyS3cr37P450r.*-` (no `.env`) |
| **Shuffle SOAR UI** (Workflow visual + Debug) | `http://localhost:3001` | `admin` | `soclab-shuffle-admin` |
| **Mailpit Webmail** (Caixa de entrada de alertas do SOC) | `http://127.0.0.1:8025` | *(sem login)* | *(sem senha)* |
| **SOC Lab SOAR API** (Documentação interativa Swagger) | `http://127.0.0.1:8080/docs` | Header `X-SOCLAB-TOKEN` | `soclab-dev-token` (no `.env`) |
| **Servidor Web Alvo** (Nginx no `linux-target`) | `http://127.0.0.1:8081` | *(público)* | *(sem senha)* |

---

## 6. Referência Completa de Comandos da CLI (`soclab`)

### 6.1. Comandos Gerais e Etapa 1 (Wazuh HIDS / SIEM)
| Comando | O que faz |
|---|---|
| `soclab version` | Exibe a versão instalada do pacote (`0.1.0`). |
| `soclab config` | Exibe a configuração carregada do `.env` (mascarando senhas e tokens com `********`). |
| `soclab health` | Consulta a API do Wazuh (`:55000`) e exibe versão, manager e contagem de agentes. |
| `soclab agents` | Lista todos os agentes registrados no Wazuh (`id`, `name`, `ip`, `status`, `os`). |
| `soclab event test` | Testa um evento SSH no sandbox `/logtest` do Wazuh sem gerar alerta real. |
| `soclab event send --yes` | Envia um evento SSH de demonstração para o motor real de análise (`/events`). |
| `soclab stage1 verify [--quick] [--watch]` | Executa os 8 grupos de verificação da Etapa 1 (Docker, Wazuh, API, Agentes, Logtest, Qualidade). |

### 6.2. Comandos da Etapa 2 (Suricata NIDS)
| Comando | O que faz |
|---|---|
| `soclab nids status` | Mostra o estado, tamanho e horário de modificação do arquivo `eve.json` (usa `runtime/suricata/eve.json` automaticamente no Windows). |
| `soclab nids alerts [--limit N] [--severity S] [--src-ip IP]` | Lista alertas do Suricata filtrados por quantidade, severidade (`low`, `medium`, `high`, `critical`) ou IP. |
| `soclab nids alerts --follow` | Acompanha novos alertas do Suricata em tempo real no terminal (`Ctrl+C` para parar). |
| `soclab nids validate <arquivo>` | Valida estatísticas de linhas, JSON válido/inválido e alertas normalizados de um arquivo EVE JSON. |
| `soclab nids demo` | Executa demonstração offline da Etapa 2 usando a fixture `tests/fixtures/suricata/eve.json`. |
| `soclab stage2 verify [--quick] [--demo]` | Executa o verificador completo da Etapa 2 (ao vivo ou forçando a fixture com `--demo`). |

### 6.3. Comandos da Etapa 3 (SOAR + Política + Firewall + Deduplicação)
| Comando | O que faz |
|---|---|
| `soclab status` | Exibe o estado da camada SOAR (bind da API, modo `dry-run`/`LIVE`, adapter, redes protegidas, caminhos de auditoria/evidência, TTL e total de alertas deduplicados). |
| `soclab run [--host H] [--port P]` | Inicia o servidor FastAPI localmente (por padrão em `127.0.0.1:8080`, modo `dry-run`). |
| `soclab unblock <IP>` | Remove regras de bloqueio para o IP informado (no container: `docker compose --profile full exec soclab soclab unblock 172.28.0.200`). |
| `soclab dedup status` | Mostra o caminho do banco SQLite (`runtime/soclab_state.db`), total de IDs processados e TTL configurado. |
| `soclab dedup clear [--older-than SEGUNDOS]` | Limpa todos os registros de deduplicação (ou apenas os mais antigos que `N` segundos). |
| `soclab demo final` | Roda a demonstração completa in-process da Etapa 3 (6 cenários de política + 6 testes da API Webhook). |
| `soclab stage3 verify [--quick] [--demo]` | Executa o verificador da Etapa 3 em diretório temporário isolado (sempre em `dry-run`). |

### 6.4. Comandos da Etapa 4 (Provisionamento, Ataques Kali e Verificação Ponta a Ponta)
| Comando | O que faz |
|---|---|
| `soclab lab provision` | Conecta `wazuh.manager` à rede `soclab-net`, atualiza `local_rules.xml` e `<integration>` no Wazuh, cria/atualiza o workflow no Shuffle e importa os 8 objetos do Dashboard. |
| `soclab stage4 verify [--quick]` | Valida ponta a ponta os 8 containers, agentes Wazuh, integração Shuffle, `eve.json` ao vivo, `/ready`, Shuffle UI/Workflow, Mailpit, Dashboard e suíte `pytest`/`ruff`/`mypy`. |
| `soclab attack check` | Testa a partir do container `kali-attacker` (`172.28.0.200`) se o servidor Web do `linux-target` está acessível (`ACCESS: OPEN`) ou bloqueado pelo firewall (`ACCESS: BLOCKED`). |
| `soclab attack recon` | Dispara reconhecimento a partir do Kali: ICMP ping + port scan `nmap` (`22, 80, 8080`) + probe HTTP `/admin` (`LOW`/`MEDIUM` $\rightarrow$ `LOG`). |
| `soclab attack web` | Dispara tentativa de SQL Injection (`UNION SELECT`) contra o Nginx (`HIGH` $\rightarrow$ `NOTIFY` + evidência + e-mail Mailpit). |
| `soclab attack ssh` | Dispara 6 logins SSH com senha inválida + tentativa de Path Traversal `/etc/passwd` (`CRITICAL` $\rightarrow$ `BLOCK_IP` no `nftables` + evidência + e-mail Mailpit). |
| `soclab attack all` | Executa em sequência `recon` + `web` + `ssh`. |

### 6.5. Comandos de Qualidade e Testes Automatizados
```powershell
# Executar os 97 testes unitários
pytest --basetemp .\.pytest_tmp

# Executar linter Ruff
ruff check .

# Executar checagem estrita de tipos Mypy
mypy src
```

---

## 7. Solução de Problemas Comuns (Troubleshooting)

1. **`soclab attack check` já começa dando `ACCESS: BLOCKED`:**
   - O IP do Kali (`172.28.0.200`) ficou bloqueado de um teste anterior de `soclab attack ssh` ou `soclab attack all`.
   - **Solução:** desbloqueie com:
     ```powershell
     docker compose --profile full exec soclab soclab unblock 172.28.0.200
     ```
2. **O navegador mostra aviso de certificado ao abrir `https://localhost` (Wazuh Dashboard):**
   - Comportamento normal: o Wazuh Docker single-node utiliza certificado TLS autoassinado. Clique em **Avançado $\rightarrow$ Continuar para localhost (não seguro)**.
3. **O Wazuh Dashboard mostra `No results found` no painel `Open SOC Lab - SOC Overview`:**
   - Verifique o filtro de tempo no canto superior direito do Dashboard (mude para **`Last 1 hour`** ou **`Last 24 hours`**) e clique em **Refresh**.
4. **`soclab lab provision` avisa que os apps `http` e `email` do Shuffle ainda não carregaram:**
   - Na primeira inicialização do Shuffle, o `shuffle-backend` leva ~20–40 segundos para indexar os apps no `shuffle-opensearch`. Aguarde 20 segundos e rode `soclab lab provision` novamente.
