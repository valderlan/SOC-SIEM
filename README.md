# Open SOC Lab - Etapa 1

## O que a Etapa 1 faz

A Etapa 1 integra uma aplicacao Python com o Wazuh para demonstracao de SOC/SIEM.

Ela permite:

- validar conectividade com a API do Wazuh;
- listar agentes Linux/Windows;
- testar regras/decoder com `logtest` sem gerar alerta real;
- enviar um evento de demonstracao controlado;
- executar uma verificacao completa em um comando unico.

## Requisitos (Windows e Ubuntu)

- Python 3.12
- uv
- Docker + Docker Compose v2
- Git

### Windows

- Windows 10/11
- PowerShell
- Docker Desktop
- WSL2 + Ubuntu

### Ubuntu Linux

- Ubuntu 22.04+ (ou Debian compatível)
- Docker Engine ativo

## Instalacao e preparo

### 0) Instalar Docker no Ubuntu Linux

No Ubuntu 24.04+ (Noble), instale Docker e Compose v2 com:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

Depois, encerre a sessao e entre novamente (ou rode `newgrp docker`) para aplicar o grupo.

Valide a instalacao:

```bash
docker --version
docker compose version
```

### 1) Instalar dependencias Python

```bash
uv sync
```

### 2) Subir infraestrutura Wazuh

#### Windows (PowerShell)

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
.\scripts\bootstrap_wazuh.ps1
```

#### Ubuntu Linux (bash)

```bash
chmod +x ./scripts/bootstrap_wazuh.sh
./scripts/bootstrap_wazuh.sh infra/wazuh-docker
```

### 3) Configurar variaveis do projeto

#### Windows (PowerShell)

```powershell
Copy-Item .env.example .env
```

#### Ubuntu Linux (bash)

```bash
cp .env.example .env
```

Edite o arquivo `.env` com os dados da API:

```dotenv
SOCLAB_WAZUH_URL=https://127.0.0.1:55000
SOCLAB_WAZUH_USERNAME=wazuh-wui
SOCLAB_WAZUH_PASSWORD=<sua-senha-da-api>
SOCLAB_WAZUH_VERIFY_TLS=false
SOCLAB_HTTP_TIMEOUT_SECONDS=10
SOCLAB_MAX_AGENTS=500
```

## Solucao de erros comuns no Linux (Ubuntu)

### Erro: `E: Impossivel encontrar o pacote docker-compose-plugin`

No Ubuntu 24.04, o pacote correto e `docker-compose-v2`.

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2
```

### Erro: `permission denied while trying to connect to docker.sock`

Seu usuario ainda nao aplicou o grupo `docker` na sessao atual.

```bash
sudo usermod -aG docker $USER
```

Depois aplique uma das opcoes:

1. logout/login completo (recomendado)
2. abrir um novo terminal apos login
3. usar comando temporario na sessao atual:

```bash
sg docker -c 'docker ps'
```

Validacao:

```bash
id -nG
getent group docker
docker ps
```

### Erro: `Docker engine is not running`

```bash
sudo systemctl enable --now docker
systemctl is-active docker
```

O status esperado e `active`.

### Erro: `Wazuh infrastructure not found in infra/wazuh-docker/single-node`

Execute o bootstrap para baixar e subir o stack oficial:

```bash
chmod +x ./scripts/bootstrap_wazuh.sh
./scripts/bootstrap_wazuh.sh infra/wazuh-docker
```

Validacao:

```bash
cd infra/wazuh-docker/single-node && docker compose ps
```

### Erro: Ruff acusando violacoes dentro de `infra/wazuh-docker`

Essa pasta e codigo de terceiro (stack oficial Wazuh). O projeto foi ajustado para o Ruff ignorar esse diretorio. Se voce estiver em uma versao antiga do repositorio, atualize e rode:

```bash
uv sync
uv run ruff check .
```

### Check final recomendado

```bash
uv run soclab stage1 verify --ensure-agent --agent-manager 127.0.0.1 --yes
```

## Comando principal para executar a Etapa 1

Use este comando para validar todo o ambiente:

```bash
uv run soclab stage1 verify
```

Modo continuo (watch):

```bash
uv run soclab stage1 verify --watch
```

Com intervalo customizado (ex.: 30s):

```bash
uv run soclab stage1 verify --watch --interval 30
```

Verificar e tentar instalar agente local automaticamente quando nao houver endpoint real:

```bash
uv run soclab stage1 verify --ensure-agent --agent-manager 127.0.0.1
```

Com nome customizado para o agente:

```bash
uv run soclab stage1 verify --ensure-agent --agent-manager 127.0.0.1 --agent-name lab-endpoint
```

Comando completo (verifica, instala agente se necessario e monitora continuamente):

```bash
uv run soclab stage1 verify --watch --interval 30 --ensure-agent --agent-manager 127.0.0.1 --agent-name lab-endpoint --yes --verbose
```

Esse comando:

- verifica a Etapa 1 em loop;
- se nao houver endpoint real (alem do `000`), tenta instalar o agente local;
- continua monitorando e atualizando o status a cada 30 segundos.

Gerar atividade real para validar alerta no Dashboard:

```bash
uv run soclab event send --yes
```

Depois abra o Dashboard em `Explore > Discover` e busque por `soclab-demo` ou `198.51.100.23` no indice `wazuh-alerts-*`.

Se o agente aparecer como `never_connected` em `uv run soclab agents`, ele foi registrado, mas ainda nao enviou telemetria.

No Windows (PowerShell como Administrador), rode:

```powershell
Restart-Service wazuhsvc
Get-Service wazuhsvc | Format-Table Status,Name,DisplayName -AutoSize
```

Depois valide novamente:

```bash
uv run soclab agents
uv run soclab stage1 verify --quick
```

No Dashboard, abra a tela de Endpoints e revise o filtro de status. Se o filtro estiver apenas em Active, um agente `never_connected` nao aparece na lista.

Observacao:

- no Windows, o script de instalacao exige PowerShell como Administrador;
- no Linux, a instalacao usa `sudo`.

## Como acessar o Dashboard do Wazuh

- URL: `https://localhost`
- Usuario padrao (stack oficial v4.14.8): `admin`
- Senha padrao (stack oficial v4.14.8): `SecretPassword`

Observacao importante:

- Dashboard e API podem usar credenciais diferentes.
- A API usada pela aplicacao Python fica em `https://127.0.0.1:55000`.

Se voce abrir `https://127.0.0.1:55000` no navegador e vir `Unauthorized`, isso esta correto:

- essa URL e da API (nao e o Dashboard);
- para interface grafica, use `https://localhost`.

Para garantir que o Dashboard esteja de pe:

```powershell
.\scripts\wazuh_status.ps1
```

ou no Linux:

```bash
cd infra/wazuh-docker/single-node && docker compose ps
```

## Comandos uteis da aplicacao

```bash
uv run soclab config
uv run soclab health
uv run soclab agents
uv run soclab event test
uv run soclab event send
```

## Resumo da Etapa 1 (implementado e testado)

Nesta etapa, ja foi implementado e validado em ambiente local:

- infraestrutura Wazuh em Docker (manager, indexer e dashboard) com status operacional;
- integracao da aplicacao Python com a API do Wazuh (autenticacao e chamadas principais);
- comando unificado `uv run soclab stage1 verify` com modos `--quick`, `--watch` e `--interval`;
- verificacao opcional com envio de evento real (`--send-event`) e confirmacao automatica (`--yes`);
- deteccao de agentes reais ignorando o agente interno `000` para criterio de prontidao;
- instalacao automatica opcional de agente local quando nao ha endpoint real (`--ensure-agent`);
- endpoint Windows registrado e ativo no Dashboard para demonstracao da disciplina;
- teste de atividade real com `uv run soclab event send --yes` e evidencias no indice `wazuh-alerts-*`;
- testes unitarios para config, CLI, cliente Wazuh e fluxo de verificacao Stage 1.

## Secao 2 - Proximas etapas (futuro)

### Etapa 2 - Monitoramento da rede com Suricata

Na Etapa 2, o projeto vai incorporar o Suricata como NIDS para ampliar a visibilidade do laboratorio com eventos de rede. O sistema passara a processar arquivos `eve.json` na aplicacao Python, fazendo validacao, normalizacao e filtragem de alertas por severidade/IP, com exibicao no terminal e demos controladas sem necessidade de ataques reais, integrando essa telemetria ao fluxo ja existente com Wazuh e Dashboard.

---

### Etapa 3 - Automacao e resposta com Shuffle

Na Etapa 3, o foco sera adicionar SOAR com Shuffle e uma API Python (FastAPI) para transformar deteccao em resposta automatizada por politica (log, notificacao, bloqueio de IP ou nenhuma acao). A execucao inicial sera em modo `dry-run` para demonstrar decisoes sem alterar firewall, com suporte multiplataforma via adapters de Windows/Linux e trilha de auditoria em `logs/audit.jsonl` para rastreabilidade das acoes.

---

## Visao geral das tres etapas

| Etapa | O que adiciona | Principal tecnologia | Resultado |
|---|---|---|---|
| **1** | Monitoramento dos endpoints | Wazuh | HIDS + SIEM |
| **2** | Monitoramento da rede | Suricata | NIDS + SIEM |
| **3** | Automacao e resposta | Shuffle + FastAPI | SOAR + Response |
