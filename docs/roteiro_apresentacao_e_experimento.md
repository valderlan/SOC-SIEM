# Roteiro Sugerido de Experimento e Apresentação — Open SOC Lab (`SOC-SIEM`)

Este documento é um **guia prático de apresentação ao vivo** pensado para o apresentador conduzir a demonstração do projeto ao professor/banca do início ao fim (~10 a 15 minutos), incluindo **como preparar o ambiente antes**, **o que falar em cada etapa**, **quais comandos copiar e colar**, **o que mostrar nas telas** e **qual o resultado esperado de cada ação**.

---

## 0. Checklist de Preparação (5 Minutos Antes da Apresentação)

Abra o PowerShell na raiz do repositório (`SOC-SIEM`) e execute estes comandos para deixar tudo no ponto antes de começar a falar:

```powershell
# 1. Ativar o ambiente virtual Python na raiz do repositório
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1

# 2. Garantir que todos os containers estão de pé e provisionados
.\scripts\up.ps1 -SkipBuild

# 3. Garantir que o atacante Kali (172.28.0.200) começa DESBLOQUEADO
docker compose --profile full exec soclab soclab unblock 172.28.0.200
soclab attack check
```
*(Confirme que a última linha respondeu `ACCESS: OPEN (HTTP 200 reachable from attacker)`.)*

### Deixe estas 4 abas já abertas e logadas no navegador:
1. **Aba 1 — Servidor Alvo (Nginx):** `http://127.0.0.1:8081`
2. **Aba 2 — Mailpit (Webmail do SOC):** `http://127.0.0.1:8025` *(se quiser começar com a caixa de entrada limpa, clique no ícone de lixeira "Delete all" no topo do Mailpit)*
3. **Aba 3 — Shuffle SOAR:** `http://localhost:3001` (`admin` / `soclab-shuffle-admin`) $\rightarrow$ abra o workflow **`SOC Lab - Wazuh Automated Response`**
4. **Aba 4 — Wazuh Dashboard:** `https://localhost` (`admin` / `SecretPassword`) $\rightarrow$ menu `≡` $\rightarrow$ *Explore* $\rightarrow$ *Dashboards* $\rightarrow$ **`Open SOC Lab - SOC Overview`** (ajuste o filtro de tempo no canto superior direito para **`Last 15 minutes`** ou **`Last 1 hour`**).

---

## Ato 1 — Apresentação da Arquitetura e Estado Inicial (~2 min)

### O que falar para a banca:
> *"Construímos um laboratório completo de SOC/SIEM 100% Open-Source integrando 5 camadas em containers Docker: um servidor Linux alvo rodando Nginx e OpenSSH monitorado por **Wazuh Agent (HIDS)** e **Suricata (NIDS)**; o **Wazuh SIEM** centralizando e correlacionando os logs; o **Shuffle SOAR** orquestrando a resposta; uma **API própria em FastAPI (`soclab`)** que avalia a política de segurança, protege redes internas, evita duplicatas em SQLite, coleta evidências forenses e aplica bloqueio real via `nftables` isolado dentro do container alvo; além do **Mailpit** para notificações por e-mail e um painel customizado no **Wazuh Dashboard**."*

### Comandos para rodar ao vivo:
```powershell
# Mostrar que todos os serviços, integrações e testes estão prontos
soclab stage4 verify --quick

# Mostrar que a API no container está em modo real (dry_run=False, adapter=linux-nftables)
Invoke-RestMethod -Uri http://127.0.0.1:8080/ready

# Mostrar que o atacante Kali (172.28.0.200) consegue acessar o servidor alvo normalmente
soclab attack check
```

### Resultado esperado na tela:
- `STAGE 4 STATUS: READY` (todos os itens em `PASS`);
- `status: ready`, `dry_run: False`, `adapter: linux-nftables`;
- `ACCESS: OPEN (HTTP 200 reachable from attacker)`.
- **O que mostrar no navegador:** mostre rapidamente a **Aba 1 (`http://127.0.0.1:8081`)** com o servidor Web alvo funcionando e a **Aba 3 (`http://localhost:3001`)** com os 3 nós do workflow no Shuffle (`Webhook` $\rightarrow$ `soclab_decision` $\rightarrow$ `notify_mailpit`).

---

## Ato 2 — Experimento 1: Ataque de Reconhecimento (`LOW / MEDIUM` $\rightarrow$ Ação `LOG`) (~2 min)

### O que falar para a banca:
> *"Vamos começar com o ataque mais leve a partir do container Kali Linux (`172.28.0.200`): um reconhecimento de rede com `ping` ICMP, port scan `nmap` nas portas 22, 80 e 8080 e sondagem na URL `/admin`. Pela nossa política de resposta, eventos `LOW` e `MEDIUM` devem ser apenas registrados (`LOG`) na auditoria e no SIEM, sem disparar e-mail para o analista (evitando fadiga de alertas) e sem bloquear o IP."*

### Comandos para rodar ao vivo:
```powershell
# 1. Disparar reconhecimento a partir do Kali
soclab attack recon

# 2. Aguardar 5 segundos para o pipeline processar
Start-Sleep -Seconds 5

# 3. Mostrar os alertas capturados pelo Suricata NIDS
soclab nids alerts --limit 5

# 4. Mostrar a decisão tomada pela API FastAPI na auditoria
Get-Content .\logs\audit.jsonl -Tail 3

# 5. Provar que o atacante continua NÃO bloqueado
soclab attack check
```

### Resultado esperado na tela:
- Na tabela `Open SOC Lab - NIDS Alerts`: aparecem os alertas `LOW` (`SOCLAB NIDS ICMP Recon Probe`) e `MEDIUM` (`Suspicious Admin Path Discovery` e `Nmap HTTP Scanner User-Agent`).
- No `logs\audit.jsonl`: aparecem registros com `"severity": "MEDIUM"`, **`"action": "LOG"`**, `"executed": false` e `"evidence_path": null`.
- No `soclab attack check`: continua **`ACCESS: OPEN`**.
- **O que mostrar no navegador:** mostre a **Aba 2 (Mailpit)** vazia/sem e-mail novo, provando que alertas `LOW/MEDIUM` não geram spam para a equipe.

---

## Ato 3 — Experimento 2: Ataque Web SQL Injection (`HIGH` $\rightarrow$ `NOTIFY` + Evidência + E-mail) (~3 min)

### O que falar para a banca:
> *"Agora vamos subir para um ataque de severidade `HIGH`: uma tentativa de SQL Injection (`UNION SELECT`) contra o Nginx. Aqui veremos duas coisas interessantes: primeiro, **defesa em profundidade** — tanto o sensor de rede **Suricata (NIDS)** quanto o leitor de logs do Nginx no **Wazuh Agent (HIDS)** detectam o ataque; segundo, a política para `HIGH` decide **`NOTIFY`**: ela ainda não bloqueia o IP no firewall, mas **captura automaticamente um arquivo JSON de evidência forense** e o Shuffle **envia um e-mail de alerta** para a caixa do analista."*

### Comandos para rodar ao vivo:
```powershell
# 1. Disparar ataque de SQL Injection contra o servidor Web
soclab attack web

# 2. Aguardar 8 segundos para o envio SMTP ao Mailpit
Start-Sleep -Seconds 8

# 3. Mostrar o alerta HIGH no Suricata
soclab nids alerts --limit 3 --severity high

# 4. Mostrar a decisão NOTIFY e o caminho da evidência no audit.jsonl
Get-Content .\logs\audit.jsonl -Tail 3

# 5. Confirmar que em HIGH o IP ainda não é bloqueado no firewall
soclab attack check
```

### Resultado esperado na tela:
- Na tabela do Suricata: `HIGH | 172.28.0.200 -> 172.28.0.20 | SOCLAB NIDS SQL Injection Attempt`.
- No `logs\audit.jsonl`: `"severity": "HIGH"`, **`"action": "NOTIFY"`**, `"executed": false` e `"evidence_path": "/app/logs/evidence/<id>.json"`.
- No `soclab attack check`: continua **`ACCESS: OPEN`**.
- **O que mostrar no navegador:** vá na **Aba 2 (Mailpit — `http://127.0.0.1:8025`)** e clique no e-mail **`[SOC Lab] HIGH - NOTIFY (172.28.0.200)`** que acabou de chegar, mostrando o ID do alerta, a ação `NOTIFY` e o caminho da evidência.

---

## Ato 4 — Experimento 3: Brute-Force SSH & Exploit Crítico (`CRITICAL` $\rightarrow$ `BLOCK_IP` Real no `nftables`) (~4 min)

### O que falar para a banca:
> *"Por fim, vamos disparar o cenário `CRITICAL`: 6 tentativas seguidas de brute-force no SSH somadas a uma tentativa de Path Traversal tentando ler `/etc/passwd`. O Wazuh correlaciona e eleva para nível 13 (`CRITICAL`), aciona o Shuffle, que chama a nossa API FastAPI. A API verifica que o IP `172.28.0.200` não pertence às redes administrativas protegidas e aplica o **bloqueio real no firewall Linux (`nftables`)** dentro do container alvo, além de salvar a evidência forense e enviar o e-mail crítico."*

### Comandos para rodar ao vivo:
```powershell
# 1. Disparar Brute-Force SSH + Path Traversal /etc/passwd (CRITICAL)
soclab attack ssh

# 2. Aguardar 10 segundos para o ciclo completo + bloqueio no firewall
Start-Sleep -Seconds 10

# 3. Tentar acessar o servidor a partir do Kali -> AGORA DEVE DAR BLOCKED!
soclab attack check

# 4. Mostrar a regra real gravada no firewall nftables dentro do container alvo
docker compose --profile full exec linux-target nft list chain inet filter input

# 5. Abrir o arquivo JSON de evidência forense capturado automaticamente
$ultimo = Get-ChildItem .\logs\evidence\ | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content $ultimo.FullName
```

### Resultado esperado na tela:
- O comando `soclab attack check` falha por timeout: **`ACCESS: BLOCKED (connection timed out or refused)`**!
- O comando `nft list chain` exibe na tela a regra ativa: **`ip saddr 172.28.0.200 drop`**.
- O `Get-Content $ultimo.FullName` mostra o JSON forense completo (dados de pacote/fluxo Suricata, regra Wazuh nível `13`, agente `001` e resposta `action: BLOCK_IP`, `executed: true`).
- **O que mostrar no navegador (Momento-chave da apresentação!):**
  1. Vá na **Aba 1 (`http://127.0.0.1:8081`)** e dê **F5 / Recarregar**: mostre que **do seu computador a página continua abrindo normalmente**, provando que o firewall bloqueou **exclusivamente o IP do atacante (`172.28.0.200`)** sem tirar o serviço do ar para usuários legítimos!
  2. Vá na **Aba 2 (Mailpit — `http://127.0.0.1:8025`)** e mostre o novo e-mail **`[SOC Lab] CRITICAL - BLOCK_IP (172.28.0.200)`** com **`Executed: True`**.

---

## Ato 5 — Visualização no Shuffle, Wazuh Dashboard e Desbloqueio Final (~3 min)

### O que mostrar no navegador:
1. **Aba 3 — Shuffle SOAR (`http://localhost:3001`):**
   - Clique na aba **`Debug`** no topo central do workflow para mostrar a lista de execuções (`FINISHED`) e clique em uma delas para exibir o JSON recebido do Wazuh e a resposta devolvida pelo nó `soclab_decision`.
2. **Aba 4 — Wazuh Dashboard (`https://localhost` $\rightarrow$ `Open SOC Lab - SOC Overview`):**
   - Clique no botão **Refresh** no canto superior direito.
   - Aponte os **6 gráficos e a tabela de Threat Hunting**:
     - Contagem total de alertas e gráfico donut por severidade;
     - Gráfico de barras por Host/Agente e Decoder (`json`, `web-accesslog`, `sshd`);
     - Linha do tempo mostrando o pico dos ataques;
     - Tabela **Anomalias de Rede (Suricata NIDS)** com todas as assinaturas disparadas por `172.28.0.200`;
     - Tabela **Respostas Automatizadas do SOAR** mostrando que o `logs/audit.jsonl` foi reingerido pelo Wazuh (`regras 100150 e 100151`) exibindo `LOG`, `NOTIFY` e `BLOCK_IP` (`executed: true`) dentro do próprio SIEM!

### Comandos finais no terminal (Rollback / Desbloqueio ao vivo):
> *"Para encerrar, demonstramos o procedimento operacional de rollback/desbloqueio quando o analista encerra o incidente:"*

```powershell
# 1. Remover o bloqueio do IP 172.28.0.200 no nftables via CLI
docker compose --profile full exec soclab soclab unblock 172.28.0.200

# 2. Mostrar que a chain do nftables voltou a ficar limpa
docker compose --profile full exec linux-target nft list chain inet filter input

# 3. Confirmar que a comunicação a partir do Kali voltou para ACCESS: OPEN
soclab attack check
```

### Resultado esperado para fechar a apresentação:
- Tabela `Open SOC Lab - Firewall unblock` mostrando `Executed: YES` e `removed ... block rule(s) for 172.28.0.200`;
- Chain `input` sem regras `drop`;
- `soclab attack check` retornando **`ACCESS: OPEN (HTTP 200 reachable from attacker)`**.
