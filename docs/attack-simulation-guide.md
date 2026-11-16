# Guia de Simulação de Ataques e Validação Ponta a Ponta

Este roteiro valida os **6 fluxos ponta a ponta** da especificação usando o container atacante **Kali Linux** (`kali-attacker`, IP `172.28.0.200`) contra o endpoint monitorado **Ubuntu + Serviços + Suricata + Wazuh Agent** (`linux-target`, IP `172.28.0.20`).

> **Segurança:** Todo o tráfego e bloqueio real (`nftables`) ocorre exclusivamente dentro da rede isolada `soclab-net` (`172.28.0.0/24`) entre containers Docker. O firewall do Windows físico permanece intacto.

---

## 1. Pré-requisitos (1-Clique)

Suba e provisione toda a infraestrutura:

```powershell
.\scripts\up.ps1
```

Confirme que o acesso do Kali para o servidor alvo está inicialmente aberto:

```powershell
.\.venv\Scripts\soclab.exe attack check
# Saída esperada: ACCESS: OPEN (HTTP 200 reachable from attacker)
```

---

## 2. Cenários de Ataque Controlados (Kali $\rightarrow$ Linux Target)

### Cenário A — Reconhecimento (Severidade LOW / MEDIUM $\rightarrow$ Ação `LOG`)
Executa ICMP ping, port scan TCP (`nmap`) e sonda HTTP com User-Agent do Nmap em `/admin`:

```powershell
.\.venv\Scripts\soclab.exe attack recon
```
* **Suricata NIDS:** dispara SIDs `910001` (`LOW`), `910002` (`MEDIUM`) e `910003` (`MEDIUM`).
* **Wazuh SIEM:** regra customizada `100103` eleva alertas Suricata de severidade 3 para nível `6`.
* **Shuffle $\rightarrow$ SOC Lab SOAR:** API responde `action=LOG` e grava em [audit.jsonl](file:///C:/Users/esdn6/Documents/SOC-SIEM/logs/audit.jsonl) sem bloquear o IP nem enviar spam de email.

### Cenário B — Ataque Web SQL Injection (Severidade HIGH $\rightarrow$ Ação `NOTIFY`)
Envia requisição HTTP simulando tentativa de `UNION SELECT`:

```powershell
.\.venv\Scripts\soclab.exe attack web
```
* **Suricata NIDS:** dispara SID `910004` (`HIGH`).
* **Wazuh SIEM:** regra `100102` (nível `10`) aciona o Shuffle.
* **Shuffle $\rightarrow$ SOC Lab SOAR:** API decide `action=NOTIFY`, coleta evidência forense em `logs/evidence/` e o Shuffle envia **email de alerta ao analista no Mailpit** (`http://127.0.0.1:8025`).

### Cenário C — Brute-Force SSH & Exploit Web Crítico (Severidade CRITICAL $\rightarrow$ Ação `BLOCK_IP`)
Executa 6 tentativas falhas de autenticação SSH + tentativa de Path Traversal (`/etc/passwd`):

```powershell
.\.venv\Scripts\soclab.exe attack ssh
```
* **Suricata NIDS:** dispara SIDs `910005` (`CRITICAL`) e `910006` (`CRITICAL`).
* **Wazuh SIEM:** regras `100101` (nível `13`) e `100110`/`100111` (nível `12`) disparam o Shuffle.
* **Shuffle $\rightarrow$ SOC Lab SOAR:** API decide **`BLOCK_IP`** para `172.28.0.200`, executa **`nft add rule inet filter input ip saddr 172.28.0.200 drop`** dentro do `linux-target`, salva a evidência em `logs/evidence/` e envia email **CRITICAL - BLOCK_IP** no Mailpit!

---

## 3. Comprovar Contenção Real, Auditoria e Rollback

1. **Comprovar que o atacante (`172.28.0.200`) foi bloqueado no firewall:**
   ```powershell
   .\.venv\Scripts\soclab.exe attack check
   # Saída esperada: ACCESS: BLOCKED (connection timed out or refused)
   ```
   *(Enquanto isso, do seu navegador no Windows físico em `http://127.0.0.1:8081`, o servidor Web continua acessível normalmente porque apenas o IP atacante foi bloqueado!)*

2. **Inspecionar a regra real aplicada no `nftables` dentro do alvo:**
   ```powershell
   docker compose --profile full exec linux-target nft list ruleset
   ```

3. **Inspecionar evidências forenses e auditoria:**
   ```powershell
   Get-Content .\logs\audit.jsonl -Tail 5
   Get-ChildItem .\logs\evidence\
   ```

4. **Visualizar tudo no Wazuh Dashboard (`https://localhost`) e Mailpit (`http://127.0.0.1:8025`):**
   * Abra **Explore $\rightarrow$ Dashboards $\rightarrow$ `Open SOC Lab - SOC Overview`**.
   * Abra **`http://127.0.0.1:8025`** para ver os emails de incidente enviados pelo Shuffle.
   * Abra **`http://localhost:3001`** (`admin` / `soclab-shuffle-admin`) $\rightarrow$ **Workflows $\rightarrow$ Executions** para ver o fluxo executado nó a nó.

5. **Desbloquear o IP atacante após a demonstração (Rollback):**
   ```powershell
   docker compose --profile full exec soclab soclab unblock 172.28.0.200
   .\.venv\Scripts\soclab.exe attack check
   # Saída esperada: ACCESS: OPEN
   ```
