# Shuffle -> SOC Lab (Stage 3)

Fluxo completo:

```
Suricata / Wazuh  ->  Shuffle (orquestra)  ->  POST /api/v1/alerts  ->  SOC Lab  ->  Firewall Adapter
     detecta              decide o fluxo          webhook             policy + dedup      dry-run / real
```

O SOC Lab nao fala com o firewall por conta propria: ele so responde quando o
Shuffle chama a API. Sem token correto a chamada e recusada com HTTP 401.

## 1. Subir o SOC Lab

```bash
# Local (Windows/Linux)
uv run soclab run

# ou via Docker Compose (profile full)
docker compose --profile full up -d soclab
```

Conferir:

```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/ready
```

## 2. Configurar o webhook no Shuffle

1. Crie um workflow com trigger **Webhook**.
2. Adicione o node **HTTP** apontando para `http://<soclab-host>:8080/api/v1/alerts`.
3. Metodo `POST`, header `Content-Type: application/json`.
4. Header de autenticacao usado para *validar* a chamada:

```json
{ "X-SOCLAB-TOKEN": "<valor de SOCLAB_WEBHOOK_TOKEN>" }
```

5. Use o valor **literal** do token no node (nunca em campo de log, output ou
   descricao do workflow). O SOC Lab nunca devolve nem registra o token.

## 3. Payload aceito

O body pode ser o alerta canonico do SOC Lab, o JSON de alerta do Wazuh ou um
envelope do Shuffle (`{"alert": {...}}`). Campos reconhecidos:

| Campo SOC Lab | Aliases aceitos |
|---|---|
| `alert_id` | `alertId`, `event_id`, `id` |
| `timestamp` | `time`, `@timestamp`, `date`, ISO-8601 ou epoch |
| `severity` | `level` (escala Wazuh 0-15), `risk`, `priority`, `warning`, `critical`... |
| `src_ip` | `srcip`, `source_ip`, `src_addr` |
| `dst_ip` | `dstip`, `dest_ip`, `destination_ip` |
| `signature` | `description`, `rule.description`, `message` |
| `signature_id` | `rule_id`, `rule.id`, `sid` |

Exemplo de chamada:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/alerts \
  -H "Content-Type: application/json" \
  -H "X-SOCLAB-TOKEN: $SOCLAB_WEBHOOK_TOKEN" \
  -d '{
    "alert": {
      "alert_id": "wazuh-5712-0001",
      "timestamp": "2026-01-01T12:00:00Z",
      "source": "wazuh",
      "rule": { "id": "5712", "level": 13, "description": "SSH brute force" },
      "srcip": "203.0.113.99",
      "dstip": "10.0.0.10"
    }
  }'
```

Resposta:

```json
{
  "alert_id": "wazuh-5712-0001",
  "severity": "CRITICAL",
  "action": "BLOCK_IP",
  "requested_action": "BLOCK_IP",
  "target_ip": "203.0.113.99",
  "executed": false,
  "dry_run": true,
  "duplicate": false,
  "protected": false,
  "adapter": "dry-run",
  "reason": "CRITICAL severity requires BLOCK_IP for 203.0.113.99 (dry-run: would block 203.0.113.99)"
}
```

## 4. Decisao aplicada

| Severidade | Acao |
|---|---|
| LOW / MEDIUM | `LOG` (somente auditoria) |
| HIGH | `NOTIFY` (registra para o analista; o Shuffle envia a notificacao) |
| CRITICAL | `BLOCK_IP` no IP de origem |

Salvaguardas:

- IPs em `SOCLAB_PROTECTED_NETWORKS` (loopback, link-local, RFC1918) e alertas
  sem `src_ip` nunca sao bloqueados: a acao cai para `NOTIFY` com
  `protected=true`.
- O mesmo `alert_id` so e processado uma vez (SQLite); reenvios do Shuffle
  retornam `duplicate=true` e `action=NONE`.
- Toda decisao vira uma linha em `logs/audit.jsonl`.
- `SOCLAB_RESPONSE_DRY_RUN=true` (padrao) simula o bloqueio. Com `false`, o
  adapter real roda: `nft add rule inet filter input ip saddr <ip> drop`
  (Linux) ou `New-NetFirewallRule ... -Action Block` (Windows, requer admin).

## 5. Codigos de resposta

| Codigo | Significado |
|---|---|
| 200 | alerta processado (inclusive duplicado) |
| 400 | payload nao mapeavel (sem severidade, timestamp invalido, etc.) |
| 401 | `X-SOCLAB-TOKEN` ausente ou invalido |
| 503 | `SOCLAB_WEBHOOK_TOKEN` nao configurado no servidor |

## 6. Validar o fluxo

```bash
uv run soclab status
uv run soclab stage3 verify --quick
uv run soclab demo final
```
