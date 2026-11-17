# Relatório da Etapa 2 — NIDS com Suricata e Integração SIEM

**Projeto:** `SOC-SIEM` (`open-soc-lab`)  
**Escopo da Etapa 2:** Incorporação de monitoramento e detecção de intrusão em rede (**NIDS**) com **Suricata**, processamento em streaming de logs **EVE JSON**, normalização para um modelo canônico (`SecurityAlert`), integração com o Wazuh Agent para envio ao SIEM e verificação automatizada (`soclab stage2 verify`) com suporte tanto a sensor ao vivo quanto a modo demonstração (`--demo`).

---

## 1. Objetivos Alcançados na Etapa 2

1. **Coleta em Streaming e Tolerância a Falhas (`SuricataEveCollector`):**
   - Leitura linha a linha de arquivos `eve.json` sem carregar o arquivo inteiro em memória (`iter_records`), além de acompanhamento em tempo real estilo `tail -f` (`follow_records` lidando com linhas parciais ainda em escrita).
   - Linhas com JSON corrompido ou schema inválido são registradas e contabilizadas (`invalid_json`, `invalid_alert_payloads`) sem interromper o processamento dos demais eventos.
2. **Modelo Canônico de Alerta (`SecurityAlert`) e Normalização de Severidade:**
   - Contrato agnóstico à fonte ([`src/soclab/domain/alert.py`](../../src/soclab/domain/alert.py)) com validação de endereços IPv4/IPv6 (`IPvAnyAddress`), portas (`0–65535`), timestamps *timezone-aware* e preservação do evento bruto (`raw`).
   - Mapeamento determinístico da prioridade numérica do Suricata para a escala interna `AlertSeverity`:
     - `1` $\rightarrow$ `CRITICAL`
     - `2` $\rightarrow$ `HIGH`
     - `3` $\rightarrow$ `MEDIUM`
     - `>= 4` ou ausente $\rightarrow$ `LOW`
   - Geração de identificador determinístico `suricata-<sha1>` para alertas que não possuem ID próprio.
3. **Resolução Automática do `eve.json` Ao Vivo e Integração com o Wazuh Agent:**
   - Função `resolve_eve_path()` ([`src/soclab/services/nids.py`](../../src/soclab/services/nids.py)) que detecta automaticamente o arquivo ao vivo exposto pelo container (`runtime/suricata/eve.json`) quando o caminho padrão `/var/log/suricata/eve.json` não existe no host Windows.
   - Scripts de instalação do Suricata e configuração idempotente do bloco `<localfile><log_format>json</log_format><location>/var/log/suricata/eve.json</location></localfile>` no `ossec.conf` do Wazuh Agent, com backup automático e validação sintática XML.

---

## 2. Arquivos Criados e Modificados na Etapa 2

| Arquivo (relativo à raiz do repositório) | Responsabilidade Técnica |
|---|---|
| [`src/soclab/domain/alert.py`](../../src/soclab/domain/alert.py) | Define o enum `AlertSeverity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) e o modelo Pydantic `SecurityAlert`. |
| [`src/soclab/collectors/suricata.py`](../../src/soclab/collectors/suricata.py) | Modelos `SuricataAlertData`, `SuricataEvent`, dataclass `EveRecord` e coletor em streaming `SuricataEveCollector` (`iter_records`, `follow_records`). |
| [`src/soclab/normalizers/suricata.py`](../../src/soclab/normalizers/suricata.py) | `normalize_suricata_severity()` e `normalize_suricata_alert()`. |
| [`src/soclab/services/nids.py`](../../src/soclab/services/nids.py) | `NidsService`, `NidsStatus`, `AlertFilters`, `EveValidationSummary`, `WazuhIntegrationStatus`, `resolve_eve_path()`, `parse_ip_filter()` e `format_size()`. |
| [`src/soclab/services/stage2_verification.py`](../../src/soclab/services/stage2_verification.py) | `Stage2VerificationService` e `Stage2VerificationReport`: valida o stack Wazuh, a fonte `eve.json` (real ou fixture `--demo`), o parsing/normalização, a integração Suricata $\rightarrow$ Wazuh e as ferramentas de qualidade. |
| [`scripts/linux/install_suricata.sh`](../../scripts/linux/install_suricata.sh) | Instala e configura o pacote `suricata` em distribuições Debian/Ubuntu ajustando a interface `af-packet` e a saída `eve-log`. |
| [`scripts/linux/configure_suricata_wazuh.sh`](../../scripts/linux/configure_suricata_wazuh.sh) | Insere o bloco `<localfile>` para `eve.json` no `ossec.conf` do Wazuh Agent, valida o XML com Python e preserva permissões/ACLs. |
| [`tests/fixtures/suricata/eve.json`](../../tests/fixtures/suricata/eve.json) | Dataset controlado com 10 linhas (incluindo eventos `alert` de todas as severidades, eventos `dns`/`flow`/`stats` ignorados e 1 linha propositalmente inválida para testar resiliência). |
| [`tests/unit/test_nids.py`](../../tests/unit/test_nids.py) e [`tests/unit/test_stage2_verification.py`](../../tests/unit/test_stage2_verification.py) | Testes unitários de streaming, tolerância a erro de schema/JSON, filtros por severidade/IP, resolução de caminho ao vivo e verificador da Etapa 2. |

---

## 3. Fluxo de Funcionamento da Etapa 2

```text
[Tráfego de Rede na Interface Monitorada (eth0)]
                      │
                      ▼
             [Suricata NIDS]
                      │  grava JSON por linha
                      ▼
       [/var/log/suricata/eve.json]  (espelhado em runtime/suricata/eve.json)
            │                        │
            ▼                        ▼
  [CLI Python: soclab nids]   [Wazuh Agent (localfile json)]
  ├── status / validate              │
  ├── alerts (--severity, --src-ip)  ▼
  └── alerts --follow         [Wazuh Manager -> Indexer -> Dashboard]
```

---

## 4. Comandos de Validação da Etapa 2

```powershell
# Verificar status do arquivo EVE JSON (usa automaticamente runtime/suricata/eve.json no host)
soclab nids status

# Listar os últimos alertas capturados pelo Suricata (com filtro opcional de severidade/IP)
soclab nids alerts --limit 10
soclab nids alerts --severity high

# Acompanhar alertas de rede em tempo real
soclab nids alerts --follow

# Validar a fixture de demonstração (ou o arquivo ao vivo)
soclab nids validate tests/fixtures/suricata/eve.json
soclab nids demo

# Executar o verificador da Etapa 2 (ao vivo ou em modo --demo)
soclab stage2 verify --quick
soclab stage2 verify --quick --demo
```
