# Demo - Stage 2 (NIDS com Suricata)

## Objetivo

Demonstrar a Etapa 2 do projeto com foco em pipeline de rede:

Network -> Suricata -> eve.json -> Python (soclab) -> Wazuh Dashboard

## Roteiro principal

1. Validar Etapa 1 rapidamente

```bash
uv run soclab stage1 verify --quick
```

2. Verificar status NIDS

```bash
uv run soclab nids status
```

3. Rodar demo local da Etapa 2 (sem Suricata real)

```bash
uv run soclab nids demo
```

4. Rodar verificador principal da Etapa 2 em modo demo

```bash
uv run soclab stage2 verify --demo
```

Resultado esperado:

STAGE 2 STATUS: READY FOR DEMO

5. Se Suricata real estiver disponivel, acompanhar alerts em tempo real

```bash
uv run soclab nids alerts --follow
```

6. Gerar trafego de laboratorio seguro e controlado

- Use apenas trafego benigno e regras de teste.
- Nao execute tecnicas ofensivas reais.

7. Validar evento no EVE

```bash
tail -f /var/log/suricata/eve.json
```

8. Confirmar chegada no Dashboard Wazuh

- Abra `https://localhost`.
- Consulte o indice `wazuh-alerts-*`.

## Modo demo (Windows/Linux)

Quando nao houver Suricata real, utilize:

```bash
uv run soclab nids demo
uv run soclab stage2 verify --quick --demo
```

## Copiar e colar (outras maquinas)

Use este bloco quando o `ossec.conf` for restaurado/sobrescrito e voce quiser reaplicar tudo sem ajuste manual:

1. Configurar integracao sem reinicio

```bash
sudo ./scripts/linux/configure_suricata_wazuh.sh /var/ossec/etc/ossec.conf /var/log/suricata/eve.json --no-restart
```

2. Se quiser forcar usuario de leitura

```bash
sudo SOCLAB_OSSEC_READ_USER=$USER ./scripts/linux/configure_suricata_wazuh.sh /var/ossec/etc/ossec.conf /var/log/suricata/eve.json --no-restart
```

3. Validar

```bash
uv run soclab nids wazuh-status --ossec-conf /var/ossec/etc/ossec.conf
uv run soclab stage2 verify
```

## Observacoes

- A demo usa fixture local em `tests/fixtures/suricata/eve.json`.
- O parser processa o arquivo em streaming (linha a linha).
- JSON invalido e tratado como warning e nao interrompe o fluxo.
