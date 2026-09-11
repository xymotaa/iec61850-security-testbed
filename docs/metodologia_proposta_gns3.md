# Resultados dos Testes — iec61850-security-testbed

Dados brutos coletados na campanha de testes (topologia: 4 switches em
estrela, 5 `ubuntu-ied`, `oraculo-1`, `atacante-1`, `ids-1`). Ver
`docs/metodologia.md` para o racional de cada teste.

## 1. Oráculo — conformidade IEC 62443-3-3 (5 IEDs)

Resultado **idêntico** nos 5 IEDs (192.168.10.11 a .15) — esperado, já
que todos usam a mesma imagem base (`ubuntu-ied:latest`), sem variação
de configuração entre eles. Achado em si: reflete um risco real de
ambientes OT, onde equipamentos do mesmo fabricante/modelo saem de
fábrica com configuração idêntica (uma vulnerabilidade afeta a frota
inteira).

**3 de 12 critérios conformes**, em todos os 5 IEDs:

| SR | Critério | Resultado |
|---|---|---|
| 1.1 | Ausência de credencial padrão/hardcoded | ❌ Não conforme |
| 1.3 | Comprimento mínimo da senha (minlen=8) | ✅ Conforme |
| 1.3 | Exige dígito (dcredit=0) | ❌ Não conforme |
| 1.3 | Exige maiúscula (ucredit=-1) | ✅ Conforme |
| 1.3 | Exige minúscula (lcredit=0) | ❌ Não conforme |
| 1.3 | Exige caractere especial (ocredit=0) | ❌ Não conforme |
| 1.5 | Mecanismo de expiração de senha existe | ❌ Não conforme (max_days=99999) |
| 1.7 | Troca periódica (90-180 dias) | ❌ Não conforme (max_days=99999) |
| 2.1 | Conta sem privilégios administrativos | ✅ Conforme |
| 3.1 | Integridade das mensagens GOOSE | ❌ Não conforme (sem IEC 62351-6) |
| 5.1 | Segmentação de rede (VLAN) | ❌ Não conforme (sem VLAN) |
| 7.1 | Limitação de taxa de conexões (anti-DoS) | ❌ Não conforme (MaxStartups padrão) |

## 2. Ataques GOOSE — detecção pelo `ids-1`

| Teste | Detectado? | Detalhe |
|---|---|---|
| **A — Flooding** | ✅ Sim | `FLOOD_START` a 20.5 pkts/s (limite 20); `FLOOD_END` após 9.6s, pico de 34.0 pkts/s |
| **B — Replay** | ✅ Sim | Detectado no 2º envio: `(stNum=23, sqNum=521)` idêntico ao já visto |
| **C1 — Masquerade (MAC falsificado, atacante sofisticado)** | ❌ **Não** | 0 alertas — o ataque passa despercebido |
| **C2 — Masquerade (MAC próprio, atacante ingênuo)** | ✅ Sim | `MAC mudou de 00:30:a7:01:b3:16 para de:ad:be:ef:00:99` |
| **D — Suppression** | ✅ Sim | `stNum saltou de 23 para 1023 (salto de 1000)` |

**Achado central:** 4 de 5 cenários de ataque são detectados pelo
`ids-1`. O único que passa despercebido (C1) faz isso *porque* também
falsifica o MAC de origem — evidenciando que detecção por anomalia de
endereço, sozinha, não é suficiente contra um atacante que também
falsifica a camada 2. Reforça a necessidade de proteção criptográfica
nativa (IEC 62351-6) em vez de depender só de heurísticas de rede.

## 3. Taxa de detecção (para a Seção de Resultados)

- **Taxa de detecção geral:** 4/5 (80%) dos cenários testados.
- **Taxa de detecção contra atacante "ingênuo"** (não falsifica MAC): 4/4 (100%).
- **Taxa de detecção contra atacante "sofisticado"** (falsifica MAC): 0/1 (0%).
- **Falsos positivos:** 0 (nenhum alerta disparado fora dos ataques deliberados, em nenhum dos 5 testes).
