# Conteúdo da apresentação — 5º Marco (23/11/2026, resultados finais)

Texto pronto para os slides e a demo. **Só entram fatos validados**; cada bloco
indica o arquivo que o sustenta. Números completos: [`docs/resultados.md`](../docs/resultados.md).

Regra de ouro para a fala: dizer sempre o que é **simulação** (HMAC estilo
IEC 62351-6, campanha offline) e o que é **real** (802.1X EAP-TLS, GNS3).

---

## Capa

**Título:** Analisador Automático de Segurança Cibernética para o Setor Elétrico — Reprodução e Extensão

**Subtítulo:** 5º Marco — Autenticação de dispositivo (IEEE 802.1X EAP-TLS), autenticação de mensagem (HMAC simulado) e Validação no GNS3

Disciplina: Segurança em Redes de Computadores — Prof. Dr. Hugo Kuribayashi
Artigo original: Oliveira & Gurjão (UFCG), SBSeg 2025 — WTICG
Lucas Mota · Matheus · Youri — Unifesspa
23 de novembro de 2026

---

## Recapitulação (30 segundos)

- Oráculo: **3 de 12 critérios conformes** nos 5 IEDs (frota homogênea).
- 4 ataques GOOSE (flood, replay, masquerade, suppression) e IDS próprio.
- Achado central do 4º Marco: **masquerade C1** (MAC clonado, `stNum+1`, `sqNum=0`)
  **não é detectável** por inspeção passiva — 0% de detecção.
- Pergunta do 5º Marco: **o que realmente barra o C1?**

---

## Bloco 1 — HMAC estilo IEC 62351-6 (SIMULAÇÃO)

> **Dizer explicitamente:** é uma simulação da *ideia* da IEC 62351-6, **não** uma
> implementação conforme.

- HMAC-SHA256 por frame sobre `gocbRef`, `stNum`, `sqNum`, `t` e `allData`, num
  trailer após o APDU; chave por `gocbRef` derivada de uma chave-mestra de teste.
- Opt-in: `ids.py --auth` (IDS verifica); `goose_attack.py --leaked-key-env VAR`
  (atacante assina com a chave "vazada"). Sem as flags, nada muda.
- Limites assumidos: sem distribuição/rotação de chaves; trailer de codificação
  arbitrária; **não impede replay** (frame reenviado mantém HMAC válido).
- Arquivos: `ids/goose_auth.py`, `atacante/goose_auth.py`.

---

## Bloco 2 — Benchmark offline (SIMULAÇÃO, sem GNS3)

Campanha **reproduzida** em `benchmark/`: N = 100 por cenário, 6 cenários,
3 modos = 1800 repetições, semente 61850, IC95% de Wilson.

> A campanha N=600 do 4º Marco teve o script **nunca versionado**; esta é uma
> reconstrução a partir da tabela. As **detecções coincidem**; as **latências não
> são comparáveis**.

| Cenário | Sem HMAC | HMAC, atacante sem chave | HMAC, chave vazada |
|---|---|---|---|
| T0 baseline (FPR) | 0/100 | 0/100 | 0/100 |
| A flooding | 100/100 | 100/100 | 100/100 |
| B replay | 100/100 | 100/100 | 100/100 |
| **C1 masquerade (MAC clonado)** | **0/100** | **100/100** (`auth_fail`) | **0/100** |
| C2 masquerade (MAC distinto) | 100/100 | 100/100 | 100/100 |
| D suppression | 100/100 | 100/100 | 100/100 |

IC95% de Wilson: 0/100 = [0,0%; 3,7%]; 100/100 = [96,3%; 100,0%].

**Mensagens:**

- HMAC **resolve o C1 contra quem não tem a chave** (0% para 100%).
- **Com a chave vazada, o C1 volta a ser indetectável.**
- Replay continua sendo pego só por `(stNum, sqNum)`.
- Taxas 0%/100% por construção (frames determinísticos); o IC quantifica a
  incerteza, não é desvio de repetições independentes.

**Sensibilidade do limiar de flooding** (limiar padrão 20 pps): TPR é um degrau.
0% até 18 pps, 82% a 20 pps, 100% a partir de 22 pps. Ataques *low-and-slow*
abaixo do limiar passam. FPR: rajadas legítimas de até 15 pps = 0%; a 20 pps = 73%.
Limiar 80 não dá falso positivo até 60 pps, mas só pega ataque acima de ~80 pps.
(Rajadas legítimas de 5–60 pps são carga **sintética assumida**.)

**Custo do HMAC (ordem de grandeza):** `verify` ~11–13 µs por chamada (mediana
11,5 µs); ~11–21 µs por frame na campanha. Python, CPU de notebook, desvio alto —
**não é o custo num IED real**. Latência do IDS por frame ~5–12 µs, três ordens
de grandeza abaixo do limite de 4000 µs.

Arquivos: `benchmark/resultados/resumo.md`, `benchmark/figuras/`.

---

## Bloco 3 — IEEE 802.1X com EAP-TLS (REAL)

> Aqui **não é simulação**: `hostapd` 2.10 (driver `wired`) fala EAPOL de verdade
> com o `wpa_supplicant`; o encaminhamento é do `nftables` (família `bridge`).

- Nó `autenticador-8021x`: nenhum dispositivo troca tráfego antes de provar
  identidade com **certificado X.509** (autenticação mútua).
- Certificado **vinculado ao MAC** (inventário CN → MAC, gerado do SCD): certificado
  válido em MAC de outro dono é rejeitado (`mac_divergente`).
- Depois de autenticado, o par (porta, MAC) é fixo: MAC forjado é descartado.
- CRL: certificado revogado é barrado (`certificado_revogado`).
- PKI de **laboratório** (`pki/gerar_pki.sh`); supplicant embutido nas 4 imagens
  (`AUTH_8021X=1`, desligado por padrão).

**Validação em `netns`** (`teste_netns.sh`): **11 execuções** em 20/11/2026,
**10 sem falha** (8 com 30 verificações, 2 com 29) e **1 com 2 falhas** (28 passaram, 2 falharam; etapa de
reautenticação após queda de link; causa não investigada). Imagens reais: 4/4
autenticam (`teste_imagens_clientes.sh`, 0 falhas).

---

## Bloco 4 — Validação no GNS3 real (20/11/2026)

GNS3 2.2.61, projeto `subestacao_8021x` (gerado por `--8021x`), 7 nós ligados
direto ao autenticador. **1 execução por cenário.**

| Cenário | Quem barra | Resultado |
|---|---|---|
| Base | — | 5 `auth_aceita`; nenhum para o atacante; `ping` ied-1→ied-2 3/3 |
| E0 — sem 802.1X | nada | `ping` 3/3; **C1 sem alerta no IDS** |
| E1 — sem certificado, MAC clonado | 802.1X (nftables) | `ping` 0/3; quadros descartados; IDS nem vê |
| E2 — certificado revogado | 802.1X (TLS + CRL) | `auth_rejeitada` `certificado_revogado` |
| E3 — certificado de outro nó, MAC do IED | 802.1X (vínculo CN↔MAC) | `mac_divergente`; `ping` 0/3 |
| E4 — certificado válido, MAC próprio | IDS (heurística de MAC) | autentica; alerta `MASQUERADE` |
| E4b — certificado válido, MAC do publicador | 802.1X (par porta+MAC) | 5 pacotes descartados (1760 bytes) |
| E5 (i) — sem chave HMAC | IDS `--auth` | `AUTH_FAIL` |
| E5 (ii) — chave vazada, MAC próprio | IDS (heurística de MAC) | `MASQUERADE` |
| E5 (iii) — chave vazada, MAC do publicador | 802.1X (par porta+MAC) | 5 pacotes descartados (1930 bytes) |

**Leitura:** o 802.1X barra o atacante **sem credencial** e o **clone de MAC** — o
mesmo C1 que o IDS não via. Mas **autentica o dispositivo, não a mensagem**: nó com
certificado válido e MAC próprio publica GOOSE forjado (E4). Por isso a
**defesa em profundidade**: 802.1X + HMAC + IDS.

Evidências: `autenticador-8021x/evidencias/gns3/`.

---

## Bloco 5 — Geração automática de topologia (resumo)

- `extrair_scd.py` + `gerar_topologia_gns3.py` fecham o fluxo extração → modelagem → GNS3
  (Fig. 1 do artigo), validados no GNS3 com SCD **real** (`simpleIO`, libiec61850,
  1 IED) no 4º Marco e com a variante `--8021x` (7 nós) em 20/11/2026.
- Variante `--8021x`: sem switches nativos; MAC fixo por nó; grava `inventario.json`.

---

## Bloco 6 — Limitações

- **Campanha offline**: sem rede, switch, IED real; latência em Python.
- **HMAC**: simulação; com a chave vazada, C1 volta; não impede replay.
- **802.1X**: autentica dispositivo, não mensagem; janela de reautenticação;
  PKI de laboratório.
- **GNS3**: 1 execução por cenário; **sem medição de overhead de autenticação**;
  revogação em operação (E2b) só em `netns`.
- IEDs são hosts genéricos (não relés reais); SCD real tem só 1 IED.
- 1 falha em 11 execuções de `teste_netns.sh` (reautenticação após queda de link).

---

## Bloco 7 — Próximos passos (trabalho futuro, **não feito**)

MACsec (IEEE 802.1AE), servidor RADIUS externo, VLAN dinâmica, IEC 62351-6
**conforme** (gestão e rotação de chaves), cenário de publicador comprometido,
medição de overhead de autenticação e repetições estatísticas no GNS3.

---

## Encerramento — mensagem final

- **IDS heurístico é necessário, mas insuficiente** contra C1.
- **Camadas se completam**: 802.1X (quem é o dispositivo), HMAC (quem assinou a
  mensagem) e IDS (o que ainda passa).
- Nenhuma delas sozinha fecha o problema; todas têm um limite medido neste projeto.

Dúvidas?

---

## Demo (se houver tempo)

Roteiro com comandos prontos: [`guia-testes-5marco.md`](guia-testes-5marco.md)
(E0 → E1 → E4). Plano B se o GNS3 falhar: mostrar `autenticador-8021x/evidencias/gns3/`
e `benchmark/resultados/resumo.md`.
