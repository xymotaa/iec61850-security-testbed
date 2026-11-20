# Relatório final de resultados — 5º Marco (23/11/2026)

Consolida, num só lugar, os resultados do projeto de reprodução e extensão do
artigo *"Analisador Automático de Segurança Cibernética para o Setor Elétrico"*
(Oliveira & Gurjão, SBSeg 2025 — WTICG): auditoria do Oráculo, ataques GOOSE e
detecção pelo IDS, mitigação por autenticação (HMAC e IEEE 802.1X),
sensibilidade do limiar, geração automática de topologia e validação no GNS3.

Os dados brutos ficam nos arquivos citados em cada seção. Nada aqui foi
estimado: onde não houve medição, está escrito.

## 0. Como ler: o que é simulação e o que é real

| Item | Natureza | Observação |
|---|---|---|
| Oráculo (auditoria SSH dos IEDs) | **Real**, em contêineres no GNS3 | Os IEDs são hosts genéricos (`ubuntu-ied`), não relés reais |
| Ataques GOOSE e IDS | **Real** no GNS3 (frames Ethernet reais em contêineres); **simulação offline** na campanha estatística | O molde GOOSE (`atacante/samples/molde.pcap`) é uma captura real de um relé SEL-351 |
| HMAC por frame (`ids --auth`, `goose_auth.py`) | **Simulação da ideia da IEC 62351-6** | Não é implementação conforme: sem gestão/rotação de chaves, trailer de codificação arbitrária, chave-mestra de teste |
| IEEE 802.1X EAP-TLS (`autenticador-8021x/`) | **Real** | `hostapd` 2.10 (driver `wired`) + `wpa_supplicant` + `nftables`; fala EAPOL de verdade. PKI de laboratório |
| Campanha estatística (`benchmark/`) | **Simulação offline** | Frames reais, relógio virtual, sem rede, switch ou IED; não substitui o GNS3 |

## 1. Dados de entrada

| SCD | Origem | IEDs | Usado em |
|---|---|---|---|
| `extracao-scd/exemplo_subestacao.scd` | sintético, estruturalmente válido | 2 (`SEL_351_1`, `SEL_351_2`) | topologia `subestacao.gns3`; topologia `subestacao_8021x.gns3` (versionada, 7 nós) |
| `extracao-scd/scd_real_simpleIO.scd` | `simpleIO_direct_control_goose.scd` do repositório open-source `mz-automation/libiec61850` (GPL-3.0) | 1 (`simpleIO`, IP `10.0.0.2/24`), 2 blocos GOOSE (`gcbEvents`, `gcbAnalogValues`), APPID 1000, VLAN 111 | topologia `subestacao_real.gns3`, validada no GNS3 no 4º Marco |

Molde GOOSE dos ataques e do IDS: `atacante/samples/molde.pcap` (relé SEL-351,
origem `00:30:a7:01:b3:16`, `gocbRef` `SEL_351_1CFG/LLN0$GO$NewGOOSEMessage`).

## 2. Oráculo — conformidade IEC 62443-3-3

Execução nos 5 IEDs (`192.168.10.11` a `.15`, `oraculo/oraculo.py <ip>`). O
resultado foi **idêntico nos 5**: **3 de 12 critérios conformes**. Todos usam a
mesma imagem (`ubuntu-ied:latest`), logo o achado reflete frota homogênea, e não
variação entre equipamentos.

| SR | Critério | Resultado |
|---|---|---|
| 1.1 | Ausência de credencial padrão | Não conforme |
| 1.3 | Comprimento mínimo da senha (`minlen=8`) | Conforme |
| 1.3 | Exige dígito (`dcredit=0`) | Não conforme |
| 1.3 | Exige maiúscula (`ucredit=-1`) | Conforme |
| 1.3 | Exige minúscula (`lcredit=0`) | Não conforme |
| 1.3 | Exige caractere especial (`ocredit=0`) | Não conforme |
| 1.5 | Mecanismo de expiração (`max_days=99999`) | Não conforme |
| 1.7 | Troca periódica (90–180 dias) | Não conforme |
| 2.1 | Conta sem privilégios administrativos | Conforme |
| 3.1 | Integridade das mensagens GOOSE (sem IEC 62351-6) | Não conforme |
| 5.1 | Segmentação (VLAN) | Não conforme |
| 7.1 | Limitação de taxa de conexões (anti-DoS) | Não conforme |

Correção ao artigo original: `ucredit = -1` no PAM (`libpam-pwquality`) impõe
cota **mínima obrigatória** de 1 maiúscula; o artigo o classificou como "não
definido". Fonte: `docs/metodologia_proposta_gns3.md`, seção 1.

O mesmo resultado 3/12 foi obtido no IED do SCD real (`ubuntu-ied-1` em
`subestacao_real.gns3`, 4º Marco; ver `changelog/README.md`).

## 3. Ataques GOOSE e detecção

Quatro ataques (`atacante/goose_attack.py`: `flood`, `replay`, `masquerade`,
`suppress`) contra o IDS próprio (`ids/ids.py`, núcleo `ids_core.GooseMonitor`).
Masquerade tem duas variantes: **C1** (sofisticado, MAC clonado) e **C2**
(ingênuo, MAC distinto).

### 3.1 Execuções pontuais no GNS3 (3º Marco, 1 execução por cenário)

| Teste | Detectado? | Detalhe |
|---|---|---|
| A — Flooding | Sim | `FLOOD_START` a 20,5 pkts/s (limite 20); `FLOOD_END` após 9,6 s, pico de 34,0 pkts/s |
| B — Replay | Sim | `(stNum=23, sqNum=521)` já visto |
| C1 — Masquerade, MAC clonado | **Não** | 0 alertas |
| C2 — Masquerade, MAC próprio | Sim | `MAC mudou de 00:30:a7:01:b3:16 para de:ad:be:ef:00:99` |
| D — Suppression | Sim | `stNum saltou de 23 para 1023` |

4 de 5 cenários (80%); 4/4 contra o atacante que não clona MAC; 0/1 contra o que
clona; 0 falso positivo. Fonte: `docs/metodologia_proposta_gns3.md`, seção 2 e 3.
Com 1 execução por cenário, isto é demonstração, não estatística.

### 3.2 Campanha do 4º Marco (N = 600) — resultado ANTERIOR

Campanha automatizada apresentada no 4º Marco (100 repetições × 6 cenários).
**O `benchmark_ids.py` original nunca foi versionado**, portanto esta tabela vem
dos slides (`changelog/conteudo-apresentacao-4marco.md`, Bloco 3B) e **não é
reproduzível a partir do repositório**. Foi mantida como referência histórica.

| Cenário | Detecções | Taxa | Latência/frame (µs) |
|---|---|---|---|
| T0 baseline | 0/100 | 0,0% (FPR) | 4,29 ± 1,34 |
| A flooding | 100/100 | 100,0% | 4,49 ± 1,55 |
| B replay | 100/100 | 100,0% | 5,56 ± 0,83 |
| C1 masquerade sofisticado | 0/100 | 0,0% | 4,03 ± 0,31 |
| C2 masquerade ingênuo | 100/100 | 100,0% | 5,07 ± 1,07 |
| D suppression | 100/100 | 100,0% | 5,84 ± 1,71 |

### 3.3 Campanha offline reproduzida (5º Marco) — N = 100 por cenário, 3 modos

`benchmark/benchmark_ids.py`, semente 61850, Python 3.12.11, duração da execução
70,1 s, **100 repetições por cenário × 6 cenários × 3 modos = 1800 repetições**
(`benchmark/resultados/campanha_trials.csv`). Cada repetição usa um
`GooseMonitor` novo, 5 heartbeats legítimos de aquecimento e depois só o tráfego
do atacante. Intervalo de confiança: **Wilson 95%**. Cópia fiel de
`benchmark/resultados/resumo.md`.

Modos: `sem_hmac` (IDS atual); `hmac` (IED assina, IDS verifica, atacante **sem**
a chave); `hmac_chave_vazada` (atacante **com** a chave-mestra de teste).

**Taxa de detecção (TPR; FPR em T0)** — detecções/100 e IC95%:

| Cenário | Sem HMAC | HMAC, atacante sem chave | HMAC, chave vazada |
|---|---|---|---|
| T0 baseline (FPR) | 0/100 — 0,0% [0,0%; 3,7%] | 0/100 — 0,0% [0,0%; 3,7%] | 0/100 — 0,0% [0,0%; 3,7%] |
| A flooding | 100/100 — 100,0% [96,3%; 100,0%] | 100/100 — 100,0% [96,3%; 100,0%] | 100/100 — 100,0% [96,3%; 100,0%] |
| B replay | 100/100 — 100,0% [96,3%; 100,0%] | 100/100 — 100,0% [96,3%; 100,0%] | 100/100 — 100,0% [96,3%; 100,0%] |
| C1 masquerade sofisticado | **0/100 — 0,0% [0,0%; 3,7%]** | **100/100 — 100,0% [96,3%; 100,0%]** | **0/100 — 0,0% [0,0%; 3,7%]** |
| C2 masquerade ingênuo | 100/100 — 100,0% [96,3%; 100,0%] | 100/100 — 100,0% [96,3%; 100,0%] | 100/100 — 100,0% [96,3%; 100,0%] |
| D suppression | 100/100 — 100,0% [96,3%; 100,0%] | 100/100 — 100,0% [96,3%; 100,0%] | 100/100 — 100,0% [96,3%; 100,0%] |

**Alertas disparados:**

| Cenário | Sem HMAC | HMAC, sem chave | HMAC, chave vazada |
|---|---|---|---|
| A flooding | `flood_start` | `auth_fail`, `flood_start` | `flood_start` |
| B replay | `replay` | `replay` (o HMAC do frame reenviado é válido) | `replay` |
| C1 | nenhum | `auth_fail` | nenhum |
| C2 | `masquerade` | `auth_fail` | `masquerade` |
| D suppression | `suppression` | `auth_fail` | `suppression` |

**Latência por frame (µs, média ± dp)** — `GooseMonitor.process` / HMAC `verify`:

| Cenário | Sem HMAC (IDS) | HMAC (IDS / verify) | Chave vazada (IDS / verify) |
|---|---|---|---|
| T0 baseline | 11,62 ± 1,68 | 5,92 ± 0,59 / 11,39 ± 1,06 | 6,93 ± 0,79 / 13,61 ± 1,25 |
| A flooding | 7,24 ± 2,59 | 5,82 ± 1,49 / 2,12 ± 0,86 | 10,36 ± 1,63 / 18,00 ± 2,97 |
| B replay | 10,73 ± 5,59 | 17,93 ± 7,07 / 15,70 ± 3,12 | 15,87 ± 4,05 / 16,68 ± 3,06 |
| C1 | 5,56 ± 3,78 | 4,97 ± 3,40 / 2,76 ± 2,45 | 8,56 ± 0,62 / 16,22 ± 2,06 |
| C2 | 7,20 ± 2,78 | 4,57 ± 1,61 / 2,49 ± 0,81 | 10,63 ± 2,66 / 17,20 ± 3,82 |
| D suppression | 7,50 ± 2,36 | 4,72 ± 3,14 / 2,38 ± 1,02 | 16,74 ± 5,89 / 21,06 ± 6,80 |

**Comparação com a campanha do 4º Marco (3.2).** As **detecções sem HMAC
coincidem** em todos os cenários (100% em A/B/C2/D, 0% em C1 e em T0). As
**latências divergem em valor absoluto** (aqui ~5–12 µs no `process`; antes
4,0–5,8 µs), plausivelmente por hardware, timer e método de medição diferentes;
ambas ficam três ordens de grandeza abaixo do limite de 4000 µs da IEC 61850.
As latências não são comparáveis entre as campanhas.

**O que o resultado mostra:**

- **C1 (MAC clonado)** é indetectável por heurística passiva (0/100, IC superior
  3,7%). Com HMAC e atacante **sem** a chave, vira 100/100 (`auth_fail`). Com a
  chave vazada volta a 0/100.
- **Replay** continua detectado só pela checagem de `(stNum, sqNum)`: o HMAC do
  frame reenviado é válido.
- FPR de T0 = 0/100 nos três modos.

**Cuidados na leitura:**

- Taxas 0% ou 100% por construção: o conteúdo dos frames é determinístico por
  (modo, parâmetro); entre as 100 repetições variam o parâmetro (ciclado ou
  sorteado) e o tempo (±10% por intervalo). O IC de Wilson quantifica a
  incerteza; **não** é um desvio de repetições independentes.
- Os parâmetros vêm da tabela 3B do 4º Marco; detalhes não documentados
  (duração do flood, aquecimento, forma das rajadas do baseline) foram
  escolhidos aqui, em `benchmark/trafego.py` e `benchmark/benchmark_ids.py`. É
  uma **reconstrução**, não a campanha original.
- Latência medida com `time.perf_counter_ns`, descontando a mediana do custo de
  uma leitura do timer (1,956 µs). É Python numa CPU de notebook compartilhada:
  valem a ordem de grandeza e as diferenças relativas.
- Com HMAC e atacante sem chave, frames sem tag saem da verificação
  imediatamente e ficam mais baratos; o custo realista do HMAC é o de
  `hmac_chave_vazada`/T0.

## 4. Sensibilidade do limiar de flooding

`benchmark/sensibilidade_limiar.py` (modo sem HMAC, N = 100 por ponto, semente
61850). Dados: `sensibilidade_flood_tpr.csv` e `sensibilidade_baseline_fpr.csv`;
figura: `benchmark/figuras/sensibilidade_limiar.{png,pdf}`.

- **TPR é um degrau em torno do limiar.** Com o limiar padrão de 20 pps: 0% até
  18 pps, 82% a 20 pps, 100% a partir de 22 pps. Ataques *low-and-slow* abaixo do
  limiar não são vistos pela checagem de taxa.
- **FPR do baseline também é degrau.** Limiar 20: 0% para rajadas legítimas de
  até 15 pps, 73% a 20 pps, 100% a 30 pps. Limiar 10: 77% já a 10 pps. Limiar 80:
  0% até 60 pps (o maior valor testado), mas só detecta ataques acima de ~80 pps.
- As rajadas legítimas (5–60 pps) são uma **carga sintética assumida**, não
  medida em subestação real. O tráfego legítimo do alvo fica em silêncio durante
  o ataque (evita conflito de `sqNum`), então a taxa vista pelo IDS é a do
  atacante.

Conclusão: o limiar é uma troca entre FPR e detecção de ataques lentos; não há
valor que elimine os dois erros.

## 5. Custo do HMAC (ordem de grandeza)

`benchmark/resultados/latencia_hmac_micro.csv` (20 000 chamadas por operação):

| Operação | Média (µs) | DP | Mediana (µs) | P99 (µs) |
|---|---|---|---|---|
| `sign` | 12,08 | 18,16 | 11,04 | 26,26 |
| `verify` | 12,85 | 5,50 | 11,53 | 35,34 |

Na campanha, o `verify` de um frame com tag custou ~11–21 µs por frame
(seção 3.3). Ordem de grandeza: **dezenas de microssegundos por frame, em Python
numa CPU de notebook**, cerca de 0,5% do orçamento de 4 ms no pior caso medido
(21 µs). **Não é o custo em um IED real** (hardware, linguagem e implementação
diferentes) e o desvio é alto; a medição não deve ser citada como valor exato.

## 6. IEEE 802.1X (EAP-TLS) — validação real

Implementação: `autenticador-8021x/` (switch autenticador com `hostapd` 2.10,
driver `wired`, um processo por porta; `nftables` na família `bridge`, política
`drop`), PKI de laboratório em `pki/` (`gerar_pki.sh`), inventário CN → MAC
gerado do SCD (`extracao-scd/inventario_8021x.py`), supplicant
(`wpa_supplicant`, `AUTH_8021X=1`) embutido nas imagens `ubuntu-ied`, `oraculo`,
`ids` e `atacante`. Desligado por padrão. O certificado é **vinculado ao MAC**:
certificado válido com MAC de outro dono é rejeitado (`mac_divergente`).

### 6.1 Validação em *network namespaces* (`teste_netns.sh`)

Docker `--privileged`, clientes em `netns`, hostapd + wpa_supplicant + nftables
reais, 9 clientes. Logs em `autenticador-8021x/evidencias/teste_netns-*.log`.

**Execuções registradas: 11**, todas em 20/11/2026:

| Resultado | Execuções | Logs (carimbo) |
|---|---|---|
| 29 verificações passaram, 0 falharam | 2 | `162347`, `162720` |
| 30 passaram, 0 falharam | 8 | `162857`, `163030`, `163203`, `163733`, `164001`, `164134`, `164258`, `164423` |
| 28 passaram, 2 falharam | 1 | `163328` |

A suíte passou de 29 para 30 verificações entre as primeiras execuções. **A
execução `163328` falhou em 2 verificações**: "c1 reautentica sozinho e volta a
alcançar c2" (após queda de link) e "c1 (não revogado) segue alcançando c6" (a
etapa seguinte, que depende da anterior). A causa **não está registrada** no
repositório; as 5 execuções seguintes passaram 30/30. Trate como uma ocorrência
observada de falha intermitente na etapa de reautenticação após queda de link
(hipótese: dependência de temporização; não confirmada). Resultado honesto: 10
de 11 execuções sem falha, 1 com 2 falhas.

O que a suíte (30 verificações) prova: certificado válido autentica e troca
tráfego; sem credencial, certificado revogado, CA falsa, CN fora do inventário e
MAC clonado em outra porta **não** passam; MAC forjado depois de autenticar é
descartado; queda/volta do link revoga a sessão e o cliente reautentica;
revogação em operação (`recarregar-crl` + `reautenticar`) derruba o cliente;
modo `aberto` (`autenticador-ctl desativar`) deixa passar e reativar volta a
bloquear.

**Imagens reais** (`teste_imagens_clientes.sh`, 1 execução, log
`teste_imagens_clientes-20261120-123354.log`): o supplicant embutido em cada
uma das 4 imagens (`ubuntu-ied`, `oraculo`, `ids`, `atacante`) autentica contra
o autenticador; `RESUMO: 0 falha(s)`.

**Testes unitários** (executados em 20/11/2026 na revisão final):
`autenticador-8021x/tests` 28 testes OK; `pki/tests` 7 OK; `extracao-scd/tests`
20 OK (1 ignorado); `benchmark/tests` 66 OK.

### 6.2 Validação no GNS3 real (20/11/2026)

GNS3 2.2.61, projeto `subestacao_8021x` (gerado por `gerar_topologia_gns3.py
--8021x`), 7 nós ligados direto ao `autenticador-8021x`. PKI de laboratório
instalada por `pki/instalar_no_gns3.py`. **Cada cenário foi executado 1 vez**
(sem repetições estatísticas). Fonte: `autenticador-8021x/evidencias/gns3/`
(`RESULTADOS_GNS3.md`, `eventos_gns3_20261120.jsonl`, `alertas_e*.jsonl`,
`tcpdump_e4.txt`).

| Cenário | Camada que barra | Observado | Evidência |
|---|---|---|---|
| Base | — | 5 `auth_aceita` (ied-1, ied-2, oraculo-1, ids-1, publicador-1), nenhum para `atacante-1`; PAE `AUTHENTICATED`, EAP-TLS; `ping` ied-1→ied-2 3/3 | `eventos_gns3_20261120.jsonl` |
| E0 — sem 802.1X | nenhuma | `ping` do atacante 3/3; C1 sem alerta no IDS | `alertas_e0.jsonl` (vazio) |
| E1 — sem certificado, MAC do publicador | 802.1X (nftables) | `ping` 0/3; `quadro_descartado` em `eth5`; nenhum alerta no IDS | `alertas_e1.jsonl` (vazio), eventos |
| E2 — certificado revogado | 802.1X (TLS + CRL) | `auth_rejeitada` `certificado_revogado` (CN `revogado-1`, serial `100B`); `ping` 0/3 | eventos |
| E3 — certificado de outro nó, MAC do `ubuntu-ied-1` | 802.1X (vínculo CN↔MAC) | TLS aceito, mas `auth_rejeitada` `mac_divergente`; `ping` 0/3 | eventos |
| E4 — certificado válido, MAC próprio | IDS (só heurística de MAC) | autentica; GOOSE forjado chega ao IDS; alerta `MASQUERADE` | `tcpdump_e4.txt`, `alertas_e4.jsonl` |
| E4b — certificado válido, origem do publicador | 802.1X (par porta+MAC) | `nft list set descartados`: `eth5 . 00:30:a7:01:b3:16`, 5 pacotes, 1760 bytes | saída do `nft` (console) |
| E5 (i) — sem chave HMAC, MAC próprio | IDS `--auth` | `AUTH_FAIL` | `alertas_e5.jsonl` |
| E5 (ii) — chave vazada, MAC próprio | IDS (heurística de MAC) | `MASQUERADE` | `alertas_e5.jsonl` |
| E5 (iii) — chave vazada, origem do publicador | 802.1X (par porta+MAC) | nenhum alerta novo; `nft`: 5 pacotes, 1930 bytes | `alertas_e5.jsonl` (2 linhas), saída do `nft` |

Leitura: o 802.1X barra o atacante **sem credencial** e o **clone de MAC de
outra porta**, mesmo quando o IDS não vê nada (E0 e E1 mostram o mesmo C1 em
dois estados da rede). Mas **autentica o dispositivo, não a mensagem**: um nó
comprometido com certificado válido e MAC próprio publica GOOSE forjado (E4);
nesse caso o IDS (heurística de MAC) ou o HMAC (E5 i) é que atuam. Defesa em
profundidade: 802.1X + HMAC + IDS.

Limites desta validação: os logs do console foram colados pelo operador; alertas
do IDS e `tcpdump` foram extraídos com `docker cp`. **E2b (revogação em
operação) não foi executada no GNS3**, só em `netns`. **Não medimos o overhead
ou a latência da autenticação** no GNS3. Sobre E4b/E5 (iii), a diferença de 34
bytes por frame (352 vs 386) é compatível com o trailer do HMAC, mas é uma
inferência a partir dos contadores.

## 7. Geração automática de topologia GNS3

`extracao-scd/extrair_scd.py` (SCD → JSON) e `gerar_topologia_gns3.py` (JSON →
`.gns3`) fecham o fluxo do artigo original (Fig. 1: extração → modelagem →
GNS3), que antes exigia montar a topologia à mão. A extração vai além do artigo:
além de IP, máscara e nome, lê blocos GOOSE/SV (`gocbRef`, `datSet`, MAC, APPID,
VLAN).

| Arquivo versionado | SCD de origem | Nós | Validado no GNS3? |
|---|---|---|---|
| `extracao-scd/subestacao.gns3` | `exemplo_subestacao.scd` (sintético, 2 IEDs) | 10 (5 switches, 2 IEDs, oráculo, IDS, atacante) | topologia original do projeto |
| `extracao-scd/subestacao_real.gns3` | `scd_real_simpleIO.scd` (libiec61850, 1 IED) | 9 | **Sim**, 4º Marco: abre sem erro, IP automático, Oráculo 3/12, replay detectado pelo IDS |
| `extracao-scd/subestacao_8021x.gns3` | `dados.json` (sintético, 2 IEDs) | 7 (autenticador, 2 IEDs, oráculo, IDS, publicador, atacante), sem switches | **Sim**, 20/11/2026 (seção 6.2) |

Correções feitas ao abrir no GNS3 real (4º Marco): posições de nó como `float`
(o schema do GNS3 exige `integer`) e nomes de nó sem número final (o
`entrypoint.sh` deriva o IP de `ubuntu-ied-N`). A variante `--8021x` fixa o MAC
de cada nó (`02:00:<IP em hexa>`) e grava o `inventario.json`.

Gerar a variante `--8021x` a partir do SCD real (`dados_real.json`) funciona
(6 nós, 5 links), verificado na revisão final apenas como geração de arquivo; **ela não foi aberta no GNS3**.

## 8. Métricas finais (resumo)

| Pergunta | Resultado | Seção |
|---|---|---|
| Conformidade dos IEDs | 3/12 critérios, nos 5 IEDs | 2 |
| Detecção pelo IDS, ataques sem MAC clonado (A, B, C2, D) | 100/100 por cenário na campanha offline, IC95% [96,3%; 100,0%]; 4/4 nas execuções no GNS3 | 3 |
| Detecção de C1 (MAC clonado) sem HMAC | 0/100 [0,0%; 3,7%]; 0/1 no GNS3 (E0) | 3, 6.2 |
| Falso positivo (baseline) | 0/100 nos 3 modos | 3.3 |
| C1 com HMAC, atacante sem chave | 100/100 (`auth_fail`) | 3.3 |
| C1 com HMAC, chave vazada | 0/100 | 3.3 |
| Latência do IDS por frame | ~5–12 µs (offline, Python) | 3.3 |
| Custo do `verify` HMAC | ~11–13 µs por chamada (mediana ~11,5 µs) | 5 |
| 802.1X em `netns` | 10 de 11 execuções sem falha; 1 com 2 falhas | 6.1 |
| 802.1X no GNS3 | base + 9 cenários (E0 a E5), 1 execução cada | 6.2 |

## 9. Limitações e trabalhos futuros

Classificação de cada item em relação ao artigo original (a lista do que o
artigo propôs vem de `changelog/README.md`).

### Quadro de situação

| Item | Situação | Onde |
|---|---|---|
| Extração do SCD (IP, máscara, nome) | **Reproduzido** | `extracao-scd/extrair_scd.py` |
| Topologia: 4 switches, 5 IEDs, Oráculo | **Reproduzido** | `subestacao.gns3` |
| Oráculo: SR 1.3 e 1.7 via SSH | **Reproduzido** | `oraculo/oraculo.py` |
| Extração de GOOSE/SV (MAC, APPID, VLAN, `gocbRef`) | **Estendido** | `extrair_scd.py` |
| Geração automática do `.gns3` | **Estendido** (a etapa de modelagem da Fig. 1 era manual neste projeto até o 3º Marco) | `gerar_topologia_gns3.py` |
| Oráculo: 8 SRs / 12 critérios; correção de `ucredit` | **Estendido** | `oraculo/oraculo.py` |
| Novos tipos de ataque (trabalho futuro do artigo): flood, replay, masquerade, suppression + IDS próprio | **Proposto pelo artigo e estendido aqui** | `atacante/`, `ids/` |
| Campanha estatística offline com IC95% | **Novo** | `benchmark/` |
| Sensibilidade do limiar de flooding | **Novo** | `benchmark/` |
| HMAC por frame (simulação da ideia da 62351-6) | **Novo — simulação** | `ids/goose_auth.py`, `atacante/goose_auth.py` |
| 802.1X EAP-TLS com PKI de teste e vínculo CN↔MAC | **Novo — real** | `autenticador-8021x/`, `pki/` |
| Validação do 802.1X em `netns` e no GNS3 | **Novo** | `autenticador-8021x/evidencias/` |
| Validar em ambientes reais (trabalho futuro do artigo) | **Em aberto**: validado em GNS3 com contêineres, não em subestação ou relés reais | — |
| MACsec (IEEE 802.1AE: cifra e integridade do quadro) | **Em aberto** | — |
| Servidor RADIUS externo (hoje, EAP embutido no hostapd) | **Em aberto** | — |
| VLAN dinâmica por usuário | **Em aberto** | — |
| IEC 62351-6 conforme (gestão e rotação de chaves, codificação normativa) | **Em aberto**; o HMAC atual é só simulação | — |
| Publicador comprometido (nó com certificado válido e a chave, enviando GOOSE legítimo e malicioso) | **Em aberto**; E4/E5 mostram que 802.1X e IDS não resolvem sozinhos | seção 6.2 |
| Medição de overhead/latência de autenticação no GNS3 | **Em aberto** | — |
| Repetições estatísticas no GNS3 | **Em aberto**: 1 execução por cenário | seção 6.2 |
| Revogação em operação (E2b) no GNS3 | **Em aberto**: só em `netns` | seção 6.1 |
| Campanha N=600 original reproduzível | **Parcial**: reconstruída e rotulada (3.3); o script original não existe | seção 3.2 |
| PKI de produção | **Em aberto**: a PKI é de laboratório | `pki/README.md` |

### Limitações específicas

- **Campanha offline:** sem rede, switch, IED real, jitter, perda ou
  reordenação de pacotes. Latência em Python numa CPU de notebook.
- **HMAC:** não impede replay; com a chave, C1 volta a ser indetectável. A chave
  "vazada" é a chave-mestra inteira; num esquema real, vazar a chave de um
  `gocbRef` comprometeria só aquele fluxo.
- **802.1X:** autentica o dispositivo, não a mensagem. Janela de
  reautenticação (`REAUTH_PERIODO`, padrão 600 s): se um nó for trocado sem
  derrubar o link, o par fica autorizado até a próxima reautenticação. Acoplado
  ao formato de log do hostapd 2.10 (versão fixada pela imagem). Se o supervisor
  morrer de forma abrupta, quem estava autorizado continua passando até o
  contêiner reiniciar.
- **IEDs simulados:** são hosts genéricos, não relés reais; não geram GOOSE
  próprio (o GOOSE vem do `molde.pcap`).
- **Oráculo:** audita só o plano de gerência (SSH). Os ataques GOOSE passam
  despercebidos por ele; é a tese da extensão.
- **SCD real:** só 1 IED.

## 10. Rastreabilidade

| O que | Onde |
|---|---|
| Campanha offline | `benchmark/` (`README.md`, `resultados/`, `figuras/`); reproduzir: `cd benchmark && .venv/bin/python benchmark_ids.py` |
| 802.1X | `autenticador-8021x/README.md`, `autenticador-8021x/evidencias/` |
| GNS3 real, 802.1X | `autenticador-8021x/evidencias/gns3/RESULTADOS_GNS3.md` |
| Roteiro da demo 802.1X | `changelog/guia-testes-5marco.md` |
| Status por marco | `changelog/README.md` |
| Texto para os slides | `changelog/conteudo-apresentacao-5marco.md` |
