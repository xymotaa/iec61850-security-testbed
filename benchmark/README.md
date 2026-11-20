# benchmark — campanha OFFLINE do IDS GOOSE

Reconstrói a campanha N=600 do 4º Marco (Bloco 3B de
`changelog/conteudo-apresentacao-4marco.md`, cujo `benchmark_ids.py` nunca
foi versionado) e a estende com dois experimentos do 5º Marco:

1. **Mitigação criptográfica** no estilo IEC 62351-6 (HMAC-SHA256 por frame),
   com e sem a chave em poder do atacante.
2. **Sensibilidade do limiar de flooding** (TPR × taxa de ataque, inclusive
   *low-and-slow*, e FPR do baseline por limiar).

> **É uma SIMULAÇÃO offline.** Os frames são bytes Ethernet reais montados por
> `goose_frame` e alimentados direto no `ids_core.GooseMonitor`, com relógio
> virtual. Não há GNS3, rede, switch nem IED real. Isto **não substitui** a
> validação ponta a ponta no GNS3 (Bloco 4 do changelog). E o HMAC é uma
> **simulação da ideia** da IEC 62351-6, **não** uma implementação conforme
> (sem gestão/rotação de chaves, codificação do trailer arbitrária).

## Como reproduzir

```bash
cd benchmark
python3 -m venv .venv
.venv/bin/pip install scapy matplotlib pytest numpy

.venv/bin/python benchmark_ids.py          # campanha principal (~1-2 min)
.venv/bin/python sensibilidade_limiar.py   # sensibilidade do limiar (~5-10 min)
.venv/bin/python gerar_graficos.py         # figuras PNG/PDF
.venv/bin/python -m pytest -q              # testes (HMAC, cenários, IDS)
```

Semente fixa (`--seed`, padrão 61850) e `--trials` (padrão 100 por cenário).
Os CSVs ficam em `resultados/` e as figuras em `figuras/`. Rode as etapas
**sem outra carga pesada na máquina**: a latência é medida com
`time.perf_counter_ns` e é sensível a ruído.

## Modos da campanha

| Modo | Quem assina | IDS | Atacante |
|---|---|---|---|
| `sem_hmac` | ninguém | IDS atual | sem HMAC |
| `hmac` | IED legítimo | `auth_valid` verificado | **sem** a chave (frames sem tag) |
| `hmac_chave_vazada` | IED legítimo | `auth_valid` verificado | **com** a chave (frames assinados) |

Cenários (mesmos parâmetros da tabela 3B): T0 baseline (heartbeat 1 Hz +
2 rajadas de 5 pps, 60 s), A flooding (pps ∈ {50, 100, 250, 500, 1000, 2000},
3 s), B replay (Δt ∈ [0,5; 10] s), C1 masquerade com MAC clonado, C2 com MAC
distinto, D suppression (ΔstNum ∈ {60, 100, 250, 500, 1000, 5000}).
Cada repetição usa um `GooseMonitor` novo, 5 heartbeats legítimos de
aquecimento e depois só tráfego do atacante. "Detectado" = algum alerta em
algum frame do atacante; em T0, algum alerta em qualquer frame (FPR).

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `trafego.py` | Gera frames legítimos e de ataque (espelha `atacante/goose_attack.py`) |
| `benchmark_ids.py` | Campanha principal: reprodução, métricas, CSVs, `resumo.md` |
| `sensibilidade_limiar.py` | Varredura de limiar × taxa de ataque / rajada legítima |
| `gerar_graficos.py` | Gráficos (português, largura de coluna SBC) |
| `tests/` | `pytest`: HMAC válido/inválido, `ids_core` com `auth_valid`, cenários, `ids.py` |
| `resultados/campanha_trials.csv` | Dado bruto: 1 linha por repetição (modo, cenário, parâmetro, detecção, tipos de alerta, latências) |
| `resultados/campanha_resumo.csv` / `resumo.md` | Agregado por modo × cenário (taxa, IC95% de Wilson, latência média ± dp) |
| `resultados/latencia_hmac_micro.csv` | Custo isolado de `sign`/`verify` (20 000 chamadas) |
| `resultados/sensibilidade_flood_tpr.csv` | TPR por (limiar, taxa de ataque) |
| `resultados/sensibilidade_baseline_fpr.csv` | FPR por (limiar, taxa da rajada legítima) |
| `resultados/execucao.json` | Semente, N, versão do Python, sobrecarga do timer descontada |
| `figuras/*.png`, `*.pdf` | (a) `tpr_por_cenario`, (b) `latencia_por_cenario`, (c) `sensibilidade_limiar` |

## Resultados desta execução

Detalhes completos em `resultados/resumo.md` (taxa com IC95% de Wilson,
latências, tipos de alerta). TPR (FPR em T0), N=100 por cenário:

| Cenário | Sem HMAC | HMAC, atacante sem chave | HMAC, chave vazada | Tabela 3B original |
|---|---|---|---|---|
| T0 baseline (FPR) | 0/100 | 0/100 | 0/100 | 0/100 |
| A flooding | 100/100 | 100/100 (`auth_fail`+`flood_start`) | 100/100 | 100/100 |
| B replay | 100/100 | 100/100 (`replay`, HMAC válido) | 100/100 | 100/100 |
| C1 masquerade sofisticado | **0/100** | **100/100** (`auth_fail`) | **0/100** | 0/100 |
| C2 masquerade ingênuo | 100/100 | 100/100 (`auth_fail`) | 100/100 (`masquerade`) | 100/100 |
| D suppression | 100/100 | 100/100 (`auth_fail`) | 100/100 | 100/100 |

As detecções sem HMAC **reproduzem exatamente** a tabela 3B. As latências
**divergem em valor absoluto**: aqui ~5-12 µs por frame no `process`
(original: 4,0-5,8 µs), plausivelmente por hardware/timer diferentes; ambas
três ordens de grandeza abaixo de 4000 µs. Custo do HMAC (verify de frame com
tag): ~9-13 µs/chamada no microbenchmark, ~11-21 µs por frame na campanha
(ver `resumo.md`), ruído alto.

Sensibilidade do limiar (`sensibilidade_*.csv`, N=100): a detecção de flooding
é um degrau em torno do limiar — TPR 0% abaixo dele, ~80% na taxa igual e 100%
logo acima (limiar 20: 0% até 18 pps, 82% a 20 pps, 100% a 22 pps). Ataques
*low-and-slow* abaixo do limiar passam despercebidos pela checagem de taxa.
FPR do baseline também é degrau: com limiar 20, rajadas legítimas de até
15 pps dão 0% e de 30 pps dão 100%; limiar 10 já dá 77% a 10 pps, e limiar 80
não tem falso positivo até 60 pps — mas só detecta ataques acima de ~80 pps.


## Limitações (leia antes de citar os números)

- **Offline, não é o GNS3.** Sem rede, sem switch, sem IED real, sem jitter de
  captura. Não há perda de pacotes nem reordenação.
- **Pouca variância por construção.** O conteúdo dos frames é determinístico
  para cada (modo, parâmetro); entre as 100 repetições variam só o parâmetro
  (ciclado ou sorteado) e o tempo (±10% em cada intervalo entre frames).
  Por isso TPR/FPR saem em 0% ou 100%, e o IC de Wilson (N=100) é o que
  quantifica a incerteza — não um desvio de repetições independentes.
- **Reconstrução, não a campanha original.** Os parâmetros vêm da tabela 3B;
  detalhes não documentados (duração do flood, aquecimento, forma das rajadas
  do baseline, como o tempo foi medido) foram escolhidos aqui e estão em
  `trafego.py`/`benchmark_ids.py`. As **detecções batem** com a tabela; as
  **latências não são comparáveis** (ver abaixo).
- **Latência.** Medida por frame (`parse`, `verify`, `process`) com
  `perf_counter_ns`, descontando a mediana do custo de uma leitura do timer
  (~2 µs neste ambiente, da mesma ordem do que se mede). É Python puro numa
  CPU de notebook compartilhada: o valor absoluto e o desvio mudam entre
  execuções; use a **ordem de grandeza** (µs, três ordens abaixo de 4000 µs)
  e as diferenças relativas. "Latência IDS" = `GooseMonitor.process`;
  "HMAC verify" = `GooseAuthenticator.verify`; o parse é registrado à parte
  no CSV bruto. Com HMAC, frames sem tag (atacante sem chave) saem da
  verificação imediatamente e descartam o frame no monitor, então ficam
  *mais baratos* que frames assinados — o custo realista do HMAC é o de
  `hmac_chave_vazada`/T0.
- **O HMAC não resolve tudo.** Replay de um frame legítimo mantém o HMAC
  válido (só a checagem de `(stNum, sqNum)` pega); com a chave, o C1 volta a
  ser indetectável. A chave "vazada" é a chave-mestra de teste inteira; num
  esquema real, vazar a chave de um `gocbRef` comprometeria só aquele fluxo.
- **Limiar de flooding:** o tráfego legítimo do atacante-alvo fica em silêncio
  durante o ataque (evita conflito de `sqNum`), então a taxa vista pelo IDS é a
  do atacante; em campo, soma-se ~1 pps de heartbeat. As rajadas legítimas do
  baseline (5–60 pps) são uma carga **sintética assumida**, não medida em
  subestação real.
- Um `auth_fail` é emitido por frame rejeitado (sem agregação): num flood sem
  chave isso gera um alerta por pacote.
