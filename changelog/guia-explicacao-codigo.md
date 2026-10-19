# Guia de explicação do código — pra defender pro professor

Roteiro módulo por módulo: o que cada arquivo faz, **por que** foi
feito assim (as decisões de design que valem a pena defender), e as
perguntas mais prováveis com a resposta pronta. Não precisa decorar —
é pra ter no bolso se o professor pedir pra abrir um arquivo específico.

Ordem sugerida de explicação (segue o pipeline de dados, do dado bruto
ao resultado final): **extração → topologia → Oráculo → ataque → IDS**.

---

## 1. `extracao-scd/extrair_scd.py` — extração de dados do SCD

**O que faz:** lê um arquivo `.scd` (XML, formato SCL da IEC 61850) e
extrai, por IED: nome, IP, máscara, e os blocos de controle GOOSE
(`gocbRef`, `datSet`, MAC, APPID, VLAN) e SV (`smvID` + mesmo
endereçamento).

**Como funciona por dentro (função a função):**
- `strip_ns()` — remove o namespace XML (`{http://www.iec.ch/61850/...}`)
  de toda tag, porque SCL usa um namespace default e isso obrigaria a
  escrever `{namespace}IED` em vez de só `IED` em todo `find`/`findall`.
  É só conveniência de leitura do código, não muda o dado.
- `parse_scd()` faz em **duas passadas**, e isso é a decisão mais
  importante do arquivo:
  1. Varre `<IED>` → `<LDevice>` → `<LN0>` → `<GSEControl>`/
     `<SampledValueControl>` pra descobrir **quais** blocos de
     controle existem (nome, dataset), mas sem endereço ainda.
  2. Varre `<ConnectedAP>` (seção `<Communication>` do SCD) e casa
     cada `<GSE>`/`<SMV>` com o bloco já descoberto, por `ldInst` +
     `cbName`, pra então preencher IP/MAC/APPID/VLAN.
  - **Por quê duas passadas:** no SCL, a *definição* do bloco GOOSE
    (o quê ele publica) e o *endereçamento* dele (IP/MAC/VLAN) ficam
    em seções **diferentes** do XML — a primeira dentro de `<IED>`,
    a segunda em `<Communication>`. Não dá pra extrair tudo numa
    passada só porque a ordem de leitura do documento não garante que
    o endereço já foi visto quando o bloco é descoberto.
- `_read_address_params()` — lê os `<P type="...">` dentro de um
  `<Address>` (ex: `type="MAC-Address"`) e mapeia pro nome de campo
  que a gente quer (`mac_address`, `appid`, etc).

**Pergunta provável: "por que não usa uma lib XML tipada / schema XSD
da IEC 61850?"**
Resposta: o parser usa `xml.etree.ElementTree`, da biblioteca padrão
do Python, fazendo parse estrutural direto (sem validar contra o XSD
oficial da norma). Isso é suficiente pro escopo do projeto — extrair
os campos que os outros módulos (`atacante/`, `ids/`) precisam — e
evita a dependência extra de uma lib de schema IEC 61850 completa, que
seria overkill pra um SCD de teste/exemplo.

**Pergunta provável: "testaram com um SCD real?"**
Resposta honesta: só com `exemplo_subestacao.scd`, sintético mas
estruturalmente válido (2 IEDs, baseado num relé SEL-351 real). Testar
com um SCD real de subestação é item do 4º Marco (ver
`changelog/README.md`).

---

## 2. `extracao-scd/gerar_topologia_gns3.py` — geração automática do `.gns3`

**O que faz:** consome o JSON da extração e monta um arquivo `.gns3`
(formato JSON do GNS3) pronto pra abrir — fecha o fluxo completo do
artigo original (Fig. 1: Extração → Modelagem → GNS3), que até o
marco anterior parava na extração.

**Como funciona por dentro:**
- `_make_switch_node()` / `_make_docker_node()` / `_make_link()` —
  montam, respectivamente, o dicionário JSON de um switch Ethernet
  nativo do GNS3, de um nó Docker, e de um link entre dois nós. Cada
  um já no formato exato que o GNS3 espera no `.gns3` (campos como
  `node_id`, `compute_id`, `properties.image`, etc. — reverse-engineered
  a partir de projetos `.gns3` reais/documentação do formato).
- `build_topology()` — a lógica central: monta 1 switch central + 4
  switches de borda em **estrela** (nunca malha — comentado no próprio
  código: o switch nativo do GNS3 não roda Spanning Tree, e malha
  completa geraria loop de broadcast), distribui os IEDs extraídos
  round-robin entre os switches de borda, e conecta `oraculo-1`,
  `ids-1`, `atacante-1` direto no switch central (porque GOOSE é
  multicast de Camada 2 — esses três precisam estar no mesmo domínio
  de broadcast que os IEDs pra funcionar).
- Cada nó recebe um `node_id` via `uuid4()` — são identificadores só
  do **projeto GNS3**, não têm relação com os dados do SCD.

**Pergunta provável: "o script registra os templates Docker no GNS3?"**
Resposta: não. Ele só **referencia** as imagens pelo nome
(`ubuntu-ied:latest`, etc. — parâmetros `--ied-image`, `--oraculo-image`...).
Os templates Docker continuam precisando estar registrados manualmente
no GNS3 antes de abrir o projeto gerado (mesmo processo descrito em
`atacante/README.md`, via API do GNS3). Isso é uma limitação assumida
e documentada, não um esquecimento.

**Pergunta provável: "como validaram que o `.gns3` gerado é válido?"**
Resposta: validação programática (estrutura JSON, contagem de nós e
links, todo link referenciando um `node_id` existente) com um SCD de
2 IEDs e com um conjunto simulado de 5 IEDs. **Ainda não foi aberto
dentro do GNS3 real** — isso é item do 4º Marco.

---

## 3. `oraculo/oraculo.py` — auditoria de conformidade IEC 62443-3-3

**O que faz:** conecta via SSH num IED e avalia 8 critérios (Security
Requirements) da norma, lendo arquivos de configuração remotos.

**Como funciona por dentro:**
- `ssh_connect()`/`run()` — wrapper simples sobre `paramiko` (lib SSH
  em Python); `run()` executa um comando remoto e retorna
  stdout/stderr decodificados.
- Cada `evaluate_srXX()` é **independente** e recebe só o dado bruto já
  coletado (não reabre conexão SSH por critério) — os 5 comandos SSH
  (`cat pwquality.conf`, `chage -l`, `id -nG`, `ip -d link show eth0`,
  `cat sshd_config`) são todos disparados uma vez em `main()`, e cada
  função de avaliação só parseia o texto que já chegou. Isso evita
  5-6 round-trips SSH desnecessários.
- `parse_pwquality()` / `parse_chage()` são parsers de texto simples
  via regex/split — não há biblioteca pra isso porque são formatos de
  saída de comando Linux padrão, não XML/JSON estruturado.
- Cada `evaluate_srXX()` retorna uma lista de tuplas
  `(label, ok, detail)`, com `ok` podendo ser `True`/`False`/`None`
  (`None` = "não definido", não "não conforme" — distinção que o
  relatório final respeita, ver `marca()`).

**Decisões de design que valem a pena destacar:**
- **SR 1.3 (`ucredit`) — divergência deliberada do artigo original**,
  documentada na docstring: o artigo original marca `ucredit=-1` como
  "Não definido", mas pela semântica real do `pwquality` um valor
  negativo significa "exige no mínimo N caracteres dessa classe" — ou
  seja, é uma exigência ativa, não ausência de configuração. Por isso
  este projeto trata `ucredit=-1` como **Conforme**, corrigindo o que
  entendemos ser uma leitura imprecisa do artigo original. Isso é bom
  de mencionar: mostra leitura crítica do artigo, não cópia cega.
- **SR 3.1 — a única avaliação sem SSH.** `evaluate_sr31()` não lê
  nenhuma configuração de host — é uma constatação estrutural do
  próprio protocolo GOOSE (sem IEC 62351-6 não há assinatura digital
  nativa), e o código deixa isso explícito citando que foi **confirmado
  empiricamente** pelo ataque de masquerade (módulo `atacante/`). É o
  ponto de conexão entre o Oráculo e os testes de ataque — vale
  explicitar essa ligação na apresentação.
- **SR 7.1 — por que comparar com `"10:30:100"` especificamente:**
  esse é o valor **padrão de fábrica** do Ubuntu pra `MaxStartups` no
  `sshd_config`. A lógica assume que, se o valor ainda é o padrão,
  ninguém configurou rate limiting de propósito — só conta como
  conforme se foi customizado.

**Pergunta provável: "por que usuário/senha fixos como default
(`usuario_IED`/`senha123`)?"**
Resposta: são as credenciais padrão da imagem `ubuntu-ied` (ver
`ubuntu-ied/Dockerfile`/`entrypoint.sh`), usadas pra simular justamente
o cenário de credencial fraca que o SR 1.1 audita. Dá pra sobrescrever
via `--user`/`--password` se o IED tiver outra credencial.

---

## 4. `atacante/goose_frame.py` / `ids/goose_frame.py` — parser/builder de frames GOOSE

**Os dois arquivos são idênticos** (241 linhas cada) — o módulo é
duplicado entre `atacante/` e `ids/` de propósito, porque cada
container Docker é isolado e builda sua própria imagem; não há um
pacote Python compartilhado instalado nos dois. Se o professor
perguntar "por que duplicado em vez de uma lib compartilhada", essa é
a resposta direta: simplicidade de build por container, sem precisar
de um mecanismo de pacote interno pro escopo deste projeto.

**O que faz:** parse e reconstrução de frames GOOSE (Ethernet + PDU
ASN.1/BER), sem depender de uma lib ASN.1 completa.

**Decisão de design mais importante do projeto inteiro: `allData`
como blob opaco.**
O payload de dados do GOOSE (`allData`, estrutura MMS Data aninhada,
específica de cada fabricante/IED) **não é parseado** — é tratado como
bytes opacos, copiados de uma captura real e só mutilados em pontos
específicos (`flip_boolean_in_data()`, que localiza um valor booleano
de 1 byte por regex binária e inverte). A justificativa, que está na
docstring do módulo: reimplementar toda a árvore ASN.1/MMS Data seria
complexo e específico de fabricante, e **não é necessário** pros 4
testes de ataque propostos — um atacante real também faz isso (captura
e muta campos específicos, não reconstrói a semântica de negócio do
payload do zero).

**Como funciona o parser (`parse_ethernet_goose`):**
- Lê MACs (12 bytes), detecta e pula tag 802.1Q opcional (VLAN), lê
  ethertype (`0x88B8` = GOOSE), depois o cabeçalho GOOSE
  (APPID + length + 2 campos reservados), e por fim o PDU ASN.1 (tag
  `0x61`), delegando pra `parse_goose_pdu()`.
- `parse_goose_pdu()` é um parser **BER genérico mas simplificado**:
  lê tag/length/value em loop (`_read_ber_length` trata forma curta e
  longa do length BER), e usa uma tabela fixa `FIELD_TAGS`
  (`0x80`→`gocbRef`, `0x85`→`stNum`, etc — são tags *context-specific*,
  daí o padrão `0x80 | número_do_campo`) pra decodificar os campos
  escalares. Qualquer tag fora dessa tabela (exceto `allData`) cai em
  `_unknown`.

**Validação que já foi feita (vale citar se perguntarem "como sabem
que o parser está certo?"):** testado contra uma mensagem GOOSE real
de um relé SEL-351 — parse seguido de reconstrução (`build_*`) produz
**bytes idênticos** ao frame original capturado. Isso é forte: prova
que o parser/builder preserva a semântica binária exata do protocolo,
não é uma aproximação.

---

## 5. `atacante/goose_attack.py` — os 4 ataques

**O que faz:** CLI com 5 subcomandos (`capture` + os 4 ataques), cada
um carregando um "molde" (`.pcap` capturado) e montando um frame
derivado dele via `goose_frame.py`.

**Padrão comum aos 4 ataques:** `_load_template()` carrega o pcap e
faz parse com `parse_ethernet_goose`; cada ataque então copia o dict
de `fields`, muda só os campos relevantes (`stNum`/`sqNum`/`t`/MAC/um
byte do `allData`), e remonta com `build_ethernet_goose_frame`.

- **`cmd_flood`** — incrementa `sqNum` e timestamp a cada pacote, em
  loop com `time.sleep(1/pps)`, por `--duration` segundos. `stNum`
  **não muda** (não simula mudança de estado real, só volume).
- **`cmd_replay`** — não constrói nada, só reenvia o `pkts[0]` do pcap
  byte a byte depois de um delay.
- **`cmd_masquerade`** — usa `flip_boolean_in_data` pra inverter 1 bit
  de estado, incrementa `stNum` (simulando mudança real) e zera
  `sqNum`. O parâmetro `--src-mac`: se **omitido**, usa o mesmo MAC do
  molde (ataque "sofisticado", indetectável por heurística de MAC); se
  **passado**, usa um MAC diferente (ataque "ingênuo", detectável). Essa
  flag existe especificamente pra demonstrar o limite do IDS.
- **`cmd_suppress`** — soma `--jump` (padrão 1000) ao `stNum` real, sem
  tocar no payload.

**Pergunta provável: "o ataque funciona contra qualquer fabricante de
IED?"**
Resposta: o cabeçalho GOOSE (tags `0x80`-`0x8A`) é padronizado pela
IEC 61850-8-1, então sim. O `allData` em si é específico de fabricante,
mas como é tratado como blob opaco (não interpretado semanticamente),
o ataque funciona igual independente do fabricante — só muda o que
exatamente o bit invertido representa fisicamente (depende do dataset
de cada IED).

---

## 6. `ids/ids_core.py` — núcleo de detecção

**O que faz:** classe `GooseMonitor`, com estado por `gocbRef`
(`_last`, `_recent_times`, `_flood_state`), que recebe cada frame já
parseado (via `process()`) e retorna alertas.

**As 4 regras de detecção, uma por método:**
- `_check_flood()` — janela deslizante de `FLOOD_WINDOW_SECONDS` (2s)
  por `gocbRef`, usando um `deque` de timestamps; se
  `len(times)/window > threshold` (20 pkts/s), dispara. **Decisão de
  design importante:** só alerta na **borda** (`flood_start`/
  `flood_end`), não a cada pacote acima do limiar — senão um flood de
  2000 pps geraria 2000 alertas/segundo, inundando o próprio log do
  IDS. O estado (`_flood_state`) guarda se já está "ativo" pra não
  repetir o alerta de início.
- `_check_masquerade()` — compara `src_mac` contra o último MAC visto
  naquele `gocbRef`; qualquer mudança dispara alerta. É a única
  heurística possível sem autenticação criptográfica nativa — e é
  exatamente a heurística que o ataque C1 (masquerade com MAC
  idêntico) foi desenhado pra evadir.
- `_check_replay()` — compara a tupla `(stNum, sqNum)` recebida contra
  a última vista; se `<=`, é replay (a norma exige estritamente
  crescente).
- `_check_suppression()` — se `stNum - último_stNum > 50`
  (`SUPPRESSION_JUMP_THRESHOLD`), dispara.

**Detalhe sutil que vale explicar se perguntarem "como vocês evitam
que um replay 'valide' um valor antigo como se fosse o mais recente":**
em `process()`, o estado (`_last`) só é atualizado com o novo
`stNum`/`sqNum` se o frame **não** foi classificado como replay — mas o
MAC de origem é sempre atualizado, mesmo em replay, porque não faria
sentido comparar um eventual masquerade seguinte contra um MAC "velho".

**`tick()`** — chamado periodicamente pelo loop principal (`ids.py`,
a cada ~1s) mesmo sem pacote novo chegar; necessário porque, sem
tráfego de fundo constante, o **fim** de um flood nunca teria um
"próximo pacote" pra disparar a checagem de borda.

**Pergunta provável: "os limiares (20 pkts/s, salto de 50) são
calibrados em cima de quê?"**
Resposta honesta: são valores de referência ajustáveis via CLI
(`--flood-pps`, `--suppression-jump` em `ids.py`), escolhidos para
este ambiente de teste/demo, não derivados de uma análise estatística
de tráfego GOOSE real de produção. Isso é uma limitação assumida — item
de possível refinamento futuro (calibrar com tráfego GOOSE real de
campo, que tem taxas de publicação bem definidas pela norma em
situação de regime permanente vs. mudança de estado).

---

## 7. `ids/ids.py` — laço principal do IDS

**O que faz:** orquestra captura (Scapy `sniff`) + `GooseMonitor` +
emissão de alertas (stdout + opcionalmente `.jsonl`).

- Filtra só frames GOOSE na captura (`lfilter` comparando os bytes 12-13
  do frame cru contra `b"\x88\xb8"`, o ethertype GOOSE) — mais barato
  que fazer parse completo de todo pacote só pra descartar não-GOOSE.
- **Por que `sniff(..., timeout=1)` dentro de um loop `while`, em vez
  de um `sniff` único e infinito:** pra poder chamar `monitor.tick()`
  a cada ~1s mesmo sem pacote novo (ver explicação do `tick()` acima)
  — sem isso, um flood nunca teria seu alerta de fim disparado se o
  atacante simplesmente parasse de mandar pacotes.
- **Handler de sinal (`_handle_sigint`) em vez de confiar em
  `KeyboardInterrupt`:** o `sniff()` do Scapy intercepta Ctrl+C
  internamente para encerrar só aquela rodada de captura, sem deixar a
  exceção propagar pro resto do programa — então um `try/except
  KeyboardInterrupt` normal no loop não funcionaria de forma confiável.
  Um `signal.signal(SIGINT, ...)` roda independente disso.

---

## Perguntas gerais sobre o projeto como um todo

**"Por que Python simples em vez de Suricata/Zeek (IDS de mercado)
pro `ids-1`?"**
Documentado no próprio `ids/README.md`: suporte a protocolos
não-IP/não-TCP como GOOSE (que roda direto sobre Ethernet, sem
IP) não é confiável na versão estável do Suricata — por isso optou-se
por um detector próprio, com controle total sobre o parsing do
protocolo.

**"Qual a cobertura de teste/validação de tudo isso?"**
- `goose_frame.py`: parse+reconstrução testados contra captura real
  (bytes idênticos).
- `ids_core.py`: testado com 6 cenários sintéticos (tráfego normal +
  mudança de estado legítima sem falso positivo; os 4 ataques
  detectados corretamente) + 1 teste ponta-a-ponta real (ataque de
  masquerade gerado pelo `atacante/` e identificado pelo `ids-1`).
- Campanha completa (5 IEDs no Oráculo, 5 cenários de ataque) está em
  `docs/metodologia_proposta_gns3.md`.
- O que **ainda não** foi testado: `gerar_topologia_gns3.py` dentro do
  GNS3 real, e extração sobre um SCD real (não sintético) — ambos já
  documentados como itens do 4º Marco em `changelog/README.md`.

**"O que vocês fariam diferente/o que é mais frágil no projeto?"**
Resposta honesta e defensável:
1. Os limiares do IDS são arbitrários, não calibrados com tráfego real.
2. `allData` como blob opaco é suficiente pros testes propostos, mas
   não generaliza pra qualquer ataque que precise *interpretar* o
   payload semanticamente (ex.: forjar um valor específico de corrente
   elétrica, não só inverter um booleano).
3. A geração automática de topologia (`gerar_topologia_gns3.py`) ainda
   não foi validada dentro do GNS3 de verdade, só estruturalmente.
4. A métrica central (C1 não detectado) não é um bug — é o achado:
   evidencia por que GOOSE puro precisa de IEC 62351-6, não só
   detecção comportamental.
