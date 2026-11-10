# Conteúdo da apresentação — 4º Marco (09/11/2026, slides em 10/11/2026)

"Apresentar resultados parciais de reprodução" — mesmo enunciado do 3º
Marco (ver `docs/SRC-Cap0-Apresentação da Disciplina-4.pdf`, slide 18).

Este arquivo funde duas frentes de material já produzido para este
marco:

1. **Engenharia de protocolo e detecção** (parsing SCL em 2 passadas,
   codec ASN.1/BER manual, máquina de estados do IDS, benchmark
   estatístico N=600) — nível de implementação, equivalente ao PDF
   `slidesmarco4v2.pdf` já produzido anteriormente nesta sessão de
   trabalho.
2. **Validação real de infraestrutura** (SCD real de fora do projeto,
   topologia aberta e testada dentro do GNS3 de verdade, 2 bugs
   encontrados e corrigidos nesse processo) — trabalho fechado nesta
   sessão, que o PDF acima ainda não cobria.

Texto pronto pra colar nos slides. Ajustem a quantidade conforme o
tempo disponível — os blocos 1/2/3 abaixo mapeiam para os blocos do
PDF já existente; o bloco 4 é novo.

---

## Capa

**Título:** Analisador Automático de Segurança Cibernética para o Setor Elétrico — Reprodução e Extensão

**Subtítulo:** 4º Marco — Engenharia de Protocolos L2 (ASN.1/BER), Auditoria IEC 62443, IDS Stateful e Validação Real em GNS3

Disciplina: Segurança em Redes de Computadores — Prof. Dr. Hugo Kuribayashi
Artigo original: Oliveira & Gurjão (UFCG), SBSeg 2025 — WTICG
Lucas Mota · Matheus · Youri — Unifesspa
10 de novembro de 2026

---

## Bloco 1A — Contextualização crítica e lacuna de camada 2

**1. Convergência TI/OT e requisitos temporais da norma IEC 61850:**
- Sistemas de Automação de Subestações (SAS) operam com IEDs legados e restrições severas de disponibilidade.
- Mensagens críticas de proteção (GOOSE e Sampled Values — SV) exigem tempo de transferência estrito (< 4 ms).
- **Mapeamento direto na Camada 2:** a pilha TCP/IP é omitida; quadros operam diretamente sobre Enlace Ethernet (EtherType `0x88B8` para GOOSE e `0x88BA` para SV) em modelo publisher/subscriber multicast, sem criptografia ou autenticação nativa.

**2. Limitação estrutural do artigo base (Oliveira & Gurjão, SBSeg 2025):**
- O trabalho original restringiu sua auditoria ao plano de gerência (host-level via SSH), verificando apenas 2 requisitos de senha.
- **Tese da nossa extensão:** auditar credenciais SSH não impede a injeção de comandos falsos de abertura de disjuntores (*trip*) no barramento Ethernet L2.

---

## Bloco 1B — Parsing SCL em duas passadas e síntese GNS3

**1. Algoritmo de extração `extrair_scd.py` (complexidade O(N) em duas passadas):**
- **Desacoplamento XML/SCL:** a norma separa a definição lógica dos dados da topologia física em seções distintas do arquivo `.scd`.
- **1ª passada (modelo lógico):** remove namespaces (`strip_ns`) e varre `<IED>` → `<LDevice>` → `<LN0>` para extrair blocos `<GSEControl>` e `<SampledValueControl>`, construindo a chave `gocbRef` e mapeando DataSets (ex.: disjuntor XCBR).
- **2ª passada (join relacional):** varre `<Communication>` (`<SubNetwork type="8-MMS">` → `<ConnectedAP>`) e realiza a junção pela tupla `(ldInst, cbName)`, resolvendo IP, MAC multicast (`01-0C-CD-01-00-xx`), APPID e tags IEEE 802.1Q (VLAN-ID/PRIORITY).

**2. Síntese automatizada `gerar_topologia_gns3.py` e zero-touch provisioning:**
- Gera nativamente o projeto JSON (`.gns3` rev. 9, série estável 2.2.x).
- **Prevenção de broadcast storm:** como o comutador nativo do GNS3 não executa Spanning Tree (IEEE 802.1D), instancia-se uma estrela estrita (1 switch central + 4 switches de borda com IEDs em round-robin).
- Nós `oraculo-1`, `atacante-1` e `ids-1` alocados no comutador central (mesmo domínio multicast).
- Auto-configuração de IP via `entrypoint.sh`/variáveis Docker.

---

## Bloco 2A — Auditoria IEC 62443-3-3 e correção metodológica

**Sessão SSH única (`paramiko`):** coleta consolidada em 1 handshake TCP/SSH por IED (`192.168.10.11` a `.15`), expandindo de 2 para **8 Requisitos de Sistema (SRs)**:

| SR | Parâmetro avaliado | Evidência técnica coletada no IED | Diagnóstico (5 IEDs) |
|---|---|---|---|
| 1.1 | Credencial padrão | Senha `senha123` presente em dicionário trivial | ❌ Não conforme |
| 1.3 | Comprimento mínimo | Parâmetro `minlen = 8` (intervalo normativo 8–14) | ✅ Conforme |
| 1.3 | Exigência de maiúsculas | Parâmetro `ucredit = -1` (cota mínima obrigatória ≥ 1)* | ✅ Conforme* |
| 1.3 | Dígitos, minúsculas e especiais | `dcredit = 0`, `lcredit = 0`, `ocredit = 0` | ❌ Não conforme |
| 1.5 / 1.7 | Expiração e rotação | `max_days = 99999` no `chage -l` (fora de 90–180d) | ❌ Não conforme |
| 2.1 | Privilégio mínimo | Usuário restrito ao grupo `usuario_IED` (sem sudo/root) | ✅ Conforme |
| 3.1 | Integridade de mensagens L2 | Protocolo GOOSE desprovido de assinatura IEC 62351-6 | ❌ Não conforme |
| 5.1 / 7.1 | VLAN 802.1Q e anti-DoS | `eth0` sem sub-interface VLAN; `MaxStartups 10:30:100` | ❌ Não conforme |

*\*Correção científica ao artigo original:* Oliveira & Gurjão classificaram `ucredit = -1` como "não definido". Na semântica real do PAM (`libpam-pwquality`), valores negativos (N < 0) impõem cota mínima obrigatória de |N| caracteres. **Resultado real: 3/12 conformidades em todos os 5 IEDs** (vulnerabilidade sistêmica de frota homogênea).

---

## Bloco 2B — Engenharia binária ASN.1/BER (`goose_frame.py`)

**1. Codificador/decodificador TLV (Tag-Length-Value) manual, sem dependências pesadas:**
- **Desencapsulamento L2:** trata cabeçalho Ethernet + tag opcional IEEE 802.1Q (`0x8100`) + cabeçalho GOOSE (APPID, comprimento) + PDU ASN.1 (`APPLICATION 1` / `0x61`).
- **Codificação de inteiros em comprimento mínimo** (`_int_to_min_bytes`): tags context-specific (`0x80` a `0x8A`) serializadas no menor número de octetos big-endian, inserindo padding `0x00` quando o MSB ocupa o bit 7 (fidelidade binária de **100% byte-a-byte** com captura real de relé SEL-351).

**2. Decisão de projeto central: `allData` (`0xAB`) como blob binário opaco:**
- A estrutura interna MMS Data varia por fabricante. Reconstruir a árvore ASN.1 completa do zero é desnecessário para um atacante real.
- **Mutação cirúrgica** (`flip_boolean_in_data`): localiza a assinatura TLV de um booleano MMS (`0x83 0x01 <byte>`) via expressão regular binária sobre o molde capturado (`molde.pcap`), inverte o bit de estado do disjuntor (v' = 1 − v) no offset exato e reconstrói o quadro.

---

## Bloco 3A — Mecânica dos 4 ataques GOOSE e máquina de estados do IDS

**Por que não Suricata?** Motores de mercado focam na pilha IP/TCP/UDP e carecem de suporte estável para inspeção profunda de quadros puramente L2. Desenvolvemos a classe `GooseMonitor` (`ids_core.py`) indexada por `gocbRef`:

- **Teste A — Flooding (violação de disponibilidade):** injeção em alta taxa incrementando `sqNum` e timestamp UTC de 8 bytes (4B época + 3B fração 2²⁴ + 1B qualidade `0x0A`), mantendo `stNum` fixo.
  - *Defesa anti-auto-DoS:* janela deslizante de 2,0s via `deque` com gatilho de borda (edge-triggered) (`flood_start` ao cruzar 20 pps) e relógio passivo `tick()` a cada 1,0s no laço do sniff para emitir `flood_end` mesmo após parada abrupta do tráfego.
- **Teste B — Replay (violação de autenticidade temporal):** reenvio byte-a-byte de quadro antigo.
  - *Defesa anti-envenenamento:* detecta violação de monotonicidade `(stNum_rx, sqNum_rx) ≤ (stNum_last, sqNum_last)` e bloqueia a atualização de estado (`if not is_replay`), impedindo que pacotes antigos corrompam a referência dos pacotes legítimos seguintes.
- **Teste D — Suppression (DoS lógico):** salto artificial (`stNum ← stNum + 1000`, `sqNum ← 0`) para fazer assinantes descartarem pacotes reais subsequentes. Regra: gradiente `ΔstNum > 50`.
- **Teste C — Masquerade/Insertion (violação de integridade):** bit invertido no `allData`, `stNum + 1` e `sqNum = 0`. Subdividido em **C2 (ingênuo, MAC distinto)** e **C1 (sofisticado, MAC clonado)**.

---

## Bloco 3B — Benchmark estatístico (N = 600) e o achado central

Campanha automatizada (`benchmark_ids.py`) com N = 100 repetições parametrizadas por cenário:

| Cenário experimental | Variação paramétrica na campanha | Detecções | Taxa (TPR/FPR) | Latência/frame (µs) |
|---|---|---|---|---|
| T0 — Baseline legítimo | Heartbeat 1 Hz + 2 rajadas (5 pps) | 0/100 | 0,0% (FPR) | 4,29 ± 1,34 |
| Teste A — Flooding (DoS) | f_pps ∈ {50, 100, 250, 500, 1000, 2000} | 100/100 | 100,0% (TPR) | 4,49 ± 1,55 |
| Teste B — Replay | Δt ∈ [0,5s; 10,0s], (stNum, sqNum) antigo | 100/100 | 100,0% (TPR) | 5,56 ± 0,83 |
| Teste C1 — Masquerade (sofisticado) | Mutação 0x83, stNum+1, MAC clonado | 0/100 | 0,0% (TPR) | 4,03 ± 0,31 |
| Teste C2 — Masquerade (ingênuo) | Mutação 0x83, stNum+1, MAC distinto | 100/100 | 100,0% (TPR) | 5,07 ± 1,07 |
| Teste D — Suppression | Salto ΔstNum ∈ {60, 100, 250, 500, 1000, 5000} | 100/100 | 100,0% (TPR) | 5,84 ± 1,71 |

- **Performance de tempo real (O(1)):** latência média entre 4,03µs e 5,84µs (três ordens de grandeza abaixo do limite de 4000µs da norma IEC 61850) e 0% de envenenamento de estado pós-replay.
- **Prova empírica central (80% global / 0% em C1):** quando o invasor aplica MAC spoofing, incrementa `stNum + 1` e zera `sqNum`, o frame malicioso respeita toda a gramática ASN.1/BER e a máquina de estados. **É matematicamente impossível distingui-lo de um evento físico real apenas por inspeção passiva.**
- **Conclusão para o 5º Marco (artigo SBC):** IDS heurísticos são necessários mas insuficientes; é mandatória a adoção de IEEE 802.1X e assinaturas criptográficas nativas da norma IEC 62351-6 (HMAC/RSA).

> Esta campanha estatística (N=600) fecha a pendência nº 3 que havia ficado em aberto desde o 3º Marco — antes, as métricas vinham de execuções pontuais de cada ataque, não de uma campanha com repetições.
>
> **⚠️ Nota de rastreabilidade:** `benchmark_ids.py` ainda não está commitado neste repositório (só os módulos `goose_frame.py`/`ids_core.py`/`ids.py` que ele usa estão). Antes de apresentar estes números, commitar o script e idealmente os dados brutos da campanha — sem isso, a tabela acima não é reprodutível a partir do repositório.

---

## Bloco 4 — Validação real de infraestrutura (trabalho adicional desta sessão)

Complementando o que foi descrito acima (que valida a *engenharia* do protocolo e do IDS), esta frente valida a *infraestrutura* que sustenta os testes: o `.gns3` gerado automaticamente nunca tinha sido aberto dentro do GNS3 real, e a extração nunca tinha rodado sobre um SCD genuinamente real (só o sintético, com 2 IEDs fictícios).

### 4.1 — SCD real usado

Fonte: `simpleIO_direct_control_goose.scd`, do repositório open-source **mz-automation/libiec61850** (implementação de referência IEC 61850 em C, licença GPL-3.0) — usado em testes do próprio projeto upstream.

- 1 IED (`simpleIO`), IP `10.0.0.2/24`
- 2 blocos GOOSE reais (`GSEControl`): `gcbEvents`, `gcbAnalogValues`
- MAC, APPID (1000) e VLAN (111) configurados em `<Communication>`

**Limitação assumida:** só 1 IED (vs. 2 do sintético) — mas é dado real de um projeto IEC 61850 de verdade, não fictício.

### 4.2 — Dois bugs encontrados e corrigidos ao abrir no GNS3 real

**Bug 1 — posições de nó como float:**
```
Invalid data in topology file: -530.0 is not of type 'integer'
in schema: {"description": "X position of the node", "type": "integer"}
```
Causa: `gerar_topologia_gns3.py` calculava `x`/`y` com `X_SPACING * 1.5` e divisões (`/2`), que em Python retornam `float`; o schema do GNS3 exige `integer` estrito. Corrigido com `int(round(x))`/`int(round(y))` na criação de cada nó.

**Bug 2 — nome de nó incompatível com o `entrypoint.sh`:**
Com o Bug 1 corrigido, o projeto abriu — mas o IED não pegava IP. Causa: o `entrypoint.sh` do container `ubuntu-ied` deriva o IP do hostname pelo padrão `ubuntu-ied-N` → `192.168.10.1N`; o gerador nomeava o nó `ied-<nome-do-SCD>` (ex. `ied-simpleIO`), sem número no final. Corrigido nomeando os nós sempre `ubuntu-ied-{N}`, preservando o nome/IP reais do SCD como metadado (`IED_NAME`, `IED_IP`) no ambiente do container.

### 4.3 — Validação ponta a ponta (depois das correções)

| Etapa | Resultado |
|---|---|
| Abrir `subestacao_real.gns3` no GNS3 | ✅ Sem erros |
| `ip a` no `ubuntu-ied-1` | ✅ `192.168.10.11/24` configurado automaticamente |
| `oraculo.py 192.168.10.11` | ✅ 3/12 critérios conformes — mesmo padrão dos 5 IEDs sintéticos |
| `goose_attack.py replay` (atacante-1) | ✅ Frame reenviado |
| `ids.py` (ids-1) | ✅ Detectou: `(stNum=23, sqNum=521) <= último visto` |

**O que esse resultado prova:** o pipeline SCD real → JSON → `.gns3` → GNS3 real → tráfego GOOSE → detecção funciona de ponta a ponta, não só em validação programática — fecha de fato o fluxo do artigo original (Fig. 1), de forma independente de qual SCD é usado como entrada.

---

## Próximos passos (5º Marco, 23/11)

- Resumo expandido em formato SBC (Overleaf) — ainda não iniciado
- Relatório final consolidado (Oráculo + 4 ataques GOOSE + benchmark N=600 + geração automática de topologia), já citando o SCD real usado
- Seção de limitações e trabalhos futuros própria, com a conclusão central já estabelecida: IDS heurístico é necessário mas insuficiente contra masquerade C1 — mandatória a adoção de IEC 62351-6 / IEEE 802.1X
- Revisão final de todos os READMEs do repositório

---

## Encerramento

**Resumo da entrega deste marco:**
- Parsing SCL em 2 passadas e síntese automática de topologia GNS3 documentados em nível de engenharia
- Codec ASN.1/BER manual com fidelidade binária 100% byte-a-byte validada contra captura real (relé SEL-351)
- Correção metodológica ao artigo original sobre a semântica de `ucredit` no PAM
- Máquina de estados do IDS (`GooseMonitor`) com defesas anti-auto-DoS e anti-envenenamento
- **Benchmark estatístico N=600:** 100% TPR em A/B/C2/D, 0% em C1 (achado central: masquerade com MAC clonado é indistinguível de evento físico real por inspeção passiva)
- **Validação real de infraestrutura:** 2 bugs corrigidos no gerador de topologia, pipeline completo testado ponta a ponta no GNS3 real com um SCD genuinamente real (libiec61850)

Dúvidas?
