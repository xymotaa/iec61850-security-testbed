# Conteúdo da apresentação — 3º Marco (20/10/2026)

Resultados parciais de reprodução. Texto pronto pra colar no slide de
vocês, slide a slide. Ajustem o número de slides conforme o tempo que
tiverem.

---

## Slide 1 — Capa

**Título:** Analisador Automático de Segurança Cibernética para o Setor Elétrico — Reprodução e Extensão

**Subtítulo:** 3º Marco — Resultados Parciais de Reprodução

Disciplina: Segurança em Redes de Computadores — Prof. Hugo Kuribayashi
Artigo original: Oliveira & Gurjão (UFCG), SBSeg 2025 — WTICG
[Nomes do grupo]

---

## Slide 2 — O artigo original

**O que ele propõe:**
- Extrai a estrutura de comunicação de uma subestação a partir de arquivos **SCL/SCD** (IEC 61850)
- Gera automaticamente a topologia num ambiente simulado (**GNS3**)
- Usa um container **"Oráculo"** que audita os IEDs via SSH contra a norma **IEC 62443-3-3**
- Verifica 2 critérios: SR 1.3 (força de senha) e SR 1.7 (expiração de senha)

**Trabalho futuro sugerido pelos próprios autores:** *"expandir os testes, incluir novos tipos de ataques e validar a metodologia em ambientes reais"*

→ Esse é exatamente o ponto de partida da nossa extensão.

---

## Slide 3 — Objetivo deste trabalho

- Reproduzir fielmente o pipeline do artigo original (extração → topologia → auditoria)
- Fechar uma lacuna do artigo: automatizar também a **geração da topologia GNS3**, não só a extração
- Estender a auditoria de conformidade de 2 para **8 critérios** da IEC 62443-3-3
- Implementar e testar **ataques ativos ao protocolo GOOSE**, respondendo diretamente à sugestão de trabalho futuro do artigo
- Desenvolver um **IDS próprio** para medir a eficácia de detecção desses ataques

---

## Slide 4 — Visão geral da arquitetura reproduzida

Topologia no GNS3 (Docker + GNS3, igual ao artigo original):

- 4 switches em estrela + switch central (GOOSE é multicast de Camada 2 — topologia em malha geraria loop, por isso estrela)
- 5 `ubuntu-ied` (IEDs simulados)
- `oraculo-1` — auditoria de conformidade
- `atacante-1` — ferramenta de ataque GOOSE *(extensão)*
- `ids-1` — detector de anomalias *(extensão)*

[Inserir aqui a imagem da topologia — print do GNS3 ou da Fig. 2 do artigo original lado a lado com a de vocês]

---

## Slide 5 — Extração de dados do SCD (reproduzido + estendido)

**Artigo original:** extrai apenas IP, máscara e nome de cada IED.

**Nossa extensão (`extracao-scd/extrair_scd.py`):** além disso, extrai os blocos de controle:
- **GOOSE**: `gocbRef`, `datSet`, MAC, APPID, VLAN
- **SV (Sampled Values)**: `smvID` + mesmo endereçamento

Esses dados são o que alimenta os testes de ataque GOOSE mostrados mais adiante — sem extrair `gocbRef`/MAC reais não daria pra montar ataques realistas.

[Inserir print do `dados.json` gerado ou da saída do script]

---

## Slide 6 — Novidade deste marco: geração automática da topologia

**Lacuna identificada:** o artigo original tem um fluxo completo (Fig. 1): *Extração → Modelagem → GNS3*. Até o marco anterior, nós tínhamos só a extração — a topologia era montada **manualmente** no GNS3.

**O que foi fechado agora:** `extracao-scd/gerar_topologia_gns3.py`
- Consome o `dados.json` da extração
- Gera um arquivo `.gns3` pronto para abrir no GNS3
- Reproduz a mesma topologia em estrela (4 switches + IEDs + Oráculo + atacante + IDS)
- Fluxo completo: **SCD → JSON → `.gns3`**, igual ao artigo original

[Inserir print do comando rodando + do projeto aberto no GNS3]

---

## Slide 7 — Oráculo: conformidade IEC 62443-3-3 (reproduzido + estendido)

**Artigo original:** 2 critérios (SR 1.3, SR 1.7).

**Nossa extensão:** 8 critérios — SR 1.1, 1.3, 1.5, 1.7, 2.1, 3.1, 5.1, 7.1.

**Resultado nos 5 IEDs simulados (192.168.10.11 a .15):**

| SR | Critério | Resultado |
|---|---|---|
| 1.1 | Credencial padrão/hardcoded | ❌ Não conforme |
| 1.3 | Comprimento mínimo (minlen=8) | ✅ Conforme |
| 1.3 | Exige dígito / minúscula / especial | ❌ Não conforme |
| 1.5 | Expiração de senha existe | ❌ Não conforme |
| 1.7 | Troca periódica (90–180 dias) | ❌ Não conforme |
| 2.1 | Conta sem privilégio admin | ✅ Conforme |
| 3.1 | Integridade das mensagens GOOSE | ❌ Não conforme (sem IEC 62351-6) |
| 5.1 | Segmentação de rede (VLAN) | ❌ Não conforme |
| 7.1 | Anti-DoS (rate limiting) | ❌ Não conforme |

**3 de 12 verificações conformes**, resultado **idêntico nos 5 IEDs** — achado relevante: mesma imagem base, mesma vulnerabilidade na frota inteira (risco real em ambientes OT).

---

## Slide 8 — Extensão: ataques ao protocolo GOOSE

Resposta direta à sugestão de trabalho futuro do artigo original.

Metodologia dos 4 testes (baseada na taxonomia PowerDuck): captura-se uma mensagem GOOSE real como **molde**, e cada ataque manipula campos específicos do cabeçalho (`stNum`, `sqNum`, `t`, MAC) reaproveitando o payload original — é o que um atacante real faz (não reconstrói a estrutura ASN.1 do zero).

| Teste | Tipo |
|---|---|
| A | Flooding (DoS) |
| B | Replay |
| C | Masquerade / Insertion |
| D | Suppression |

---

## Slide 9 — Ataque A: Flooding

**Como funciona:** reenvia o molde em alta taxa (`--pps`), incrementando `sqNum` e atualizando o timestamp a cada pacote, sem mudar `stNum` (não é mudança de estado real, é volume). Objetivo: saturar o barramento L2 e sobrecarregar os assinantes GOOSE.

**Regra de detecção do `ids-1`:** taxa de pacotes numa janela deslizante de 2s por `gocbRef`; alerta na borda (início/fim), não a cada pacote.

**Resultado medido:** `FLOOD_START` a 20,5 pkts/s (limite 20); `FLOOD_END` após 9,6s, pico de 34,0 pkts/s.

**✅ Detectado.**

---

## Slide 10 — Ataque B: Replay

**Como funciona:** reenvia o frame capturado byte a byte, sem nenhuma alteração — simula um atacante que apenas re-injeta tráfego legítimo antigo (ex.: um comando antigo de trip de disjuntor).

**Regra de detecção:** IEC 61850 exige `(stNum, sqNum)` estritamente crescentes por `gocbRef`. Se o par recebido é `≤` ao último visto, é replay.

**Resultado medido:** detectado já no 2º envio — `(stNum=23, sqNum=521)` idêntico ao já visto.

**✅ Detectado.**

---

## Slide 11 — Ataque C: Masquerade/Insertion (achado central)

**Como funciona:** forja uma mensagem nova com um bit de estado invertido no payload (ex.: status de disjuntor), `stNum` incrementado e `sqNum` reiniciado — simula uma mudança de estado real. Dois modos:

- **C1 — atacante sofisticado:** usa o **mesmo MAC** do IED legítimo
- **C2 — atacante ingênuo:** usa um MAC próprio/forjado

**Regra de detecção:** compara o MAC de origem contra o último visto naquele `gocbRef` — GOOSE puro não tem assinatura criptográfica, então é a única heurística possível.

**Resultado medido:**
- C1 (MAC idêntico): **0 alertas — passa despercebido**
- C2 (MAC forjado): detectado — "MAC mudou de X para Y"

---

## Slide 12 — Por que o masquerade C1 importa

Um atacante que também falsifica a camada 2 (MAC spoofing — trivial em qualquer switch sem port security/802.1X) é **completamente invisível** para um IDS baseado em heurística de rede.

**Implicação:** nenhuma heurística de tráfego resolve esse caso — só proteção criptográfica nativa na própria mensagem (**IEC 62351-6**) resolveria.

Esse é o achado mais forte da nossa extensão: validamos empiricamente, com ataque e detector próprios, uma limitação estrutural do protocolo GOOSE que a literatura já apontava teoricamente.

---

## Slide 13 — Ataque D: Suppression

**Como funciona:** envia um frame com `stNum` saltado muito à frente do real (`--jump`, ex. 1000). Assinantes descartam qualquer mensagem com `stNum` igual ou menor ao último aceito — logo, **todas** as mensagens legítimas subsequentes do IED real passam a ser descartadas como "antigas". Suprime a comunicação sem precisar inundar a rede.

**Regra de detecção:** salto de `stNum` acima de um limiar de plausibilidade (50) é tratado como anômalo.

**Resultado medido:** `stNum` saltou de 23 para 1023 (salto de 1000).

**✅ Detectado.**

---

## Slide 14 — Métricas consolidadas

| Cenário | Detectado | Taxa |
|---|---|---|
| Geral (A, B, C1, C2, D) | 4/5 | **80%** |
| Contra atacante "ingênuo" (A, B, C2, D) | 4/4 | **100%** |
| Contra atacante "sofisticado" (C1) | 0/1 | **0%** |
| Falsos positivos | — | **0** |

**Narrativa:** o IDS heurístico é eficaz contra os vetores clássicos do protocolo GOOSE, mas tem um limite estrutural claro contra um atacante que também falsifica a camada 2 — reforça empiricamente a necessidade da IEC 62351-6 como mitigação definitiva, não apenas detecção comportamental.

---

## Slide 15 — Comparativo: artigo original × nossa reprodução

| Etapa | Artigo original | Este projeto |
|---|---|---|
| Extração SCD | IP, máscara, nome | + blocos GOOSE/SV (MAC, APPID, VLAN) |
| Topologia GNS3 | Gerada automaticamente | Gerada automaticamente *(fechado neste marco)* |
| Auditoria de conformidade | 2 critérios (SR 1.3, 1.7) | 8 critérios (IEC 62443-3-3) |
| Testes de ataque | Nenhum (sugerido como trabalho futuro) | 4 ataques GOOSE + IDS próprio |
| Detecção/métricas | — | 80% geral, 0 falsos positivos |

---

## Slide 16 — Próximos passos (4º e 5º Marco)

**4º Marco (09/11):**
- Validar o `.gns3` gerado automaticamente dentro do GNS3 real (abrir, conectar templates, testar a rede)
- Rodar a extração sobre um SCD real de subestação (hoje é um exemplo sintético)
- Campanha de testes do IDS com mais repetições por cenário

**5º Marco (23/11) — resultados finais:**
- Resumo expandido em formato SBC (Overleaf)
- Relatório final consolidado com todas as métricas
- Seção de limitações e trabalhos futuros, incluindo a necessidade de IEC 62351-6

---

## Slide 17 — Encerramento

**Resumo da entrega deste marco:**
- Pipeline completo do artigo original reproduzido e automatizado de ponta a ponta (SCD → topologia → auditoria)
- Auditoria de conformidade ampliada em 4x (2 → 8 critérios)
- Extensão de segurança ativa: 4 ataques GOOSE + IDS próprio, respondendo à sugestão de trabalho futuro do artigo original
- Achado relevante: limite estrutural da detecção heurística contra masquerade com MAC falsificado, reforçando a necessidade de IEC 62351-6

Dúvidas?

---

## Apêndice (slide de reserva, se sobrar tempo ou houver pergunta técnica)

- Mecânica de manipulação de campos GOOSE (`stNum`/`sqNum`/`t`) em cada ataque
- Detalhe da janela deslizante de detecção de flood (2s, limiar 20 pkts/s)
- Print ao vivo do console do `ids-1` reagindo em tempo real (ver `changelog/roteiro-demo.md` para os comandos exatos da demonstração)
