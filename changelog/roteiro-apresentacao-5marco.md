# Roteiro da apresentação: 5º Marco (23/11/2026, resultados finais): 10 minutos

Enunciado do marco (`docs/SRC-Cap0-Apresentação da Disciplina-4.pdf`): *apresentar resultados finais e entrega de artigo (resumo expandido)*.

Complementa [`conteudo-apresentacao-5marco.md`](conteudo-apresentacao-5marco.md) (texto longo dos slides) com **tempo, fala e cuidados** por slide, alinhado ao artigo (`artigo/versao-2/main.pdf`). Onde os dois divergem, vale este (números e termos do artigo).

**Duração: 10 min, 9 slides, sem demo ao vivo** (o plano B e a demo opcional estão no fim). Ritmo: ≈130 palavras por minuto; a fala de cada slide já está no tamanho do tempo. Divisão entre os apresentadores: definam entre vocês; os pontos naturais de troca são depois dos slides 3 e 5.

**Regra de ouro da fala:** dizer sempre o que é **simulação** (HMAC estilo IEC 62351-6; campanha *offline*) e o que é **real** (802.1X com EAP-TLS no GNS3). Nunca dizer "implementamos a IEC 62351-6".

---

## Tempos

| # | Slide | Tempo |
|---|---|---|
| 1 | Capa | 0:20 |
| 2 | Problema, achado do 4º Marco e pergunta | 1:00 |
| 3 | Ambiente e o que é real × simulado | 1:00 |
| 4 | As três camadas de defesa | 1:30 |
| 5 | Resultados da campanha *offline* (com limiar e custo) | 1:45 |
| 6 | Resultados no GNS3 | 1:45 |
| 7 | Síntese: onde cada camada falha | 1:00 |
| 8 | Limitações e reprodutibilidade | 1:00 |
| 9 | Conclusão | 0:40 |
| | **Total** | **10:00** |

**Se estourar o tempo:** corte primeiro a última frase do slide 5 (limiar e custo, 15 s) e depois o slide 8 vira três itens (30 s).

---

## Slide 1: Capa (0:20)

**Slide:** *Masquerade em GOOSE: por que IDS de estado, autenticação por mensagem (HMAC) e 802.1X, isoladamente, não bastam.* Lucas Mota · Matheus · Youri, Unifesspa. Segurança em Redes de Computadores, Prof. Dr. Hugo Kuribayashi. 23/11/2026.

**Fala:** "Esta é a entrega final da reprodução do artigo de Oliveira e Gurjão, do SBSeg 2025. Hoje mostramos o que barra o ataque que o nosso IDS não via, e onde cada defesa falha."

---

## Slide 2: Problema, achado do 4º Marco e pergunta (1:00)

**Slide:**
- GOOSE: multicast de camada 2 (EtherType `0x88B8`), sem autenticação nativa. O artigo base audita só o plano de gerência (SSH).
- 4 ataques: flooding, replay, masquerade, suppression.
- **Achado do 4º Marco:** masquerade com MAC clonado (**C1**) tem **0% de detecção** pelo IDS de estado.
- **Pergunta:** o que cobrem IDS de estado, HMAC e 802.1X contra o C1 (MAC clonado) e o C2 (MAC próprio), onde cada um falha e como se compensam?

**Fala:** "No C1 o quadro forjado respeita toda a regra de estado: `stNum` mais um, `sqNum` zerado e o MAC do próprio publicador. Para um IDS passivo, é igual a um evento real. A pergunta de hoje é o que realmente barra isso. Não queremos dizer que uma defesa é melhor, e sim o que cada uma cobre e onde quebra."

**Cuidado:** não citar "N=600" nem "limite de 4 ms da norma" (perguntas 5 e 6).

---

## Slide 3: Ambiente e o que é real × simulado (1:00)

**Slide:**
- Todos os quadros derivam de **um único quadro** capturado de um relé SEL-351 (`molde.pcap`, 367 bytes).
- **Três ambientes, não somados:** campanha *offline* (100 repetições por cenário e modo); GNS3 (1 execução por cenário); *network namespaces* (30 verificações por execução).
- **Simulação:** HMAC e campanha *offline*. **Real:** `hostapd`, `wpa_supplicant` e `nftables` (802.1X EAP-TLS).
- **Não há assinante GOOSE** nem IED publicador independente.

**Fala:** "O publicador é emulado pela mesma ferramenta do atacante, e não há assinante. Por isso não medimos o efeito de um quadro forjado sobre um disjuntor. Medimos o que cada camada detecta ou barra."

---

## Slide 4: As três camadas de defesa (1:30)

**Slide:** três colunas.

| IDS de estado | HMAC (simulado) | 802.1X com EAP-TLS (real) |
|---|---|---|
| Passivo: só alerta | HMAC-SHA256 de 32 bytes por quadro, em um trailer | `autenticador-8021x`: ninguém troca tráfego sem certificado X.509 |
| Estado por `gocbRef` | Cobre `gocbRef`, `stNum`, `sqNum`, `t`, `allData` (não cobre o MAC) | **Vínculo certificado × MAC** (inventário CN→MAC do SCD) |
| Regras: replay, suppression > 50, MAC diferente, flooding > 20 pacotes/s | Chave de teste, **pública**; sem gestão de chaves | CRL; par (porta, MAC) fixo após autenticar; PKI de laboratório |

**Fala:** "O IDS não descarta quadros. O HMAC é uma simulação da ideia da IEC 62351-6, não uma implementação conforme; e a 'chave vazada' é a chave-mestra inteira. O 802.1X é real, e o vínculo entre certificado e MAC é decisão nossa, não do padrão."

---

## Slide 5: Resultados da campanha offline (1:45)

**Slide:** (Tabela 13 do artigo; 100 repetições por célula)

| Cenário | Sem HMAC | HMAC, sem a chave | HMAC, chave vazada |
|---|---|---|---|
| T0, falso positivo | 0/100 | 0/100 | 0/100 |
| A, flooding | 100/100 | 100/100 | 100/100 |
| B, replay | 100/100 | 100/100 | 100/100 |
| **C1, MAC clonado** | **0/100** | **100/100** | **0/100** |
| C2, MAC distinto | 100/100 | 100/100 | 100/100 |
| D, suppression | 100/100 | 100/100 | 100/100 |

Rodapé: limiar de flooding 20 pacotes/s: 0% até 18, 100% a partir de 22; rajada legítima de 20 pacotes/s: 73% de falso positivo. Custo por quadro ≈95 µs no pior caso (Python).

**Fala:** "Sem HMAC, o C1 passa em 100%. Com HMAC e sem a chave, a verificação rejeita o quadro: `auth_fail`, e quem classifica é a verificação criptográfica, não o IDS. Com a chave vazada, o C1 volta a passar. O replay de um quadro assinado continua dependendo do estado do IDS. O limiar de flooding é um degrau: ataque lento abaixo dele passa. E o custo por quadro, em Python, é de dezenas de microssegundos; não medimos o EAP-TLS."

**Cuidados:** 0% e 100% saem assim porque os quadros são determinísticos; o IC de Wilson mede a incerteza. O 4 ms é critério experimental nosso, não da norma.

---

## Slide 6: Resultados no GNS3 (1:45)

**Slide:** (Tabela 15 do artigo; **1 execução por cenário**, 20/11/2026)

| Cenário | Efeito observado |
|---|---|
| E0, sem 802.1X | `ping` 3/3; **C1 sem alerta no IDS** |
| E1, sem certificado, MAC clonado | `ping` 0/3; quadros descartados |
| E2, certificado revogado | `certificado_revogado`; `ping` 0/3 |
| E3, certificado válido do nó comprometido, MAC de um IED | `mac_divergente`; `ping` 0/3 |
| E4, certificado válido, MAC próprio | autentica; alerta `masquerade` (só o IDS) |
| E4b, certificado válido, MAC do publicador | `nftables`: 5 pacotes descartados (1760 B) |
| E5 (i)/(ii)/(iii), HMAC | `auth_fail` / `masquerade` / 5 pacotes descartados (1930 B) |

**Fala:** "O 802.1X barra quem não tem credencial e o clone de MAC: o mesmo C1 que o IDS não via no E0. Mas ele autentica o dispositivo, não a mensagem: com certificado válido e MAC próprio, o atacante publica GOOSE forjado (E4), e aí só o IDS alerta."

**Cuidados:** em E2, E3 e E4b o IDS **não estava em execução**: nada se conclui sobre o que ele detectaria. Não explicar a diferença entre 352, 386 e os 367 B do molde (causa não identificada). Uma execução por cenário: sem estatística.

---

## Slide 7: Síntese, onde cada camada falha (1:00)

**Slide:** (Figura 8 do artigo)

| Camada | Cobre | Falha em |
|---|---|---|
| IDS de estado | flooding, replay, suppression, C2 | **C1** (MAC clonado) |
| Verificação HMAC | quadros sem tag válida (C1 sem a chave) | **chave vazada**; replay de quadro assinado |
| 802.1X | sem credencial, clone de MAC, revogado | **nó autenticado com o próprio MAC (C2)** |

**Fala:** "Nos cenários avaliados, as camadas se complementaram. Isso não é proteção completa: depende de a chave não ter vazado, de o inventário estar correto e de a PKI não estar comprometida."

---

## Slide 8: Limitações e reprodutibilidade (1:00)

**Slide:**
- Tráfego sintético, de **um quadro**; HMAC simulado; IDS passivo.
- GNS3: 1 execução por cenário. *Namespaces*: 11 execuções, **1 com 2 falhas** (28/2), causa não registrada.
- **Não medimos a latência nem a sobrecarga do EAP-TLS.**
- Reprodutível: `github.com/xymotaa/iec61850-security-testbed`, **commit `e813f70`**; semente fixa; PKI gerada por script.

**Fala:** "Preferimos declarar o que não foi medido. A campanha *offline* é uma reconstrução: o script do 4º Marco não foi preservado. As detecções coincidem, as latências não são comparáveis. O artigo, em formato SBC, traz tudo isso."

---

## Slide 9: Conclusão (0:40)

**Slide:**
- **IDS de estado é necessário, mas insuficiente** contra o C1.
- **Camadas se completam** nos cenários avaliados: 802.1X (quem é o dispositivo), HMAC (quem assinou a mensagem), IDS (o que ainda passa).
- Trabalho futuro (**não feito**): medir o EAP-TLS, flooding e suppression com 802.1X, efeito sobre IEDs reais, IEC 62351-6 conforme.

**Fala:** "Nenhuma defesa sozinha fecha o problema; todas têm um limite que medimos. Obrigado. Dúvidas?"

---

## Perguntas prováveis (e respostas honestas)

1. **"Isso é a IEC 62351-6?"** Não: é uma simulação da ideia (HMAC-SHA256 por quadro). Formato e gestão de chaves são nossos.
2. **"Por que o IDS não bloqueia?"** Foi uma escolha: é passivo, só alerta. O bloqueio ficou com o 802.1X.
3. **"O 802.1X já resolve tudo?"** Não: autentica o dispositivo, não a mensagem (E4).
4. **"O vínculo certificado × MAC é do padrão?"** Não, é decisão do projeto, implementada num supervisor e no `nftables`.
5. **"Cabe nos 4 ms da norma? Qual a latência do EAP-TLS?"** O 4 ms é critério experimental nosso. O processamento por quadro (≈95 µs no pior caso, em Python) está bem abaixo, mas isso não prova nada sobre um IED real. O EAP-TLS não foi medido.
6. **"E o N=600 do 4º Marco?"** O script não foi versionado. Reconstruímos com 100 repetições por cenário e modo; as detecções coincidem, as latências não.
7. **"100% e 0% não é estatística fraca?"** Os quadros são determinísticos; o intervalo de Wilson quantifica a incerteza sob o modelo binomial, mas não torna o tráfego representativo de uma subestação real.
8. **"Rodaram quantas vezes no GNS3? Houve falha?"** Uma por cenário, sem taxas. Em *namespaces*, 1 de 11 execuções falhou (28 de 30), na reautenticação após queda de link; causa não registrada.
9. **"Na literatura, ninguém fez isso?"** Só afirmamos "nos trabalhos analisados": oito trabalhos, por busca no texto e leitura dos trechos relevantes; sem ineditismo. Hussain et al. simulam um IED comprometido, mas não avaliam o vazamento da chave.
10. **"E um publicador comprometido?"** Fora do escopo; trabalho futuro.

---

## Demo ao vivo (não cabe nos 10 min)

Se o professor pedir: [`guia-demo-5marco.md`](guia-demo-5marco.md) (versão curta: **E1 → E4**, ≈2 min; completa com E4b, ≈4 min; traz o plano B e a solução de problemas). O guia com todos os cenários e a coleta de evidências é o [`guia-testes-5marco.md`](guia-testes-5marco.md).
