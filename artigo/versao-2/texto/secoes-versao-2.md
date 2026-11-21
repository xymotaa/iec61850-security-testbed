# Rascunho consolidado: seções aprovadas

> Texto aprovado em conversa e salvo aqui para não se perder. **Não é o `main.tex`**:
> o `.tex` ainda não foi alterado e continua na versão antiga. Citações no formato
> do `.bib` (autor ano). Tabelas numeradas em sequência (Tabelas 1 a 3 na Seção 2;
> 4 a 8 na Seção 3).

| Parte | Versão | Situação |
|---|---|---|
| Título e subtítulo | aprovados | fechado |
| 1. Introdução | v2, com a oração sobre Moore atualizada | aprovada |
| 2. Fundamentação e trabalhos relacionados | v1, com o parágrafo do 802.1X/TLS revisado | aprovada |
| 3. Modelo de ameaças e casos de uso | v2, com a Tabela 8 corrigida (E4b) | **fechada** |
| 4. Ambiente experimental e metodologia | v2 | **fechada** |
| 5. Técnicas de defesa e modificações no testbed | v1 com 3 correções e 2 conferências | **fechada** |
| 6. Resultados e análise | v1 com 2 ajustes (6.4 E3; 6.5 HMAC) | **fechada** |
| 7. Discussão, limitações e ameaças à validade | v1 com 2 ajustes (7.1) | **fechada** |
| 8. Conclusão, contribuições e trabalhos futuros | v1 com ajuste na contribuição 3 | **fechada** |

---

## Título

**Masquerade em GOOSE: por que IDS de estado, autenticação por mensagem (HMAC) e 802.1X, isoladamente, não bastam**

*Avaliação experimental em testbed emulado, com quadros GOOSE derivados de um único quadro real capturado de um relé SEL-351*

EN: *GOOSE masquerade: why a state-based IDS, per-message authentication (HMAC) and 802.1X are not enough on their own: an experimental evaluation in an emulated testbed with GOOSE frames derived from a single real frame captured from an SEL-351 relay*

---

## Resumo e Abstract

**Resumo.** O masquerade em GOOSE forja quadros coerentes com o estado do protocolo. Avaliamos, com MAC clonado (C1) e próprio (C2), um IDS de estado passivo, autenticação por mensagem simulada (HMAC) e controle 802.1X com EAP-TLS e vínculo entre certificado e MAC. Os quadros derivam de um único quadro capturado de um relé SEL-351; combinamos uma campanha *offline* (100 repetições por cenário) e o GNS3 (uma execução por cenário). O IDS detectou C2, mas não C1; a verificação HMAC rejeitou C1 sem a chave, mas não quando ela foi vazada; o 802.1X barrou credenciais inválidas e MAC divergente, mas não um nó autenticado com o próprio MAC. Nos cenários avaliados, as camadas se complementaram, sem comprovar proteção completa.

**Palavras-chave:** IEC 61850; GOOSE; masquerade; detecção de intrusão; IEEE 802.1X.

**Abstract.** GOOSE masquerade forges frames consistent with the protocol's state. We evaluate, with a cloned (C1) or the attacker's own (C2) MAC, a passive state-based IDS, simulated per-message authentication (HMAC), and 802.1X with EAP-TLS and a certificate-MAC binding. Frames derive from a single frame captured from an SEL-351 relay, combining an offline campaign (100 repetitions per scenario) with GNS3 executions (one per scenario). The IDS detected C2 but not C1; HMAC verification rejected C1 without the key, but not once the key leaked; 802.1X blocked invalid credentials and MAC mismatches, but not an authenticated node using its own MAC. In the evaluated scenarios the layers complemented each other, without proving full protection.

**Keywords:** IEC 61850; GOOSE; masquerade; intrusion detection; IEEE 802.1X.

---

## 1. Introdução

A digitalização das subestações elétricas, orientada pela norma IEC 61850, substituiu a fiação rígida entre os dispositivos de proteção e controle por redes Ethernet [Herath et al. 2025] e, com isso, ampliou a superfície de ataque do setor elétrico [Oliveira e Gurjão 2025; de Oliveira et al. 2023]. Nesse modelo, as mensagens GOOSE (*Generic Object Oriented Substation Event*) levam entre os IEDs eventos de proteção, como a ordem de abertura de um disjuntor. Em razão dos requisitos de baixa latência, elas são mapeadas diretamente sobre a camada de enlace, em multicast e no modelo publicador-assinante [Herath et al. 2025; de Oliveira et al. 2023] e, em sua forma básica, sem as extensões de segurança da IEC 62351-6, não oferecem nenhum mecanismo de segurança embutido [Herath et al. 2025]. Um adversário que obtenha acesso à rede local da subestação pode, assim, atacar esse tráfego [Herath et al. 2025].

Entre os ataques ao GOOSE, o *masquerade* (mascaramento) se distingue porque o quadro forjado pode respeitar as regras de evolução de estado do protocolo. Nos trabalhos analisados, a atualidade de uma mensagem é inferida pela evolução de `stNum`, que cresce a cada mudança de estado, e de `sqNum`, que cresce a cada retransmissão e volta a zero quando o estado muda [Herath et al. 2025; Conceição Alberto et al. 2026]. Em experimentos de *hardware-in-the-loop*, Conceição Alberto et al. (2026) reportam que um quadro forjado com `stNum` igual ao do último quadro legítimo mais um e `sqNum` zerado foi aceito pelos assinantes, e que as atualizações legítimas seguintes, com `stNum` menor, foram rejeitadas. Esses autores sintetizam ainda que replay, envenenamento e flooding não provocaram má operação observável em condições realistas, ao passo que o masquerade a provocou de forma consistente. De Oliveira et al. (2023), porém, descrevem efeitos de replay e de negação de serviço em seu cenário, além da abertura de um disjuntor simulado por um masquerade construído a partir de mensagens de um IED real.

A literatura analisada responde a esse risco com três famílias de defesa. Sistemas de detecção de intrusão (IDS) verificam a semântica do protocolo, por regras sobre `stNum`, `sqNum` e temporização [Herath et al. 2025] ou por aprendizado de máquina [Conceição Alberto et al. 2026; Moore 2026]. A autenticação por mensagem, prevista na IEC 62351-6 [IEC 2020], anexa a cada quadro um código de autenticação calculado com uma chave compartilhada [Herath et al. 2025; Hussain et al. 2023]. *Switches* definidos por software, por fim, bloqueiam a porta do dispositivo malicioso, mas depois da detecção [Girdhar et al. 2023]. Há trabalhos que combinam as duas primeiras famílias [Herath et al. 2025], e a comparação detalhada é apresentada na Seção 2.

Essas avaliações partem, porém, de hipóteses que podem não se sustentar. No trabalho analisado que combina autenticação e detecção, a verificação de MAC é avaliada contra quadros adulterados, e a possibilidade de comprometimento da chave não é tratada [Herath et al. 2025]; em outro, o comprometimento de dispositivos e o acesso a chaves criptográficas são excluídos do modelo de ameaças [Conceição Alberto et al. 2026]. A distribuição segura de chaves compartilhadas é, aliás, apontada como um desafio [Hussain et al. 2023]. Também não identificamos, nos trabalhos analisados, a avaliação de um controle de acesso à porta que impeça a entrada do atacante na rede, como o IEEE 802.1X [IEEE 2020] com EAP-TLS; o bloqueio de porta de Girdhar et al. (2023) ocorre depois da detecção do ataque. Por fim, o endereço MAC de origem do quadro forjado, que pode ser o do próprio atacante (C2) ou clonado do publicador legítimo (C1), não é tratado como variável experimental nesses trabalhos; Moore (2026) descreve o masquerade como falsificação do MAC de origem, mas descarta os campos de MAC, entre outras colunas de alta cardinalidade, do conjunto de atributos. Falta, portanto, nos trabalhos analisados, uma avaliação experimental da interação entre detecção, autenticação e controle de acesso diante do masquerade, sobretudo quando a chave é comprometida e quando o MAC de origem é clonado.

Este trabalho se propõe a endereçar essa lacuna. A pergunta de pesquisa é: diante do masquerade em GOOSE com MAC clonado (C1) ou próprio (C2), o que cobrem o IDS de estado (detecção), a autenticação por mensagem (HMAC) e o controle de acesso 802.1X (identidade de rede vinculada ao MAC); onde cada um falha isoladamente, inclusive com a chave comprometida; e como se compensam? O objetivo geral é avaliar experimentalmente essa interação em um *testbed* emulado, com quadros GOOSE derivados de um quadro real capturado de um relé SEL-351.

Duas delimitações orientam a leitura. A autenticação avaliada é uma simulação baseada em HMAC, que representa a ideia da IEC 62351-6 sem implementar o mecanismo normativo. E o IDS é passivo, pois emite alertas em vez de descartar quadros, de modo que seus resultados não se comparam à mitigação em linha nem ao desempenho de abordagens de aprendizado de máquina. Os detalhes estão nas Seções 4 e 5.

As contribuições são: (i) a caracterização experimental do ponto cego de um IDS de estado diante do masquerade com MAC clonado (C1), em contraste com a detecção do masquerade com MAC próprio (C2); (ii) a avaliação da autenticação por mensagem simulada, com e sem a chave em poder do atacante, que delimita o ganho que ela traz e onde deixa de proteger; (iii) a implementação e a validação, em *testbed* emulado, de um controle de acesso 802.1X real com EAP-TLS, com vínculo entre o certificado de cada nó e o seu endereço MAC, a partir de um inventário gerado no mesmo fluxo que produz a topologia a partir do arquivo SCD; e (iv) uma análise por cenário e por camada que identifica onde cada defesa falha isoladamente e como elas se compensam.

O restante do artigo está organizado assim: a Seção 2 apresenta a fundamentação, as normas e os trabalhos relacionados; a Seção 3, o modelo de ameaças e os casos de uso; a Seção 4, o ambiente experimental e a metodologia; a Seção 5, as três camadas de defesa e as modificações feitas no *testbed*; a Seção 6, os resultados e as análises; a Seção 7, a discussão e as limitações; e a Seção 8, a conclusão.

---

## 2. Fundamentação e trabalhos relacionados

Esta seção apresenta os elementos necessários para avaliar as três camadas de defesa do trabalho. A Seção 2.1 descreve o GOOSE e a taxonomia de ataques adotada; a 2.2, as normas e os mecanismos de autenticação e de controle de acesso; a 2.3, os trabalhos relacionados, organizados pelas três camadas; e a 2.4 situa este trabalho em relação ao artigo que o originou.

### 2.1. GOOSE, semântica de estado e taxonomia de ataques

O GOOSE é um serviço orientado a eventos, definido na IEC 61850-7-2 e mapeado diretamente sobre Ethernet na IEC 61850-8-1: seus quadros são multicast de camada 2, com marcação VLAN e prioridade, no modelo publicador-assinante [Herath et al. 2025]. Em regime permanente, as mensagens são retransmitidas em intervalo fixo, com `stNum` constante e `sqNum` crescente; quando ocorre um evento, o publicador envia uma mensagem com novo `stNum` e `sqNum` igual a zero e passa a retransmiti-la em rajada, com intervalos que crescem até o regime permanente [Herath et al. 2025; Conceição Alberto et al. 2026]. Os assinantes inferem a atualidade de uma mensagem a partir dessa evolução monotônica e de restrições de temporização, como o `timeAllowedToLive` [Conceição Alberto et al. 2026].

Os requisitos de tempo variam conforme a fonte e a classe de mensagem. Herath et al. (2025) citam 3 ms para o GOOSE do tipo 1A; Conceição Alberto et al. (2026), cerca de 3 ms para as classes de desempenho P2 e P3 da IEC 61850-5; e Moore (2026) adota 4 ms como o tempo de disparo da proteção de distância. Neste trabalho, o valor de 4 ms é usado como critério experimental de viabilidade nas medições de latência (Seção 6), e não como requisito normativo, pois não consultamos o texto da IEC 61850-5.

A literatura descreve os ataques ao GOOSE com variações de nomenclatura. Conceição Alberto et al. (2026) listam masquerade ou spoofing, replay, `stNum` elevado (envenenamento), injeção de mensagens e flooding; Herath et al. (2025), replay, masquerade, flooding e descarte de pacotes; Zemanek et al. (2022), replay, inserção, suppression e flooding. Este trabalho usa quatro ataques: flooding, replay, masquerade e suppression. A associação do nosso suppression ao envenenamento por `stNum` elevado de Conceição Alberto et al. (2026) e à classe suppression de Zemanek et al. (2022) é uma interpretação da nossa taxonomia, e não uma equivalência estabelecida nesses trabalhos. O descarte de pacotes de Herath et al. (2025) é um ataque distinto, ao encaminhamento, e não é avaliado aqui.

### 2.2. Normas e mecanismos de segurança

Segundo Herath et al. (2025), a IEC 62351-6 [IEC 2020] recomenda, para o GOOSE, códigos de autenticação de mensagem (MAC) calculados com chaves pré-compartilhadas e anexados ao quadro em campos de extensão, que incluem um vetor de inicialização, o identificador da chave e a tag, com o AES-GMAC-128 como algoritmo principal. Os mesmos autores indicam que a norma recomenda integrar verificações por regras à verificação de MAC, e que a proteção contra replay é tratada em uma etapa adicional, que verifica `stNum` e `sqNum`. A distribuição segura das chaves pré-compartilhadas é apontada como um desafio [Hussain et al. 2023].

A IEC 62443-3-3 [IEC 2013] estabelece requisitos técnicos de segurança para sistemas de controle industrial. O artigo que originou este trabalho a utilizou para verificar a política de senhas dos IEDs [Oliveira e Gurjão 2025]; o Oráculo deste projeto, que realiza a auditoria por SSH, avalia ainda credenciais padrão, privilégio da conta, integridade das mensagens GOOSE, segmentação por VLAN e limitação de taxa de conexões. Citamos esses requisitos pelo conteúdo, e não pelo número, porque a correspondência com a numeração da norma ainda não foi verificada contra o texto normativo.

O IEEE 802.1X [IEEE 2020] trata do controle de acesso à rede baseado em porta: o dispositivo só tem a porta liberada depois de ser autenticado. Com o EAP-TLS, a autenticação é mútua e baseada em certificados [Simon et al. 2008]. Segundo o RFC 9190, o servidor deve se autenticar com um certificado e é recomendável que exija também o certificado do par [Preuß Mattsson e Sethi 2022]. O RFC 5216 define o EAP-TLS, e o RFC 9190 o atualiza para o TLS 1.3, mantendo o RFC 5216 aplicável quando o TLS 1.2 é negociado [Preuß Mattsson e Sethi 2022]. Em uma medição em ambiente de depuração, fora do GNS3, com `hostapd` e `wpa_supplicant` 2.10 e OpenSSL 3.5.7 e a configuração do projeto, a negociação resultou em TLS 1.2; o TLS 1.3 não foi negociado nem quando habilitado explicitamente nas duas pontas, e a causa não foi investigada. Para a configuração medida, o texto aplicável é, portanto, o RFC 5216 (a medição está disponível no repositório do projeto).

A Tabela 1 relaciona cada ataque à propriedade comprometida e ao que as normas e os trabalhos analisados dizem sobre ele; as observações do nosso *testbed* ficam para a Seção 6.

*Tabela 1. Ataques, propriedade comprometida e o que dizem as normas e a literatura analisada.*

| Ataque | Propriedade | Previsão normativa | Resultados reportados |
|---|---|---|---|
| Flooding | Disponibilidade | Proteção contra negação de serviço (IEC 62443-3-3, pelo conteúdo) | Com MAC, os quadros não autenticados são rejeitados; um IDS por regras perdeu o sincronismo sob 1000 Hz [Herath et al. 2025] |
| Replay | Autenticidade temporal | Etapa adicional que verifica `stNum` e `sqNum` (IEC 62351-6, segundo Herath et al. 2025) | O MAC não o detecta, pois a tag é válida; o IDS por regras o detecta [Herath et al. 2025] |
| Masquerade | Integridade e autenticidade | Autenticação de mensagem (IEC 62351-6) | O MAC o detecta; o IDS por regras falha, pois o quadro respeita `stNum`, `sqNum` e temporização [Herath et al. 2025] |
| Suppression (nossa taxonomia) | Disponibilidade lógica | n/c | Classe de Zemanek et al. (2022); sem avaliação de defesas |

*n/c: não consta nos trechos analisados.*

### 2.3. Trabalhos relacionados

*Detecção de intrusão.* Herath et al. (2025) implementam um IDS por regras sobre `stNum`, `sqNum` e temporização, executado em linha no caminho de encaminhamento, que descarta os quadros reprovados. Conceição Alberto et al. (2026) propõem um IDS sobre tráfego espelhado, com LightGBM e atributos derivados de `stNum`, `sqNum` e temporização, e uma resposta que injeta quadros corretivos; os autores excluem do modelo de ameaças o comprometimento de dispositivos e o acesso a chaves. Moore (2026) compara modelos supervisionados e não supervisionados sobre o conjunto ERENO e relata a latência por predição; nesse trabalho, o masquerade é descrito como falsificação do MAC de origem e dos identificadores GOOSE, mas os campos de MAC são descartados, entre outras colunas de alta cardinalidade, do conjunto de atributos. O IDS deste trabalho é baseado em regras e passivo (emite alertas e não descarta quadros); por isso, não equivale aos IDS em linha e não é comparado, em desempenho, às abordagens de aprendizado de máquina.

*Autenticação por mensagem.* Herath et al. (2025) implementam a verificação de MAC com AES-GMAC-128 no formato da IEC 62351-6:2020 e mostram que ela detecta o masquerade e o flooding, mas não o replay de um quadro legítimo, cuja tag permanece válida; a combinação com o IDS por regras cobre o replay. Hussain et al. (2023) combinam o MAC com chave pré-compartilhada e a validação do conteúdo junto a IEDs vizinhos. Nos trabalhos analisados, a possibilidade de comprometimento da chave não é avaliada: Herath et al. (2025) não a tratam, e Conceição Alberto et al. (2026) a excluem do modelo de ameaças. A autenticação avaliada aqui é uma simulação baseada em HMAC (Seção 5.2), que representa a ideia da IEC 62351-6 sem implementar o seu mecanismo normativo, e seus resultados não são comparáveis aos de Herath et al. (2025).

*Controle de rede e de acesso.* Moore (2026) observa que o protocolo foi concebido para redes isoladas, nas quais o controle de acesso físico bastava, e que essa premissa deixa de valer em redes Ethernet maiores, onde qualquer dispositivo do segmento pode receber, reproduzir ou forjar quadros sem autenticação. Girdhar et al. (2023) integram um IDS por regras a *switches* definidos por software, que localizam o dispositivo atacante e desativam a sua porta, ação que ocorre depois da detecção. Herath et al. (2025) concluem que o descarte de pacotes exige, além da detecção, mecanismos de controle de tráfego, como SDN, ou redundância (PRP e HSR). Nos trabalhos analisados, não identificamos a avaliação de um controle de acesso à porta baseado em autenticação do dispositivo, como o 802.1X. Nossas buscas por esse tema em subestações foram limitadas e não permitem afirmar que ele nunca tenha sido estudado.

*Ambientes e conjuntos de dados.* Herath et al. (2025) usam um *testbed* ciberfísico, com simulador em tempo real e IEDs comerciais, no qual as defesas rodam em um IED simulado; Conceição Alberto et al. (2026) e de Oliveira et al. (2023) usam *hardware-in-the-loop* com relés ou IEDs comerciais. Zemanek et al. (2022) publicam um conjunto de dados gravado em um *testbed* físico com três IEDs, sem avaliar defesas. Roomi et al. (2025) geram um *cyber range* a partir de arquivos SCL, com Mininet e simulação elétrica, e o artigo base [Oliveira e Gurjão 2025] gera a topologia no GNS3 a partir do SCD. O ambiente deste trabalho é emulado (GNS3 e Docker), sem hardware real, e usa como molde um único quadro GOOSE capturado de um relé SEL-351; seus resultados não são comparáveis, em desempenho, aos dos ambientes com hardware.

*Tabela 2. Trabalhos analisados e as lacunas tratadas neste artigo. n/c: não consta nos trechos analisados.*

| Trabalho | Ambiente | Camadas avaliadas | Chave comprometida | MAC de origem como variável |
|---|---|---|---|---|
| Herath et al. (2025) | Ciberfísico, IED simulado | IDS por regras e MAC | n/c | n/c |
| Conceição Alberto et al. (2026) | HIL, relés comerciais | IDS com aprendizado | Excluída do modelo | n/c |
| Hussain et al. (2023) | RTDS e Snort | MAC e validação de conteúdo | Citada como desafio | n/c |
| Girdhar et al. (2023) | HIL e Mininet | IDS por regras e bloqueio de porta | n/c | n/c |
| Moore (2026) | Conjunto ERENO | Aprendizado de máquina | n/c | Descrito; campos descartados |
| de Oliveira et al. (2023) | RTDS e IED real | Sem defesa | n/c | n/c |
| Zemanek et al. (2022) | *Testbed* físico | Sem defesa | n/c | n/c |
| **Este trabalho** | Emulado | IDS, HMAC simulado e 802.1X | Avaliada | C1 e C2 |

*Roomi et al. (2025) não aparece na Tabela 2 porque tratam da geração do ambiente, e não de defesas; só parte do texto foi lida.*

### 2.4. Relação com o artigo base

Oliveira e Gurjão (2025) geram automaticamente, a partir de arquivos SCL, a topologia de uma subestação no GNS3, com quatro *switches* e cinco IEDs em contêineres Docker, e introduzem o Oráculo, um contêiner que verifica requisitos de segurança dos IEDs com base na IEC 62443; nessa versão, a verificação cobre a política de senhas. O tráfego GOOSE não é atacado, e os autores indicam como trabalho futuro a inclusão de novos tipos de ataque e a validação em ambientes reais.

A auditoria de credenciais, por mais completa que seja, não impede que um dispositivo com acesso à rede local forje mensagens GOOSE, que trafegam na camada de enlace sem autenticação [Herath et al. 2025; Moore 2026]. Este trabalho parte dessa lacuna: reutiliza o fluxo SCD→GNS3 e o Oráculo, e acrescenta ataques ao tráfego GOOSE e as três camadas de defesa avaliadas. O Oráculo foi estendido com novos critérios de auditoria, descritos na Seção 2.2. Os ataques ao tráfego GOOSE, o IDS de estado e a validação do gerador com um SCD real de um projeto de referência também estendem o artigo base.

---

## 3. Modelo de ameaças e casos de uso

Esta seção delimita o que o trabalho protege, contra quem e em que cenários. As Seções 3.1 e 3.2 definem os ativos e o adversário; as Seções 3.3 e 3.4, as variantes de masquerade e o cenário de chave comprometida; a Seção 3.5, os ataques avaliados e os excluídos; e a Seção 3.6, os casos de uso e os cenários experimentais.

### 3.1. Ativos e componentes

Três ativos orientam o modelo: a autenticidade e a integridade dos eventos GOOSE de um publicador, representadas pelo `gocbRef` e pelo estado transportado em `allData`; a disponibilidade da comunicação GOOSE; e o acesso à rede local em que esse tráfego circula. A Tabela 3 lista os componentes do *testbed* e o papel de cada um no modelo.

Duas características do *testbed* condicionam a leitura dos resultados. A primeira é que **não existe um IED publicador independente**: os nós `ubuntu-ied` são *hosts* genéricos, que não geram GOOSE, e o publicador legítimo é emulado por `publicador-1`, que usa a mesma ferramenta de geração de quadros do atacante e o mesmo quadro-molde capturado de um relé SEL-351 (a campanha *offline* usa um gerador de tráfego equivalente). Publicador e atacante diferem, portanto, pelo papel e pelas credenciais de que dispõem (certificado 802.1X e posse da chave), e não por serem implementações distintas do protocolo; o MAC de origem do atacante pode ser distinto do publicador (C2) ou clonado dele (C1), como definido na Seção 3.3. A segunda é que **não há assinante GOOSE**: o único observador do tráfego é o IDS. Por isso, o efeito de um quadro forjado sobre um dispositivo de proteção, como a abertura de um disjuntor, não é medido; ele é tomado da literatura [Conceição Alberto et al. 2026; de Oliveira et al. 2023].

*Tabela 3. Componentes do testbed e seus papéis no modelo.*

| Componente | Papel no modelo | Implementação |
|---|---|---|
| Publicador (emulado) | Emite os quadros GOOSE legítimos; assina, quando o HMAC está ativo | `publicador-1` (imagem do atacante, MAC do molde); gerador de tráfego legítimo |
| Atacante | Forja e injeta quadros | `atacante-1`; gerador de tráfego de ataque |
| IDS de estado | Observa o tráfego e emite alertas; não descarta quadros | `ids-1`; monitor alimentado diretamente |
| Autenticador 802.1X | Libera ou bloqueia o encaminhamento por porta e MAC | `autenticador-8021x` (hostapd e nftables) |
| PKI e inventário | Emite os certificados e vincula o CN ao MAC | `pki/`; inventário CN→MAC |
| IEDs simulados | Hosts que se autenticam; não geram GOOSE | `ubuntu-ied` |
| Assinantes GOOSE | Não implementados | — |

### 3.2. Adversário: capacidades e limitações

O adversário é um dispositivo ligado a uma porta do domínio de camada 2 em que o GOOSE circula (no *testbed*, o nó `atacante-1`), com privilégio de *socket* cru. Ele captura passivamente um quadro GOOSE legítimo, reaproveita o `allData` da captura (conhecendo a posição do valor booleano de estado) e constrói quadros com `stNum`, `sqNum`, `t` e MAC de origem arbitrários, inclusive alterando o MAC da própria interface, sem exigir credenciais do IED nem a exploração do dispositivo. Não atua como intermediário (*man-in-the-middle*) nem descarta seletivamente quadros em trânsito entre outros nós.

O masquerade e o suppression pressupõem que o adversário conheça o último `stNum` do publicador; o `sqNum` não precisa ser conhecido, porque o quadro forjado o zera. Adotamos essa condição como **premissa do modelo de ameaças**. Herath et al. (2025) descrevem uma premissa mais ampla para o masquerade (conhecer `stNum` e `sqNum` do último quadro), e Conceição Alberto et al. (2026) modelam um adversário que observa passivamente o tráfego do barramento e injeta quadros forjados. O *testbed* facilita esse conhecimento, porque o publicador repete o quadro-molde de que o atacante parte; em uma rede real, isso depende de o adversário observar o tráfego do publicador a tempo. O replay e o flooding não exigem essa premissa.

O adversário não dispõe da chave de autenticação por mensagem, exceto no cenário de chave comprometida (Seção 3.4). No máximo, dispõe do certificado e da chave privada de um nó comprometido (`atacante-comprometido`, que os fornece ao atacante), e nunca dos certificados e das chaves privadas dos IEDs ou do publicador. Não compromete a CA, o autenticador nem o publicador, e não tem acesso físico para substituir um dispositivo em uma porta já autenticada; essas exclusões são decisões de modelagem, e o comprometimento do publicador permanece como trabalho em aberto. A Tabela 4 organiza os níveis do atacante diante do 802.1X.

*Tabela 4. Níveis do atacante diante do controle de acesso 802.1X.*

| Nível | Credencial 802.1X | MAC de origem | Cenários |
|---|---|---|---|
| N0 | Controle de acesso desligado | Clonado do publicador (C1) | E0 |
| N1 | Nenhuma | Clonado do publicador | E1 |
| N2 | Certificado revogado (ou fora do inventário, ou de CA desconhecida) | Próprio | E2; *netns* |
| N3 | Certificado válido e chave privada de um nó comprometido | De outro nó (um IED, E3; o publicador, após autenticar, E4b e E5 (iii)) | E3, E4b, E5 (iii) |
| N4 | Certificado válido e chave privada de um nó comprometido | Próprio (C2) | E4, E5 (i) e (ii) |

### 3.3. Masquerade: variantes C1 e C2

O masquerade forja uma mudança de estado do publicador. O quadro forjado mantém o `gocbRef`, o endereço de destino e o APPID do quadro-molde; inverte o primeiro valor booleano de `allData`; incrementa o `stNum` em uma unidade; zera o `sqNum`; e atualiza o `t`. É o comportamento esperado de uma transição de estado real, e por isso o quadro respeita a gramática descrita na Seção 2.1 [Herath et al. 2025; Conceição Alberto et al. 2026]. As duas variantes diferem apenas no MAC de origem. Em **C1**, o MAC é o do publicador legítimo, clonado pelo atacante. Em **C2**, o MAC é diferente do publicador, em geral o do próprio atacante.

O que define C2 é a divergência em relação ao publicador, e não a origem do valor. Nas campanhas, o MAC de C2 variou: a campanha *offline* usa um MAC fixo atribuído ao atacante, as execuções do 4.º Marco usaram um MAC arbitrário informado à ferramenta, e as execuções com 802.1X no GNS3 usaram o MAC da própria interface. Para o IDS de estado, a regra que distingue as duas variantes compara o MAC de origem de cada quadro com o último visto para o mesmo `gocbRef`; as demais regras observam `stNum`, `sqNum` e a taxa de quadros. Os resultados dessa distinção são apresentados na Seção 6.

### 3.4. Comprometimento da chave HMAC

A autenticação por mensagem avaliada é uma simulação (Seção 5.2): cada quadro assinado leva um HMAC-SHA256 calculado com uma chave própria do `gocbRef`, derivada de uma chave-mestra. No cenário de chave comprometida, o atacante recebe a **chave-mestra inteira** e assina com ela os quadros forjados de flooding, masquerade e suppression. Esse é um cenário deliberadamente **mais forte** do que o comprometimento de uma chave individual por fluxo: em um esquema com chaves por `gocbRef`, o vazamento de uma chave comprometeria apenas aquele fluxo, o que este trabalho não avalia.

**O replay não recebe assinatura nesse modo.** O quadro reenviado é uma cópia byte a byte de um quadro legítimo e já carrega a tag original, que permanece válida; por isso, a chave comprometida não altera o replay. No modo em que o atacante não tem a chave, seus quadros saem sem tag e são tratados como inválidos pelo verificador, e não modelamos tentativas de forjar a tag. A forma como a chave vaza também não é modelada: é uma premissa. Por fim, comprometer a chave não equivale a comprometer o publicador, caso que está fora do escopo.

*Tabela 5. Variantes de masquerade e a posse da chave.*

| Variante | MAC de origem | Tag HMAC no quadro forjado | Premissas do atacante |
|---|---|---|---|
| C1 | Do publicador (clonado) | Ausente, sem a chave; válida (chave-mestra), com a chave | Último `stNum` do publicador e posição do booleano; com a chave, também a chave-mestra |
| C2 | Diferente do publicador | Ausente, sem a chave; válida (chave-mestra), com a chave | Último `stNum` do publicador e posição do booleano; com a chave, também a chave-mestra |

### 3.5. Ataques considerados e fora do escopo

Avaliamos quatro ataques sobre o mesmo quadro-molde, descritos operacionalmente na Tabela 6: flooding (A), replay (B), masquerade (C1 e C2) e suppression (D). A correspondência com a terminologia da literatura está na Seção 2.1, e a Figura 1 os organiza pela propriedade comprometida.

*Tabela 6. Ataques avaliados.*

| Ataque | Propriedade | Construção do quadro | Parâmetros avaliados | Premissa: conhece o último `stNum` | CU |
|---|---|---|---|---|---|
| Flooding (A) | Disponibilidade | Reenvia o molde em alta taxa, com `sqNum` crescente e `stNum` fixo | 50 a 2000 pacotes/s | Não | CU3 |
| Replay (B) | Autenticidade temporal | Reenvia o quadro capturado, sem alteração | Atraso de 0,5 a 10 s | Não | CU1 |
| Masquerade (C1, C2) | Integridade e autenticidade | Seção 3.3 | MAC de origem | Sim | CU1 |
| Suppression (D) | Disponibilidade lógica | Soma um salto ao `stNum` e zera o `sqNum` | Salto de 60 a 5000 | Sim | CU2 |

Ficam **fora do escopo**: o comprometimento do publicador, da CA ou do autenticador; o descarte seletivo de pacotes no encaminhamento [Herath et al. 2025]; os ataques a *Sampled Values* e MMS e ao plano de gerência, além da auditoria do Oráculo; e a cifra e a integridade do enlace (MACsec). Também não avaliamos, por falta de cenário, o flooding e o suppression com o 802.1X ativo, já que os cenários com 802.1X usam apenas masquerade, nem o efeito dos quadros forjados sobre assinantes.

*Figura 1 (a desenhar, sem cores de resultado).* Árvore de ataques: raiz "Comprometer a função de proteção GOOSE (OU)"; ramo "Disponibilidade", com flooding (A, CU3) e suppression (D, CU2); ramo "Integridade e autenticidade", com replay (B, CU1), masquerade C2 (CU1) e masquerade C1 (CU1).

### 3.6. Casos de uso e cenários experimentais

Os quatro ataques se agrupam em três casos de uso, que organizamos para a leitura dos resultados. O **CU1**, abertura indevida de disjuntor, é o masquerade, que forja uma mudança de estado e pode induzir a abertura indevida de um disjuntor; inclui o replay como variante sem mutação, que reenvia um comando antigo, sem que isso garanta a abertura de um disjuntor. O **CU2**, bloqueio de proteção, é o suppression: um único quadro com `stNum` à frente do estado real pode levar os assinantes a rejeitar as atualizações legítimas seguintes, sem inundar a rede. O **CU3**, perda de *heartbeat*, é o flooding, que pode degradar a comunicação e consumir recursos de processamento dos assinantes. Esses efeitos são possibilidades descritas na documentação do projeto e na literatura; **não foram medidos no *testbed***, que não tem assinantes. Dois eixos de variação aparecem nos cenários, e não constituem casos de uso novos: a posse da chave de autenticação (Seção 3.4) e o acesso do atacante à rede, descrito pelos níveis da Tabela 4.

A avaliação usa **três ambientes distintos**, e os resultados de cada um são apresentados e interpretados separadamente: eles **não formam uma única campanha**, têm números de repetições diferentes e não são somados. A Tabela 7 os distingue.

*Tabela 7. Ambientes de avaliação e seus cenários.*

| Ambiente | Cenários | Camadas ativas | Execuções |
|---|---|---|---|
| Campanha *offline* (sem GNS3, rede ou *switch*) | T0 (tráfego legítimo), A, B, C1, C2 e D, nos modos sem HMAC, com HMAC e com chave comprometida; sensibilidade do limiar de flooding | IDS; IDS e HMAC | 100 por cenário e modo |
| GNS3 com 802.1X | E0 a E5 (Tabela 4), todos masquerade | E0: IDS; E1 a E4b: 802.1X (IDS ativo apenas em E1 e E4); E5: 802.1X, HMAC e IDS | 1 por cenário |
| *Network namespaces* | Cenários equivalentes a E0 a E4b, mais revogação em operação (E2b), certificado fora do inventário, CA desconhecida e queda de link | 802.1X, sem HMAC e sem IDS | 30 verificações por execução |

---

## 4. Ambiente experimental e metodologia

Esta seção descreve como o ambiente é construído (Seção 4.1), de onde vêm os quadros (Seção 4.2), como cada um dos três ambientes de avaliação é montado e executado (Seção 4.3), quais métricas e critérios são usados (Seção 4.4) e o que está disponível para reprodução (Seção 4.5).

### 4.1. Testbed e geração a partir do SCD

O ambiente é gerado a partir de um arquivo SCD (Figura 2). Um extrator lê o SCD em duas passadas: a primeira percorre o modelo lógico (IEDs, dispositivos lógicos e blocos de controle GOOSE e de valores amostrados); a segunda une esses blocos à seção de comunicação e resolve IP, MAC multicast, APPID e VLAN, gravando um arquivo JSON. Um gerador transforma o JSON em um projeto do GNS3, com um nó Docker por IED, e, na variante `--8021x`, grava também um inventário que vincula o nome de cada nó ao seu MAC. A PKI de laboratório emite a CA, um certificado por nó e a lista de revogação, e um instalador copia esses arquivos para os volumes dos nós do projeto. Usamos duas entradas: um SCD sintético, com 2 IEDs, e um SCD real do projeto libiec61850 [MZ Automation s.d.], com 1 IED e 2 blocos GOOSE.

A topologia de referência do gerador é uma estrela de *switches*, com um central e quatro de borda, em que os IEDs, o Oráculo (o contêiner que audita os requisitos de segurança dos IEDs, Seção 2.4), o IDS e o atacante compartilham o domínio multicast. A variante `--8021x` dispensa os *switches* nativos do GNS3, que podem inundar quadros EAPOL e não executam o Spanning Tree: o autenticador é o único elemento de camada 2, e cada nó se liga a uma de suas portas. Para que o vínculo entre certificado e MAC seja determinístico, o gerador fixa o MAC de cada nó em `02:00:<IP em hexadecimal>`, e não o lê do SCD; apenas o publicador usa o MAC do quadro-molde (Seção 4.2), de modo que o IDS veja o mesmo emissor da referência.

A topologia gerada do SCD real foi validada no 4.º Marco, a quarta entrega parcial do projeto, em novembro de 2026. Todas as execuções no GNS3 deste artigo usam a variante `--8021x` gerada do SCD sintético (Tabela 8, Figura 3). A topologia de cinco IEDs usada em uma entrega anterior do projeto não está versionada.

*Figura 2. Pipeline de geração do ambiente: SCD (sintético ou real) → extrator de duas passadas → JSON → gerador de topologia (variante `--8021x`) → projeto GNS3 e inventário nome→MAC; em paralelo, gerador de PKI → CA, certificados por nó e lista de revogação; instalador (projeto, inventário e PKI) → volumes dos nós no GNS3.*

*Tabela 8. Topologias geradas pelo projeto.*

| Arquivo | SCD de origem e nós | Uso neste artigo |
|---|---|---|
| `subestacao.gns3` | Sintético (2 IEDs); 10 nós: 5 *switches*, 2 IEDs, Oráculo, IDS, atacante | Topologia de referência do gerador; não usada nos cenários E0 a E5 |
| `subestacao_real.gns3` | Real (`simpleIO`, 1 IED); 9 nós | Validação do gerador com SCD real (4.º Marco): abre sem erro, IP automático, replay detectado pelo IDS |
| `subestacao_8021x.gns3` | Sintético (2 IEDs); 7 nós: autenticador, 2 IEDs, Oráculo, IDS, publicador, atacante; sem *switches* | Todos os cenários E0 a E5 no GNS3 |

*Figura 3. Topologia `subestacao_8021x` no GNS3 2.2.61 durante a validação de 20/11/2026: sete nós Docker, cada um ligado a uma porta do `autenticador-8021x`, sem *switches* nativos.* (imagem: `artigo/figuras/gns3_topologia_8021x.png`)

### 4.2. Quadro-molde e codec GOOSE

Todos os quadros GOOSE do trabalho derivam de um único quadro, capturado de um relé SEL-351, conforme a documentação do projeto. A Tabela 9 resume seus campos. O codec interpreta o cabeçalho e os campos escalares do PDU e trata o `allData` como um bloco de bytes opaco, reaproveitado da captura; o valor booleano de estado é localizado pela assinatura TLV de um booleano MMS (`0x83 0x01 <v>`). A reconstrução do quadro pelo codec é idêntica, byte a byte, ao original, o que é verificado por teste automatizado. Como todos os quadros derivam do molde, a variedade do tráfego é sintética: os ataques alteram, no máximo, `stNum`, `sqNum`, `t`, o MAC de origem, o valor booleano de estado e, nos modos com HMAC, a tag de autenticação (ausente, se o atacante não tem a chave, ou calculada com a chave-mestra, se a tem).

*Tabela 9. Campos do quadro-molde.*

| Campo | Valor |
|---|---|
| Tamanho do quadro | 367 bytes |
| MAC de origem / destino | `00:30:a7:01:b3:16` / `01:0c:cd:01:00:03` |
| APPID; marcação VLAN | `0x0003`; ausente |
| `gocbRef` | `SEL_351_1CFG/LLN0$GO$NewGOOSEMessage` |
| `datSet`; `goID` | `SEL_351_1CFG/LLN0$three51to2411`; `SEL_351_1` |
| `stNum` / `sqNum` | 23 / 521 |
| `timeAllowedToLive`; `confRev` | 2000; 1 |
| `allData` | 223 bytes (bloco opaco) |

### 4.3. Ambientes de avaliação

A avaliação usa três ambientes, descritos a seguir; a Tabela 7 resume seus cenários. Cada um produz evidências de natureza diferente, e seus resultados não são somados.

*4.3.1. Campanha offline.* A campanha constrói os quadros a partir do molde, relê-os com o codec e os entrega diretamente ao monitor do IDS, com um relógio virtual: não há rede, *switch* nem IED. Cada repetição usa um monitor novo, cinco *heartbeats* legítimos de aquecimento a 1 Hz e, depois, apenas o tráfego do atacante; os intervalos entre quadros variam ±10%, e a semente é fixa (61850). Os cenários são T0 (tráfego legítimo, 60 s, com *heartbeat* a 1 Hz e duas rajadas de 5 pacotes/s), A (flooding, 3 s), B (replay), C1 e C2 (masquerade) e D (suppression), nos modos sem HMAC, com HMAC e com chave comprometida (Seção 3.4). São 100 repetições por cenário e modo, e não por parâmetro. No flooding, as 100 repetições percorrem ciclicamente as taxas de 50, 100, 250, 500, 1000 e 2000 pacotes/s, e, no suppression, os saltos de 60, 100, 250, 500, 1000 e 5000; isso dá 17 repetições para cada um dos quatro primeiros valores e 16 para cada um dos dois últimos. No replay, o atraso é sorteado a cada repetição, de forma uniforme, entre 0,5 e 10 s. Em T0, C1 e C2 não há parâmetro. O denominador de cada TPR e do FPR é, portanto, 100 por cenário e modo, agregando os parâmetros do cenário. A sensibilidade do limiar de flooding é varrida à parte (Seção 6), para limiares de 10, 20, 40 e 80 pacotes/s, com 100 repetições por combinação de limiar e taxa. **A campanha é uma reconstrução:** o script de uma campanha anterior do projeto, apresentada no 4.º Marco, não foi preservado. Os parâmetros dos cenários seguem os dessa campanha; os detalhes não documentados (duração do flooding, aquecimento, forma das rajadas do tráfego legítimo e método de cronometragem) foram escolhidos na reconstrução. Ela foi executada em Python 3.12.11, em Linux (*kernel* 7.3.4, CachyOS), e durou 70,1 s.

*4.3.2. GNS3 com 802.1X.* A avaliação usa a topologia `subestacao_8021x` (Figura 3), aberta no GNS3 2.2.61 em 20/11/2026: sete nós Docker, a partir de cinco imagens, cada um ligado a uma porta do autenticador, com a PKI de laboratório instalada nos volumes dos nós. Os cenários E0 a E5 (Tabela 4) foram executados **uma vez cada**, seguindo um roteiro, e o `atacante-1` envia o masquerade com o MAC e a credencial de cada cenário. O IDS esteve ativo em E0, E1, E4 e E5: sem verificação de HMAC em E0, E1 e E4 e com verificação (`--auth`) em E5, com uma chave de teste; nesses cenários, o `publicador-1` emite quadros legítimos que estabelecem a referência do `gocbRef` no IDS (assinados em E5). Em E2, E3 e E4b, o IDS não estava em execução (o roteiro não o inicia em E2 e E3, e no E4b ele havia sido parado), e a evidência de cada um desses cenários é: em E2, o evento `auth_rejeitada` por certificado revogado, a mensagem do *supplicant* e o `ping`; em E3, o evento `auth_rejeitada` por `mac_divergente`, o conjunto de pares autorizados e o `ping`; e, em E4b, o contador do `nftables`. As evidências do conjunto são o log JSONL do autenticador, copiado do volume do nó; os alertas do IDS e o `tcpdump`, extraídos do contêiner; e saídas de console coladas pelo operador (`ping` e `nft list set`). Uma medição auxiliar, feita em ambiente de depuração (contêiner privilegiado, fora do GNS3), registrou o TLS 1.2 como versão negociada (Seção 2.2); ela não é um ambiente de avaliação.

*4.3.3. Network namespaces.* O teste roda em um contêiner Docker privilegiado, com o `hostapd`, o `wpa_supplicant` (versão 2.10) e o `nftables` reais; nove clientes, em *namespaces* distintos, são ligados por pares veth à ponte do contêiner, sem passar pela ponte do *host*, que descartaria o EAPOL. A PKI é temporária. O teste não envia tráfego GOOSE: verifica, por `ping` e pelos eventos do autenticador, quem é autenticado, quem alcança quem e quais motivos de rejeição são registrados. Cada execução faz 30 verificações. Há 11 execuções registradas, todas em 20/11/2026: oito com 30 verificações aprovadas e nenhuma falha; duas com 29 aprovadas e nenhuma falha, de uma versão da suíte com uma verificação a menos; e **uma com 28 aprovadas e 2 falhas**, a sexta em ordem cronológica. As falhas foram "c1 reautentica sozinho e volta a alcançar c2" e "c1 (não revogado) segue alcançando c6", esta dependente da anterior. A causa não está registrada no repositório, e as cinco execuções seguintes registraram 30 verificações aprovadas. A suíte passou de 29 para 30 verificações entre as primeiras execuções, e o README do autenticador registra correções de código nos componentes testados; esses fatos não são relacionados aqui à execução com 28/2. **As 11 execuções não são amostras independentes**, porque a suíte e o código mudaram durante a série; por isso não calculamos taxas nem intervalos de confiança. Um teste à parte confirma que o *supplicant* embutido nas quatro imagens de nós autentica contra o autenticador (16 verificações, nenhuma falha).

### 4.4. Métricas e critérios

*Detecção.* "Detectado" significa que algum quadro do atacante gerou ao menos um alerta; em T0, qualquer alerta é um falso positivo. Reportamos a taxa de detecção (TPR) por cenário e modo, a taxa de falsos positivos (FPR) em T0 e o intervalo de confiança de 95% de Wilson. Como o conteúdo dos quadros é determinístico para cada par (modo, parâmetro), e as repetições de um cenário variam apenas no parâmetro (ciclado ou sorteado, Seção 4.3.1) e no tempo (±10% nos intervalos), as taxas saem em 0% ou 100%, e o intervalo de Wilson (N = 100 por cenário e modo) é o que quantifica a incerteza, e não um desvio entre repetições independentes.

*Latência.* A latência é medida por quadro, com `perf_counter_ns`, descontando a mediana do custo de uma leitura do cronômetro (cerca de 2 µs neste ambiente). Separamos o *parse*, a verificação do HMAC e o processamento no monitor do IDS, e um microbenchmark isolado mede a assinatura e a verificação (20.000 chamadas cada). Como a implementação é em Python, o valor absoluto e o desvio variam entre execuções; interpretamos a ordem de grandeza e as diferenças relativas. Adotamos 4 ms (4.000 µs) como critério experimental de viabilidade, uma escolha deste trabalho (Seção 2.1), e não como requisito normativo.

*GNS3 e network namespaces.* As evidências desses ambientes são qualitativas ou de contagem: eventos do autenticador, contadores do `nftables`, alertas do IDS, `ping` de poucos pacotes e verificações aprovadas ou não. Não calculamos taxas nem intervalos de confiança com elas. Não medimos a latência nem a sobrecarga de autenticação do EAP-TLS em nenhum ambiente.

### 4.5. Reprodutibilidade e disponibilidade

O código, os scripts da campanha, as evidências dos três ambientes e a medição auxiliar de TLS estão no repositório do projeto (<https://github.com/xymotaa/iec61850-security-testbed>), no commit [COMMIT DE REFERÊNCIA: a informar na entrega]. As evidências estão em `benchmark/resultados/` (campanha *offline*), `autenticador-8021x/evidencias/gns3/` (GNS3), `autenticador-8021x/evidencias/` (logs `teste_netns-*.log` dos *network namespaces*) e `autenticador-8021x/evidencias/tls/` (medição de TLS). A PKI é de laboratório: as chaves privadas não são versionadas e são geradas por um script do projeto. A campanha *offline* usa semente fixa, e os comandos de cada ambiente estão nos arquivos de documentação do repositório.

---

## 5. Técnicas de defesa e modificações no testbed

Esta seção descreve as três técnicas avaliadas e as alterações feitas no testbed para implementá-las. O modelo de ameaças está na Seção 3 e os resultados na Seção 6; aqui interessam apenas os mecanismos necessários para interpretá-los. Os mecanismos de defesa são ativados conforme a variante experimental utilizada (Seção 5.4).

### 5.1. IDS de estado

O IDS observa passivamente o tráfego GOOSE e mantém, para cada `gocbRef`, o último `stNum`, o último `sqNum` e o último MAC de origem visto. Ele não atua sobre a rede: gera alertas, escritos na saída padrão e, opcionalmente, em um arquivo JSONL. O primeiro quadro de um `gocbRef` apenas cria a referência e não gera alerta, de modo que o IDS não distingue um publicador legítimo de um falso se o primeiro quadro observado já for forjado.

A Figura 4 mostra o fluxo de decisão para cada quadro, e a Tabela 10 resume as regras. A taxa de quadros é verificada primeiro, em uma janela deslizante de 2 s: há alerta quando a taxa média na janela excede 20 pacotes/s, isto é, mais de 40 quadros em 2 s. O alerta é emitido apenas nas bordas, `flood_start` no início e `flood_end` no fim, e não a cada quadro. Como o fim de uma rajada não tem um quadro seguinte que o revele, um relógio de reavaliação (`tick`), chamado cerca de uma vez por segundo, também encerra o estado de flooding. Em seguida, se a autenticação estiver ativa e a verificação falhar, o IDS emite `auth_fail` e descarta o quadro sem atualizar o estado. Do contrário, aplica as regras de masquerade (MAC diferente do último MAC do `gocbRef`), replay (par `(stNum, sqNum)` menor ou igual ao último) e suppression (salto de `stNum` maior que 50). Um quadro classificado como replay não faz o estado avançar, mas o MAC de origem é atualizado.

*Figura 4. Fluxo de decisão do monitor de estado do IDS para cada quadro GOOSE recebido. [A desenhar: entrada do quadro → criação da referência, se for o primeiro do `gocbRef` → verificação de taxa (flooding) → verificação de autenticação, se ativa (`auth_fail` encerra) → masquerade, replay, suppression → atualização do estado, sem avanço de `stNum`/`sqNum` em caso de replay.]*

*Tabela 10. Regras do IDS de estado.*

| Regra | Condição de alerta | Parâmetro (padrão) | Alerta |
|---|---|---|---|
| Flooding | Taxa média na janela > limiar | Janela de 2 s; 20 pacotes/s | `flood_start`, `flood_end` |
| Autenticação (opcional) | Tag HMAC ausente, malformada ou inválida | — | `auth_fail` |
| Masquerade | MAC de origem ≠ último MAC do `gocbRef` | — | `masquerade` |
| Replay | (`stNum`, `sqNum`) ≤ último par visto | — | `replay` |
| Suppression | `stNum` − último `stNum` > limiar | 50 | `suppression` |

Os limiares de flooding e de suppression são escolhas deste trabalho e podem ser alterados por linha de comando (`--flood-pps`, `--suppression-jump`); a sensibilidade do limiar de flooding é avaliada na Seção 6. A regra de masquerade compara apenas o MAC de origem com o do quadro anterior, de modo que um atacante que use o MAC do publicador não a aciona; esse caso é tratado pelas outras camadas.

### 5.2. Autenticação por mensagem (HMAC) simulada

Para avaliar o efeito de um código de autenticação sobre o IDS, implementamos uma simulação de autenticação por mensagem. Ela é inspirada no princípio da IEC 62351-6 [IEC 2020], que acrescenta um código de autenticação ao GOOSE, mas **não implementa o perfil da norma** nem é interoperável com ele: o formato do quadro e a gestão de chaves são escolhas deste trabalho, e a única relação com a norma que afirmamos é a do princípio, conforme descrito na literatura [Herath et al. 2025].

Cada quadro leva uma tag HMAC-SHA256 de 32 bytes, sem truncamento, calculada com uma chave específica do `gocbRef`, derivada da chave-mestra por HMAC-SHA256 do texto `gocbRef:` seguido do próprio `gocbRef`. A tag cobre os campos `gocbRef`, `stNum`, `sqNum`, `t` e `allData`, cada um precedido de seu tamanho em 4 bytes; os campos de `stNum` e `sqNum` entram com 8 bytes. A Tabela 11 lista o que a tag cobre e o que fica de fora. Como a tag não cobre o MAC de origem, o `timeAllowedToLive`, o `datSet`, o `goID`, o `test`, o `confRev`, o `ndsCom`, o `numDatSetEntries`, o APPID nem a marcação VLAN, o HMAC não protege esses campos contra alteração. A verificação usa `hmac.compare_digest`, e um quadro sem tag ou com tag malformada é tratado como inválido.

A tag é transportada em um trailer TLV após o APDU GOOSE: o byte `0xA0`, o comprimento em BER e os 32 bytes da tag (Figura 5). O comprimento do cabeçalho GOOSE passa a incluir o trailer, e o campo `Reserved1` carrega o tamanho do trailer, valendo 0 quando não há tag; assim, os quadros sem tag permanecem idênticos, byte a byte, aos do codec original. O uso de `0xA0` e de `Reserved1` para essa finalidade é uma escolha do trabalho. O IDS só verifica a tag quando iniciado com `--auth`, e o resultado da verificação entra na decisão descrita na Seção 5.1.

*Figura 5. Quadro GOOSE com o trailer de autenticação: cabeçalho Ethernet, cabeçalho GOOSE (com `Reserved1` igual ao tamanho do trailer), APDU e trailer (`0xA0`, comprimento BER, tag de 32 B). [A desenhar, com os campos cobertos pela tag destacados.]*

*Tabela 11. Campos do quadro GOOSE cobertos e não cobertos pela tag HMAC.*

| Cobertos | Não cobertos |
|---|---|
| `gocbRef`, `stNum`, `sqNum`, `t`, `allData` | `timeAllowedToLive`, `datSet`, `goID`, `test`, `confRev`, `ndsCom`, `numDatSetEntries`; MAC de origem e de destino; APPID; marcação VLAN |

A chave-mestra vem da variável de ambiente `GOOSE_HMAC_KEY`; se ela não for definida, o IDS usa uma constante pública de teste, `TEST_MASTER_KEY`, que é também a chave da campanha *offline*. Nos cenários do GNS3 com HMAC (E5), usamos outra chave de teste, `chave-de-teste`, passada por `GOOSE_HMAC_KEY`. **As duas chaves são públicas e exclusivas do experimento; não protegem nada.** A simulação não tem distribuição nem rotação de chaves. A autenticação HMAC, isoladamente, não impede o replay de um quadro legítimo assinado: uma cópia integral preserva a tag válida. A identificação de duplicatas depende de um mecanismo adicional de controle de estado, como a regra de replay do IDS. No lado do atacante, a opção `--leaked-key-env` indica uma variável de ambiente com a chave-mestra, usada para assinar os quadros de flooding, masquerade e suppression; sem ela, os quadros saem sem tag, e o replay, que reenvia um quadro já assinado, não é afetado. "Chave vazada" refere-se, portanto, à chave-mestra inteira, uma hipótese mais forte do que o vazamento da chave de um único fluxo.

### 5.3. Controle de acesso 802.1X com EAP-TLS

O controle de acesso usa o padrão IEEE 802.1X [IEEE 2020] com EAP-TLS [Simon et al. 2008], implementado com componentes reais: o `hostapd`, o `wpa_supplicant` e o `nftables`. A Figura 6 mostra a arquitetura e o fluxo de decisão.

**Arquitetura.** O `autenticador-8021x` é um único contêiner que forma uma ponte de camada 2 (`br0`), com 9 portas por padrão, à qual cada nó se liga. O `hostapd` roda com o driver *wired*, em um processo, com um arquivo de configuração por porta. O servidor de autenticação EAP está embutido no `hostapd`, sem servidor RADIUS externo, e aceita qualquer identidade (`eap_user: * TLS`), de modo que a decisão fica a cargo da verificação do certificado e do inventário. A reautenticação ocorre a cada 600 s. Os nós usam um *supplicant* opcional (`AUTH_8021X=1`), com `wpa_supplicant` em modo *wired*, `eap=TLS` e verificação do sufixo de domínio do servidor; um *watchdog* o reinicia após uma perda de portadora ou após 20 s sem autorização.

**PKI.** Uma PKI de laboratório, gerada por script, emite uma CA (válida por 3650 dias), um certificado de servidor com `serverAuth` e certificados de cliente com `clientAuth` por nó (825 dias), todos com RSA de 2048 bits e SHA-256, mais uma lista de revogação (CRL). O `hostapd` recebe a CA e a CRL concatenadas, com `check_crl=1` e recarga da CRL a cada 60 s. As chaves privadas não são versionadas.

**Decisão de acesso.** A autenticação do certificado não basta para liberar o tráfego: um supervisor lê o log do `hostapd` (a interface de controle expõe apenas a identidade declarada pelo cliente) e cruza o nome comum (CN) do certificado com um inventário que associa cada CN ao MAC autorizado, gerado a partir do SCD. A autorização só é concedida se o certificado for aceito **e** o MAC de origem da porta coincidir com o MAC do inventário para aquele CN. O resultado alimenta o `nftables`, que opera no gancho *forward* da ponte, com política de descarte: um quadro é encaminhado se vier de uma porta confiável ou se o par (interface de entrada, MAC de origem) estiver no conjunto de pares autorizados e a porta de saída tiver ao menos um dispositivo autorizado. O EAPOL (01:80:C2:00:00:03) não passa por essas regras, pois é tratado pelo autenticador. As regras são carregadas antes de as portas entrarem na ponte, de modo que o sistema falha fechado. Os quadros descartados são contados em um conjunto dinâmico, com validade de 120 s, e geram eventos periódicos. A lista de portas confiáveis existe como mecanismo de exceção, mas fica vazia e não foi usada em nenhum cenário.

O supervisor escreve eventos JSONL: `auth_aceita`, `auth_rejeitada`, `sessao_encerrada` e `quadro_descartado`. A Tabela 12 lista os motivos de rejeição.

*Figura 6. (a) Arquitetura do `autenticador-8021x`: nós ligados às portas da ponte `br0`, um processo `hostapd` por porta, supervisor com o inventário CN→MAC e regras `nftables` no gancho *forward*. (b) Fluxo de decisão: EAP-TLS → validação do certificado e da CRL → CN no inventário → MAC da porta igual ao do inventário → autorização do par (porta, MAC) no `nftables`; cada falha gera um evento `auth_rejeitada` com o motivo correspondente. [A desenhar, em dois painéis.]*

*Tabela 12. Motivos de rejeição registrados pelo autenticador.*

| Motivo | Situação |
|---|---|
| `sem_certificado` | O cliente recusa o EAP-TLS (sem credencial configurada) |
| `certificado_invalido` | Erro de TLS na verificação do certificado, exceto revogação |
| `certificado_revogado` | Erro de TLS indicando revogação (código X509 23, da CRL) |
| `cn_fora_do_inventario` | CN do certificado ausente do inventário |
| `mac_divergente` | CN presente no inventário, mas MAC de origem fora do conjunto de MACs autorizados para esse CN |
| `falha_eap` | EAP termina em falha sem erro de certificado |

Quanto ao TLS, a configuração do projeto não fixa a versão. Em uma medição de depuração, fora do GNS3 (Seção 4.3.2), o EAP-TLS negociou o TLS 1.2, e por isso a RFC 5216 [Simon et al. 2008] é a referência aplicável; a RFC 9190 [Preuß Mattsson e Sethi 2022] só se aplicaria com TLS 1.3. Habilitar o TLS 1.3 nas duas pontas também resultou em TLS 1.2, sem que a causa tenha sido investigada. O vínculo entre certificado e MAC é uma decisão deste trabalho, e não uma exigência do 802.1X.

### 5.4. Modificações no testbed

As modificações abaixo preservam o comportamento da topologia padrão quando os recursos adicionais não são habilitados. No IDS, a opção `--auth`, o parâmetro `auth_valid` e o evento `auth_fail`; sem eles, não há verificação de HMAC. No codec GOOSE, o trailer de autenticação (tag `0xA0`, `Reserved1`); sem tag, os quadros são idênticos, byte a byte, aos do codec original. No atacante, a opção `--leaked-key-env`, que assina os quadros de flooding, masquerade e suppression; sem ela, os quadros de ataque saem sem tag HMAC. Na topologia e na identidade, `ATACANTE_IP` e o uso da imagem do atacante como `publicador-1`; sem `ATACANTE_IP`, a imagem usa o IP padrão do atacante (192.168.10.40). Nas imagens dos nós, o *supplicant* 802.1X embutido nas quatro imagens, desligado por padrão (`AUTH_8021X=1` o ativa). No gerador de topologia, a variante `--8021x`, o inventário nome→MAC e o MAC fixo por nó; sem a variante, a topologia padrão, com *switches*. Também foram acrescentados, como componentes adicionais usados só na variante `--8021x`, a imagem `autenticador-8021x` (`hostapd`, supervisor e `nftables`), o script de PKI e o instalador nos volumes dos nós; e, para a avaliação, a campanha *offline* e a varredura do limiar do IDS.

---

## 6. Resultados e análise

Esta seção apresenta os resultados em três níveis de evidência, que não são somados. Os resultados **medidos** vêm da campanha *offline* (Seções 6.1 a 6.3), com N = 100 por cenário e modo. As evidências **qualitativas** vêm das execuções no GNS3 (Seção 6.4), com uma execução por cenário. As **limitações** do que foi medido estão na Seção 6.5 e são discutidas na Seção 7. Os cenários seguem a nomenclatura da Seção 3: T0 (tráfego legítimo), A (flooding), B (replay), C1 e C2 (masquerade) e D (suppression).

### 6.1. Detecção pelo IDS na campanha *offline*

A Tabela 13 mostra as detecções por cenário e modo. Para 0/100, o intervalo de Wilson de 95% é [0,0%; 3,7%], e para 100/100 é [96,3%; 100,0%]. Como o conteúdo dos quadros é determinístico para cada par (modo, parâmetro) (Seção 4.4), os resultados saem em 0% ou 100%, e a tabela indica qual regra cobre qual cenário, não uma estimativa de desempenho em tráfego real.

*Tabela 13. Detecções por cenário e modo (N = 100 por célula); entre parênteses, os tipos de alerta observados. No cenário T0, a medida é o falso positivo (FPR).*

| Cenário | Sem HMAC | HMAC, atacante sem a chave | HMAC, chave vazada |
|---|---|---|---|
| T0 (FPR) | 0/100 | 0/100 | 0/100 |
| A (flooding) | 100/100 (`flood_start`) | 100/100 (`auth_fail`, `flood_start`) | 100/100 (`flood_start`) |
| B (replay) | 100/100 (`replay`) | 100/100 (`replay`) | 100/100 (`replay`) |
| C1 (masquerade, MAC do publicador) | **0/100** | 100/100 (`auth_fail`) | **0/100** |
| C2 (masquerade, outro MAC) | 100/100 (`masquerade`) | 100/100 (`auth_fail`) | 100/100 (`masquerade`) |
| D (suppression) | 100/100 (`suppression`) | 100/100 (`auth_fail`) | 100/100 (`suppression`) |

Os resultados mostram quatro pontos.

- **Falsos positivos.** Em T0, nenhum alerta ocorreu nos três modos. Esse resultado vale para o tráfego sintético desta campanha (um *heartbeat* de 1 Hz e rajadas de 5 pacotes/s).
- **C1.** O masquerade com o MAC do publicador clonado não é detectado sem HMAC nem com a chave vazada, porque o quadro forjado é consistente com o estado do IDS, que só compara o MAC com o do quadro anterior. Com HMAC e sem a chave, o mesmo ataque é detectado em todas as repetições, pelo alerta `auth_fail`. A tag, portanto, torna detectável um ataque que o IDS de estado não vê; a chave vazada elimina esse ganho.
- **C2.** O IDS de estado detecta o masquerade por `masquerade` sem HMAC e com a chave vazada. Com HMAC e sem a chave, o alerta registrado é `auth_fail`, porque o IDS descarta o quadro antes de aplicar a regra de MAC (Seção 5.1).
- **B.** O replay de um quadro assinado é detectado em todos os modos, e apenas pelo alerta `replay`: a tag do quadro copiado é válida, e a detecção depende do estado do IDS (Seção 5.2).

Essas taxas descrevem as regras e os parâmetros desta campanha, e não permitem concluir superioridade sobre outras abordagens, como as que usam aprendizado de máquina.

### 6.2. Sensibilidade do limiar de flooding

A Figura 7 mostra como o limiar de flooding afeta a detecção de ataques e os falsos positivos. Cada ponto usa 100 repetições, com limiares de 10, 20, 40 e 80 pacotes/s. O painel (a) varia a taxa do ataque (de 5 a 2000 pacotes/s) e o painel (b) varia a taxa de uma rajada legítima (de 5 a 60 pacotes/s).

*Figura 7. Sensibilidade do limiar de flooding do IDS (100 repetições por ponto): (a) taxa de detecção em função da taxa do ataque; (b) taxa de falsos positivos em função da taxa de uma rajada legítima, para os limiares de 10, 20, 40 e 80 pacotes/s. [A desenhar a partir de `sensibilidade_flood_tpr.csv` e `sensibilidade_baseline_fpr.csv`, com o limiar de cada curva identificado.]*

Em ambos os painéis, a transição ocorre onde a taxa se iguala ao limiar. Abaixo do limiar, a taxa de detecção e a de falsos positivos são de 0%. Com a taxa igual ao limiar, ficam entre 72% e 82% na detecção (72%, 82%, 81% e 78% para os limiares 10, 20, 40 e 80) e em 73% a 77% nos falsos positivos (77%, 73% e 73% para os limiares 10, 20 e 40). Na primeira taxa amostrada acima do limiar, chegam a 100%: 15 para o limiar 10, 22 para o 20, 50 para o 40 e 100 para o 80. Esse comportamento é compatível com a regra de alerta, que exige uma taxa estritamente maior que o limiar, combinada com a variação de ±10% nos intervalos (Seção 4.3.1); não testamos essa explicação isoladamente.

O limiar define, portanto, uma faixa de operação: um ataque mais lento que o limiar não é detectado (por exemplo, com limiar 80, os ataques de 50 e de 60 pacotes/s têm taxa de detecção 0), e uma rajada legítima mais rápida o dispara. O limiar de 20 pacotes/s, usado na campanha, separa as rajadas legítimas testadas de até 15 pacotes/s dos ataques testados a partir de 22 pacotes/s; nada se mediu para rajadas entre 15 e 20 pacotes/s. As rajadas legítimas são hipóteses de teste, e não medidas de uma subestação, e para o limiar 80 a maior rajada testada (60 pacotes/s) é inferior ao limiar, de modo que seu ponto de transição não aparece no painel (b).

### 6.3. Latência por quadro

A Tabela 14 resume o tempo gasto por quadro em cada etapa do processamento. Os valores são médias por repetição, e as faixas mostram o menor e o maior valor entre os seis cenários de cada modo; o microbenchmark mede apenas a assinatura e a verificação, com 20.000 chamadas cada.

*Tabela 14. Latência por quadro na campanha *offline* (µs): faixa entre cenários das médias por repetição e microbenchmark do HMAC.*

| Modo | *Parse* | Verificação do HMAC | Processamento no IDS | Soma das médias |
|---|---|---|---|---|
| Sem HMAC | 29,3 a 61,1 | não se aplica | 5,6 a 11,6 | 36 a 73 |
| HMAC, atacante sem a chave | 32,2 a 50,6 | 2,1 a 15,7 | 4,6 a 17,9 | 50 a 84 |
| HMAC, chave vazada | 39,5 a 57,6 | 13,6 a 21,1 | 6,9 a 16,7 | 60 a 95 |

| Microbenchmark | Média | Mediana | P99 | Desvio-padrão |
|---|---|---|---|---|
| Assinatura (`sign`) | 12,08 | 11,04 | 26,26 | 18,16 |
| Verificação (`verify`) | 12,85 | 11,53 | 35,34 | 5,50 |

A leitura é a seguinte.

- **Verificação.** Uma tag válida custa de 11 a 21 µs, em linha com o microbenchmark (12,85 µs em média). Uma tag ausente ou inválida custa de 2 a 3 µs, porque a verificação termina cedo. Por isso, o custo da verificação só deve ser comparado entre quadros de mesma natureza.
- **Peso relativo.** O *parse* do codec é a etapa mais cara em todos os modos, em média mais que a verificação do HMAC.
- **Ordem de grandeza.** A maior soma das médias, 95 µs (modo com chave vazada, cenário D), corresponde a cerca de 2,4% do critério experimental de 4 ms (Seção 4.4). Esse critério é uma escolha deste trabalho, e a comparação cobre apenas o processamento por quadro em Python.

Esses valores não incluem rede, fila nem *hardware* de IED, e variam entre execuções (Seção 4.4); interpretamos a ordem de grandeza. **Não medimos a latência nem a sobrecarga do EAP-TLS em nenhum ambiente, e este trabalho não afirma que ele atenda ao critério de 4 ms.**

### 6.4. Camadas combinadas no GNS3

A Tabela 15 resume os cenários executados no GNS3 (Seção 4.3.2), cada um **uma vez**, em 20/11/2026. Na linha de base, o log do autenticador registra cinco `auth_aceita` (`ubuntu-ied-1`, `ubuntu-ied-2`, `oraculo-1`, `ids-1` e `publicador-1`) e nenhuma para o `atacante-1`; o `ping` de `ubuntu-ied-1` para `ubuntu-ied-2` retornou 3/3. As evidências são de natureza diferente (log do autenticador, saída de console, contador do `nftables` e alertas do IDS), e a coluna final identifica a de cada linha. A Figura 8 mostra, para cada cenário, qual camada atuou e de que forma.

*Tabela 15. Cenários E0 a E5 no GNS3 (uma execução por cenário): efeito observado e evidência.*

| Cenário (credencial; MAC) | Efeito observado | Evidência |
|---|---|---|
| E0: 802.1X desativado; C1 | `ping` do atacante 3/3 (RTT médio 0,468 ms); nenhum alerta do IDS registrado | Console; `alertas_e0.jsonl` (vazio) |
| E1: sem credencial; MAC do publicador | `ping` 0/3 (*Destination Host Unreachable*); `quadro_descartado` na porta do atacante, com o MAC do publicador (motivo `origem_nao_autorizada`); nenhum alerta do IDS registrado | Console; log do autenticador; `alertas_e1.jsonl` (vazio) |
| E2: certificado revogado | `auth_rejeitada` com motivo `certificado_revogado`; *supplicant*: porta não autorizada após 15 s; `ping` 0/3 | Log do autenticador; console |
| E3: certificado válido do nó comprometido (CN `atacante-comprometido`, vinculado ao MAC do atacante); MAC de um IED | TLS aceito (o *supplicant* imprime porta autorizada), mas `auth_rejeitada` com motivo `mac_divergente`; `ping` 0/3 | Log do autenticador; console |
| E4: certificado válido; MAC próprio (C2) | Autentica; o quadro forjado chega ao IDS (`tcpdump`); alerta `masquerade` | `tcpdump_e4.txt`; `alertas_e4.jsonl` |
| E4b: certificado válido; MAC do publicador | Conjunto `descartados` do `nftables`: par (porta do atacante, MAC do publicador), 5 pacotes, 1760 B | Console (`nft list set`) |
| E5 (i): HMAC; sem a chave; MAC próprio | Alerta `auth_fail` | `alertas_e5.jsonl` |
| E5 (ii): HMAC; chave vazada; MAC próprio | Alerta `masquerade` | `alertas_e5.jsonl` |
| E5 (iii): HMAC; chave vazada; MAC do publicador | Nenhum alerta novo registrado; conjunto `descartados`: mesmo par, 5 pacotes, 1930 B | `alertas_e5.jsonl`; console (`nft list set`) |

*Figura 8. Camadas que atuaram em cada cenário do GNS3, segundo a Tabela 15. [A desenhar como matriz: linhas E0, E1, E2, E3, E4, E4b, E5 (i), E5 (ii) e E5 (iii); colunas 802.1X (`nftables` e autenticação), HMAC e IDS; cada célula indica "bloqueio" (descarte no autenticador), "alerta" (IDS), "sem alerta registrado" ou "não em execução". Nenhuma célula com valor numérico.]*

Três observações decorrem da tabela.

1. **802.1X.** Em E1, E2 e E3, o 802.1X impediu o `ping` (0/3). Em E3, o atacante usou a credencial do nó comprometido (CN `atacante-comprometido`, associada no inventário ao MAC do atacante) com o MAC de um IED. A barreira não está na autenticação TLS, que o certificado válido supera, e sim no vínculo entre CN e MAC: o MAC usado não pertence ao CN, e o par não entra no conjunto de pares autorizados.
2. **IDS.** Em E4 e E5 (i) e (ii), os quadros chegaram ao IDS, que apenas alertou; o IDS é passivo (Seção 5.1) e não bloqueou nenhum quadro. A combinação de certificado válido e MAC próprio (E4, E5 (ii)) só foi detectada pelo IDS.
3. **Par (porta, MAC).** Em E4b e E5 (iii), o `nftables` descartou os quadros com o MAC do publicador enviados pela porta do atacante, mesmo com credencial válida e, em E5 (iii), com a chave vazada. Registramos apenas os contadores observados (5 pacotes, 1760 B e 1930 B); o contador do `nftables` registrou os descartes em ambos, e o IDS não registrou alerta novo em E5 (iii).

Sobre o que **não** se pode afirmar: em E2, E3 e E4b, o IDS não estava em execução (Seção 4.3.2), e não há alertas registrados, de modo que nada se conclui sobre o que ele teria detectado. Em E0 e E1, a ausência de alerta no arquivo do IDS é a evidência registrada, e não prova que o IDS tenha ou não detectado o ataque além disso. Os cenários não são estatísticos: cada um foi executado uma vez, e não calculamos taxas nem intervalos de confiança com eles. A revogação em operação (E2b) não foi executada no GNS3 e só foi verificada nos *network namespaces*, que também não geram tráfego GOOSE. Esses testes verificam o funcionamento do autenticador por meio de 30 verificações por execução, com os resultados e a execução com duas falhas, de causa não registrada, descritos na Seção 4.3.3; eles não são tratados aqui como medida de desempenho.

### 6.5. Síntese

Com os dados medidos, cada camada cobre um conjunto distinto de cenários. O IDS de estado cobre flooding, replay, suppression e o masquerade com MAC diferente (C2), mas não o masquerade com o MAC do publicador (C1). A verificação HMAC rejeita quadros sem tag válida de um atacante sem a chave, incluindo os usados nos cenários de flooding, C1, C2 e suppression. Esse efeito desaparece quando a chave é vazada. O replay de um quadro legítimo assinado continua dependendo do estado do IDS. O 802.1X, no GNS3, barrou as tentativas sem credencial válida e as que associam uma credencial a um MAC que não é o dela, mas não impede, por si só, o masquerade de um nó autenticado com o próprio MAC (E4 e E5 (ii)), que só o IDS detectou. Os efeitos sobre a operação do IED, a sobrecarga do EAP-TLS e o desempenho em tráfego real não foram medidos; as limitações e a interpretação desses resultados estão na Seção 7.

---

## 7. Discussão, limitações e ameaças à validade

### 7.1. Discussão

Nos cenários avaliados, as três camadas se complementam, e cada uma falha isoladamente em um ponto diferente. O IDS de estado não detecta o masquerade com o MAC do publicador clonado (C1), porque o quadro forjado é consistente com o estado que ele mantém (Tabela 13). A verificação HMAC rejeita esse ataque quando o atacante não tem a chave, mas deixa de fazê-lo quando a chave é vazada; nesse caso, e com o MAC do publicador, o descarte ocorreu no GNS3 pelo par (porta, MAC) do 802.1X (E5 (iii), Tabela 15). O 802.1X, por sua vez, não impede o masquerade de um nó autenticado com o próprio MAC, que só o IDS detectou (E4 e E5 (ii)). A complementaridade depende de condições que os experimentos assumem: o vínculo entre certificado e MAC vem de um inventário correto, a porta do atacante não é a do publicador e a PKI não foi comprometida. Ela também mistura efeitos diferentes: o IDS é passivo e apenas alerta, enquanto o autenticador descarta quadros. Por isso, os resultados não permitem afirmar que a combinação ofereça proteção completa. Eles indicam que, nos cenários em que as camadas pertinentes foram combinadas e estavam ativas, seus mecanismos se complementaram, cobrindo limitações observadas em camadas isoladas.

Dois resultados dialogam com a literatura. Herath et al. (2025) relatam que a verificação do código de autenticação de mensagem (*Message Authentication Code* — MAC), no formato da IEC 62351-6, detecta o masquerade e o flooding, mas não o replay de um quadro legítimo, cuja tag permanece válida; nossos resultados qualitativos coincidem nesse ponto, embora a nossa autenticação seja uma simulação e a comparação não seja quantitativa. Nos trabalhos analisados, a possibilidade de comprometimento da chave não é avaliada (Seção 2.3); aqui ela é um modo explícito, e o resultado é que o HMAC deixa de agregar detecção de C1 quando a chave é vazada.

### 7.2. Limitações

**Tráfego e ambiente.** Todos os quadros derivam de um único quadro-molde, capturado de um relé SEL-351, e a campanha *offline* os entrega diretamente ao monitor, sem rede nem IED. Os resultados descrevem, portanto, a lógica das regras sobre tráfego sintético, e não o desempenho do IDS em uma subestação real. O GNS3 e os *network namespaces* são ambientes emulados, sem IEDs comerciais.

**Efeitos sobre a operação.** Não medimos o efeito dos quadros forjados sobre assinantes ou IEDs: os efeitos descritos nos casos de uso CU1 a CU3 (Seção 3.6) são hipóteses de impacto, não resultados. O flooding e o suppression também não foram avaliados com o 802.1X ativo, porque os cenários com 802.1X usam apenas masquerade.

**HMAC e chaves.** A autenticação é uma simulação, não conforme à IEC 62351-6 (Seção 5.2). Não há distribuição nem rotação de chaves, as chaves de teste são públicas, e a hipótese de chave vazada cobre a chave-mestra inteira, mais forte do que o vazamento da chave de um fluxo.

**IDS.** O IDS é passivo, tem regras e limiares escolhidos por nós (a sensibilidade do limiar de flooding está na Seção 6.2) e não distingue um publicador legítimo de um falso se o primeiro quadro observado já for forjado.

**802.1X e TLS.** O autenticador usa EAP embutido, sem RADIUS, e uma PKI de laboratório. A versão de TLS foi medida apenas em um ambiente de depuração, fora do GNS3, com o TLS 1.2 negociado; o cliente da imagem `ubuntu-ied` não foi medido. Essa medição é distinta da **ausência de medição da latência e da sobrecarga do EAP-TLS** em qualquer ambiente, incluindo o GNS3: não sabemos quanto a autenticação acrescenta ao tempo de acesso à rede, e este trabalho não afirma que ela atenda ao critério de 4 ms.

**Evidência dos cenários.** No GNS3, cada cenário foi executado uma vez e o IDS não estava em execução em E2, E3 e E4b (Seção 4.3.2), de modo que nada se conclui sobre o que ele teria detectado. Nos *network namespaces*, as 11 execuções não são amostras independentes, e a causa da execução com duas falhas não está registrada.

**Escopo.** Ficam fora do escopo o comprometimento do publicador, da CA e do autenticador (Seção 3.5), de modo que a análise não cobre um nó legítimo comprometido que ocupe a porta do publicador.

### 7.3. Ameaças à validade

**Validade interna.** A campanha *offline* é uma reconstrução: os parâmetros dos cenários seguem os de uma campanha anterior, mas a duração do flooding, o aquecimento, a forma das rajadas legítimas e o método de cronometragem foram escolhidos por nós (Seção 4.3.1). A latência foi medida em Python, em um único ambiente, com valores que variam entre execuções; interpretamos a ordem de grandeza.

**Validade externa.** Os resultados partem de um molde de um relé, de dois IEDs no GNS3 e de um ambiente emulado, e não se generalizam a outros equipamentos, outras tabelas de blocos de controle ou outro volume de tráfego.

**Validade de construto.** "Detectado" significa que algum quadro do atacante gerou ao menos um alerta, o que não mede a rapidez da detecção nem a utilidade operacional do alerta. A taxa de falsos positivos vale para o tráfego sintético de T0, cujas rajadas legítimas são hipóteses de teste. O critério de 4 ms é uma escolha deste trabalho, não um requisito normativo.

**Validade de conclusão.** O conteúdo dos quadros é determinístico para cada par (modo, parâmetro), de modo que as taxas saem em 0% ou 100% (Seção 4.4). Os intervalos de Wilson quantificam a incerteza estatística sob o modelo binomial, mas não tornam os quadros sintéticos representativos de tráfego real e não corrigem a falta de variabilidade da campanha. Os resultados do GNS3 e dos *network namespaces* não têm tratamento estatístico.

---

## 8. Conclusão, contribuições e trabalhos futuros

Este trabalho avaliou, em um *testbed* emulado e com quadros derivados de um único quadro GOOSE capturado de um relé SEL-351, o que cobrem um IDS de estado, uma autenticação por mensagem simulada (HMAC) e um controle de acesso 802.1X com EAP-TLS diante do masquerade com MAC clonado (C1) e com MAC próprio (C2). Nos cenários avaliados, nenhuma das três camadas bastou isoladamente: o IDS de estado não detectou C1; a verificação HMAC deixou de rejeitar os quadros do atacante quando a chave foi vazada e não afeta a detecção do replay de um quadro assinado; e o 802.1X não impediu o masquerade de um nó autenticado com o próprio MAC. Nos cenários em que as camadas pertinentes foram combinadas e estavam ativas, elas se complementaram. Esses resultados não permitem afirmar proteção completa nem estendê-los a tráfego real, a outros equipamentos ou a outras configurações (Seção 7).

As contribuições anunciadas na Introdução correspondem aos seguintes resultados.

1. **Ponto cego do IDS de estado.** Na campanha *offline*, o IDS detectou o masquerade com MAC próprio (C2) em 100 das 100 repetições e não detectou o com MAC clonado (C1) em nenhuma (Tabela 13). No GNS3, E0 (C1 sem 802.1X) não registrou alerta, e E4 (C2) registrou `masquerade` (Tabela 15).
2. **Autenticação por mensagem simulada.** Sem a chave, o atacante teve C1 detectado em 100 das 100 repetições, por `auth_fail`; com a chave vazada, C1 voltou a 0 de 100. O replay de um quadro assinado foi detectado só pela regra do IDS. A verificação do HMAC custou de 11 a 21 µs por quadro com tag válida (Tabela 14), e a latência e a sobrecarga do EAP-TLS não foram medidas.
3. **802.1X real com EAP-TLS e vínculo entre certificado e MAC.** O autenticador, gerado no mesmo fluxo que produz a topologia a partir do SCD, barrou no GNS3 as tentativas sem credencial válida e com certificado revogado. A verificação adicional do vínculo entre certificado e MAC rejeitou a tentativa de usar uma credencial válida com o MAC de outro nó (E3), além de descartar o uso do MAC do publicador por outra porta (E4b e E5 (iii)). Cada cenário foi executado uma vez, e os resultados são qualitativos.
4. **Análise por cenário e por camada.** As Tabelas 13 e 15 e a Figura 8 identificam onde cada defesa falha isoladamente e quais cenários cada uma cobre, no escopo da Seção 7.

Os trabalhos futuros decorrem das limitações declaradas, e são intenções, não resultados. Primeiro, medir a latência e a sobrecarga do EAP-TLS no GNS3 e a versão de TLS negociada com o cliente da imagem `ubuntu-ied`. Segundo, avaliar flooding e suppression com o 802.1X ativo. Terceiro, medir o efeito dos quadros forjados sobre assinantes e IEDs reais, para verificar os casos de uso CU1 a CU3. Quarto, substituir a simulação por uma implementação conforme à IEC 62351-6, com distribuição e rotação de chaves. Quinto, ampliar o número de execuções no GNS3 e a variedade do tráfego, para além de um único quadro-molde.

---


## Pendências registradas (não bloqueiam a redação)
- Seção 6: Figuras 7 (dois painéis) e 8 por desenhar. As faixas de *parse* da Tabela 17 foram calculadas a partir de `benchmark/resultados/campanha_trials.csv` (o `resumo.md` não as traz). A explicação do jitter na 6.2 é "compatível com", não testada.
- Seção 5: Figuras 4, 5 e 6 (dois painéis) por desenhar. A frase sobre a IEC 62351-6 se apoia em Herath et al. (2025), fonte secundária; o texto normativo não foi lido.
- Numeração dos SRs da IEC 62443-3-3 (o texto cita pelo conteúdo).
- Edição da IEC 61850-8-1; páginas do artigo base; local de publicação do Girdhar.
- Roomi (Auto-SGCR): leitura parcial.
- TLS do cliente `ubuntu-ied` (Ubuntu, OpenSSL 3.0.13) não medido; a medição versionada usa o cliente Debian.
- Cláusulas do IEEE 802.1X (descrição no nível do título da norma).
- Modelo de CPU da campanha *offline*: removido do texto por falta de confirmação do autor (candidata: AMD Ryzen 5 3500U, desta máquina; o `execucao.json` não registra a CPU). Se confirmado, restaurar na 4.3.1, na 4.4 ("processador de notebook compartilhado") e na Tabela 11.
- Commit de referência (placeholder na 4.5), a informar na entrega.
- `[MZ Automation s.d.]` no `.bib` tem URL, mas não data de acesso (URL verificada em 21/11/2026: página responde, licença GPL-3.0).
- `benchmark/benchmark_ids.py` (constante `LIMITE_NORMA_US` e seu comentário) atribui os 4000 µs à IEC 61850-5; o artigo os trata como critério experimental. Código não alterado.
- Seção 4.3.2: a ausência do IDS em E2 e E3 se apoia no roteiro e na falta de arquivo de alertas; só o E4b foi observado com o IDS parado.
- Aplicação do texto ao `main.tex`, figuras (b) e (c), reversão dos três desvios do template e compilação final.
