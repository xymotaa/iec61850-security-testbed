#!/usr/bin/env python3
"""Aplica os cortes autorizados ao texto aprovado e grava o texto da versao-2.

Entrada : ../rascunho/secoes-aprovadas.md (texto aprovado; NAO e alterado)
Saida   : texto/secoes-versao-2.md (usado por md2tex.py e verificar.py)

Cada substituicao exige exatamente uma ocorrencia (senao o script falha), e as
tabelas sao renumeradas depois da remocao das Tabelas 3, 11 e 15.
Uso: python3 aplicar_cortes.py <secoes-aprovadas.md> <saida.md>
"""
import re
import sys

SRC, OUT = sys.argv[1], sys.argv[2]
L = open(SRC, encoding="utf-8").read().split("\n")


def idx_start(prefix):
    hits = [i for i, l in enumerate(L) if l.startswith(prefix)]
    assert len(hits) == 1, f"{len(hits)} linhas comecam com {prefix!r}"
    return hits[0]


def replace_line(prefix, new):
    L[idx_start(prefix)] = new


def replace_in_line(prefix, old, new):
    i = idx_start(prefix)
    assert L[i].count(old) == 1, f"trecho nao encontrado em {prefix!r}: {old!r}"
    L[i] = L[i].replace(old, new)


def table_span(caption_prefix):
    i = idx_start(caption_prefix)
    j = i + 1
    while not L[j].startswith("|"):
        j += 1
    k = j
    while k < len(L) and L[k].startswith("|"):
        k += 1
    return i, j, k  # legenda, primeira linha da tabela, fim (exclusivo)


def remove_table(caption_prefix):
    i, j, k = table_span(caption_prefix)
    while k < len(L) and not L[k].strip():
        k += 1
    del L[i:k]


def set_table_rows(caption_prefix, rows):
    i, j, k = table_span(caption_prefix)
    L[j:k] = ["| " + " | ".join(r) + " |" for r in rows[:1]] + \
             ["|" + "---|" * len(rows[0])] + ["| " + " | ".join(r) + " |" for r in rows[1:]]


# ---------------------------------------------------------------- 1. Tabela 3
remove_table("*Tabela 3. ")
replace_in_line(
    "A auditoria de credenciais, por mais completa",
    " A Tabela 3 resume a relação.",
    " O Oráculo foi estendido com novos critérios de auditoria, descritos na Seção 2.2. "
    "Os ataques ao tráfego GOOSE, o IDS de estado e a validação do gerador com um SCD real de "
    "um projeto de referência também estendem o artigo base.")

# ---------------------------------------------------------------- 2. Tabela 11
remove_table("*Tabela 11. ")
replace_in_line(
    "A avaliação usa três ambientes, descritos a seguir",
    "descritos a seguir e resumidos na Tabela 11. Cada um produz",
    "descritos a seguir; a Tabela 8 resume seus cenários. Cada um produz")
replace_in_line(
    "*4.3.3. Network namespaces.*",
    "com o `hostapd`, o `wpa_supplicant` e o `nftables` reais;",
    "com o `hostapd`, o `wpa_supplicant` (versão 2.10) e o `nftables` reais;")
replace_in_line(
    "O código, os scripts da campanha, as evidências",
    "estão no repositório do projeto [COMMIT DE REFERÊNCIA: a informar na entrega].",
    "estão no repositório do projeto (<https://github.com/xymotaa/iec61850-security-testbed>), no commit "
    "[COMMIT DE REFERÊNCIA: a informar na entrega]. As evidências estão em `benchmark/resultados/` "
    "(campanha *offline*), `autenticador-8021x/evidencias/gns3/` (GNS3), `autenticador-8021x/evidencias/` "
    "(logs `teste_netns-*.log` dos *network namespaces*) e `autenticador-8021x/evidencias/tls/` (medição de TLS).")

# ---------------------------------------------------------------- 3. Tabela 6
set_table_rows("*Tabela 6. ", [
    ["Variante", "MAC de origem", "Tag HMAC no quadro forjado", "Premissas do atacante"],
    ["C1", "Do publicador (clonado)", "Ausente, sem a chave; válida (chave-mestra), com a chave",
     "Último `stNum` do publicador e posição do booleano; com a chave, também a chave-mestra"],
    ["C2", "Diferente do publicador", "Ausente, sem a chave; válida (chave-mestra), com a chave",
     "Último `stNum` do publicador e posição do booleano; com a chave, também a chave-mestra"],
])

# ---------------------------------------------------------------- 4. Tabela 9
set_table_rows("*Tabela 9. ", [
    ["Arquivo", "SCD de origem e nós", "Uso neste artigo"],
    ["`subestacao.gns3`", "Sintético (2 IEDs); 10 nós: 5 *switches*, 2 IEDs, Oráculo, IDS, atacante",
     "Topologia de referência do gerador; não usada nos cenários E0 a E5"],
    ["`subestacao_real.gns3`", "Real (`simpleIO`, 1 IED); 9 nós",
     "Validação do gerador com SCD real (4.º Marco): abre sem erro, IP automático, replay detectado pelo IDS"],
    ["`subestacao_8021x.gns3`", "Sintético (2 IEDs); 7 nós: autenticador, 2 IEDs, Oráculo, IDS, publicador, "
     "atacante; sem *switches*", "Todos os cenários E0 a E5 no GNS3"],
])

# ---------------------------------------------------------------- 5. Tabela 4 (sem a coluna Ambiente)
i, j, k = table_span("*Tabela 4. ")
rows = [[c.strip() for c in L[n].strip().strip("|").split("|")] for n in range(j, k)]
col = rows[0].index("Ambiente")
rows = [r[:col] + r[col + 1:] for r in rows if not re.match(r"^-+$", r[0])]
set_table_rows("*Tabela 4. ", rows)

# ---------------------------------------------------------------- 6. Seções 3.1 e 3.2
replace_line(
    "Duas características do *testbed*",
    "Duas características do *testbed* condicionam a leitura dos resultados. A primeira é que "
    "**não existe um IED publicador independente**: os nós `ubuntu-ied` são *hosts* genéricos, que não "
    "geram GOOSE, e o publicador legítimo é emulado por `publicador-1`, que usa a mesma ferramenta de "
    "geração de quadros do atacante e o mesmo quadro-molde capturado de um relé SEL-351 (a campanha "
    "*offline* usa um gerador de tráfego equivalente). Publicador e atacante diferem, portanto, pelo "
    "papel e pelas credenciais de que dispõem (certificado 802.1X e posse da chave), e não por serem "
    "implementações distintas do protocolo; o MAC de origem do atacante pode ser distinto do publicador "
    "(C2) ou clonado dele (C1), como definido na Seção 3.3. A segunda é que **não há assinante GOOSE**: "
    "o único observador do tráfego é o IDS. Por isso, o efeito de um quadro forjado sobre um dispositivo "
    "de proteção, como a abertura de um disjuntor, não é medido; ele é tomado da literatura "
    "[Conceição Alberto et al. 2026; de Oliveira et al. 2023].")
replace_line(
    "O adversário é um dispositivo ligado a uma porta",
    "O adversário é um dispositivo ligado a uma porta do domínio de camada 2 em que o GOOSE circula "
    "(no *testbed*, o nó `atacante-1`), com privilégio de *socket* cru. Ele captura passivamente um "
    "quadro GOOSE legítimo, reaproveita o `allData` da captura (conhecendo a posição do valor booleano "
    "de estado) e constrói quadros com `stNum`, `sqNum`, `t` e MAC de origem arbitrários, inclusive "
    "alterando o MAC da própria interface, sem exigir credenciais do IED nem a exploração do "
    "dispositivo. Não atua como intermediário (*man-in-the-middle*) nem descarta seletivamente quadros "
    "em trânsito entre outros nós.")
replace_line(
    "O masquerade e o suppression pressupõem",
    "O masquerade e o suppression pressupõem que o adversário conheça o último `stNum` do publicador; "
    "o `sqNum` não precisa ser conhecido, porque o quadro forjado o zera. Adotamos essa condição como "
    "**premissa do modelo de ameaças**. Herath et al. (2025) descrevem uma premissa mais ampla para o "
    "masquerade (conhecer `stNum` e `sqNum` do último quadro), e Conceição Alberto et al. (2026) modelam "
    "um adversário que observa passivamente o tráfego do barramento e injeta quadros forjados. O "
    "*testbed* facilita esse conhecimento, porque o publicador repete o quadro-molde de que o atacante "
    "parte; em uma rede real, isso depende de o adversário observar o tráfego do publicador a tempo. "
    "O replay e o flooding não exigem essa premissa.")
replace_line(
    "O adversário não dispõe da chave de autenticação",
    "O adversário não dispõe da chave de autenticação por mensagem, exceto no cenário de chave "
    "comprometida (Seção 3.4). No máximo, dispõe do certificado e da chave privada de um nó "
    "comprometido (`atacante-comprometido`, que os fornece ao atacante), e nunca dos certificados e das "
    "chaves privadas dos IEDs ou do publicador. Não compromete a CA, o autenticador nem o publicador, e "
    "não tem acesso físico para substituir um dispositivo em uma porta já autenticada; essas exclusões "
    "são decisões de modelagem, e o comprometimento do publicador permanece como trabalho em aberto. "
    "A Tabela 5 organiza os níveis do atacante diante do 802.1X.")

# ---------------------------------------------------------------- Tabela 15 -> texto na 5.4
remove_table("*Tabela 15. ")
replace_line(
    "A Tabela 15 resume o que foi acrescentado",
    "As modificações abaixo preservam o comportamento da topologia padrão quando os recursos adicionais "
    "não são habilitados. No IDS, a opção `--auth`, o parâmetro `auth_valid` e o evento `auth_fail`; sem "
    "eles, não há verificação de HMAC. No codec GOOSE, o trailer de autenticação (tag `0xA0`, "
    "`Reserved1`); sem tag, os quadros são idênticos, byte a byte, aos do codec original. No atacante, "
    "a opção `--leaked-key-env`, que assina os quadros de flooding, masquerade e suppression; sem ela, "
    "os quadros de ataque saem sem tag HMAC. Na topologia e na identidade, `ATACANTE_IP` e o uso da "
    "imagem do atacante como `publicador-1`; sem `ATACANTE_IP`, a imagem usa o IP padrão do atacante "
    "(192.168.10.40). Nas imagens dos nós, o *supplicant* 802.1X embutido nas quatro imagens, desligado "
    "por padrão (`AUTH_8021X=1` o ativa). No gerador de topologia, a variante `--8021x`, o inventário "
    "nome→MAC e o MAC fixo por nó; sem a variante, a topologia padrão, com *switches*. Também foram "
    "acrescentados, como componentes adicionais usados só na variante `--8021x`, a imagem "
    "`autenticador-8021x` (`hostapd`, supervisor e `nftables`), o script de PKI e o instalador nos "
    "volumes dos nós; e, para a avaliação, a campanha *offline* e a varredura do limiar do IDS.")

# ---------------------------------------------------------------- Seção 2.3 (condensação)
replace_line(
    "*Detecção de intrusão.*",
    "*Detecção de intrusão.* Herath et al. (2025) implementam um IDS por regras sobre `stNum`, `sqNum` e "
    "temporização, executado em linha no caminho de encaminhamento, que descarta os quadros reprovados. "
    "Conceição Alberto et al. (2026) propõem um IDS sobre tráfego espelhado, com LightGBM e atributos "
    "derivados de `stNum`, `sqNum` e temporização, e uma resposta que injeta quadros corretivos; os "
    "autores excluem do modelo de ameaças o comprometimento de dispositivos e o acesso a chaves. Moore "
    "(2026) compara modelos supervisionados e não supervisionados sobre o conjunto ERENO e relata a "
    "latência por predição; nesse trabalho, o masquerade é descrito como falsificação do MAC de origem e "
    "dos identificadores GOOSE, mas os campos de MAC são descartados, entre outras colunas de alta "
    "cardinalidade, do conjunto de atributos. O IDS deste trabalho é baseado em regras e passivo (emite "
    "alertas e não descarta quadros); por isso, não equivale aos IDS em linha e não é comparado, em "
    "desempenho, às abordagens de aprendizado de máquina.")
replace_line(
    "*Autenticação por mensagem.*",
    "*Autenticação por mensagem.* Herath et al. (2025) implementam a verificação de MAC com AES-GMAC-128 "
    "no formato da IEC 62351-6:2020 e mostram que ela detecta o masquerade e o flooding, mas não o "
    "replay de um quadro legítimo, cuja tag permanece válida; a combinação com o IDS por regras cobre o "
    "replay. Hussain et al. (2023) combinam o MAC com chave pré-compartilhada e a validação do conteúdo "
    "junto a IEDs vizinhos. Nos trabalhos analisados, a possibilidade de comprometimento da chave não é "
    "avaliada: Herath et al. (2025) não a tratam, e Conceição Alberto et al. (2026) a excluem do modelo "
    "de ameaças. A autenticação avaliada aqui é uma simulação baseada em HMAC (Seção 5.2), que representa "
    "a ideia da IEC 62351-6 sem implementar o seu mecanismo normativo, e seus resultados não são "
    "comparáveis aos de Herath et al. (2025).")
replace_line(
    "*Controle de rede e de acesso.*",
    "*Controle de rede e de acesso.* Moore (2026) observa que o protocolo foi concebido para redes "
    "isoladas, nas quais o controle de acesso físico bastava, e que essa premissa deixa de valer em redes "
    "Ethernet maiores, onde qualquer dispositivo do segmento pode receber, reproduzir ou forjar quadros "
    "sem autenticação. Girdhar et al. (2023) integram um IDS por regras a *switches* definidos por "
    "software, que localizam o dispositivo atacante e desativam a sua porta, ação que ocorre depois da "
    "detecção. Herath et al. (2025) concluem que o descarte de pacotes exige, além da detecção, "
    "mecanismos de controle de tráfego, como SDN, ou redundância (PRP e HSR). Nos trabalhos analisados, "
    "não identificamos a avaliação de um controle de acesso à porta baseado em autenticação do "
    "dispositivo, como o 802.1X. Nossas buscas por esse tema em subestações foram limitadas e não "
    "permitem afirmar que ele nunca tenha sido estudado.")
replace_line(
    "*Ambientes e conjuntos de dados.*",
    "*Ambientes e conjuntos de dados.* Herath et al. (2025) usam um *testbed* ciberfísico, com simulador "
    "em tempo real e IEDs comerciais, no qual as defesas rodam em um IED simulado; Conceição Alberto et "
    "al. (2026) e de Oliveira et al. (2023) usam *hardware-in-the-loop* com relés ou IEDs comerciais. "
    "Zemanek et al. (2022) publicam um conjunto de dados gravado em um *testbed* físico com três IEDs, "
    "sem avaliar defesas. Roomi et al. (2025) geram um *cyber range* a partir de arquivos SCL, com "
    "Mininet e simulação elétrica, e o artigo base [Oliveira e Gurjão 2025] gera a topologia no GNS3 a "
    "partir do SCD. O ambiente deste trabalho é emulado (GNS3 e Docker), sem hardware real, e usa como "
    "molde um único quadro GOOSE capturado de um relé SEL-351; seus resultados não são comparáveis, em "
    "desempenho, aos dos ambientes com hardware.")

# ---------------------------------------------------------------- Resumo e Abstract (10 linhas)
i0 = idx_start("## Resumo e Abstract")
i1 = next(k for k in range(i0, len(L)) if L[k].startswith("---"))
L[i0 + 1:i1] = [
    "",
    "**Resumo.** O masquerade em GOOSE forja quadros coerentes com o estado do protocolo. Avaliamos, "
    "com MAC clonado (C1) e próprio (C2), um IDS de estado passivo, autenticação por mensagem simulada "
    "(HMAC) e controle 802.1X com EAP-TLS e vínculo entre certificado e MAC. Os quadros derivam de um "
    "único quadro capturado de um relé SEL-351; combinamos uma campanha *offline* (100 repetições por "
    "cenário) e o GNS3 (uma execução por cenário). O IDS detectou C2, mas não C1; a verificação HMAC "
    "rejeitou C1 sem a chave, mas não quando ela foi vazada; o 802.1X barrou credenciais inválidas e MAC "
    "divergente, mas não um nó autenticado com o próprio MAC. Nos cenários avaliados, as camadas se "
    "complementaram, sem comprovar proteção completa.",
    "",
    "**Palavras-chave:** IEC 61850; GOOSE; masquerade; detecção de intrusão; IEEE 802.1X.",
    "",
    "**Abstract.** GOOSE masquerade forges frames consistent with the protocol's state. We evaluate, "
    "with a cloned (C1) or the attacker's own (C2) MAC, a passive state-based IDS, simulated "
    "per-message authentication (HMAC), and 802.1X with EAP-TLS and a certificate-MAC binding. Frames "
    "derive from a single frame captured from an SEL-351 relay, combining an offline campaign (100 "
    "repetitions per scenario) with GNS3 executions (one per scenario). The IDS detected C2 but not C1; "
    "HMAC verification rejected C1 without the key, but not once the key leaked; 802.1X blocked "
    "invalid credentials and MAC mismatches, but not an authenticated node using its own MAC. In the "
    "evaluated scenarios the layers complemented each other, without proving full protection.",
    "",
    "**Keywords:** IEC 61850; GOOSE; masquerade; intrusion detection; IEEE 802.1X.",
    "",
]

# ---------------------------------------------------------------- renumeracao das tabelas
fim = next(i for i, l in enumerate(L) if l.startswith("## Pendências"))
corpo = "\n".join(L[:fim])
restantes = [int(n) for n in re.findall(r"^\*Tabela (\d+)\. ", corpo, re.M)]
mapa = {old: new for new, old in enumerate(restantes, 1)}
REF = re.compile(r"\b(Tabelas?)\s+(\d+(?:\s*(?:,|e|a)\s*\d+)*)")


def renum(m):
    def um(n):
        old = int(n.group(0))
        assert old in mapa, f"referencia a tabela removida: Tabela {old}"
        return str(mapa[old])
    return m.group(1) + " " + re.sub(r"\d+", um, m.group(2))


a = corpo.index("## Resumo e Abstract")
corpo = corpo[:a] + REF.sub(renum, corpo[a:])
open(OUT, "w", encoding="utf-8").write(corpo + "\n\n" + "\n".join(L[fim:]))
print("tabelas restantes (antigo->novo):", mapa)
