# Conteúdo da apresentação — 4º Marco (09/11/2026)

"Apresentar resultados parciais de reprodução" — mesmo enunciado do 3º
Marco (ver `docs/SRC-Cap0-Apresentação da Disciplina-4.pdf`, slide 18).
Este marco fecha lacunas que ficaram em aberto no 3º Marco (ver
`changelog/README.md`), com foco em **validação real** do que antes
era só validação estrutural/programática.

Texto pronto pra colar no slide, slide a slide. Ajustem o número de
slides conforme o tempo que tiverem.

---

## Slide 1 — Capa

**Título:** Analisador Automático de Segurança Cibernética para o Setor Elétrico — Reprodução e Extensão

**Subtítulo:** 4º Marco — Validação Real e Fechamento de Lacunas

Disciplina: Segurança em Redes de Computadores — Prof. Hugo Kuribayashi
Artigo original: Oliveira & Gurjão (UFCG), SBSeg 2025 — WTICG
[Nomes do grupo]

---

## Slide 2 — Recapitulando o 3º Marco

No marco anterior, entregamos o pipeline completo do artigo original
reproduzido e estendido:

- Extração de SCD + geração automática de topologia GNS3 (`.gns3`)
- Oráculo: 8 critérios de conformidade IEC 62443-3-3 (vs. 2 do artigo original)
- 4 ataques GOOSE + IDS próprio, com 80% de detecção geral e 0 falsos positivos

Mas isso tinha 3 lacunas explícitas, assumidas no changelog:

1. `gerar_topologia_gns3.py` nunca tinha sido testado dentro do GNS3 real (só validado programaticamente)
2. A extração só tinha sido testada com um SCD **sintético** (2 IEDs fictícios)
3. As métricas do IDS vinham de execuções pontuais, não de uma campanha com repetições

---

## Slide 3 — Objetivo deste marco

Fechar as duas primeiras lacunas com **validação real**, não só
estrutural:

- Abrir e testar o `.gns3` gerado automaticamente dentro do GNS3 de verdade
- Rodar o pipeline completo (extração → topologia → auditoria → ataque → detecção) sobre um **SCD real**, não mais sintético
- Reportar com transparência os bugs reais encontrados nesse processo — e como foram corrigidos

---

## Slide 4 — Por que isso importa

Um script que "parece certo" e passa em validação programática
(JSON bem formado, UUIDs válidos, contagem de nós/links correta) não
é garantia de que funciona de fato. Só abrir no GNS3 real revela
problemas que a validação estrutural não pega — é exatamente o que
aconteceu aqui, e por isso reportamos os dois bugs encontrados como
parte do resultado, não como nota de rodapé.

---

## Slide 5 — Conseguindo um SCD real

**Lacuna do 3º Marco:** só tínhamos `exemplo_subestacao.scd`, sintético, com 2 IEDs fictícios.

**Fonte usada:** `simpleIO_direct_control_goose.scd`, do repositório
open-source **mz-automation/libiec61850** (implementação de referência
IEC 61850 em C, licença GPL-3.0) — usado em testes do próprio projeto
upstream.

**Conteúdo real:**
- 1 IED (`simpleIO`), IP `10.0.0.2/24`
- 2 blocos GOOSE reais (`GSEControl`): `gcbEvents`, `gcbAnalogValues`
- MAC, APPID (1000) e VLAN (111) configurados em `<Communication>`

**Limitação assumida:** só 1 IED (vs. 2 do sintético) — mas é dado real de um projeto IEC 61850 de verdade, não fictício.

[Inserir print do `python3 extrair_scd.py scd_real_simpleIO.scd --json dados_real.json`]

---

## Slide 6 — Bug 1: posições de nó como float

Ao gerar o `.gns3` a partir do SCD real e abrir no GNS3, o projeto
**não abriu**:

```
Invalid data in topology file: -530.0 is not of type 'integer'
in schema: {"description": "X position of the node", "type": "integer"}
```

**Causa:** `gerar_topologia_gns3.py` calcula as posições `x`/`y` dos
nós com `X_SPACING * 1.5` e divisões (`/2`) — em Python isso retorna
`float` (`-530.0`), mas o schema do GNS3 exige `integer` estrito.

**Correção:** `int(round(x))` / `int(round(y))` na criação de cada nó.

[Inserir print do popup de erro no GNS3]

---

## Slide 7 — Bug 2: nome de nó incompatível com o entrypoint

Com o Bug 1 corrigido, o projeto abriu — mas o IED não pegava IP.

**Causa:** o `entrypoint.sh` do container `ubuntu-ied` deriva o IP do
**hostname**, que o GNS3 define a partir do nome do nó: o padrão
`ubuntu-ied-N` vira `192.168.10.1N`. O gerador nomeava o nó como
`ied-<nome-do-SCD>` (ex. `ied-simpleIO`) — sem número no final, então
nenhum IP era configurado.

**Correção:** nós IED sempre nomeados `ubuntu-ied-{N}` (compatível com
o `entrypoint.sh` existente); o nome/IP reais extraídos do SCD ficam
preservados como metadado (`IED_NAME`, `IED_IP` no ambiente do
container), sem quebrar a convenção de rede já usada no resto do
projeto.

---

## Slide 8 — Validação ponta a ponta (depois das correções)

Com os 2 bugs corrigidos, pipeline completo testado dentro do GNS3 real:

| Etapa | Resultado |
|---|---|
| Abrir `subestacao_real.gns3` no GNS3 | ✅ Sem erros |
| `ip a` no `ubuntu-ied-1` | ✅ `192.168.10.11/24` configurado automaticamente |
| `oraculo.py 192.168.10.11` | ✅ Relatório completo via SSH, 3/12 critérios conformes — **mesmo padrão** dos 5 IEDs sintéticos do 3º Marco |
| `goose_attack.py replay` (atacante-1) | ✅ Frame reenviado |
| `ids.py` (ids-1) | ✅ Detectou o replay: `(stNum=23, sqNum=521) <= último visto` |

[Inserir print do console do oraculo-1 e do ids-1 lado a lado]

---

## Slide 9 — O que esse resultado prova

- O pipeline **SCD → JSON → `.gns3` → GNS3 real → tráfego GOOSE →
  detecção** funciona de ponta a ponta com um SCD real, não só com
  dado sintético — fecha de fato o fluxo do artigo original (Fig. 1)
- O gerador de topologia agora generaliza para qualquer SCD real
  válido, independente do número de IEDs que ele descreve
- Validação honesta: reportamos os bugs encontrados e como foram
  corrigidos, não só o resultado final "funcionando"

---

## Slide 10 — O que ainda falta (3ª lacuna do 3º Marco)

**Campanha de testes do IDS com mais repetições** — ainda não feita.
As métricas atuais (4/5 detecção, 0 falsos positivos) seguem vindo de
execuções pontuais de cada ataque, não de uma campanha estatística
(múltiplas repetições por cenário, variação de `--pps` no flood ou
`--jump` no suppress).

Fica registrado como item em aberto para o relatório final.

---

## Slide 11 — Próximos passos (5º Marco, 23/11)

- Resumo expandido em formato SBC (Overleaf) — ainda não iniciado
- Campanha de testes do IDS com repetições (pendência que ficou deste marco)
- Relatório final consolidado (Oráculo + ataques GOOSE + geração automática de topologia), já citando o SCD real usado
- Seção de limitações e trabalhos futuros própria, incluindo a necessidade de IEC 62351-6 (achado do 3º Marco sobre masquerade com MAC idêntico)
- Revisão final de todos os READMEs do repositório

---

## Slide 12 — Encerramento

**Resumo da entrega deste marco:**
- Validação real (não só estrutural) do `gerar_topologia_gns3.py` dentro do GNS3
- 2 bugs reais encontrados e corrigidos no processo (posições float; nomenclatura incompatível com o entrypoint)
- Pipeline completo testado ponta a ponta com um SCD real de um projeto IEC 61850 open-source (libiec61850), não mais sintético
- Resultado consistente com o 3º Marco: mesma auditoria de conformidade, mesma detecção de ataque GOOSE, agora sobre dado real

Dúvidas?
