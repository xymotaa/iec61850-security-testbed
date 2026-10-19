# extracao-scd/

Scripts de extração de dados de um arquivo SCD (IEC 61850 SCL) e de
geração automática da topologia GNS3 — reproduz e estende o fluxo
completo do artigo original (Fig. 1: Extração → Modelagem → GNS3), que
antes terminava na extração (IP/máscara/nome do IED) e exigia montar a
topologia manualmente.

**Arquivos:**
- `extrair_scd.py` — extração (SCD → JSON).
- `gerar_topologia_gns3.py` — modelagem (JSON → `.gns3`).
- `exemplo_subestacao.scd` — SCD sintético (mas estruturalmente válido) usado para testar o script, com 2 IEDs.

## 1. Extração (`extrair_scd.py`)

**O que extrai:** IP, máscara e nome de cada IED (igual ao original) +
blocos GOOSE (`gocbRef`, `datSet`, MAC, APPID, VLAN) e SV (`smvID` +
mesmo endereçamento) — necessário para os testes do `atacante/` e `ids/`.

```bash
python3 extrair_scd.py exemplo_subestacao.scd
python3 extrair_scd.py exemplo_subestacao.scd --json dados.json
```

## 2. Geração da topologia (`gerar_topologia_gns3.py`)

Consome o JSON da extração e gera um arquivo `.gns3` pronto para abrir
no GNS3 — fecha o elo que faltava com o fluxograma do artigo original.
Reproduz a topologia que o projeto já usa (ver `README.md` da raiz): 4
switches de borda em estrela ligados a um switch central (sem malha —
o switch nativo do GNS3 não roda Spanning Tree), um nó `ubuntu-ied` por
IED extraído, e `oraculo-1`/`ids-1`/`atacante-1` direto no switch
central (GOOSE é multicast de Camada 2 — precisam estar no mesmo
domínio de broadcast que os IEDs).

```bash
python3 gerar_topologia_gns3.py dados.json --out subestacao.gns3
```

Abra o arquivo gerado direto no GNS3 (File > Open Project) ou copie
para `~/GNS3/projects/<nome>/<nome>.gns3`. **Os templates Docker
(`ubuntu-ied`, `oraculo`, `atacante`, `ids`) precisam já estar
registrados no GNS3 antes de abrir o projeto** — esse passo continua
manual (ver `atacante/README.md`); o script só monta a topologia que
referencia essas imagens pelo nome, não registra os templates.

**Limitações conhecidas:** layout automático simples (ajustar
visualmente depois de abrir é normal); não valida se os templates
citados (`--ied-image`, `--oraculo-image`, etc.) de fato existem no
GNS3 antes de gerar o arquivo.

**Importante:** estas ferramentas não têm relação direta com os
resultados dos testes (Oráculo, ataques, IDS) — elas só processam
`.scd`/geram topologia. Os resultados da campanha de testes estão em
`docs/metodologia_proposta_gns3.md`.
