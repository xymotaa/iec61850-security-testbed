# extracao-scd/

Script de extração de dados de um arquivo SCD (IEC 61850 SCL) —
reproduz e estende o que o artigo original fazia (que extraía só
IP/máscara/nome do IED).

**Arquivos:**
- `extrair_scd.py` — o script.
- `exemplo_subestacao.scd` — SCD sintético (mas estruturalmente válido) usado para testar o script, com 2 IEDs.

**O que extrai:** IP, máscara e nome de cada IED (igual ao original) +
blocos GOOSE (`gocbRef`, `datSet`, MAC, APPID, VLAN) e SV (`smvID` +
mesmo endereçamento) — necessário para os testes do `atacante/` e `ids/`.

**Uso:**
```bash
python3 extrair_scd.py exemplo_subestacao.scd
python3 extrair_scd.py exemplo_subestacao.scd --json dados.json
```

**Importante:** esta ferramenta não tem relação com os resultados dos
testes (Oráculo, ataques, IDS) — ela só processa arquivos `.scd`. Os
resultados da campanha de testes estão em `docs/resultados.md`.
