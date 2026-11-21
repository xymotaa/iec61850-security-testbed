# artigo/versao-2: versão de trabalho do artigo (SBC, português)

Gerada a partir dos textos aprovados em `../rascunho/secoes-aprovadas.md`, **com os cortes autorizados** (ver abaixo).
O `../main.tex` antigo, o `../overleaf-upload/` e o `../overleaf-upload.zip` **não foram alterados**; esta pasta é a única autorizada para edição.

Título: *Masquerade em GOOSE: por que IDS de estado, autenticação por mensagem (HMAC) e 802.1X, isoladamente, não bastam*.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `main.tex`, `main.pdf` | Artigo (29 páginas) e PDF compilado (TeX Live 2026, `pdflatex` + `bibtex`) |
| `texto/secoes-versao-2.md` | Texto da versão-2: o texto aprovado com os cortes aplicados (gerado; não editar à mão) |
| `referencias.bib`, `sbc-template.sty`, `sbc.bst` | Cópias das versões de `artigo/` (nada novo foi editado no `.bib`) |
| `figuras/` | `fig1.tex`, `fig2.tex`, `fig4.tex` a `fig8.tex` (TikZ/pgfplots) e `gns3_topologia_8021x.png` (Figura 3) |
| `overleaf-upload.zip` | Pacote para o Overleaf (`main.tex`, `referencias.bib`, `sbc-template.sty`, `sbc.bst`, `figuras/`) |
| `gerar/` | Scripts (abaixo) |

## Como regenerar e verificar

```bash
cd artigo/versao-2
python3 gerar/aplicar_cortes.py ../rascunho/secoes-aprovadas.md texto/secoes-versao-2.md   # aprovado -> versão-2
python3 gerar/md2tex.py texto/secoes-versao-2.md main.tex                                   # Markdown -> LaTeX
python3 gerar/fig7_dados.py ../../benchmark/resultados figuras/fig7.tex                     # Figura 7 vem dos CSVs
docker run --rm --user $(id -u):$(id -g) -v "$PWD":/w -w /w tex-sbc sh gerar/compilar.sh     # compila
pdftotext -layout main.pdf /tmp/texto.txt && python3 gerar/verificar.py texto/secoes-versao-2.md /tmp/texto.txt
```

`verificar.py` confere: numeração de seções, tabelas e figuras; referências e bibliografia (chaves citadas × `.bib` × lista); e se todo parágrafo, célula de tabela e legenda de `texto/secoes-versao-2.md` está no `main.tex`.

## Cortes aplicados (decisão do autor)

Tabelas 3 e 11 removidas (duas frases na 2.4 e a lista de evidências na 4.5 as substituem; versão do `wpa_supplicant` na 4.3.3); Tabela 6 reduzida a C1 e C2; Tabela 9 com as colunas "SCD de origem" e "Nós" unidas; Tabela 4 sem a coluna "Ambiente"; Seções 3.1 e 3.2 condensadas; Tabela 15 substituída por texto na 5.4; Seção 2.3 condensada (≈10%); Figuras 4 e 6 compactadas na vertical; Resumo e Abstract em 10 linhas. As tabelas foram renumeradas (agora são 15). Figura 3 mantida em 0,8 da largura: em 0,6 os rótulos do print ficam ilegíveis.

## Pendências (não mascaradas no PDF)

- `[COMMIT DE REFERÊNCIA: a informar na entrega]` (Seção 4.5), em vermelho.
- `referencias.bib`: `Páginas: VERIFICAR` (Oliveira e Gurjão 2025), `(não confirmado)` (Girdhar et al. 2023), nota "Cabeçalho do PDF" (Herath et al. 2025) e `MZ Automation (s.d.)` sem data de acesso aparecem na lista de referências; `iec61850-8-1` não é citada no texto e não entra na lista.
- Afiliação e e-mails dos autores: o PDF traz só a Unifesspa, sem e-mails; nomes só com o primeiro nome, como definido.
- O modelo SBC não exige o título em inglês; ele não aparece no PDF.
- Figura 3: os rótulos do print do GNS3 são pequenos; um print novo com rótulos maiores melhoraria a legibilidade.
- Revisão visual das Figuras 4 a 8 e conferência do PDF final pelo autor.
- `benchmark/benchmark_ids.py` (`LIMITE_NORMA_US`) não foi alterado.
