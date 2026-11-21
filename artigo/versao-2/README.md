# artigo/versao-2: artigo novo (SBC, português)

Versão nova do artigo, gerada **a partir dos textos aprovados** em `../rascunho/secoes-aprovadas.md`.
O `../main.tex` antigo, o `../overleaf-upload/` e o `../overleaf-upload.zip` antigos **não foram alterados**.

Título: *Masquerade em GOOSE: por que IDS de estado, autenticação por mensagem (HMAC) e 802.1X, isoladamente, não bastam*.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `main.tex` | Artigo completo (gerado por `gerar/md2tex.py`; pode ser editado à mão daqui em diante) |
| `main.pdf` | PDF compilado (TeX Live 2026, `pdflatex` + `bibtex`) |
| `referencias.bib`, `sbc-template.sty`, `sbc.bst` | Cópias das versões de `artigo/` (o `.bib` com as correções já feitas; nada novo foi editado) |
| `figuras/` | `fig1.tex`, `fig2.tex`, `fig4.tex` a `fig8.tex` (TikZ/pgfplots) e `gns3_topologia_8021x.png` (Figura 3, print real do GNS3) |
| `overleaf-upload.zip` | Pacote para o Overleaf: `main.tex`, `referencias.bib`, `sbc-template.sty`, `sbc.bst`, `figuras/` |
| `gerar/` | Scripts: conversão Markdown→LaTeX, dados da Figura 7, compilação e verificações |

## Como compilar

Overleaf: subir o conteúdo de `overleaf-upload.zip`; compilador pdfLaTeX; arquivo principal `main.tex`.

Local (imagem Docker `tex-sbc`):

```bash
cd artigo/versao-2
docker run --rm --user $(id -u):$(id -g) -v "$PWD":/w -w /w tex-sbc sh gerar/compilar.sh
```

## Como foi gerado e verificado

- `python3 gerar/md2tex.py ../rascunho/secoes-aprovadas.md main.tex`: converte o texto aprovado sem reescrevê-lo. As citações ficam como no texto aprovado (`[Herath et al. 2025]`, `Herath et al. (2025)`) e cada uma registra a entrada com `\nocite`; "Tabela N", "Figura N" e "Seção N.M" viram `\ref`.
- `python3 gerar/fig7_dados.py ../../benchmark/resultados figuras/fig7.tex`: a Figura 7 sai direto dos CSVs de sensibilidade, sem número digitado à mão.
- `python3 gerar/verificar.py ../rascunho/secoes-aprovadas.md <texto>` (rodar depois de compilar): confere (1) a numeração de seções, tabelas e figuras contra o texto aprovado, (2) referências e bibliografia, (3) se todo parágrafo, célula de tabela e legenda aprovados está no `main.tex`.

## Os três desvios do template

Revertidos nesta versão: `\raggedbottom` (o modelo usa `\flushbottom`), a redefinição de `\paragraph` e as referências em `\footnotesize`. As tabelas usam `\footnotesize`, para caberem na largura do texto.

## Pendências (não mascaradas no PDF)

- `[COMMIT DE REFERÊNCIA: a informar na entrega]` (Seção 4.5), em vermelho.
- `referencias.bib`: `Páginas: VERIFICAR` (Oliveira e Gurjão 2025) e `(não confirmado)` (Girdhar et al. 2023) aparecem na lista de referências; `MZ Automation (s.d.)` sem data de acesso; `iec61850-8-1` não é citada no texto aprovado e, por isso, não entra na lista.
- Afiliação e e-mails dos autores: o PDF traz só a Unifesspa, sem e-mails; nomes conforme definido (só o nome).
- Resumo e Abstract passam de 10 linhas (o modelo SBC pede até 10 linhas e na primeira página).
- Número de páginas acima da meta de 14 a 15: ver o relatório da conversa.
- `benchmark/benchmark_ids.py` (`LIMITE_NORMA_US`) não foi alterado.
