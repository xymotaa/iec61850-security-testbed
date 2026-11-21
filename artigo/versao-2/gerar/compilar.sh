#!/bin/sh
# Compila no contêiner tex-sbc (TeX Live 2026). Uso (na pasta versao-2):
#   docker run --rm --user $(id -u):$(id -g) -v "$PWD":/w -w /w tex-sbc sh gerar/compilar.sh
export PATH=/usr/local/texlive/2026/bin/x86_64-linux:$PATH
export HOME=/tmp
pdflatex -interaction=nonstopmode main.tex >/dev/null 2>&1
bibtex main >/dev/null 2>&1
pdflatex -interaction=nonstopmode main.tex >/dev/null 2>&1
pdflatex -interaction=nonstopmode main.tex >/dev/null 2>&1
pdfinfo main.pdf | grep Pages
echo "overfull: $(grep -c Overfull main.log)  underfull: $(grep -c Underfull main.log)"
grep -E "^! |LaTeX Warning|Package .* Warning|Citation|undefined" main.log | sort | uniq -c | sort -rn | head -20
