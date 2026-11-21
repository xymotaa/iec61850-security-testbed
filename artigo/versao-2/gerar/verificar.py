#!/usr/bin/env python3
"""Verificacoes do artigo compilado (rodar na pasta versao-2, depois de compilar):
 1. numeracao: cada rotulo sec:N / tab:N / fig:N sai com o mesmo numero do texto aprovado;
 2. referencias cruzadas e citacoes sem '?' ; bibliografia (chaves citadas x entradas x avisos do BibTeX);
 3. fidelidade: todo paragrafo, celula de tabela e legenda do .md aprovado aparece no PDF.
Uso: python3 verificar.py <secoes-aprovadas.md> <texto-do-pdf.txt>"""
import re
import sys
import unicodedata

md_path, txt_path = sys.argv[1], sys.argv[2]
ok = True


def falha(msg):
    global ok
    ok = False
    print("FALHA:", msg)


# 1. numeracao
aux = open("main.aux", encoding="utf-8").read()
labs = re.findall(r"\\newlabel\{((?:sec|tab|fig):[^}]+)\}\{\{([^}]*)\}", aux)
bad = [(k, v) for k, v in labs if k.split(":", 1)[1] != v]
print(f"rotulos: {len(labs)}; divergentes: {bad}")
if bad:
    falha("numeracao divergente")

# 2. referencias e bibliografia
log = open("main.log", encoding="utf-8", errors="replace").read()
for pat in ("undefined", "Citation", "multiply"):
    if re.search(r"LaTeX Warning:.*" + pat, log):
        falha("aviso de LaTeX: " + pat)
blg = open("main.blg", encoding="utf-8", errors="replace").read()
print("BibTeX:", [l for l in blg.splitlines() if "arning" in l or "rror" in l] or "sem avisos nem erros")
if re.search(r"^Warning|error message", blg, re.M):
    falha("avisos do BibTeX")
tex = open("main.tex", encoding="utf-8").read()
bib = open("referencias.bib", encoding="utf-8").read()
keys_bib = set(re.findall(r"^@\w+\{([^,]+),", bib, re.M))
keys_cit = set()
for m in re.finditer(r"\\(?:cit|citn)\{[^}]*\}\{([^}]*)\}", tex):
    keys_cit.update(m.group(1).split(","))
bbl = open("main.bbl", encoding="utf-8").read()
n_bbl = len(re.findall(r"\\bibitem", bbl))
print(f"chaves citadas: {len(keys_cit)}; entradas no .bib: {len(keys_bib)}; itens na lista de referencias: {n_bbl}")
print("citadas e ausentes do .bib:", sorted(keys_cit - keys_bib) or "nenhuma")
print("no .bib e nunca citadas:", sorted(keys_bib - keys_cit) or "nenhuma")
if keys_cit - keys_bib:
    falha("chave citada sem entrada no .bib")
if n_bbl != len(keys_cit):
    falha("itens da bibliografia diferem das chaves citadas")

# 3. fidelidade (nivel TeX): todo paragrafo, celula de tabela e legenda do .md aprovado
#    aparece no main.tex gerado, depois de remover os comandos de LaTeX. (O PDF nao serve para
#    isso: os flutuantes interrompem os paragrafos na ordem de extracao do texto.)
def norm(s):
    s = unicodedata.normalize("NFKD", s)
    return re.sub(r"[^0-9a-zA-Z]", "", s).lower()


numero = dict(labs)


def limpa_tex(t):
    t = re.sub(r"\\ref\{([^}]*)\}", lambda m: numero.get(m.group(1), "?"), t)
    t = re.sub(r"\\cit\{([^}]*)\}\{[^}]*\}", r"[\1]", t)
    t = re.sub(r"\\citn\{([^}]*)\}\{[^}]*\}", r"\1", t)
    t = re.sub(r"\\label\{[^}]*\}", "", t)
    t = re.sub(r"\\textcolor\{[^}]*\}", "", t)
    t = re.sub(r"\\(?:textordmasculine|textmu|ensuremath)\b", "", t)
    t = re.sub(r"\\[a-zA-Z]+\*?", "", t)
    t = t.replace("\\", "")
    return t


corpo = norm(limpa_tex(tex[tex.index("\\begin{abstract}"):tex.index("\\bibliographystyle")]))
md = open(md_path, encoding="utf-8").read().split("\n")
i0 = next(i for i, l in enumerate(md) if l.startswith("## Resumo e Abstract"))
i1 = next(i for i, l in enumerate(md) if l.startswith("## Pendências"))
itens, para = [], []
for l in md[i0:i1]:
    if l.startswith("|"):
        if re.match(r"^\|[-| ]+\|$", l):
            continue
        itens += [c.strip() for c in l.strip().strip("|").split("|")]
        continue
    if not l.strip() or l.startswith("#") or l.startswith("---"):
        if para:
            itens.append(" ".join(para))
            para = []
        continue
    if re.match(r"^\d+\. ", l) and para:
        itens.append(" ".join(para))
        para = []
    para.append(l.strip())
if para:
    itens.append(" ".join(para))
n = faltam = 0
for it in itens:
    t = re.sub(r"\s*\[A desenhar[^\]]*\]", "", it)
    t = re.sub(r"\s*\(imagem: [^)]*\)", "", t)
    t = re.sub(r"^\*Figura 1 \(a desenhar[^)]*\)\.\*\s*", "*Figura 1.* ", t)
    t = re.sub(r"^\d+\. ", "", t)
    t = re.sub(r"^\*(?:Tabela|Figura) \d+\.\s*", "*", t)
    t = re.sub(r"^\*\*\w[^*]*\*\*\s*$", "", t)
    t = t.replace("**", "").replace("*", "").replace("`", "")
    t = t.replace("º", "").replace("µ", "").replace("−", "")
    k = norm(t)
    if len(k) < 4:
        continue
    n += 1
    if k not in corpo:
        faltam += 1
        print("  nao encontrado no main.tex:", t[:120])
print(f"fidelidade: {n - faltam}/{n} blocos do texto aprovado encontrados no main.tex")
if faltam:
    falha(f"{faltam} blocos ausentes")
print("RESULTADO:", "OK" if ok else "COM FALHAS")
sys.exit(0 if ok else 1)
