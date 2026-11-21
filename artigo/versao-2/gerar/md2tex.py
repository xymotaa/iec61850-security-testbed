#!/usr/bin/env python3
"""Converte artigo/rascunho/secoes-aprovadas.md em main.tex (template SBC).

O texto aprovado NAO e reescrito: so e convertido de Markdown para LaTeX.
 - citacoes literais ("[Herath et al. 2025]", "Herath et al. (2025)") sao mantidas
   como no texto aprovado e registradas na bibliografia com \\nocite;
 - "Tabela N", "Figura N", "Secao N.M" viram \\ref quando ha rotulo;
 - legendas de figura perdem as notas de rascunho ("[A desenhar: ...]", "(imagem: ...)").

Uso: python3 md2tex.py <secoes-aprovadas.md> <saida main.tex>
"""
import re
import sys

SRC, OUT = sys.argv[1], sys.argv[2]
md = open(SRC, encoding="utf-8").read().split("\n")

# ---------------------------------------------------------------- citacoes
CITE = {
    "Herath et al. 2025": "herath2025evaluation",
    "Conceição Alberto et al. 2026": "alberto2026gooseidrs",
    "de Oliveira et al. 2023": "oliveira2023ataques",
    "IEC 2020": "iec62351-6",
    "IEC 2013": "iec62443-3-3",
    "IEEE 2020": "ieee8021x",
    "Oliveira e Gurjão 2025": "oliveira2025analisador",
    "Preuß Mattsson e Sethi 2022": "rfc9190",
    "Simon et al. 2008": "rfc5216",
    "Hussain et al. 2023": "hussain2023hybrid",
    "Girdhar et al. 2024": "girdhar2024sdn",
    "Moore 2026": "moore2026anomaly",
    "Zemanek et al. 2022": "zemanek2022powerduck",
    "Roomi et al. 2025": "roomi2025autosgcr",
    "MZ Automation s.d.": "libiec61850",
}
NARR = {  # "Autor (ano)" -> chave
    "Herath et al. (2025)": "herath2025evaluation",
    "Conceição Alberto et al. (2026)": "alberto2026gooseidrs",
    "de Oliveira et al. (2023)": "oliveira2023ataques",
    "Oliveira e Gurjão (2025)": "oliveira2025analisador",
    "Hussain et al. (2023)": "hussain2023hybrid",
    "Girdhar et al. (2024)": "girdhar2024sdn",
    "Moore (2026)": "moore2026anomaly",
    "Zemanek et al. (2022)": "zemanek2022powerduck",
    "Roomi et al. (2025)": "roomi2025autosgcr",
}
cited_keys = set()
problems = []

UNI = {
    "→": r"\ensuremath{\rightarrow}", "↔": r"\ensuremath{\leftrightarrow}",
    "≤": r"\ensuremath{\leq}", "≠": r"\ensuremath{\neq}", "−": r"\ensuremath{-}",
    "±": r"\ensuremath{\pm}", "µ": r"\textmu{}", "º": r"\textordmasculine{}",
}


def esc_text(s):
    out = []
    for ch in s:
        if ch in UNI:
            out.append(UNI[ch])
        elif ch == "\\":
            out.append(r"\textbackslash{}")
        elif ch in "&%#_{}$":
            out.append("\\" + ch)
        elif ch == "^":
            out.append(r"\textasciicircum{}")
        elif ch == "~":
            out.append(r"\textasciitilde{}")
        else:
            out.append(ch)
    return "".join(out)


def esc_code(s):
    out = []
    for i, ch in enumerate(s):
        if ch in UNI:
            out.append(UNI[ch])
        elif ch == "\\":
            out.append(r"\textbackslash{}")
        elif ch == "_":
            out.append(r"\_\allowbreak{}")
        elif ch == "/":
            out.append(r"/\allowbreak{}")
        elif ch == "-":
            out.append("{-}")
        elif ch == ".":
            out.append(r".\allowbreak{}" if i + 1 < len(s) and s[i + 1].isalpha() else ".")
        elif ch == "$":
            out.append(r"\$\allowbreak{}")
        elif ch in "&%#{}":
            out.append("\\" + ch)
        elif ch == "^":
            out.append(r"\textasciicircum{}")
        elif ch == "~":
            out.append(r"\textasciitilde{}")
        elif ch == "|":
            out.append(r"\textbar{}")
        elif ch == '"':
            out.append(r"\textquotedbl{}")
        else:
            out.append(ch)
    return r"\texttt{" + "".join(out) + "}"


# rotulos conhecidos (preenchidos numa primeira passada)
LABELS = {"sec": set(), "tab": set(), "fig": set()}
for ln in md:
    m = re.match(r"^#{2,3} (\d+(?:\.\d+)*)\.? ", ln)
    if m:
        LABELS["sec"].add(m.group(1))
    m = re.match(r"^\*Tabela (\d+)\. ", ln)
    if m:
        LABELS["tab"].add(m.group(1))
    m = re.match(r"^\*Figura (\d+)[ .(]", ln)
    if m:
        LABELS["fig"].add(m.group(1))

REF_RE = re.compile(
    r"\b(Tabelas?|Figuras?|Seç(?:ão|ões))\s+"
    r"(\d+(?:\.\d+)*(?:\s*(?:,|e|a|ou)\s*\d+(?:\.\d+)*)*)")


def do_refs(s):
    def repl(m):
        kind = m.group(1)
        pref = "tab" if kind.startswith("Tabela") else "fig" if kind.startswith("Figura") else "sec"

        def one(n):
            num = n.group(0)
            if num in LABELS[pref]:
                return r"\ref{%s:%s}" % (pref, num)
            return num
        body = re.sub(r"\d+(?:\.\d+)*", one, m.group(2))
        return kind + "~" + body
    return REF_RE.sub(repl, s)


def inline(s, caption=False):
    toks = []

    def keep(tex):
        toks.append(tex)
        return "\x00%d\x00" % (len(toks) - 1)

    # codigo
    s = re.sub(r"`([^`]+)`", lambda m: keep(esc_code(m.group(1))), s)
    # enderecos
    s = re.sub(r"<(https?://[^>\s]+)>", lambda m: keep(r"\url{%s}" % m.group(1)), s)
    # placeholder de pendencia (visivel de proposito)
    s = s.replace("[COMMIT DE REFERÊNCIA: a informar na entrega]",
                  keep(r"\textcolor{red}{\textbf{[COMMIT DE REFER\^ENCIA: a informar na entrega]}}"))

    # citacoes entre colchetes
    def brk(m):
        items = [x.strip() for x in m.group(1).split(";")]
        keys = []
        for it in items:
            if it not in CITE:
                problems.append("citacao sem chave: [%s]" % it)
                return m.group(0)
            keys.append(CITE[it])
        cited_keys.update(keys)
        return keep(r"\cit{%s}{%s}" % (esc_text("; ".join(items)), ",".join(keys)))
    s = re.sub(r"\[([^\[\]]*?\b(?:1[89]|20)\d\d|[^\[\]]*s\.d\.)\]", brk, s)

    # citacoes narrativas
    for name, key in NARR.items():
        if name in s:
            cited_keys.add(key)
            s = s.replace(name, keep(r"\citn{%s}{%s}" % (esc_text(name), key)))

    s = re.sub(r'"([^"\n]+)"', "\x01\\1\x02", s)
    s = esc_text(s)
    s = s.replace("\x01", r"\textquotedblleft{}").replace("\x02", r"\textquotedblright{}")
    s = do_refs(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"\\textbf{\1}", s)
    s = re.sub(r"\*(.+?)\*", r"\\emph{\1}", s)
    if "*" in s:
        problems.append("asterisco sobrando: " + s[:80])
    s = re.sub(r"\x00(\d+)\x00", lambda m: toks[int(m.group(1))], s)
    return s


# ---------------------------------------------------------------- blocos
def split_row(line):
    cells = line.strip().strip("|").split("|")
    return [c.strip() for c in cells]


def plain_len(c):
    return len(re.sub(r"[`*]", "", c))


def table_tex(rows):
    head, body = rows[0], rows[2:]
    n = len(head)
    TOTAL = 15.0 - 0.35 * n  # cm uteis (largura do texto menos o espacamento de coluna)
    prop, minw = [], []
    for j in range(n):
        cells = [head[j]] + [r[j] for r in body if j < len(r)]
        lens = [plain_len(c) for c in cells]
        avg = sum(lens[1:]) / max(1, len(lens) - 1)
        prop.append(max(6.0, min(max(avg, 0.45 * lens[0]), 48.0)))
        words = [len(x) for c in cells for x in re.sub(r"`[^`]*`", " ", c).replace("*", "").split()]
        codes = [len(ch) for c in cells for x in re.findall(r"`([^`]+)`", c)
                 for ch in re.findall(r"[^/_.]*[/_.]?", x)]
        m = max(words) * 0.19 if words else 0.0
        if codes:
            m = max(m, min(max(codes), 20) * 0.22)
        minw.append(m + 0.1)
    tot = sum(prop)
    wid = [TOTAL * x / tot for x in prop]
    for _ in range(10):  # garante a largura minima de cada coluna e redistribui o resto
        fixed = [i for i in range(n) if wid[i] < minw[i]]
        if not fixed:
            break
        free = [i for i in range(n) if i not in fixed]
        rest = TOTAL - sum(minw[i] for i in fixed)
        ptot = sum(prop[i] for i in free) or 1.0
        for i in fixed:
            wid[i] = minw[i]
        for i in free:
            wid[i] = max(minw[i], rest * prop[i] / ptot)
    w = [x * n / sum(wid) for x in wid]
    spec = "".join(r">{\hsize=%.3f\hsize\raggedright\arraybackslash}X" % x for x in w)
    out = [r"\footnotesize", r"\begin{tabularx}{\linewidth}{%s}" % spec, r"\toprule"]
    out.append(" & ".join(r"\textbf{%s}" % inline(c) for c in head) + r" \\")
    out.append(r"\midrule")
    for r in body:
        if len(r) != n:
            problems.append("linha de tabela com %d colunas (esperado %d): %s" % (len(r), n, r[0]))
        out.append(" & ".join(inline(c) for c in r) + r" \\")
    out.append(r"\bottomrule")
    out.append(r"\end{tabularx}")
    return "\n".join(out)


CAP_TAB = re.compile(r"^\*Tabela (\d+)\. (.*)\*$")
CAP_FIG = re.compile(r"^\*Figura (\d+)\. (.*)\*(?: \(imagem: .*\))?$")
CAP_FIG1 = re.compile(r"^\*Figura (\d+) \(a desenhar[^)]*\)\.\* (.*)$")
FIGFILE = {"3": r"\includegraphics[width=0.8\linewidth]{figuras/gns3_topologia_8021x.png}"}


def clean_fig_caption(c):
    c = re.sub(r"\s*\[A desenhar[^\]]*\]", "", c)
    c = re.sub(r"\s*\(imagem: [^)]*\)", "", c)
    return c.strip()


def sections():
    """Devolve a lista de (nivel, titulo, linhas) e o bloco de resumo."""
    res, cur = {}, None
    secs = []
    i = 0
    while i < len(md):
        ln = md[i]
        if ln.startswith("## Resumo e Abstract"):
            j = i + 1
            while not md[j].startswith("---"):
                j += 1
            res["lines"] = md[i + 1:j]
            i = j
        elif re.match(r"^## \d+\. ", ln):
            j = i + 1
            while not (md[j].startswith("---") or md[j].startswith("## ")):
                j += 1
            secs.append(md[i:j])
            i = j
        else:
            i += 1
    return res, secs


def body(lines):
    out = []
    i = 0
    para = []

    def flush():
        if para:
            out.append(inline(" ".join(para)) + "\n")
            para.clear()

    pending_tab = None
    while i < len(lines):
        ln = lines[i].rstrip()
        if not ln.strip():
            flush()
            i += 1
            continue
        m = re.match(r"^(#{2,3}) (\d+(?:\.\d+)*)\.? (.*)$", ln)
        if m:
            flush()
            cmd = "section" if len(m.group(1)) == 2 else "subsection"
            out.append("\\%s{%s}\\label{sec:%s}\n" % (cmd, inline(m.group(3)), m.group(2)))
            i += 1
            continue
        m = CAP_TAB.match(ln)
        if m:
            flush()
            num, cap = m.group(1), m.group(2)
            i += 1
            while not lines[i].strip():
                i += 1
            if not lines[i].startswith("|"):
                problems.append("legenda de tabela sem tabela: " + num)
            tabs = []
            while True:
                rows = []
                while i < len(lines) and lines[i].startswith("|"):
                    rows.append(split_row(lines[i]))
                    i += 1
                tabs.append(rows)
                k = i
                while k < len(lines) and not lines[k].strip():
                    k += 1
                if k < len(lines) and lines[k].startswith("|"):
                    i = k
                    continue
                break
            note = None
            k = i
            while k < len(lines) and not lines[k].strip():
                k += 1
            if k < len(lines) and re.match(r"^\*[^*].*\*$", lines[k].strip()) \
                    and not CAP_TAB.match(lines[k].strip()) and not CAP_FIG.match(lines[k].strip()) \
                    and not lines[k].startswith("*Figura") and not lines[k].startswith("*Tabela"):
                note = lines[k].strip()[1:-1]
                i = k + 1
            t = [r"\begin{table}[!t]", r"\centering",
                 r"\caption{%s}\label{tab:%s}" % (inline(cap, True), num)]
            for n, rows in enumerate(tabs):
                if n:
                    t.append(r"\vspace{6pt}")
                t.append(table_tex(rows))
            if note:
                t.append(r"\par\vspace{2pt}{\footnotesize %s}" % inline(note))
            t.append(r"\end{table}" + "\n")
            out.append("\n".join(t))
            continue
        m = CAP_FIG.match(ln) or CAP_FIG1.match(ln)
        if m:
            flush()
            num, cap = m.group(1), clean_fig_caption(m.group(2))
            content = FIGFILE.get(num, r"\input{figuras/fig%s}" % num)
            out.append("\\begin{figure}[!t]\n\\centering\n%s\n\\caption{%s}\\label{fig:%s}\n\\end{figure}\n"
                       % (content, inline(cap, True), num))
            i += 1
            continue
        m = re.match(r"^(\d+)\. (.*)$", ln)
        if m:
            flush()
            items = []
            while i < len(lines) and re.match(r"^\d+\. ", lines[i]):
                items.append(re.sub(r"^\d+\. ", "", lines[i].rstrip()))
                i += 1
            out.append("\\begin{enumerate}\n" + "\n".join("\\item " + inline(x) for x in items)
                       + "\n\\end{enumerate}\n")
            continue
        if ln.startswith("- "):
            flush()
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(lines[i][2:].rstrip())
                i += 1
            out.append("\\begin{itemize}\n" + "\n".join("\\item " + inline(x) for x in items)
                       + "\n\\end{itemize}\n")
            continue
        para.append(ln.strip())
        i += 1
    flush()
    return "\n".join(out)


# ---------------------------------------------------------------- titulo / resumo
title = sub = None
for k, ln in enumerate(md):
    if ln.startswith("## Título"):
        for x in md[k + 1:k + 8]:
            if x.startswith("**") and title is None:
                title = x.strip().strip("*")
            elif x.startswith("*") and not x.startswith("**") and sub is None and "EN:" not in x:
                sub = x.strip().strip("*")
        break

res, secs = sections()
rl = [x for x in res["lines"] if x.strip()]


def pick(prefix):
    for x in rl:
        if x.startswith(prefix):
            return x
    problems.append("resumo: faltou " + prefix)
    return ""


def abs_block(head, kw):
    t = pick(head)
    t = re.sub(r"^\*\*[^*]+\*\*\s*", "", t)
    k = re.sub(r"^\*\*[^*]+\*\*\s*", "", pick(kw))
    return inline(t) + "\n\n\\noindent\\textbf{%s} %s" % (kw.strip("*:"), inline(k))


abstract_en = abs_block("**Abstract.**", "**Keywords:**")
resumo_pt = abs_block("**Resumo.**", "**Palavras-chave:**")

PRE = r"""\documentclass[12pt]{article}

\usepackage{sbc-template}
\usepackage{graphicx,url}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage[brazilian]{babel}
\usepackage{booktabs,array,tabularx}
\usepackage{xcolor}
\usepackage{tikz}
\usetikzlibrary{positioning,shapes.geometric,arrows.meta,fit,calc,patterns,backgrounds}
\usepackage{pgfplots}
\pgfplotsset{compat=1.17}

\sloppy

% Estilos comuns das figuras (TikZ)
\tikzset{
  caixa/.style={draw, rounded corners=2pt, align=center, font=\footnotesize,
    inner sep=3pt, fill=white},
  cinza/.style={fill=gray!15},
  seta/.style={-{Stealth[length=2.2mm]}, thick},
}

% Citacoes: o texto aprovado usa o formato "[Autor ano]" e "Autor (ano)";
% \nocite registra a entrada na bibliografia.
\newcommand{\cit}[2]{[#1]\nocite{#2}}
\newcommand{\citn}[2]{#1\nocite{#2}}

"""

doc = [PRE]
doc.append("\\title{%s\\\\[6pt]{\\large\\mdseries %s}}\n" % (inline(title), inline(sub)))
doc.append(r"""\author{Lucas Mota\inst{1}, Matheus\inst{1}, Youri\inst{1}}

\address{Universidade Federal do Sul e Sudeste do Par\'a (Unifesspa)}

\begin{document}

\maketitle

\begin{abstract}
%s
\end{abstract}

\begin{resumo}
%s
\end{resumo}
""" % (abstract_en, resumo_pt))
for s in secs:
    doc.append(body(s))
doc.append("\n\\bibliographystyle{sbc}\n\\bibliography{referencias}\n\n\\end{document}\n")
open(OUT, "w", encoding="utf-8").write("\n".join(doc))

print("chaves citadas:", len(cited_keys))
print("\n".join(sorted(cited_keys)))
if problems:
    print("PROBLEMAS:")
    print("\n".join(problems))
    sys.exit(1)
