#!/usr/bin/env python3
"""Gera figuras/fig7.tex (pgfplots) a partir dos CSVs de sensibilidade do benchmark.
Nenhum valor e digitado a mao: tudo vem de benchmark/resultados/*.csv.
Uso: python3 fig7_dados.py <dir dos CSVs> <saida fig7.tex>"""
import csv
import sys
from collections import defaultdict

d, out = sys.argv[1], sys.argv[2]
tpr = defaultdict(list)
for r in csv.DictReader(open(f"{d}/sensibilidade_flood_tpr.csv")):
    tpr[int(r["limiar_pps"])].append((int(r["taxa_ataque_pps"]), float(r["tpr"])))
fpr = defaultdict(list)
for r in csv.DictReader(open(f"{d}/sensibilidade_baseline_fpr.csv")):
    fpr[int(r["limiar_pps"])].append((int(r["rajada_legitima_pps"]), float(r["fpr"])))

estilos = {10: "mark=square*, solid", 20: "mark=triangle*, dashed",
           40: "mark=o, dotted, thick", 80: "mark=diamond*, dash dot"}
cores = {10: "black", 20: "gray!70!black", 40: "black!55", 80: "black!85"}


def curvas(dados, legenda=True):
    s = []
    for lim in sorted(dados):
        pts = " ".join(f"({x},{y:.4f})" for x, y in dados[lim])
        s.append(f"\\addplot[{estilos[lim]}, color={cores[lim]}, mark size=1.6pt] coordinates {{{pts}}};")
        if legenda:
            s.append(f"\\addlegendentry{{limiar {lim}}}")
    return "\n".join(s)


tex = r"""\pgfplotsset{
  sens/.style={width=0.97\linewidth, height=5.2cm, ymin=-0.03, ymax=1.05,
    ytick={0,0.25,0.5,0.75,1}, yticklabels={0\%,25\%,50\%,75\%,100\%},
    grid=major, grid style={gray!25}, tick label style={font=\scriptsize},
    label style={font=\footnotesize}, legend style={font=\scriptsize, draw=gray}}}
\begin{minipage}[t]{0.5\linewidth}
\centering
\begin{tikzpicture}
\begin{axis}[sens, xmode=log, xmin=4, xmax=2500, xlabel={Taxa do ataque (pacotes/s)}, ylabel={Taxa de detecção}, xtick={10,100,1000}, legend columns=4, legend to name=legfig7]
""" + curvas(tpr) + r"""
\end{axis}
\end{tikzpicture}

\footnotesize (a)
\end{minipage}%
\begin{minipage}[t]{0.5\linewidth}
\centering
\begin{tikzpicture}
\begin{axis}[sens, xmin=3, xmax=62, xtick={10,20,30,40,60}, xlabel={Rajada legítima (pacotes/s)}, ylabel={Taxa de falsos positivos}]
""" + curvas(fpr, False) + r"""
\end{axis}
\end{tikzpicture}

\footnotesize (b)
\end{minipage}

\vspace{3pt}
\pgfplotslegendfromname{legfig7}
"""
open(out, "w", encoding="utf-8").write(tex)
print("ok", {k: len(v) for k, v in tpr.items()}, {k: len(v) for k, v in fpr.items()})
