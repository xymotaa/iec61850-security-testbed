#!/usr/bin/env python3
"""
gerar_graficos.py — figuras do artigo (PNG 300 dpi + PDF vetorial) a partir
dos CSVs em resultados/. Rótulos em português; tamanho pensado para uma
coluna SBC (~8,3 cm de largura).

Figuras (em figuras/):
  tpr_por_cenario     barras de TPR (FPR em T0) por cenário, por modo de HMAC
  latencia_por_cenario  latência por frame (µs, escala log) vs limite de 4000 µs
  sensibilidade_limiar  TPR x taxa de ataque e FPR do baseline, por limiar
"""
import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

PASTA = Path(__file__).resolve().parent
LIMITE_NORMA_US = 4000
LARGURA_COLUNA_POL = 3.4  # ~8,6 cm

# Paleta Okabe-Ito (daltônico-segura) + hachuras para leitura em P&B.
MODOS = [
    ("sem_hmac", "Sem HMAC (IDS atual)", "#0072B2", ""),
    ("hmac", "HMAC, atacante sem chave", "#009E73", "///"),
    ("hmac_chave_vazada", "HMAC, chave vazada", "#D55E00", "xxx"),
]
CENARIOS = [
    ("T0_baseline", "T0 Baseline (FPR)"),
    ("A_flooding", "A Flooding"),
    ("B_replay", "B Replay"),
    ("C1_masquerade_sofisticado", "C1 Masq. sofisticado"),
    ("C2_masquerade_ingenuo", "C2 Masq. ingênuo"),
    ("D_suppression", "D Supressão"),
]
CORES_LIMIAR = {10: "#CC79A7", 20: "#0072B2", 40: "#E69F00", 80: "#009E73"}
MARCADORES_LIMIAR = {10: "v", 20: "o", 40: "s", 80: "^"}

plt.rcParams.update({
    "font.size": 7, "axes.titlesize": 7.5, "axes.labelsize": 7,
    "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.3, "grid.linewidth": 0.4,
    "axes.axisbelow": True, "pdf.fonttype": 42,
})


def ler_csv(caminho):
    with open(caminho, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def salvar(fig, destino, nome):
    destino.mkdir(parents=True, exist_ok=True)
    for extensao in ("png", "pdf"):
        fig.savefig(destino / f"{nome}.{extensao}", dpi=300, bbox_inches="tight")
    plt.close(fig)


def _barras_agrupadas(ax, valores, formato_do_rotulo):
    """valores[modo][cenario]; barras horizontais agrupadas, 1.º cenário no
    topo. Cada barra recebe o valor como rótulo, para que 0% seja visível."""
    altura = 0.26
    for j, (modo, rotulo, cor, hachura) in enumerate(MODOS):
        posicoes = [i + (j - 1) * altura for i in range(len(CENARIOS))]
        barras = ax.barh(posicoes, [valores[modo][c] for c, _ in CENARIOS],
                         height=altura, color=cor, hatch=hachura,
                         edgecolor="white", linewidth=0.3, label=rotulo)
        ax.bar_label(barras, labels=[formato_do_rotulo(valores[modo][c])
                                     for c, _ in CENARIOS],
                     padding=1.5, fontsize=5.2)
    ax.set_yticks(range(len(CENARIOS)), [r for _, r in CENARIOS])
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)


def figura_tpr(resumo, destino):
    taxa = {m: {r["cenario"]: 100 * float(r["taxa"]) for r in resumo if r["modo"] == m}
            for m, *_ in MODOS}
    fig, ax = plt.subplots(figsize=(LARGURA_COLUNA_POL, 2.7))
    _barras_agrupadas(ax, taxa, lambda v: f"{v:.0f}%")
    ax.set_xlim(0, 112)
    ax.set_xticks(range(0, 101, 20))
    ax.set_xlabel("Taxa de detecção (TPR) ou de falsos positivos (T0), %")
    ax.legend(loc="upper center", bbox_to_anchor=(0.4, -0.2), ncol=1, frameon=False)
    salvar(fig, destino, "tpr_por_cenario")


def figura_latencia(resumo, destino):
    latencia = {m: {r["cenario"]: float(r["latencia_total_us_media"])
                    for r in resumo if r["modo"] == m} for m, *_ in MODOS}
    fig, ax = plt.subplots(figsize=(LARGURA_COLUNA_POL, 2.7))
    _barras_agrupadas(ax, latencia, lambda v: f"{v:.0f}")
    ax.set_xscale("log")
    ax.set_xlim(1, 2e4)
    ax.axvline(LIMITE_NORMA_US, color="black", linestyle="--", linewidth=0.9)
    ax.text(LIMITE_NORMA_US * 1.15, len(CENARIOS) - 0.55, "limite\n4000 µs",
            fontsize=6, va="bottom", ha="left")
    ax.set_xlabel("Latência do IDS por frame (µs, escala log)")
    ax.legend(loc="upper center", bbox_to_anchor=(0.4, -0.2), ncol=1, frameon=False)
    salvar(fig, destino, "latencia_por_cenario")


def figura_sensibilidade(tpr, fpr, destino):
    fig, (ax_tpr, ax_fpr) = plt.subplots(2, 1, figsize=(LARGURA_COLUNA_POL, 4.6))

    for limiar in sorted({int(r["limiar_pps"]) for r in tpr}):
        pontos = sorted((int(r["taxa_ataque_pps"]), 100 * float(r["tpr"]))
                        for r in tpr if int(r["limiar_pps"]) == limiar)
        ax_tpr.plot(*zip(*pontos), marker=MARCADORES_LIMIAR[limiar], markersize=3,
                    linewidth=1, color=CORES_LIMIAR[limiar],
                    label=f"limiar = {limiar} pps" + (" (padrão)" if limiar == 20 else ""))
    ax_tpr.axvspan(5, 40, color="0.85", zorder=0)
    ax_tpr.text(14, 50, "low-and-slow\n(5–40 pps)", fontsize=6, ha="center", va="center")
    ax_tpr.set_xscale("log")
    ax_tpr.set_xlabel("Taxa do ataque de flooding (pacotes/s)")
    ax_tpr.set_ylabel("TPR (%)")
    ax_tpr.set_ylim(-3, 103)
    ax_tpr.legend(loc="lower right", frameon=False)
    ax_tpr.set_title("(a) Detecção de flooding × taxa do ataque", loc="left")

    for limiar in sorted({int(r["limiar_pps"]) for r in fpr}):
        pontos = sorted((int(r["rajada_legitima_pps"]), 100 * float(r["fpr"]))
                        for r in fpr if int(r["limiar_pps"]) == limiar)
        ax_fpr.plot(*zip(*pontos), marker=MARCADORES_LIMIAR[limiar], markersize=3,
                    linewidth=1, color=CORES_LIMIAR[limiar], label=f"limiar = {limiar} pps")
    ax_fpr.set_xlabel("Taxa da rajada legítima do baseline (pacotes/s)")
    ax_fpr.set_ylabel("FPR (%)")
    ax_fpr.set_ylim(-3, 103)
    ax_fpr.set_title("(b) Falsos positivos do baseline × rajada legítima", loc="left")

    fig.tight_layout(h_pad=1.4)
    salvar(fig, destino, "sensibilidade_limiar")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--resultados", type=Path, default=PASTA / "resultados")
    ap.add_argument("--saida", type=Path, default=PASTA / "figuras")
    args = ap.parse_args()

    resumo = ler_csv(args.resultados / "campanha_resumo.csv")
    figura_tpr(resumo, args.saida)
    figura_latencia(resumo, args.saida)
    figura_sensibilidade(ler_csv(args.resultados / "sensibilidade_flood_tpr.csv"),
                         ler_csv(args.resultados / "sensibilidade_baseline_fpr.csv"),
                         args.saida)
    print(f"Figuras gravadas em {args.saida}")


if __name__ == "__main__":
    main()
