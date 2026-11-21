"""Gera as figuras do artigo derivadas das evidencias do GNS3 (20/11/2026).

- recorta os prints dos consoles do E1 (arquivos gns3_e1_*_full.png nao sao
  versionados; os recortes finais gns3_e1_*.png sao);
- gera a matriz "cenario x camada que barra" (camadas_por_cenario.pdf/.png) a
  partir de autenticador-8021x/evidencias/gns3/RESULTADOS_GNS3.md (dados
  transcritos abaixo; cada linha cita o arquivo de evidencia).

Uso: benchmark/.venv/bin/python artigo/figuras/gerar_figuras_gns3.py
"""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

AQUI = Path(__file__).resolve().parent

# (cenario, 802.1X, HMAC, IDS, passou)  -- 1 = camada que barrou/detectou
LINHAS = [
    ("E0  sem 802.1X, MAC clonado (C1)",                      0, 0, 0, 1),
    ("E1  sem certificado, MAC clonado",                      1, 0, 0, 0),
    ("E2  certificado revogado",                              1, 0, 0, 0),
    ("E3  cert. válido de outro nó, MAC de um IED", 1, 0, 0, 0),
    ("E4  cert. válido, MAC próprio",               0, 0, 1, 0),
    ("E4b cert. válido, origem do publicador",           1, 0, 0, 0),
    ("E5(i)  sem chave HMAC, MAC próprio",               0, 1, 0, 0),
    ("E5(ii) chave vazada, MAC próprio",                 0, 0, 1, 0),
    ("E5(iii) chave vazada, origem do publicador",            1, 0, 0, 0),
]
COLUNAS = ["802.1X\n(porta)", "HMAC\n(IDS --auth)", "IDS\n(estado/MAC)", "Frame\npassou"]
TONS = ["#4d4d4d", "#4d4d4d", "#4d4d4d", "#bdbdbd"]  # legivel em tons de cinza


def figura():
    n = len(LINHAS)
    fig, ax = plt.subplots(figsize=(4.4, 0.34 * n + 0.8))
    for i, lin in enumerate(LINHAS):
        y = n - 1 - i
        ax.text(-0.15, y + 0.5, lin[0], ha="right", va="center", fontsize=8)
        for j in range(4):
            on = lin[1 + j]
            ax.add_patch(Rectangle((j, y), 1, 1, fill=bool(on),
                                   facecolor=TONS[j] if on else "white",
                                   edgecolor="#808080", lw=0.6))
            if on:
                camada_barrou = j < 3
                ax.text(j + 0.5, y + 0.5, "✓" if camada_barrou else "passou",
                        ha="center", va="center",
                        color="white" if camada_barrou else "black",
                        fontsize=9 if camada_barrou else 7, fontweight="bold")
    for j, c in enumerate(COLUNAS):
        ax.text(j + 0.5, n + 0.15, c, ha="center", va="bottom", fontsize=8)
    ax.set_xlim(0, 4)
    ax.set_ylim(0, n + 1.1)
    ax.axis("off")
    for ext in ("pdf", "png"):
        fig.savefig(AQUI / f"camadas_por_cenario.{ext}", bbox_inches="tight", dpi=200)


def recortes():
    from PIL import Image
    a = AQUI / "gns3_e1_atacante.png"
    b = AQUI / "gns3_e1_autenticador.png"
    for arq, box in ((a, (0, 95, 700, 290)), (b, (0, 0, 960, 252))):
        full = arq.with_name(arq.stem + "_full.png")
        if not full.exists():
            arq.rename(full)
        Image.open(full).convert("RGB").crop(box).save(arq)


if __name__ == "__main__":
    figura()
    if (AQUI / "gns3_e1_atacante.png").exists() or (AQUI / "gns3_e1_atacante_full.png").exists():
        recortes()
    print("ok")
