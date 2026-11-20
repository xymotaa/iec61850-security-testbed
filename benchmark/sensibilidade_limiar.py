#!/usr/bin/env python3
"""
sensibilidade_limiar.py — sensibilidade do limiar de flooding do IDS.

Varre o limite de taxa (`flood_pps_threshold`, padrão 20 pkts/s) e:
  * taxa de ataque (incl. "low-and-slow", 5-40 pps) -> TPR;
  * taxa de rajada legítima -> FPR do baseline.

Mesmos frames, mesma reprodução offline da campanha principal
(benchmark_ids.reproduzir), sempre em modo sem HMAC: o limiar só atua na
checagem de taxa.

Saída em resultados/: sensibilidade_flood_tpr.csv e sensibilidade_baseline_fpr.csv.
"""
import argparse
import random
from pathlib import Path

import trafego
from benchmark_ids import (PASTA_RESULTADOS, SEMENTE_PADRAO, TRIALS_PADRAO,
                           executar_trial,
                           gravar_csv)

LIMIARES_PPS = (10, 20, 40, 80)
# 5-40 pps cobre o regime low-and-slow, abaixo/ao redor do limiar padrão.
TAXAS_DE_ATAQUE_PPS = (5, 10, 15, 18, 20, 22, 25, 30, 35, 40, 50, 60, 80,
                       100, 250, 500, 1000, 2000)
RAJADAS_LEGITIMAS_PPS = (5, 10, 15, 20, 30, 40, 60)


def _alguma_deteccao(resultados, so_ataque):
    return any(r.alertas for r in resultados if r.is_attack or not so_ataque)


def sensibilidade_tpr(trials, semente):
    linhas = []
    for limiar in LIMIARES_PPS:
        for pps in TAXAS_DE_ATAQUE_PPS:
            rng = random.Random(f"{semente}|tpr|{limiar}|{pps}")
            itens = trafego.trafego_flood(trafego.SEM_HMAC, pps)
            deteccoes = sum(
                _alguma_deteccao(
                    executar_trial(itens, trafego.SEM_HMAC, rng,
                                   flood_pps_threshold=limiar), so_ataque=True)
                for _ in range(trials))
            linhas.append({"limiar_pps": limiar, "taxa_ataque_pps": pps,
                           "n": trials, "deteccoes": deteccoes,
                           "tpr": deteccoes / trials})
    return linhas


def sensibilidade_fpr(trials, semente):
    linhas = []
    for limiar in LIMIARES_PPS:
        for pps in RAJADAS_LEGITIMAS_PPS:
            rng = random.Random(f"{semente}|fpr|{limiar}|{pps}")
            itens = trafego.trafego_baseline(trafego.SEM_HMAC, rajada_pps=pps)
            falsos = sum(
                _alguma_deteccao(
                    executar_trial(itens, trafego.SEM_HMAC, rng,
                                   flood_pps_threshold=limiar), so_ataque=False)
                for _ in range(trials))
            linhas.append({"limiar_pps": limiar, "rajada_legitima_pps": pps,
                           "n": trials, "falsos_positivos": falsos,
                           "fpr": falsos / trials})
    return linhas


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=TRIALS_PADRAO)
    ap.add_argument("--seed", type=int, default=SEMENTE_PADRAO)
    ap.add_argument("--saida", type=Path, default=PASTA_RESULTADOS)
    args = ap.parse_args()

    args.saida.mkdir(parents=True, exist_ok=True)
    gravar_csv(args.saida / "sensibilidade_flood_tpr.csv",
               sensibilidade_tpr(args.trials, args.seed))
    gravar_csv(args.saida / "sensibilidade_baseline_fpr.csv",
               sensibilidade_fpr(args.trials, args.seed))
    print(f"CSVs gravados em {args.saida}")


if __name__ == "__main__":
    main()
