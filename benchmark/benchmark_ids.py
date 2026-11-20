#!/usr/bin/env python3
"""
benchmark_ids.py — campanha OFFLINE (sem GNS3) de avaliação do IDS GOOSE.

Reconstrução da campanha N=600 do 4º Marco (Bloco 3B de
changelog/conteudo-apresentacao-4marco.md) e extensão com a simulação de
autenticação estilo IEC 62351-6 (HMAC-SHA256 por frame). O script original
não foi versionado; este é uma reimplementação a partir da tabela.

Frames reais (bytes Ethernet) são montados por goose_frame, lidos de volta
por goose_frame.parse_ethernet_goose e entregues a ids_core.GooseMonitor,
com relógio virtual. Modos:
  sem_hmac           IDS atual (nada autenticado)
  hmac               IED assina, IDS verifica; atacante SEM a chave
  hmac_chave_vazada  idem, mas o atacante TEM a chave

Uso:
    python benchmark_ids.py                  # N=100 por cenário
    python benchmark_ids.py --trials 20 --saida /tmp/teste
"""
import argparse
import csv
import json
import math
import platform
import random
import statistics
import sys
import time
from collections import namedtuple
from pathlib import Path

import trafego
from trafego import HMAC, HMAC_CHAVE_VAZADA, MODOS, SEM_HMAC

import goose_frame as gf
from goose_auth import GooseAuthenticator
from ids_core import GooseMonitor

SEMENTE_PADRAO = 61850
TRIALS_PADRAO = 100
JITTER_DO_INTERVALO = 0.10  # cada intervalo entre frames varia +-10 %
LIMITE_NORMA_US = 4000      # tempo de transferência da IEC 61850-5 (tipo 1A, classe P2/P3)

TAXAS_FLOOD_PPS = (50, 100, 250, 500, 1000, 2000)
SALTOS_SUPRESSAO = (60, 100, 250, 500, 1000, 5000)
REPLAY_DELTA_T_S = (0.5, 10.0)

PASTA_RESULTADOS = Path(__file__).resolve().parent / "resultados"

ResultadoFrame = namedtuple(
    "ResultadoFrame", "is_attack alertas parse_us verify_us process_us")


def calibrar_sobrecarga_do_timer_us(amostras=100_000):
    """Mediana do custo de uma leitura de perf_counter_ns. Neste ambiente
    (VM/sandbox) é da ordem de microssegundos — da mesma ordem do que se
    quer medir —, então é descontada de cada etapa cronometrada."""
    custos = []
    for _ in range(amostras):
        t0 = time.perf_counter_ns()
        custos.append(time.perf_counter_ns() - t0)
    return statistics.median(custos) / 1e3


def reproduzir(itens, rng, monitor, autenticador, sobrecarga_timer_us=0.0):
    """Entrega os frames ao IDS, com relógio virtual, e mede o custo de cada
    etapa (já descontada a sobrecarga do timer). Retorna um ResultadoFrame
    por frame; verify_us é 0 quando não há autenticador."""
    def etapa_us(inicio_ns, fim_ns):
        return max(0.0, (fim_ns - inicio_ns) / 1e3 - sobrecarga_timer_us)

    agora = trafego.INSTANTE_INICIAL
    resultados = []
    for indice, item in enumerate(itens):
        if indice:
            agora += item.gap_s * (1 + rng.uniform(-JITTER_DO_INTERVALO,
                                                   JITTER_DO_INTERVALO))
        t0 = time.perf_counter_ns()
        parsed = gf.parse_ethernet_goose(item.raw)
        t1 = time.perf_counter_ns()
        campos = parsed["fields"]
        auth_valid = (autenticador.verify(campos, parsed["auth_tag"])
                      if autenticador else None)
        t2 = time.perf_counter_ns()
        alertas = monitor.process(
            gocb_ref=campos["gocbRef"], src_mac=parsed["src_mac"],
            st_num=campos["stNum"], sq_num=campos["sqNum"],
            timestamp=agora, auth_valid=auth_valid)
        t3 = time.perf_counter_ns()
        resultados.append(ResultadoFrame(
            item.is_attack, tuple(a["type"] for a in alertas),
            etapa_us(t0, t1), etapa_us(t1, t2) if autenticador else 0.0,
            etapa_us(t2, t3)))
    return resultados


def novo_autenticador(modo):
    return GooseAuthenticator() if modo != SEM_HMAC else None


def executar_trial(itens, modo, rng, sobrecarga_timer_us=0.0, **parametros_do_monitor):
    """Uma repetição: monitor novo + reprodução do tráfego."""
    monitor = GooseMonitor(**parametros_do_monitor)
    return reproduzir(itens, rng, monitor, novo_autenticador(modo), sobrecarga_timer_us)


# --- cenários da campanha -------------------------------------------------

def _cenario_baseline(modo, i, rng):
    return trafego.trafego_baseline(modo), "rajada=5pps"


def _cenario_flood(modo, i, rng):
    pps = TAXAS_FLOOD_PPS[i % len(TAXAS_FLOOD_PPS)]
    return trafego.trafego_flood(modo, pps), f"pps={pps}"


def _cenario_replay(modo, i, rng):
    delta_t = rng.uniform(*REPLAY_DELTA_T_S)
    return trafego.trafego_replay(modo, delta_t), f"delta_t={delta_t:.2f}s"


def _cenario_c1(modo, i, rng):
    return trafego.trafego_masquerade(modo, mac_proprio=False), "mac_clonado"


def _cenario_c2(modo, i, rng):
    return trafego.trafego_masquerade(modo, mac_proprio=True), "mac_distinto"


def _cenario_supressao(modo, i, rng):
    salto = SALTOS_SUPRESSAO[i % len(SALTOS_SUPRESSAO)]
    return trafego.trafego_supressao(modo, salto), f"salto={salto}"


# nome -> (gerador, métrica). Em T0 a "detecção" é falso positivo (FPR).
CENARIOS = {
    "T0_baseline": (_cenario_baseline, "FPR"),
    "A_flooding": (_cenario_flood, "TPR"),
    "B_replay": (_cenario_replay, "TPR"),
    "C1_masquerade_sofisticado": (_cenario_c1, "TPR"),
    "C2_masquerade_ingenuo": (_cenario_c2, "TPR"),
    "D_suppression": (_cenario_supressao, "TPR"),
}


def _frames_avaliados(resultados, cenario):
    """T0 mede todos os frames; nos ataques, só os frames do atacante."""
    if cenario == "T0_baseline":
        return resultados
    return [r for r in resultados if r.is_attack]


def resumir_trial(resultados, cenario):
    avaliados = _frames_avaliados(resultados, cenario)
    tipos = sorted({t for r in avaliados for t in r.alertas})
    alertas_fora_da_avaliacao = (
        0 if cenario == "T0_baseline"
        else sum(len(r.alertas) for r in resultados if not r.is_attack))
    media = lambda campo: statistics.fmean(getattr(r, campo) for r in avaliados)
    return {
        "detectado": int(bool(tipos)),
        "tipos_de_alerta": ";".join(tipos),
        "alertas_no_aquecimento": alertas_fora_da_avaliacao,
        "frames_avaliados": len(avaliados),
        "latencia_parse_us": media("parse_us"),
        "latencia_verify_us": media("verify_us"),
        "latencia_process_us": media("process_us"),
    }


def executar_campanha(trials, semente, sobrecarga_timer_us=0.0):
    linhas = []
    for modo in MODOS:
        for cenario, (gerar, _metrica) in CENARIOS.items():
            rng = random.Random(f"{semente}|{modo}|{cenario}")
            for i in range(trials):
                itens, parametro = gerar(modo, i, rng)
                resultados = executar_trial(itens, modo, rng, sobrecarga_timer_us)
                linhas.append({"modo": modo, "cenario": cenario, "trial": i,
                               "parametro": parametro,
                               **resumir_trial(resultados, cenario)})
    return linhas


# --- agregação -------------------------------------------------------------

def intervalo_wilson(sucessos, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = sucessos / n
    centro = (p + z * z / (2 * n)) / (1 + z * z / n)
    margem = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, centro - margem), min(1.0, centro + margem))


def _media_e_desvio(valores):
    return statistics.fmean(valores), (statistics.stdev(valores) if len(valores) > 1 else 0.0)


def agregar(linhas):
    resumo = []
    for modo in MODOS:
        for cenario, (_g, metrica) in CENARIOS.items():
            grupo = [l for l in linhas if l["modo"] == modo and l["cenario"] == cenario]
            n = len(grupo)
            deteccoes = sum(l["detectado"] for l in grupo)
            low, high = intervalo_wilson(deteccoes, n)
            proc_m, proc_s = _media_e_desvio([l["latencia_process_us"] for l in grupo])
            ver_m, ver_s = _media_e_desvio([l["latencia_verify_us"] for l in grupo])
            tipos = sorted({t for l in grupo for t in l["tipos_de_alerta"].split(";") if t})
            resumo.append({
                "modo": modo, "cenario": cenario, "metrica": metrica, "n": n,
                "deteccoes": deteccoes, "taxa": deteccoes / n,
                "ic95_inf": low, "ic95_sup": high,
                "latencia_process_us_media": proc_m, "latencia_process_us_dp": proc_s,
                "latencia_verify_us_media": ver_m, "latencia_verify_us_dp": ver_s,
                "latencia_total_us_media": proc_m + ver_m,
                "tipos_de_alerta": ";".join(tipos),
            })
    return resumo


def microbenchmark_hmac(sobrecarga_timer_us, repeticoes=20000):
    """Custo isolado de assinar e verificar um frame (campos já parseados)."""
    parsed = trafego._carregar_molde()
    campos = parsed["fields"]
    autenticador = GooseAuthenticator()
    tag = autenticador.sign(campos)
    linhas = []
    for operacao, funcao in (("sign", lambda: autenticador.sign(campos)),
                             ("verify", lambda: autenticador.verify(campos, tag))):
        funcao()  # aquece o cache de chaves
        amostras = []
        for _ in range(repeticoes):
            t0 = time.perf_counter_ns()
            funcao()
            amostras.append(max(0.0, (time.perf_counter_ns() - t0) / 1e3
                                - sobrecarga_timer_us))
        amostras.sort()
        linhas.append({
            "operacao": operacao, "repeticoes": repeticoes,
            "media_us": statistics.fmean(amostras), "dp_us": statistics.stdev(amostras),
            "mediana_us": amostras[len(amostras) // 2],
            "p99_us": amostras[int(len(amostras) * 0.99)],
        })
    return linhas


# --- saída ------------------------------------------------------------------

def gravar_csv(caminho, linhas):
    with open(caminho, "w", newline="", encoding="utf-8") as fh:
        escritor = csv.DictWriter(fh, fieldnames=list(linhas[0]))
        escritor.writeheader()
        for linha in linhas:
            escritor.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v)
                               for k, v in linha.items()})


def _pct(x):
    return f"{100 * x:.1f}%".replace(".", ",")


def _us(media, dp):
    return f"{media:.2f} ± {dp:.2f}".replace(".", ",")


def gerar_markdown(resumo, micro, trials, semente):
    saida = [f"# Resumo da campanha offline (N={trials} por cenário, semente {semente})\n"]
    for modo in MODOS:
        saida.append(f"\n## Modo `{modo}`\n")
        saida.append("| Cenário | Detecções | Taxa (IC95% Wilson) | Latência IDS (µs) | "
                     "Latência HMAC verify (µs) | Alertas |")
        saida.append("|---|---|---|---|---|---|")
        for r in (r for r in resumo if r["modo"] == modo):
            saida.append(
                f"| {r['cenario']} | {r['deteccoes']}/{r['n']} | "
                f"{_pct(r['taxa'])} {r['metrica']} "
                f"[{_pct(r['ic95_inf'])}; {_pct(r['ic95_sup'])}] | "
                f"{_us(r['latencia_process_us_media'], r['latencia_process_us_dp'])} | "
                f"{_us(r['latencia_verify_us_media'], r['latencia_verify_us_dp'])} | "
                f"{r['tipos_de_alerta'] or '-'} |")
    saida.append("\n## Microbenchmark do HMAC (por chamada)\n")
    saida.append("| Operação | Média (µs) | DP | Mediana | P99 |")
    saida.append("|---|---|---|---|---|")
    for m in micro:
        saida.append(f"| {m['operacao']} | {m['media_us']:.2f} | {m['dp_us']:.2f} | "
                     f"{m['mediana_us']:.2f} | {m['p99_us']:.2f} |")
    return "\n".join(saida) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=TRIALS_PADRAO)
    ap.add_argument("--seed", type=int, default=SEMENTE_PADRAO)
    ap.add_argument("--saida", type=Path, default=PASTA_RESULTADOS)
    args = ap.parse_args()

    args.saida.mkdir(parents=True, exist_ok=True)
    inicio = time.time()
    sobrecarga_timer_us = calibrar_sobrecarga_do_timer_us()
    linhas = executar_campanha(args.trials, args.seed, sobrecarga_timer_us)
    resumo = agregar(linhas)
    micro = microbenchmark_hmac(sobrecarga_timer_us)

    gravar_csv(args.saida / "campanha_trials.csv", linhas)
    gravar_csv(args.saida / "campanha_resumo.csv", resumo)
    gravar_csv(args.saida / "latencia_hmac_micro.csv", micro)
    (args.saida / "resumo.md").write_text(
        gerar_markdown(resumo, micro, args.trials, args.seed), encoding="utf-8")
    (args.saida / "execucao.json").write_text(json.dumps({
        "semente": args.seed, "trials_por_cenario": args.trials,
        "jitter_do_intervalo": JITTER_DO_INTERVALO,
        "sobrecarga_do_timer_descontada_us": round(sobrecarga_timer_us, 3),
        "python": platform.python_version(), "plataforma": platform.platform(),
        "duracao_s": round(time.time() - inicio, 1),
    }, indent=2), encoding="utf-8")
    print((args.saida / "resumo.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    sys.exit(main())
