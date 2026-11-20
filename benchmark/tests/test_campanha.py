"""Cenários da campanha offline: o que cada modo de autenticação detecta."""
import random

import pytest

import benchmark_ids as bi
import sensibilidade_limiar as sl
import trafego
from trafego import HMAC, HMAC_CHAVE_VAZADA, SEM_HMAC

# Detecção esperada por cenário em cada modo.
ESPERADO = {
    SEM_HMAC:          dict(T0=False, A=True, B=True, C1=False, C2=True, D=True),
    HMAC:              dict(T0=False, A=True, B=True, C1=True,  C2=True, D=True),
    HMAC_CHAVE_VAZADA: dict(T0=False, A=True, B=True, C1=False, C2=True, D=True),
}
CENARIOS = {
    "T0": ("T0_baseline", lambda m: trafego.trafego_baseline(m)),
    "A": ("A_flooding", lambda m: trafego.trafego_flood(m, 50)),
    "B": ("B_replay", lambda m: trafego.trafego_replay(m, 3.7)),
    "C1": ("C1_masquerade_sofisticado", lambda m: trafego.trafego_masquerade(m, False)),
    "C2": ("C2_masquerade_ingenuo", lambda m: trafego.trafego_masquerade(m, True)),
    "D": ("D_suppression", lambda m: trafego.trafego_supressao(m, 60)),
}


def _rodar(modo, chave_do_cenario):
    nome, gerar = CENARIOS[chave_do_cenario]
    resultados = bi.executar_trial(gerar(modo), modo, random.Random(1))
    return bi.resumir_trial(resultados, nome)


@pytest.mark.parametrize("modo", bi.MODOS)
@pytest.mark.parametrize("cenario", CENARIOS)
def test_deteccao_esperada_por_modo_e_cenario(modo, cenario):
    resumo = _rodar(modo, cenario)

    assert bool(resumo["detectado"]) == ESPERADO[modo][cenario], resumo


@pytest.mark.parametrize("modo", bi.MODOS)
@pytest.mark.parametrize("cenario", [c for c in CENARIOS if c != "T0"])
def test_aquecimento_legitimo_nao_gera_alertas(modo, cenario):
    assert _rodar(modo, cenario)["alertas_no_aquecimento"] == 0


def test_atacante_sem_chave_e_pego_por_auth_fail_no_masquerade_sofisticado():
    assert _rodar(HMAC, "C1")["tipos_de_alerta"] == "auth_fail"


def test_replay_passa_no_hmac_e_e_pego_pela_ordem_de_sequencia():
    assert _rodar(HMAC, "B")["tipos_de_alerta"] == "replay"


def test_mesma_semente_gera_mesmas_deteccoes():
    def rodar():
        linhas = bi.executar_campanha(trials=1, semente=7)
        return [(l["modo"], l["cenario"], l["parametro"], l["detectado"], l["tipos_de_alerta"])
                for l in linhas]

    assert rodar() == rodar()


def test_latencia_de_verificacao_e_zero_sem_hmac_e_positiva_com_hmac():
    sem = _rodar(SEM_HMAC, "T0")
    com = _rodar(HMAC, "T0")

    assert sem["latencia_verify_us"] == 0.0
    assert com["latencia_verify_us"] > 0.0


def test_intervalo_de_wilson_contem_a_proporcao_observada():
    inf, sup = bi.intervalo_wilson(100, 100)

    assert sup == pytest.approx(1.0) and 0.95 < inf < 1.0
    assert bi.intervalo_wilson(0, 100)[0] == 0.0


def test_taxa_de_ataque_abaixo_do_limiar_passa_e_acima_e_detectada():
    def tpr(limiar, pps):
        itens = trafego.trafego_flood(SEM_HMAC, pps)
        res = bi.executar_trial(itens, SEM_HMAC, random.Random(3), flood_pps_threshold=limiar)
        return sl._alguma_deteccao(res, so_ataque=True)

    assert not tpr(limiar=20, pps=10)
    assert tpr(limiar=20, pps=100)
    assert tpr(limiar=5, pps=10)


def test_rajada_legitima_acima_do_limiar_gera_falso_positivo():
    def fp(limiar, rajada_pps):
        itens = trafego.trafego_baseline(SEM_HMAC, rajada_pps=rajada_pps)
        res = bi.executar_trial(itens, SEM_HMAC, random.Random(3), flood_pps_threshold=limiar)
        return sl._alguma_deteccao(res, so_ataque=False)

    assert not fp(limiar=20, rajada_pps=5)
    assert fp(limiar=20, rajada_pps=60)
