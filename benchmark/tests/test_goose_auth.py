"""HMAC estilo IEC 62351-6 (simulação): assinatura, verificação e formato do frame."""
import hmac
from pathlib import Path

import pytest

import goose_auth
import goose_frame as gf
import trafego
from goose_auth import GooseAuthenticator

RAIZ = Path(trafego.RAIZ_DO_REPOSITORIO)


@pytest.fixture
def molde():
    return trafego._carregar_molde()


def _frame_assinado(molde, autenticador, campos=None):
    campos = campos or dict(molde["fields"])
    tag = autenticador.sign(campos)
    raw = bytes(gf.build_ethernet_goose_frame(
        molde["dst_mac"], molde["src_mac"], molde["appid"], campos, auth_tag=tag))
    return raw, campos


def test_hmac_valido_sobrevive_ao_ciclo_build_parse(molde):
    autenticador = GooseAuthenticator()
    raw, _ = _frame_assinado(molde, autenticador)

    parsed = gf.parse_ethernet_goose(raw)

    assert len(parsed["auth_tag"]) == goose_auth.TAG_SIZE
    assert autenticador.verify(parsed["fields"], parsed["auth_tag"])


@pytest.mark.parametrize("campo,novo_valor", [
    ("stNum", 24), ("sqNum", 522), ("t", b"\x00" * 8),
    ("gocbRef", "OUTRO/LLN0$GO$Fluxo"), ("allData", b"\xa2\x03\x83\x01\x01"),
])
def test_hmac_invalido_quando_campo_protegido_e_alterado(molde, campo, novo_valor):
    autenticador = GooseAuthenticator()
    raw, _ = _frame_assinado(molde, autenticador)
    parsed = gf.parse_ethernet_goose(raw)
    adulterado = dict(parsed["fields"], **{campo: novo_valor})

    assert not autenticador.verify(adulterado, parsed["auth_tag"])


def test_hmac_invalido_com_outra_chave(molde):
    raw, _ = _frame_assinado(molde, GooseAuthenticator(b"chave-do-atacante"))
    parsed = gf.parse_ethernet_goose(raw)

    assert not GooseAuthenticator().verify(parsed["fields"], parsed["auth_tag"])


def test_tag_antiga_nao_vale_para_conteudo_forjado(molde):
    autenticador = GooseAuthenticator()
    _, campos = _frame_assinado(molde, autenticador)
    tag_antiga = autenticador.sign(campos)
    forjado = dict(campos, stNum=campos["stNum"] + 1, sqNum=0)

    assert not autenticador.verify(forjado, tag_antiga)


def test_frame_sem_tag_e_invalido(molde):
    assert not GooseAuthenticator().verify(molde["fields"], None)


def test_campos_ausentes_nao_levantam_excecao():
    assert not GooseAuthenticator().verify({"stNum": 1}, b"\x00" * goose_auth.TAG_SIZE)


def test_verificacao_usa_comparacao_em_tempo_constante(molde, monkeypatch):
    chamadas = []
    original = hmac.compare_digest
    monkeypatch.setattr(goose_auth.hmac, "compare_digest",
                        lambda a, b: chamadas.append(1) or original(a, b))
    autenticador = GooseAuthenticator()

    autenticador.verify(molde["fields"], autenticador.sign(molde["fields"]))

    assert chamadas == [1]


def test_chave_por_gocbref_difere_entre_fluxos(molde):
    autenticador = GooseAuthenticator()
    outro_fluxo = dict(molde["fields"], gocbRef="OUTRO/LLN0$GO$Fluxo")

    assert autenticador.sign(molde["fields"]) != autenticador.sign(outro_fluxo)


def test_chave_mestra_vem_da_variavel_de_ambiente(monkeypatch, molde):
    monkeypatch.setenv(goose_auth.KEY_ENV_VAR, "chave-do-ambiente")

    assert GooseAuthenticator.from_env().sign(molde["fields"]) == \
        GooseAuthenticator(b"chave-do-ambiente").sign(molde["fields"])
    assert not GooseAuthenticator.uses_test_key()


def test_frame_sem_tag_continua_identico_ao_original(molde):
    original = bytes(trafego.rdpcap(str(trafego.MOLDE_PCAP))[0])
    reconstruido = bytes(gf.build_ethernet_goose_frame(
        molde["dst_mac"], molde["src_mac"], molde["appid"], molde["fields"]))

    assert reconstruido == original
    assert gf.parse_ethernet_goose(original)["auth_tag"] is None


def test_trailer_truncado_vira_tag_ausente(molde):
    raw, _ = _frame_assinado(molde, GooseAuthenticator())

    assert gf.parse_ethernet_goose(raw[:-5])["auth_tag"] is None


@pytest.mark.parametrize("modulo", ["goose_frame.py", "goose_auth.py"])
def test_copias_de_ids_e_atacante_sao_identicas(modulo):
    assert (RAIZ / "ids" / modulo).read_bytes() == (RAIZ / "atacante" / modulo).read_bytes()
