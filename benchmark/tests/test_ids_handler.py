"""ids.py ponta a ponta (sem rede): frames crus entram no handler do IDS."""
import ids
import trafego
from goose_auth import GooseAuthenticator
from ids_core import GooseMonitor


def _enviar(frames, autenticador):
    handler = ids.make_handler(GooseMonitor(), None, autenticador)
    for frame in frames:
        handler(frame)  # bytes(frame) == frame


def test_ids_com_auth_alerta_masquerade_sofisticado(capsys):
    itens = trafego.trafego_masquerade(trafego.HMAC, mac_proprio=False)

    _enviar([i.raw for i in itens], GooseAuthenticator())

    assert "AUTH_FAIL" in capsys.readouterr().out


def test_ids_com_auth_aceita_trafego_legitimo_assinado(capsys):
    # só o aquecimento: o handler usa o relógio real, e o baseline inteiro
    # chegaria de uma vez só, parecendo flooding
    itens = [i for i in trafego.trafego_flood(trafego.HMAC, 50) if not i.is_attack]

    _enviar([i.raw for i in itens], GooseAuthenticator())

    assert capsys.readouterr().out == ""


def test_ids_sem_auth_ignora_o_trailer_e_mantem_o_comportamento_antigo(capsys):
    itens = trafego.trafego_masquerade(trafego.SEM_HMAC, mac_proprio=False)

    _enviar([i.raw for i in itens], None)

    assert capsys.readouterr().out == ""


def test_reserved1_minusculo_com_a0_nao_derruba_o_parse():
    # Reserved1=1 e o último byte 0xA0: antes lançava IndexError e o frame
    # era descartado em silêncio, mesmo com a autenticação desligada.
    import goose_frame as gf
    raw = bytearray(trafego.trafego_baseline(trafego.SEM_HMAC)[0].raw)
    off = 14 if raw[12:14] == b"\x88\xb8" else 18
    raw[off + 4:off + 6] = (1).to_bytes(2, "big")
    raw += b"\xa0"

    assert gf.parse_ethernet_goose(bytes(raw))["auth_tag"] is None
