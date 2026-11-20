"""Integração do resultado da verificação de HMAC com ids_core.GooseMonitor."""
from ids_core import GooseMonitor

REF, MAC = "IED/LLN0$GO$A", "00:11:22:33:44:55"


def _tipos(alertas):
    return [a["type"] for a in alertas]


def test_sem_autenticacao_o_comportamento_nao_muda():
    monitor = GooseMonitor()
    monitor.process(REF, MAC, 1, 1, 0.0)

    assert monitor.process(REF, MAC, 1, 2, 1.0) == []
    assert _tipos(monitor.process(REF, MAC, 1, 1, 2.0)) == ["replay"]


def test_auth_invalido_gera_auth_fail():
    monitor = GooseMonitor()

    assert _tipos(monitor.process(REF, MAC, 1, 1, 0.0, auth_valid=False)) == ["auth_fail"]


def test_auth_valido_nao_gera_alerta():
    monitor = GooseMonitor()
    monitor.process(REF, MAC, 1, 1, 0.0, auth_valid=True)

    assert monitor.process(REF, MAC, 1, 2, 1.0, auth_valid=True) == []


def test_frame_nao_autenticado_nao_altera_o_estado():
    monitor = GooseMonitor()
    monitor.process(REF, MAC, 5, 3, 0.0, auth_valid=True)
    monitor.process(REF, "02:00:00:00:00:66", 6, 0, 1.0, auth_valid=False)

    # o próximo frame legítimo segue a sequência original: sem replay/masquerade
    assert monitor.process(REF, MAC, 5, 4, 2.0, auth_valid=True) == []


def test_frame_valido_continua_sujeito_as_demais_checagens():
    monitor = GooseMonitor()
    monitor.process(REF, MAC, 5, 3, 0.0, auth_valid=True)

    assert _tipos(monitor.process(REF, MAC, 5, 3, 1.0, auth_valid=True)) == ["replay"]
