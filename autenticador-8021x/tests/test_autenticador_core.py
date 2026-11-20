"""Testes do núcleo do autenticador 802.1X (sem hostapd, sem nftables).

As linhas de log são trechos reais do hostapd v2.10 (`hostapd -d`) capturados
em teste_netns.sh.
"""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from autenticador import FirewallNft  # noqa: E402
from autenticador_core import (  # noqa: E402
    ControladorAcesso, EventoAcesso, InterpretadorLogHostapd, Inventario,
    RegistroJsonl, extrair_cn, MOTIVO_CERTIFICADO_INVALIDO, MOTIVO_CERTIFICADO_REVOGADO,
    MOTIVO_CN_FORA_DO_INVENTARIO, MOTIVO_FALHA_EAP, MOTIVO_MAC_DIVERGENTE,
    MOTIVO_SEM_CERTIFICADO)

MAC_IED1 = "02:00:c0:a8:0a:0b"
MAC_ATACANTE = "02:00:c0:a8:0a:28"
INVENTARIO = {
    "ubuntu-ied-1": {"macs": [MAC_IED1]},
    "atacante-comprometido": {"macs": [MAC_ATACANTE.upper()]},
}


def _pacote(iface, mac, resposta="EAP Response-TLS (13)"):
    return [
        f"{iface}: STA {mac} IEEE 802.1X: received EAP packet (code=2 id=170 len=190) from STA: {resposta}",
        f"IEEE 802.1X: {mac} BE_AUTH entering state RESPONSE",
    ]


def _linhas_sucesso(mac, cn, iface="p1"):
    return [
        f"{iface}: CTRL-EVENT-EAP-STARTED {mac}",
        *_pacote(iface, mac),
        f"authsrv: peer certificate: depth=0 serial_num=1001 subject=/O=Testbed IEC61850 (LAB)/CN={cn}",
        f"{iface}: CTRL-EVENT-EAP-SUCCESS {mac}",
        f"{iface}: AP-STA-CONNECTED {mac}",
    ]


def _eventos(linhas):
    interpretador = InterpretadorLogHostapd()
    return [e for linha in linhas for e in interpretador.processar(linha)]


class ExtrairCnTest(unittest.TestCase):
    def test_usa_o_ultimo_cn_do_subject(self):
        self.assertEqual(extrair_cn("/O=Testbed (LAB)/CN=ubuntu-ied-1"), "ubuntu-ied-1")

    def test_sem_cn_devolve_none(self):
        self.assertIsNone(extrair_cn("/O=Testbed"))


class InterpretadorLogTest(unittest.TestCase):
    def test_sucesso_traz_cn_e_serial_do_certificado_verificado(self):
        eventos = _eventos(_linhas_sucesso("aa:bb:cc:dd:ee:01", "ubuntu-ied-1"))
        sucesso = [e for e in eventos if e.tipo == "sucesso"]
        self.assertEqual(len(sucesso), 1)
        self.assertEqual((sucesso[0].iface, sucesso[0].mac, sucesso[0].cn, sucesso[0].serial),
                         ("p1", "aa:bb:cc:dd:ee:01", "ubuntu-ied-1", "1001"))

    def test_certificado_revogado(self):
        mac = "aa:bb:cc:dd:ee:02"
        eventos = _eventos([
            f"p2: CTRL-EVENT-EAP-STARTED {mac}",
            *_pacote("p2", mac),
            "authsrv: peer certificate: depth=0 serial_num=100B subject=/O=Testbed IEC61850 (LAB)/CN=revogado-1",
            "TLS: Certificate verification failed, error 23 (certificate revoked) depth 0 for "
            "'/O=Testbed IEC61850 (LAB)/CN=revogado-1'",
            f"p2: CTRL-EVENT-EAP-FAILURE {mac}",
        ])
        falha = eventos[-1]
        self.assertEqual((falha.tipo, falha.motivo, falha.cn),
                         ("falha", MOTIVO_CERTIFICADO_REVOGADO, "revogado-1"))

    def test_ca_desconhecida_e_certificado_invalido(self):
        mac = "aa:bb:cc:dd:ee:03"
        eventos = _eventos([
            f"p3: CTRL-EVENT-EAP-STARTED {mac}",
            *_pacote("p3", mac),
            "TLS: Certificate verification failed, error 20 (unable to get local issuer certificate) "
            "depth 0 for '/CN=ubuntu-ied-1'",
            f"p3: CTRL-EVENT-EAP-FAILURE {mac}",
        ])
        self.assertEqual(eventos[-1].motivo, MOTIVO_CERTIFICADO_INVALIDO)
        self.assertEqual(eventos[-1].cn, "ubuntu-ied-1")
        self.assertIn("unable to get local issuer", eventos[-1].detalhe)

    def test_cliente_sem_credencial_responde_nak(self):
        mac = "aa:bb:cc:dd:ee:04"
        eventos = _eventos([
            f"p4: CTRL-EVENT-EAP-STARTED {mac}",
            *_pacote("p4", mac, "EAP Response-Identity (1)"),
            *_pacote("p4", mac, "EAP Response-unknown (3)"),
            f"p4: CTRL-EVENT-EAP-FAILURE {mac}",
        ])
        self.assertEqual(eventos[-1].motivo, MOTIVO_SEM_CERTIFICADO)

    def test_falha_sem_indicio_de_certificado_e_falha_eap_generica(self):
        mac = "aa:bb:cc:dd:ee:05"
        eventos = _eventos([f"p5: CTRL-EVENT-EAP-STARTED {mac}", f"p5: CTRL-EVENT-EAP-FAILURE {mac}"])
        self.assertEqual(eventos[-1].motivo, MOTIVO_FALHA_EAP)

    def test_estado_de_uma_tentativa_nao_vaza_para_a_seguinte(self):
        mac = "aa:bb:cc:dd:ee:06"
        _tentativa_revogada = [
            f"p1: CTRL-EVENT-EAP-STARTED {mac}",
            *_pacote("p1", mac),
            "TLS: Certificate verification failed, error 23 (certificate revoked) depth 0 for '/CN=x'",
            f"p1: CTRL-EVENT-EAP-FAILURE {mac}",
        ]
        eventos = _eventos(_tentativa_revogada + [f"p1: CTRL-EVENT-EAP-STARTED {mac}",
                                                    f"p1: CTRL-EVENT-EAP-FAILURE {mac}"])
        self.assertEqual(eventos[-1].motivo, MOTIVO_FALHA_EAP)

    def test_processamento_intercalado_atribui_cada_certificado_a_sua_estacao(self):
        mac_a, mac_b = "aa:bb:cc:dd:ee:07", "aa:bb:cc:dd:ee:08"
        eventos = _eventos([
            *_pacote("p1", mac_a)[:1], *_pacote("p2", mac_b)[:1],   # recebe A, recebe B
            _pacote("p1", mac_a)[1], "authsrv: peer certificate: depth=0 serial_num=1 subject=/CN=dono-de-A",
            _pacote("p2", mac_b)[1], "authsrv: peer certificate: depth=0 serial_num=2 subject=/CN=dono-de-B",
            f"p1: CTRL-EVENT-EAP-SUCCESS {mac_a}", f"p2: CTRL-EVENT-EAP-SUCCESS {mac_b}",
        ])
        self.assertEqual([(e.iface, e.cn) for e in eventos], [("p1", "dono-de-A"), ("p2", "dono-de-B")])

    def test_mac_clonado_em_duas_portas_com_interpretador_por_porta(self):
        mac = "aa:bb:cc:dd:ee:0a"
        # Ordem adversa observada no hostapd real: a porta do clonador (p5)
        # processa antes da do legítimo (p1). Um interpretador por processo
        # não pode confundir os certificados.
        p1 = _eventos(_linhas_sucesso(mac, "legitimo", "p1"))
        p5 = _eventos(_linhas_sucesso(mac, "clonador", "p5"))
        self.assertEqual([(e.iface, e.cn) for e in p1 + p5 if e.tipo == "sucesso"],
                         [("p1", "legitimo"), ("p5", "clonador")])

    def test_desconexao(self):
        eventos = _eventos(["p1: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:09"])
        self.assertEqual([(e.tipo, e.iface) for e in eventos], [("desconexao", "p1")])

    def test_linha_irrelevante_nao_gera_evento(self):
        self.assertEqual(_eventos(["OpenSSL: RX ver=0x303 content_type=22"]), [])


class InventarioTest(unittest.TestCase):
    def setUp(self):
        self.inventario = Inventario(INVENTARIO)

    def test_cn_e_mac_correspondentes_sao_aceitos(self):
        self.assertEqual(self.inventario.avaliar("ubuntu-ied-1", MAC_IED1), (True, None))

    def test_comparacao_de_mac_ignora_caixa_e_hifen(self):
        self.assertTrue(self.inventario.avaliar("atacante-comprometido", "02-00-C0-A8-0A-28")[0])

    def test_cn_desconhecido(self):
        self.assertEqual(self.inventario.avaliar("intruso", MAC_IED1), (False, MOTIVO_CN_FORA_DO_INVENTARIO))

    def test_cn_valido_com_mac_de_outro_dispositivo(self):
        self.assertEqual(self.inventario.avaliar("atacante-comprometido", MAC_IED1),
                         (False, MOTIVO_MAC_DIVERGENTE))


class FirewallFalso:
    def __init__(self):
        self.autorizados = set()

    def autorizar(self, iface, mac):
        self.autorizados.add((iface, mac))

    def revogar(self, iface, mac):
        existia = (iface, mac) in self.autorizados
        self.autorizados.discard((iface, mac))
        return existia

    def revogar_porta(self, iface):
        macs = sorted(m for i, m in self.autorizados if i == iface)
        for mac in macs:
            self.revogar(iface, mac)
        return macs


class ControladorAcessoTest(unittest.TestCase):
    def setUp(self):
        self.firewall = FirewallFalso()
        self.buffer = io.StringIO()
        self.registro = RegistroJsonl(self.buffer)
        self.desautenticados = []
        self.controlador = ControladorAcesso(
            Inventario(INVENTARIO), self.firewall, self.registro,
            lambda iface, mac: self.desautenticados.append((iface, mac)))

    def registros(self):
        return [json.loads(linha) for linha in self.buffer.getvalue().splitlines()]

    def test_autenticacao_valida_libera_o_par_porta_mac(self):
        self.controlador.tratar(EventoAcesso("sucesso", "p1", MAC_IED1, cn="ubuntu-ied-1", serial="1001"))
        self.assertEqual(self.firewall.autorizados, {("p1", MAC_IED1)})
        self.assertEqual(self.registros()[0]["evento"], "auth_aceita")

    def test_cn_valido_com_mac_divergente_nao_libera_e_derruba_a_sessao(self):
        self.controlador.tratar(EventoAcesso("sucesso", "p5", MAC_IED1, cn="atacante-comprometido"))
        self.assertEqual(self.firewall.autorizados, set())
        self.assertEqual(self.desautenticados, [("p5", MAC_IED1)])
        registro = self.registros()[0]
        self.assertEqual((registro["evento"], registro["motivo"]), ("auth_rejeitada", MOTIVO_MAC_DIVERGENTE))
        self.assertIn(MAC_ATACANTE, registro["detalhe"])

    def test_cn_fora_do_inventario_e_rejeitado(self):
        self.controlador.tratar(EventoAcesso("sucesso", "p7", MAC_IED1, cn="fora-do-inventario-1"))
        self.assertEqual(self.registros()[0]["motivo"], MOTIVO_CN_FORA_DO_INVENTARIO)

    def test_falha_eap_registra_motivo_sem_liberar(self):
        self.controlador.tratar(EventoAcesso("falha", "p4", MAC_IED1, cn="revogado-1",
                                             motivo=MOTIVO_CERTIFICADO_REVOGADO, detalhe="certificate revoked"))
        self.assertEqual(self.firewall.autorizados, set())
        self.assertEqual(self.registros()[0]["motivo"], MOTIVO_CERTIFICADO_REVOGADO)

    def test_falha_na_reautenticacao_revoga_o_acesso_existente(self):
        self.firewall.autorizar("p1", MAC_IED1)
        self.controlador.tratar(EventoAcesso("falha", "p1", MAC_IED1, motivo=MOTIVO_FALHA_EAP))
        self.assertEqual(self.firewall.autorizados, set())

    def test_desconexao_revoga_e_registra_uma_vez(self):
        self.firewall.autorizar("p1", MAC_IED1)
        self.controlador.tratar(EventoAcesso("desconexao", "p1", MAC_IED1))
        self.controlador.tratar(EventoAcesso("desconexao", "p1", MAC_IED1))
        self.assertEqual([r["evento"] for r in self.registros()], ["sessao_encerrada"])

    def test_queda_de_link_revoga_todos_os_pares_da_porta(self):
        self.firewall.autorizar("p1", MAC_IED1)
        self.firewall.autorizar("p2", MAC_ATACANTE)
        self.controlador.porta_caiu("p1")
        self.assertEqual(self.firewall.autorizados, {("p2", MAC_ATACANTE)})
        self.assertEqual(self.registros()[0]["motivo"], "link_down")

    def test_descartes_so_sao_reportados_quando_o_contador_muda(self):
        self.controlador.reportar_descartes([("p3", MAC_IED1, 5)])
        self.controlador.reportar_descartes([("p3", MAC_IED1, 5)])
        self.controlador.reportar_descartes([("p3", MAC_IED1, 9)])
        self.assertEqual([r["pacotes"] for r in self.registros()], [5, 9])


class FirewallNftTest(unittest.TestCase):
    def setUp(self):
        self.comandos = []
        self.firewall = FirewallNft(self.comandos.append)

    def test_autorizar_adiciona_par_e_porta(self):
        self.firewall.autorizar("p1", MAC_IED1)
        self.assertEqual(self.comandos[0][-2:], ["autorizados", f'{{ "p1" . {MAC_IED1} }}'])
        self.assertEqual(self.comandos[1][-2:], ["portas_autorizadas", '{ "p1" }'])

    def test_porta_so_sai_do_set_quando_nao_resta_nenhum_mac(self):
        self.firewall.autorizar("p1", MAC_IED1)
        self.firewall.autorizar("p1", MAC_ATACANTE)
        self.comandos.clear()
        self.assertTrue(self.firewall.revogar("p1", MAC_IED1))
        self.assertEqual(len(self.comandos), 1)
        self.firewall.revogar("p1", MAC_ATACANTE)
        self.assertEqual(self.comandos[-1][-2:], ["portas_autorizadas", '{ "p1" }'])
        self.assertEqual(self.comandos[-1][0], "delete")

    def test_revogar_par_inexistente_nao_executa_nada(self):
        self.assertFalse(self.firewall.revogar("p9", MAC_IED1))
        self.assertEqual(self.comandos, [])


if __name__ == "__main__":
    unittest.main()
