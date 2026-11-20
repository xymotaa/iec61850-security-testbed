"""Testes de instalar_no_gns3.py com um projeto GNS3 e uma PKI falsos."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import instalar_no_gns3 as instalador  # noqa: E402

NOS = {"autenticador-8021x": "id-aut", "ubuntu-ied-1": "id-ied1", "atacante-1": "id-atq",
       "switch-qualquer": "id-sw"}


def _criar_projeto(pasta):
    topologia = {"topology": {"nodes": [
        {"name": nome, "node_id": node_id,
         "node_type": "ethernet_switch" if nome == "switch-qualquer" else "docker"}
        for nome, node_id in NOS.items()]}}
    (pasta / "p.gns3").write_text(json.dumps(topologia))


def _criar_pki(pasta):
    for pacote in ("autenticador-8021x", "ubuntu-ied-1", "atacante-comprometido",
                   "revogado-1", "fora-do-inventario-1"):
        for arquivo in ("ca.pem", "cert.pem", "key.pem"):
            (pasta / "nos" / pacote).mkdir(parents=True, exist_ok=True)
            (pasta / "nos" / pacote / arquivo).write_text(f"{pacote}/{arquivo}")
    (pasta / "nos" / "autenticador-8021x" / "crl.pem").write_text("crl")


class InstalarNoGns3Test(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        raiz = Path(self._tmp.name)
        self.projeto, self.pki = raiz / "projeto", raiz / "pki"
        self.projeto.mkdir()
        _criar_projeto(self.projeto)
        _criar_pki(self.pki)
        self.inventario = raiz / "inventario.json"
        self.inventario.write_text("{}")

    def tearDown(self):
        self._tmp.cleanup()

    def volume(self, node_id):
        return self.projeto / "project-files" / "docker" / node_id / "etc" / "8021x"

    def test_cada_no_recebe_o_proprio_pacote(self):
        instalador.instalar(self.projeto, self.pki, self.inventario)
        self.assertEqual((self.volume("id-ied1") / "cert.pem").read_text(), "ubuntu-ied-1/cert.pem")

    def test_atacante_recebe_cert_comprometido_e_alternativos(self):
        instalador.instalar(self.projeto, self.pki, self.inventario)
        self.assertEqual((self.volume("id-atq") / "cert.pem").read_text(), "atacante-comprometido/cert.pem")
        self.assertTrue((self.volume("id-atq") / "alternativos" / "revogado-1" / "key.pem").is_file())
        self.assertTrue((self.volume("id-atq") / "alternativos" / "fora-do-inventario-1" / "cert.pem").is_file())

    def test_autenticador_recebe_crl_e_inventario(self):
        instalador.instalar(self.projeto, self.pki, self.inventario)
        self.assertTrue((self.volume("id-aut") / "crl.pem").is_file())
        self.assertTrue((self.volume("id-aut") / "inventario.json").is_file())

    def test_chave_privada_fica_so_com_o_dono(self):
        instalador.instalar(self.projeto, self.pki, self.inventario)
        modo = stat.S_IMODE((self.volume("id-ied1") / "key.pem").stat().st_mode)
        self.assertEqual(modo, 0o600)

    def test_no_que_nao_e_docker_e_ignorado(self):
        instalador.instalar(self.projeto, self.pki, self.inventario)
        self.assertFalse((self.projeto / "project-files" / "docker" / "id-sw").exists())

    def test_pki_ausente_falha_com_mensagem_clara(self):
        with self.assertRaises(instalador.InstalacaoErro):
            instalador.instalar(self.projeto, self.pki / "nao-existe", self.inventario)

    def test_inventario_ausente_falha(self):
        with self.assertRaises(instalador.InstalacaoErro):
            instalador.instalar(self.projeto, self.pki, self.projeto / "nao-existe.json")


if __name__ == "__main__":
    unittest.main()
