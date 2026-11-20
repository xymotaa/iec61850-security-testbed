"""Testes do inventário 802.1X e da topologia `--8021x` (gerar_topologia_gns3.py)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
PASTA_SCD = os.path.join(AQUI, "..")
sys.path.insert(0, PASTA_SCD)

import gerar_topologia_gns3 as gerador  # noqa: E402
import inventario_8021x as inventario  # noqa: E402

IEDS = [{"name": "SEL_351_1"}, {"name": "SEL_351_2"}, {"name": "SEL_351_3"}]
NOMES_FIXOS = ["oraculo-1", "ids-1", "publicador-1", "atacante-1"]


class InventarioTest(unittest.TestCase):
    def test_mac_derivado_do_ip(self):
        self.assertEqual(inventario.mac_do_ip("192.168.10.11"), "02:00:c0:a8:0a:0b")

    def test_ip_invalido_e_rejeitado(self):
        with self.assertRaises(ValueError):
            inventario.mac_do_ip("192.168.10")

    def test_ip_do_ied_segue_o_entrypoint(self):
        self.assertEqual(inventario.ip_do_ied(3), "192.168.10.13")

    def test_ied_numero_alto_demais_falha_cedo(self):
        with self.assertRaises(ValueError):
            inventario.ip_do_ied(150)

    def test_inventario_cobre_ieds_e_nos_fixos(self):
        dispositivos = inventario.construir_inventario(IEDS)["dispositivos"]
        self.assertEqual(sorted(dispositivos), sorted(
            ["ubuntu-ied-1", "ubuntu-ied-2", "ubuntu-ied-3", "oraculo-1", "ids-1",
             "publicador-1", inventario.CN_ATACANTE_COMPROMETIDO]))
        self.assertEqual(dispositivos["ubuntu-ied-2"]["ied"], "SEL_351_2")

    def test_publicador_usa_o_mac_de_origem_do_goose(self):
        dispositivos = inventario.construir_inventario(IEDS)["dispositivos"]
        self.assertEqual(dispositivos["publicador-1"]["macs"], [inventario.MAC_ORIGEM_GOOSE_MOLDE])

    def test_nenhum_mac_se_repete_entre_dispositivos(self):
        dispositivos = inventario.construir_inventario(IEDS)["dispositivos"]
        macs = [m for d in dispositivos.values() for m in d["macs"]]
        self.assertEqual(len(macs), len(set(macs)))

    def test_cli_grava_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            entrada, saida = os.path.join(tmp, "dados.json"), os.path.join(tmp, "inv.json")
            with open(entrada, "w") as f:
                json.dump(IEDS, f)
            self.assertEqual(inventario.main([entrada, "--out", saida]), 0)
            with open(saida) as f:
                self.assertIn("ubuntu-ied-1", json.load(f)["dispositivos"])

    def test_cli_sem_ieds_falha(self):
        with tempfile.TemporaryDirectory() as tmp:
            entrada = os.path.join(tmp, "dados.json")
            with open(entrada, "w") as f:
                json.dump([], f)
            self.assertEqual(inventario.main([entrada, "--out", os.path.join(tmp, "x.json")]), 1)


class TopologiaTest(unittest.TestCase):
    def setUp(self):
        self.inventory = inventario.construir_inventario(IEDS)
        self.topology = gerador.build_topology_8021x(IEDS, "subestacao_8021x", self.inventory)
        self.nodes = {n["name"]: n for n in self.topology["topology"]["nodes"]}
        self.links = self.topology["topology"]["links"]

    def test_nao_ha_switches_so_docker(self):
        self.assertEqual({n["node_type"] for n in self.nodes.values()}, {"docker"})
        self.assertEqual(sorted(self.nodes), sorted(
            [gerador.AUTENTICADOR_NAME, "ubuntu-ied-1", "ubuntu-ied-2", "ubuntu-ied-3", *NOMES_FIXOS]))

    def test_autenticador_tem_um_adaptador_por_dispositivo(self):
        autenticador = self.nodes[gerador.AUTENTICADOR_NAME]
        self.assertEqual(autenticador["properties"]["adapters"], len(self.nodes) - 1)
        self.assertIn(f"AUTENTICADOR_PORTAS={len(self.nodes) - 1}", autenticador["properties"]["environment"])

    def test_cada_dispositivo_ligado_a_um_adaptador_distinto_do_autenticador(self):
        autenticador_id = self.nodes[gerador.AUTENTICADOR_NAME]["node_id"]
        adaptadores = []
        for link in self.links:
            lado_autenticador = next(n for n in link["nodes"] if n["node_id"] == autenticador_id)
            adaptadores.append(lado_autenticador["adapter_number"])
        self.assertEqual(sorted(adaptadores), list(range(len(self.nodes) - 1)))
        self.assertEqual(len(self.links), len(self.nodes) - 1)

    def test_mac_dos_nos_vem_do_inventario(self):
        dispositivos = self.inventory["dispositivos"]
        self.assertEqual(self.nodes["ubuntu-ied-1"]["custom_adapters"],
                         [{"adapter_number": 0, "mac_address": dispositivos["ubuntu-ied-1"]["macs"][0]}])
        self.assertEqual(self.nodes["atacante-1"]["custom_adapters"][0]["mac_address"],
                         dispositivos[inventario.CN_ATACANTE_COMPROMETIDO]["macs"][0])

    def test_supplicant_ligado_nos_legitimos_e_desligado_no_atacante(self):
        for nome in ("ubuntu-ied-1", "oraculo-1", "ids-1", "publicador-1"):
            self.assertIn("AUTH_8021X=1", self.nodes[nome]["properties"]["environment"], nome)
        self.assertIn("AUTH_8021X=0", self.nodes["atacante-1"]["properties"]["environment"])

    def test_publicador_reutiliza_a_imagem_do_atacante_com_outro_ip(self):
        publicador = self.nodes["publicador-1"]["properties"]
        self.assertEqual(publicador["image"], "atacante:latest")
        self.assertIn(f"ATACANTE_IP={inventario.IP_PUBLICADOR}", publicador["environment"])

    def test_volumes_persistentes_para_certificados_e_eventos(self):
        self.assertEqual(self.nodes["ids-1"]["properties"]["extra_volumes"], ["/etc/8021x"])
        self.assertEqual(self.nodes[gerador.AUTENTICADOR_NAME]["properties"]["extra_volumes"],
                         ["/etc/8021x", "/var/log/8021x"])

    def test_posicoes_inteiras_e_formato_rev9(self):
        self.assertEqual(self.topology["revision"], 9)
        for node in self.nodes.values():
            self.assertIsInstance(node["x"], int)
            self.assertIsInstance(node["y"], int)

    def test_valida_contra_o_schema_do_gns3_quando_disponivel(self):
        try:
            import jsonschema
            from gns3server.schemas.topology import TOPOLOGY_SCHEMA
        except ImportError:
            self.skipTest("jsonschema/gns3server indisponíveis neste interpretador")
        jsonschema.validate(self.topology, TOPOLOGY_SCHEMA)


class TopologiaOriginalIntactaTest(unittest.TestCase):
    def test_sem_a_flag_continua_gerando_os_cinco_switches(self):
        topologia = gerador.build_topology(IEDS, "subestacao")
        tipos = [n["node_type"] for n in topologia["topology"]["nodes"]]
        self.assertEqual(tipos.count("ethernet_switch"), 5)
        for node in topologia["topology"]["nodes"]:
            self.assertEqual(node.get("custom_adapters"), [])

    def test_cli_com_flag_grava_gns3_e_inventario_lado_a_lado(self):
        with tempfile.TemporaryDirectory() as tmp:
            entrada, saida = os.path.join(tmp, "dados.json"), os.path.join(tmp, "p.gns3")
            with open(entrada, "w") as f:
                json.dump(IEDS, f)
            subprocess.run([sys.executable, os.path.join(PASTA_SCD, "gerar_topologia_gns3.py"),
                            entrada, "--out", saida, "--8021x"], check=True, capture_output=True)
            self.assertTrue(os.path.isfile(saida))
            self.assertTrue(os.path.isfile(os.path.join(tmp, "inventario.json")))


if __name__ == "__main__":
    unittest.main()
