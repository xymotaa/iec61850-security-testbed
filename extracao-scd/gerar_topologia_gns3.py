#!/usr/bin/env python3
"""
gerar_topologia_gns3.py — Gera automaticamente um arquivo de projeto
.gns3 a partir dos dados extraídos de um SCD (saída de extrair_scd.py),
fechando o elo que faltava com o fluxograma do artigo original
(Script de Extração -> Script de Modelagem -> GNS3, Fig. 1 do artigo):
até aqui a topologia era montada manualmente no GNS3.

Reproduz, em código, a topologia que o projeto já usa manualmente
(README.md): 4 switches em estrela (sem malha, pra não gerar loop —
o switch nativo do GNS3 não roda Spanning Tree) + 1 nó Docker por IED
extraído do SCD + oraculo-1 + ids-1 + atacante-1, todos no switch
central (GOOSE é multicast de Camada 2, não é roteável — precisa estar
no mesmo domínio de broadcast).

Uso:
    # 1) extrair os dados do SCD (já existente)
    python3 extrair_scd.py exemplo_subestacao.scd --json dados.json

    # 2) gerar o projeto .gns3 a partir desse JSON
    python3 gerar_topologia_gns3.py dados.json --out subestacao.gns3

    # opcional: customizar nomes dos templates Docker já registrados
    # no GNS3 (ver atacante/README.md) se não usar os nomes padrão
    python3 gerar_topologia_gns3.py dados.json --out subestacao.gns3 \\
        --ied-image ubuntu-ied:latest --oraculo-image oraculo:latest \\
        --atacante-image atacante:latest --ids-image ids:latest

O arquivo gerado pode ser aberto diretamente no GNS3 (File > Open
Project) ou copiado para a pasta de projetos do GNS3
(~/GNS3/projects/<nome>/<nome>.gns3) antes de abrir.

Limitações assumidas (documentadas em docs/changelog/README.md):
- Usa `appliance_id`/`node_id` gerados localmente (uuid4); o GNS3 os
  aceita como identificadores de projeto, mas os templates Docker
  (ubuntu-ied, oraculo, atacante, ids) ainda precisam estar registrados
  no GNS3 antes de abrir o projeto (mesmo processo manual descrito em
  atacante/README.md) — este script não registra templates, só monta
  a topologia que os referencia pelo nome da imagem Docker.
- As posições dos nós no canvas são calculadas por um layout simples
  (estrela/grade); ajustar visualmente depois de abrir é normal.
"""
import argparse
import json
import math
import sys
import uuid


GNS3_VERSION = "2.2.0"

# Posições de referência (coordenadas do canvas GNS3, em pixels).
SWITCH_Y = -150
HOST_Y_TOP = -350
HOST_Y_BOTTOM = 150
CENTER_X = 0
X_SPACING = 200


def _uuid():
    return str(uuid.uuid4())


def _make_switch_node(name, x, y):
    """Nó 'ethernet_switch' nativo do GNS3 (sem Spanning Tree — por
    isso a topologia é em estrela, nunca em malha, ver README.md)."""
    node_id = _uuid()
    return {
        "compute_id": "local",
        "console": None,
        "console_type": None,
        "custom_adapters": [],
        "first_port_name": None,
        "height": 32,
        "label": {
            "text": name, "style": "font-size: 10; font-family: Verdana",
            "x": None, "y": -20, "rotation": 0,
        },
        "locked": False,
        "name": name,
        "node_id": node_id,
        "node_type": "ethernet_switch",
        "port_name_format": "Ethernet{0}",
        "port_segment_size": 0,
        "properties": {"ports_mapping": [
            {"name": f"Ethernet{i}", "port_number": i, "type": "access", "vlan": 1}
            for i in range(8)
        ]},
        "symbol": ":/symbols/ethernet_switch.svg",
        "width": 72,
        "x": x, "y": y, "z": 1,
    }


def _make_docker_node(name, image, x, y, start_command=None, environment=None):
    """Nó Docker genérico (mesmo tipo usado para ubuntu-ied, oraculo,
    atacante, ids — já registrados como templates no GNS3, ver
    atacante/README.md)."""
    node_id = _uuid()
    properties = {
        "image": image,
        "adapters": 1,
        "start_command": start_command or "",
        "environment": environment or "",
        "console_type": "telnet",
        "console_auto_start": False,
        "console_resolution": "1024x768",
        "console_http_port": 80,
        "console_http_path": "/",
        "extra_hosts": "",
        "extra_volumes": [],
        "usage": "",
    }
    return {
        "compute_id": "local",
        "console": None,
        "console_type": "telnet",
        "custom_adapters": [],
        "first_port_name": None,
        "height": 45,
        "label": {
            "text": name, "style": "font-size: 10; font-family: Verdana",
            "x": None, "y": -25, "rotation": 0,
        },
        "locked": False,
        "name": name,
        "node_id": node_id,
        "node_type": "docker",
        "port_name_format": "eth{0}",
        "port_segment_size": 0,
        "properties": properties,
        "symbol": ":/symbols/docker_guest.svg",
        "width": 45,
        "x": x, "y": y, "z": 1,
    }


def _make_link(node_a_id, port_a, node_b_id, port_b):
    return {
        "link_id": _uuid(),
        "link_style": {},
        "suspend": False,
        "filters": {},
        "nodes": [
            {"adapter_number": 0, "port_number": port_a, "node_id": node_a_id, "label": {
                "text": "", "x": 0, "y": 0, "rotation": 0}},
            {"adapter_number": 0, "port_number": port_b, "node_id": node_b_id, "label": {
                "text": "", "x": 0, "y": 0, "rotation": 0}},
        ],
    }


def build_topology(ieds, project_name,
                    ied_image="ubuntu-ied:latest",
                    oraculo_image="oraculo:latest",
                    atacante_image="atacante:latest",
                    ids_image="ids:latest"):
    """Monta nós e links reproduzindo a topologia descrita no
    README.md: 4 switches em estrela ligados por um switch central,
    com os IEDs distribuídos entre os switches de borda e
    oraculo-1/ids-1/atacante-1 direto no switch central (precisam
    enxergar todo o tráfego GOOSE multicast)."""
    nodes = []
    links = []

    # Switch central + switches de borda, em estrela (sem malha).
    switch_central = _make_switch_node("Switch-Central", CENTER_X, SWITCH_Y)
    nodes.append(switch_central)

    n_edge_switches = 4
    edge_switches = []
    edge_x_start = CENTER_X - (n_edge_switches - 1) * X_SPACING * 1.5 / 2
    for i in range(n_edge_switches):
        x = edge_x_start + i * X_SPACING * 1.5
        sw = _make_switch_node(f"Switch-{i + 1}", x, HOST_Y_TOP + 100)
        edge_switches.append(sw)
        nodes.append(sw)
        links.append(_make_link(switch_central["node_id"], i,
                                 sw["node_id"], 0))

    # Um nó ubuntu-ied por IED extraído do SCD, distribuído round-robin
    # entre os switches de borda.
    ied_nodes = []
    for idx, ied in enumerate(ieds):
        sw = edge_switches[idx % n_edge_switches]
        slot = idx // n_edge_switches
        x = sw["x"] - 80 + (slot % 2) * 160
        y = HOST_Y_TOP - 80 - (slot // 2) * 120
        node_name = f"ied-{ied['name']}"
        node = _make_docker_node(
            node_name, ied_image, x, y,
            environment=(f"IED_NAME={ied['name']}\n"
                         f"IED_IP={ied.get('ip') or ''}\n"
                         f"IED_SUBNET={ied.get('subnet') or ''}"),
        )
        ied_nodes.append(node)
        nodes.append(node)
        # porta 1 em diante no switch de borda (porta 0 é o uplink pro
        # switch central)
        port = 1 + sum(1 for n in ied_nodes if n is not node and
                        _node_switch(n, edge_switches, ieds) is sw)
        links.append(_make_link(sw["node_id"], port, node["node_id"], 0))

    # oraculo-1, ids-1 e atacante-1 direto no switch central (GOOSE é
    # multicast L2 — precisam estar no mesmo domínio de broadcast que
    # os IEDs pra enxergar/testar tudo).
    central_extra = []
    oraculo = _make_docker_node("oraculo-1", oraculo_image,
                                 CENTER_X - 160, HOST_Y_BOTTOM)
    ids_node = _make_docker_node("ids-1", ids_image,
                                  CENTER_X, HOST_Y_BOTTOM)
    atacante = _make_docker_node("atacante-1", atacante_image,
                                  CENTER_X + 160, HOST_Y_BOTTOM)
    for i, node in enumerate((oraculo, ids_node, atacante)):
        central_extra.append(node)
        nodes.append(node)
        links.append(_make_link(switch_central["node_id"],
                                 n_edge_switches + i, node["node_id"], 0))

    topology = {
        "project_id": _uuid(),
        "revision": 9,
        "version": GNS3_VERSION,
        "type": "topology",
        "name": project_name,
        "auto_start": False,
        "auto_open": False,
        "auto_close": True,
        "scene_height": 1000,
        "scene_width": 2000,
        "topology": {
            "computes": [],
            "drawings": [],
            "links": links,
            "nodes": nodes,
        },
    }
    return topology


def _node_switch(node, edge_switches, ieds):
    # helper só pra lógica de contagem de porta acima; não guarda
    # estado real, recalcula pela posição x mais próxima.
    return min(edge_switches, key=lambda sw: abs(sw["x"] - node["x"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json_file", help="saída de extrair_scd.py (--json)")
    ap.add_argument("--out", required=True, help="caminho do .gns3 a gerar")
    ap.add_argument("--project-name", default=None,
                     help="nome do projeto (padrão: nome do arquivo de saída)")
    ap.add_argument("--ied-image", default="ubuntu-ied:latest")
    ap.add_argument("--oraculo-image", default="oraculo:latest")
    ap.add_argument("--atacante-image", default="atacante:latest")
    ap.add_argument("--ids-image", default="ids:latest")
    args = ap.parse_args()

    try:
        with open(args.json_file, encoding="utf-8") as f:
            ieds = json.load(f)
    except FileNotFoundError:
        print(f"[!] Arquivo não encontrado: {args.json_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] JSON inválido em {args.json_file}: {e}")
        sys.exit(1)

    if not ieds:
        print("[!] Nenhum IED no JSON de entrada — rode extrair_scd.py "
              "primeiro (ver extracao-scd/README.md).")
        sys.exit(1)

    project_name = args.project_name or args.out.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    topology = build_topology(
        ieds, project_name,
        ied_image=args.ied_image, oraculo_image=args.oraculo_image,
        atacante_image=args.atacante_image, ids_image=args.ids_image,
    )

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(topology, f, indent=2, ensure_ascii=False)

    n_nodes = len(topology["topology"]["nodes"])
    n_links = len(topology["topology"]["links"])
    print(f"[+] Projeto '{project_name}' gerado em {args.out}")
    print(f"    {len(ieds)} IED(s) + oraculo-1 + ids-1 + atacante-1 "
          f"+ 5 switches = {n_nodes} nós, {n_links} links")
    print("[!] Templates Docker (ubuntu-ied, oraculo, atacante, ids) "
          "precisam já estar registrados no GNS3 antes de abrir o "
          "projeto — ver atacante/README.md.")


if __name__ == "__main__":
    main()
