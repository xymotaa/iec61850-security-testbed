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

Variante IEEE 802.1X (EAP-TLS): `--8021x` troca o switch central e os de
borda por UM nó `autenticador-8021x` (hostapd + nftables; ver
autenticador-8021x/README.md), com todos os dispositivos ligados direto
nele — os switches nativos do GNS3 podem inundar EAPOL, então a variante
não usa Switch1..4. Também grava o `inventario.json` (CN do certificado ->
MAC) ao lado do .gns3:
    python3 gerar_topologia_gns3.py dados.json --out subestacao_8021x.gns3 --8021x

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
import os
import sys
import uuid

import inventario_8021x


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
        "x": int(round(x)), "y": int(round(y)), "z": 1,
    }


def _make_docker_node(name, image, x, y, start_command=None, environment=None,
                      adapters=1, extra_volumes=None, mac_address=None):
    """Nó Docker genérico (mesmo tipo usado para ubuntu-ied, oraculo,
    atacante, ids — já registrados como templates no GNS3, ver
    atacante/README.md)."""
    node_id = _uuid()
    properties = {
        "image": image,
        "adapters": adapters,
        "start_command": start_command or "",
        "environment": environment or "",
        "console_type": "telnet",
        "console_auto_start": False,
        "console_resolution": "1024x768",
        "console_http_port": 80,
        "console_http_path": "/",
        "extra_hosts": "",
        "extra_volumes": extra_volumes or [],
        "usage": "",
    }
    return {
        "compute_id": "local",
        "console": None,
        "console_type": "telnet",
        "custom_adapters": ([{"adapter_number": 0, "mac_address": mac_address}]
                            if mac_address else []),
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
        "x": int(round(x)), "y": int(round(y)), "z": 1,
    }


def _make_link(node_a_id, port_a, node_b_id, port_b, adapter_a=0, adapter_b=0):
    return {
        "link_id": _uuid(),
        "link_style": {},
        "suspend": False,
        "filters": {},
        "nodes": [
            {"adapter_number": adapter_a, "port_number": port_a, "node_id": node_a_id, "label": {
                "text": "", "x": 0, "y": 0, "rotation": 0}},
            {"adapter_number": adapter_b, "port_number": port_b, "node_id": node_b_id, "label": {
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
        # O nome do nó precisa terminar em número e seguir o padrão
        # "ubuntu-ied-N": é dele que o entrypoint.sh de ubuntu-ied
        # deriva o IP (hostname "ubuntu-ied-3" -> 192.168.10.13), e
        # ele ignora as variáveis de ambiente IED_NAME/IED_IP abaixo
        # (mantidas só como metadado/documentação do nó, não são lidas
        # pelo container). Ver ubuntu-ied/entrypoint.sh.
        node_name = f"ubuntu-ied-{idx + 1}"
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

    return _wrap_topology(project_name, nodes, links)


def _wrap_topology(project_name, nodes, links):
    """Envelope de projeto GNS3 (revisão 9) comum às duas topologias."""
    return {
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


# --- Variante IEEE 802.1X -------------------------------------------------

AUTENTICADOR_NAME = "autenticador-8021x"
CERT_VOLUME = "/etc/8021x"          # certificados + inventário (copiados por pki/instalar_no_gns3.py)
LOG_VOLUME = "/var/log/8021x"       # eventos.jsonl do autenticador (evidência)
PUBLICADOR_NAME = "publicador-1"
ATACANTE_NAME = "atacante-1"
HOST_X_SPACING = 160


def _row_x(index, count):
    """x inteiro de `index` numa fileira de `count` nós centrada em CENTER_X."""
    return int(round(CENTER_X + (index - (count - 1) / 2) * HOST_X_SPACING))


def _device_specs_8021x(ieds, inventory):
    """(nome, imagem-chave, linha, ambiente) de cada dispositivo, na ordem das
    portas do autenticador: IEDs, oráculo, IDS, publicador, atacante."""
    macs = {nome: info["macs"][0] for nome, info in inventory["dispositivos"].items()}
    macs[ATACANTE_NAME] = macs[inventario_8021x.CN_ATACANTE_COMPROMETIDO]
    specs = []
    for idx, ied in enumerate(ieds, start=1):
        specs.append((f"ubuntu-ied-{idx}", "ied", "top",
                      f"AUTH_8021X=1\nIED_NAME={ied['name']}"))
    specs += [
        ("oraculo-1", "oraculo", "bottom", "AUTH_8021X=1"),
        ("ids-1", "ids", "bottom", "AUTH_8021X=1"),
        (PUBLICADOR_NAME, "atacante", "bottom",
         f"AUTH_8021X=1\nATACANTE_IP={inventario_8021x.IP_PUBLICADOR}"),
        # O atacante liga o supplicant à mão em cada cenário (AUTH_8021X=0).
        (ATACANTE_NAME, "atacante", "bottom", "AUTH_8021X=0"),
    ]
    return [(nome, chave, linha, env, macs[nome]) for nome, chave, linha, env in specs]


def build_topology_8021x(ieds, project_name, inventory,
                         ied_image="ubuntu-ied:latest",
                         oraculo_image="oraculo:latest",
                         atacante_image="atacante:latest",
                         ids_image="ids:latest",
                         autenticador_image="autenticador-8021x:latest"):
    """Estrela de UM nível: `autenticador-8021x` no centro, cada dispositivo
    ligado direto a um adaptador dele (sem switches nativos)."""
    images = {"ied": ied_image, "oraculo": oraculo_image,
              "atacante": atacante_image, "ids": ids_image}
    devices = _device_specs_8021x(ieds, inventory)
    row_size = {"top": sum(1 for d in devices if d[2] == "top"),
                "bottom": sum(1 for d in devices if d[2] == "bottom")}
    row_filled = {"top": 0, "bottom": 0}

    autenticador = _make_docker_node(
        AUTENTICADOR_NAME, autenticador_image, CENTER_X, SWITCH_Y,
        environment=(f"AUTENTICADOR_MODO=8021x\nAUTENTICADOR_PORTAS={len(devices)}"),
        adapters=len(devices), extra_volumes=[CERT_VOLUME, LOG_VOLUME])
    nodes, links = [autenticador], []

    for adapter, (nome, chave, linha, env, mac) in enumerate(devices):
        x = _row_x(row_filled[linha], row_size[linha])
        row_filled[linha] += 1
        y = HOST_Y_TOP if linha == "top" else HOST_Y_BOTTOM
        node = _make_docker_node(nome, images[chave], x, y, environment=env,
                                 extra_volumes=[CERT_VOLUME], mac_address=mac)
        nodes.append(node)
        links.append(_make_link(autenticador["node_id"], 0, node["node_id"], 0,
                                adapter_a=adapter, adapter_b=0))
    return _wrap_topology(project_name, nodes, links)


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
    ap.add_argument("--8021x", dest="com_8021x", action="store_true",
                     help="variante IEEE 802.1X: nó autenticador-8021x no lugar dos switches")
    ap.add_argument("--autenticador-image", default="autenticador-8021x:latest")
    ap.add_argument("--inventario-out", default=None,
                     help="com --8021x: onde gravar o inventario.json "
                          "(padrão: ao lado do .gns3)")
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
    images = dict(ied_image=args.ied_image, oraculo_image=args.oraculo_image,
                  atacante_image=args.atacante_image, ids_image=args.ids_image)
    if args.com_8021x:
        inventory = inventario_8021x.construir_inventario(ieds)
        topology = build_topology_8021x(ieds, project_name, inventory,
                                        autenticador_image=args.autenticador_image, **images)
    else:
        topology = build_topology(ieds, project_name, **images)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(topology, f, indent=2, ensure_ascii=False)

    n_nodes = len(topology["topology"]["nodes"])
    n_links = len(topology["topology"]["links"])
    print(f"[+] Projeto '{project_name}' gerado em {args.out}")
    if args.com_8021x:
        inventory_path = args.inventario_out or os.path.join(
            os.path.dirname(os.path.abspath(args.out)), "inventario.json")
        with open(inventory_path, "w", encoding="utf-8") as f:
            json.dump(inventory, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"    {len(ieds)} IED(s) + oraculo-1 + ids-1 + publicador-1 + atacante-1 "
              f"+ autenticador-8021x = {n_nodes} nós, {n_links} links (sem switches)")
        print(f"[+] Inventário (CN -> MAC) em {inventory_path}")
        print("[!] Próximo passo: pki/gerar_pki.sh e pki/instalar_no_gns3.py "
              "(ver autenticador-8021x/README.md).")
    else:
        print(f"    {len(ieds)} IED(s) + oraculo-1 + ids-1 + atacante-1 "
              f"+ 5 switches = {n_nodes} nós, {n_links} links")
    print("[!] Templates Docker (ubuntu-ied, oraculo, atacante, ids"
          f"{', autenticador-8021x' if args.com_8021x else ''}) "
          "precisam já estar registrados no GNS3 antes de abrir o "
          "projeto — ver atacante/README.md.")


if __name__ == "__main__":
    main()
