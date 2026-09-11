#!/usr/bin/env python3
"""
extrair_scd.py — Extrai dados de IEDs e blocos de controle GOOSE/SV de um
arquivo SCD (IEC 61850 SCL), reproduzindo e estendendo o que o script do
artigo original fazia (que extraía só IP, máscara e nome do IED).

Novidade em relação ao original: também extrai os blocos GOOSE
(GoCBRef, dataset, MAC de destino, APPID, VLAN) e SV (SmvID, MAC, APPID),
necessários para o atacante/ e o ids/ deste projeto.

Uso:
    python3 extrair_scd.py caminho/para/subestacao.scd
    python3 extrair_scd.py caminho/para/subestacao.scd --json saida.json
"""
import argparse
import json
import xml.etree.ElementTree as ET


def strip_ns(tree):
    """Remove o namespace de todas as tags (arquivos SCL usam um
    namespace default, ex: '{http://www.iec.ch/61850/2003/SCL}IED'),
    pra poder usar nomes simples ('IED') em todo find/findall sem
    precisar registrar/gerenciar namespace o tempo todo."""
    for elem in tree.iter():
        if "}" in elem.tag:
            elem.tag = elem.tag.split("}", 1)[1]
    return tree


def _read_address_params(address_el):
    """Lê os <P type="..."> dentro de um <Address>, retornando os campos
    que interessam pra GOOSE/SV (o que não existir fica None)."""
    result = {"mac_address": None, "appid": None,
              "vlan_id": None, "vlan_priority": None}
    if address_el is None:
        return result
    tipo_para_chave = {
        "MAC-Address": "mac_address",
        "APPID": "appid",
        "VLAN-ID": "vlan_id",
        "VLAN-PRIORITY": "vlan_priority",
    }
    for p in address_el.findall("P"):
        chave = tipo_para_chave.get(p.get("type"))
        if chave:
            result[chave] = p.text
    return result


def parse_scd(path):
    """Retorna uma lista de dicts, um por IED, com IP/máscara e os
    blocos de controle GOOSE/SV já com endereçamento resolvido."""
    tree = ET.parse(path)
    root = strip_ns(tree.getroot())

    ieds = {}

    # 1) Para cada IED: nome + blocos GOOSE/SV declarados (sem endereço
    #    ainda -- o endereço mora numa seção separada, Communication).
    for ied_el in root.findall("IED"):
        ied_name = ied_el.get("name")
        ieds[ied_name] = {
            "name": ied_name,
            "ip": None,
            "subnet": None,
            "goose_control_blocks": [],
            "sv_control_blocks": [],
        }
        for ldevice in ied_el.iter("LDevice"):
            ld_inst = ldevice.get("inst")
            for ln0 in ldevice.findall("LN0"):
                for gse in ln0.findall("GSEControl"):
                    ieds[ied_name]["goose_control_blocks"].append({
                        "ld_inst": ld_inst,
                        "cb_name": gse.get("name"),
                        "dat_set": gse.get("datSet"),
                        "gocb_ref": f"{ied_name}{ld_inst}/LLN0$GO${gse.get('name')}",
                        "mac_address": None, "appid": None,
                        "vlan_id": None, "vlan_priority": None,
                    })
                for smv in ln0.findall("SampledValueControl"):
                    ieds[ied_name]["sv_control_blocks"].append({
                        "ld_inst": ld_inst,
                        "cb_name": smv.get("name"),
                        "dat_set": smv.get("datSet"),
                        "smv_id": smv.get("smvID"),
                        "mac_address": None, "appid": None,
                        "vlan_id": None, "vlan_priority": None,
                    })

    # 2) Seção Communication: resolve IP/máscara do IED e o endereçamento
    #    (MAC/APPID/VLAN) de cada bloco GOOSE/SV, casando por ldInst+cbName.
    for connected_ap in root.iter("ConnectedAP"):
        ied_name = connected_ap.get("iedName")
        if ied_name not in ieds:
            continue

        address = connected_ap.find("Address")
        if address is not None:
            for p in address.findall("P"):
                if p.get("type") == "IP":
                    ieds[ied_name]["ip"] = p.text
                elif p.get("type") == "IP-SUBNET":
                    ieds[ied_name]["subnet"] = p.text

        for gse in connected_ap.findall("GSE"):
            endereco = _read_address_params(gse.find("Address"))
            for cb in ieds[ied_name]["goose_control_blocks"]:
                if cb["ld_inst"] == gse.get("ldInst") and cb["cb_name"] == gse.get("cbName"):
                    cb.update(endereco)

        for smv in connected_ap.findall("SMV"):
            endereco = _read_address_params(smv.find("Address"))
            for cb in ieds[ied_name]["sv_control_blocks"]:
                if cb["ld_inst"] == smv.get("ldInst") and cb["cb_name"] == smv.get("cbName"):
                    cb.update(endereco)

    return list(ieds.values())


def print_summary(ieds):
    for ied in ieds:
        print(f"\nIED: {ied['name']}")
        print(f"  IP: {ied['ip']}   Máscara: {ied['subnet']}")
        for cb in ied["goose_control_blocks"]:
            print(f"  GOOSE  gocbRef={cb['gocb_ref']}")
            print(f"         datSet={cb['dat_set']}  MAC={cb['mac_address']}  "
                  f"APPID={cb['appid']}  VLAN={cb['vlan_id']}/{cb['vlan_priority']}")
        for cb in ied["sv_control_blocks"]:
            print(f"  SV     smvID={cb['smv_id']}")
            print(f"         datSet={cb['dat_set']}  MAC={cb['mac_address']}  "
                  f"APPID={cb['appid']}  VLAN={cb['vlan_id']}/{cb['vlan_priority']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scd_file")
    ap.add_argument("--json", help="salva a saída também em um arquivo JSON")
    args = ap.parse_args()

    try:
        ieds = parse_scd(args.scd_file)
    except FileNotFoundError:
        print(f"[!] Arquivo não encontrado: {args.scd_file}")
        raise SystemExit(1)
    except ET.ParseError as e:
        print(f"[!] XML inválido em {args.scd_file}: {e}")
        raise SystemExit(1)

    if not ieds:
        print("[!] Nenhum <IED> encontrado neste arquivo — confirme se é um SCD/ICD válido.")
        raise SystemExit(1)

    print_summary(ieds)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(ieds, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Dados salvos em {args.json}")


if __name__ == "__main__":
    main()
