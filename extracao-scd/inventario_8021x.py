#!/usr/bin/env python3
"""
inventario_8021x.py — inventário de identidades para o autenticador 802.1X.

Vincula o CN do certificado de cada dispositivo (= nome do nó no GNS3)
aos MACs que ele pode usar: um certificado válido apresentado por um MAC
diferente do cadastrado é rejeitado pelo autenticador (ver
autenticador-8021x/README.md). Parte dos dados vem do SCD (saída de
extrair_scd.py); o resto são os nós fixos do laboratório.

Esquema de MACs: administrados localmente (bit 0x02) com os 4 octetos do
IP ao final — `02:00:<IP em hexa>`. É o mesmo endereço que o
gerar_topologia_gns3.py grava em `custom_adapters` dos nós; o IP segue a
regra dos entrypoints (ubuntu-ied-N -> 192.168.10.1N).

Uso:
    python3 inventario_8021x.py dados.json --out inventario.json
"""
import argparse
import json
import sys

PREFIXO_REDE = "192.168.10."
IP_ORACULO, IP_IDS, IP_ATACANTE, IP_PUBLICADOR = (
    f"{PREFIXO_REDE}{n}" for n in (20, 30, 40, 50))
# MAC de origem do GOOSE em atacante/samples/molde.pcap (relé SEL-351):
# o publicador legítimo o usa para que o IDS veja o mesmo emissor do baseline.
MAC_ORIGEM_GOOSE_MOLDE = "00:30:a7:01:b3:16"
# O atacante é um nó invadido com um certificado legítimo (cenário de limite).
CN_ATACANTE_COMPROMETIDO = "atacante-comprometido"


def mac_do_ip(ip):
    """MAC administrado localmente derivado do IPv4 (`02:00:` + octetos)."""
    octetos = [int(o) for o in ip.split(".")]
    if len(octetos) != 4 or not all(0 <= o <= 255 for o in octetos):
        raise ValueError(f"IPv4 inválido: {ip!r}")
    return "02:00:" + ":".join(f"{o:02x}" for o in octetos)


def ip_do_ied(numero):
    """Mesma regra de ubuntu-ied/entrypoint.sh: hostname ...-N -> 192.168.10.1N."""
    octeto = int(f"1{numero}")
    if octeto > 254:
        raise ValueError(f"ubuntu-ied-{numero}: IP fora da faixa (.{octeto})")
    return f"{PREFIXO_REDE}{octeto}"


def _entrada(ip, macs=None, **extras):
    return {"ip": ip, "macs": macs or [mac_do_ip(ip)], **extras}


def construir_inventario(ieds, mac_publicador=MAC_ORIGEM_GOOSE_MOLDE):
    """`ieds`: lista de dicts de extrair_scd.py. Devolve o dict do inventário."""
    dispositivos = {}
    for indice, ied in enumerate(ieds, start=1):
        dispositivos[f"ubuntu-ied-{indice}"] = _entrada(ip_do_ied(indice), ied=ied["name"])
    dispositivos["oraculo-1"] = _entrada(IP_ORACULO)
    dispositivos["ids-1"] = _entrada(IP_IDS)
    dispositivos["publicador-1"] = _entrada(IP_PUBLICADOR, macs=[mac_publicador.lower()])
    dispositivos[CN_ATACANTE_COMPROMETIDO] = _entrada(IP_ATACANTE)
    return {"versao": 1, "dispositivos": dispositivos}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json_file", help="saída de extrair_scd.py (--json)")
    ap.add_argument("--out", required=True, help="inventario.json a gerar")
    ap.add_argument("--mac-publicador", default=MAC_ORIGEM_GOOSE_MOLDE,
                    help="MAC do nó publicador-1 (padrão: origem do molde.pcap)")
    args = ap.parse_args(argv)
    try:
        with open(args.json_file, encoding="utf-8") as f:
            ieds = json.load(f)
    except (OSError, json.JSONDecodeError) as erro:
        print(f"[!] Não foi possível ler {args.json_file}: {erro}")
        return 1
    if not ieds:
        print("[!] Nenhum IED no JSON de entrada — rode extrair_scd.py primeiro.")
        return 1
    inventario = construir_inventario(ieds, args.mac_publicador)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(inventario, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"[+] Inventário com {len(inventario['dispositivos'])} dispositivos em {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
