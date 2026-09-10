#!/usr/bin/env python3
"""
ids.py — IDS para GOOSE (detecta os Testes A–D da metodologia: flooding,
replay, masquerade, suppression), usando o núcleo de detecção em
ids_core.py e o parser validado em goose_frame.py.

Uso típico dentro do container `ids-1` no GNS3 (mesma sub-rede dos IEDs):

    sudo python3 ids.py --iface eth0
    sudo python3 ids.py --iface eth0 --log alertas.jsonl

Requer privilégio de root (raw socket).
"""
import argparse
import json
import time

from scapy.all import sniff

import goose_frame as gf
from ids_core import GooseMonitor


def make_handler(monitor, log_fh):
    def handle(pkt):
        raw = bytes(pkt)
        try:
            parsed = gf.parse_ethernet_goose(raw)
        except Exception:
            return  # não é GOOSE válido ou frame malformado — ignora

        fields = parsed["fields"]
        alerts = monitor.process(
            gocb_ref=fields.get("gocbRef", ""),
            src_mac=parsed["src_mac"],
            st_num=fields.get("stNum", 0),
            sq_num=fields.get("sqNum", 0),
            timestamp=time.time(),
        )
        for alert in alerts:
            emit(alert, log_fh)
    return handle


def emit(alert, log_fh):
    record = {"ts": time.time(), **alert}
    print(f"[ALERTA] {alert['type'].upper():<12} "
          f"{alert['gocb_ref']}: {alert['detail']}")
    if log_fh:
        log_fh.write(json.dumps(record) + "\n")
        log_fh.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--log", help="arquivo .jsonl pra gravar os alertas (opcional)")
    ap.add_argument("--flood-pps", type=float, default=20)
    ap.add_argument("--suppression-jump", type=int, default=50)
    args = ap.parse_args()

    monitor = GooseMonitor(flood_pps_threshold=args.flood_pps,
                            suppression_jump=args.suppression_jump)
    log_fh = open(args.log, "a") if args.log else None
    handler = make_handler(monitor, log_fh)

    print(f"[*] Monitorando GOOSE em {args.iface}... (Ctrl+C para parar)")
    try:
        while True:
            # sniff por até 1s de cada vez; entre uma rodada e outra, dá um
            # "tick" pro monitor — é isso que detecta o FIM de um flood
            # mesmo quando nenhum pacote novo chega depois do ataque parar.
            sniff(iface=args.iface, prn=handler, store=False, timeout=1,
                  lfilter=lambda p: bytes(p)[12:14] == b"\x88\xb8")
            for alert in monitor.tick(time.time()):
                emit(alert, log_fh)
    except KeyboardInterrupt:
        print("\n[*] Encerrando.")


if __name__ == "__main__":
    main()
