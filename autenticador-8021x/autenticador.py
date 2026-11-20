#!/usr/bin/env python3
"""
autenticador.py — supervisor do switch autenticador IEEE 802.1X.

Sobe um hostapd por porta (uma configuração e um processo por porta: o
driver `wired` não aceita vários BSS no mesmo arquivo e o log de cada
processo identifica a porta sem ambiguidade), lê o log de depuração
deles em tempo real e, a cada autenticação EAP-TLS:

  - aceita  -> adiciona o par (porta, MAC) ao set `autorizados` do nftables;
  - rejeita -> não adiciona (ou remove) e derruba a sessão no hostapd;
  - sempre  -> registra uma linha JSON em --eventos.

Por que ler o log em vez de `hostapd_cli -a`: o subject do certificado
(necessário ao vínculo CN <-> MAC) só aparece no log; o ctrl_iface expõe
apenas a identidade EAP declarada pelo cliente. Consumir o evento e o
certificado do MESMO fluxo também elimina condição de corrida.

Uso (chamado por iniciar_autenticador.sh):
    autenticador.py --inventario inv.json --eventos eventos.jsonl \\
        --portas eth0 eth1 ... --hostapd-conf /run/8021x/hostapd-eth0.conf ...
"""
import argparse
import json
import signal
import subprocess
import sys
import threading

from autenticador_core import (ControladorAcesso, InterpretadorLogHostapd,
                               Inventario, RegistroJsonl)

TABELA_NFT = "acesso8021x"
INTERVALO_MONITOR_S = 1.0
HOSTAPD_CTRL_DIR = "/run/hostapd"


class FirewallNft:
    """Mantém os sets `autorizados` e `portas_autorizadas` via comando `nft`.

    `executar(args)` roda `nft <args>` e levanta CalledProcessError em falha
    (fail early: sem o set atualizado o acesso não pode ser concedido).
    """

    def __init__(self, executar, tabela=TABELA_NFT):
        self._executar = executar
        self._tabela = tabela
        self._pares = {}
        self._trava = threading.RLock()

    def autorizar(self, iface, mac):
        with self._trava:
            self._executar(["add", "element", "bridge", self._tabela, "autorizados",
                            f'{{ "{iface}" . {mac} }}'])
            self._executar(["add", "element", "bridge", self._tabela, "portas_autorizadas",
                            f'{{ "{iface}" }}'])
            self._pares.setdefault(iface, set()).add(mac)

    def revogar(self, iface, mac):
        """True se o par estava autorizado."""
        with self._trava:
            if mac not in self._pares.get(iface, ()):
                return False
            self._executar(["delete", "element", "bridge", self._tabela, "autorizados",
                            f'{{ "{iface}" . {mac} }}'])
            self._pares[iface].discard(mac)
            if not self._pares[iface]:
                self._executar(["delete", "element", "bridge", self._tabela,
                                "portas_autorizadas", f'{{ "{iface}" }}'])
            return True

    def revogar_porta(self, iface):
        """Revoga todos os pares da porta; devolve os MACs revogados."""
        with self._trava:
            macs = sorted(self._pares.get(iface, ()))
            for mac in macs:
                self.revogar(iface, mac)
            return macs


def executar_nft(args):
    subprocess.run(["nft", *args], check=True, capture_output=True, text=True)


def listar_descartes():
    """(iface, mac, pacotes) de cada elemento do set dinâmico `descartados`."""
    saida = subprocess.run(["nft", "-j", "list", "set", "bridge", TABELA_NFT, "descartados"],
                           check=True, capture_output=True, text=True).stdout
    elementos = []
    for item in json.loads(saida)["nftables"]:
        for elem in item.get("set", {}).get("elem", []):
            if "elem" in elem:
                iface, mac = elem["elem"]["val"]["concat"]
                elementos.append((iface, mac, elem["elem"].get("counter", {}).get("packets", 0)))
    return elementos


def desautenticar_no_hostapd(iface, mac):
    """Melhor esforço: o bloqueio real é o nftables; isto encerra a sessão EAP."""
    subprocess.run(["hostapd_cli", "-p", HOSTAPD_CTRL_DIR, "-i", iface, "deauthenticate", mac],
                   capture_output=True, text=True, check=False)


def portas_com_link(portas):
    """Mapa porta -> bool (carrier). Porta sem leitura possível conta como sem link."""
    def tem_carrier(iface):
        try:
            with open(f"/sys/class/net/{iface}/carrier", encoding="ascii") as f:
                return f.read().strip() == "1"
        except OSError:
            return False
    return {iface: tem_carrier(iface) for iface in portas}


def monitorar(controlador, portas, parar):
    """Vigia link das portas e descartes do firewall (thread auxiliar)."""
    anterior = portas_com_link(portas)
    while not parar.wait(INTERVALO_MONITOR_S):
        atual = portas_com_link(portas)
        for iface in portas:
            if anterior[iface] and not atual[iface]:
                controlador.porta_caiu(iface)
        anterior = atual
        try:
            controlador.reportar_descartes(listar_descartes())
        except (subprocess.CalledProcessError, ValueError, KeyError) as erro:
            print(f"[autenticador] aviso: leitura de descartes falhou: {erro}", file=sys.stderr)


def iniciar_hostapd(arquivo_conf):
    return subprocess.Popen(["hostapd", "-d", arquivo_conf], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)


def consumir_log(iface, processo, controlador, log_bruto, trava_log, parar):
    """Lê o log de UM hostapd (uma porta) com um interpretador próprio.

    Um processo por porta torna a porta de cada evento inequívoca: o log de
    TLS (`peer certificate`) não traz a interface, e com um único processo
    dois MACs iguais em portas distintas (clonagem) podiam ter o certificado
    de um atribuído ao outro.
    """
    interpretador = InterpretadorLogHostapd()
    for linha in processo.stdout:
        if log_bruto:
            with trava_log:
                log_bruto.write(f"[{iface}] {linha}")
        for evento in interpretador.processar(linha):
            try:
                controlador.tratar(evento)
            except Exception as erro:  # noqa: BLE001 - uma falha não pode parar a leitura (o hostapd travaria no pipe)
                print(f"[autenticador] ERRO ao tratar {evento}: {erro}", file=sys.stderr)
    if not parar.is_set():   # morreu sozinho (não por encerramento): ninguém segue autorizado na porta
        controlador.porta_caiu(iface)


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inventario", required=True)
    ap.add_argument("--eventos", required=True, help="arquivo .jsonl de eventos")
    ap.add_argument("--portas", nargs="+", required=True)
    ap.add_argument("--hostapd-conf", nargs="+", required=True)
    ap.add_argument("--log-hostapd", help="grava o log bruto do hostapd (depuração)")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    registro = RegistroJsonl.em_arquivo(args.eventos)
    controlador = ControladorAcesso(Inventario.de_arquivo(args.inventario),
                                    FirewallNft(executar_nft), registro,
                                    desautenticar_no_hostapd)
    log_bruto = open(args.log_hostapd, "a", encoding="utf-8", buffering=1) if args.log_hostapd else None
    if len(args.portas) != len(args.hostapd_conf):
        sys.exit("--portas e --hostapd-conf devem ter o mesmo número de itens")
    processos = {iface: iniciar_hostapd(conf) for iface, conf in zip(args.portas, args.hostapd_conf)}
    parar = threading.Event()
    threading.Thread(target=monitorar, args=(controlador, args.portas, parar), daemon=True).start()

    def encerrar(*_):
        parar.set()
        for processo in processos.values():
            processo.terminate()
    signal.signal(signal.SIGTERM, encerrar)
    signal.signal(signal.SIGINT, encerrar)

    registro.emitir("autenticador_iniciado", portas=",".join(args.portas),
                    pid_hostapd=",".join(str(p.pid) for p in processos.values()))
    trava_log = threading.Lock()
    leitores = [threading.Thread(target=consumir_log, args=(iface, processo, controlador, log_bruto, trava_log, parar))
                for iface, processo in processos.items()]
    for leitor in leitores:
        leitor.start()
    for leitor in leitores:
        leitor.join()
    parar.set()
    codigos = [processo.wait() for processo in processos.values()]
    registro.emitir("autenticador_encerrado", codigo_hostapd=",".join(str(c) for c in codigos))
    return 0 if all(c in (0, -signal.SIGTERM) for c in codigos) else 1


if __name__ == "__main__":
    sys.exit(main())
