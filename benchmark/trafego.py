"""
trafego.py — gera tráfego GOOSE (legítimo e de ataque) para a campanha
offline, SEM rede nem GNS3.

Todos os frames são bytes Ethernet reais, montados por `goose_frame`
(o mesmo módulo usado por atacante/ e ids/) a partir do molde
`atacante/samples/molde.pcap`. O tempo é virtual: cada item carrega só o
intervalo (`gap_s`) até o frame anterior, e quem reproduz o tráfego
decide os timestamps (ver `benchmark_ids.reproduzir`).

O conteúdo dos frames é determinístico para um mesmo (modo, parâmetros);
por isso os geradores públicos são memoizados — só o tempo varia entre
as repetições da campanha.
"""
import sys
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parents[1]
# O benchmark exercita as cópias de produção dos módulos, sem duplicá-las.
sys.path.insert(0, str(RAIZ_DO_REPOSITORIO / "ids"))

from scapy.all import rdpcap  # noqa: E402

import goose_frame as gf  # noqa: E402
from goose_auth import GooseAuthenticator  # noqa: E402

MOLDE_PCAP = RAIZ_DO_REPOSITORIO / "atacante" / "samples" / "molde.pcap"

# Modos de autenticação da campanha
SEM_HMAC = "sem_hmac"                  # IDS atual, nenhum frame autenticado
HMAC = "hmac"                          # IED assina, IDS verifica; atacante SEM a chave
HMAC_CHAVE_VAZADA = "hmac_chave_vazada"  # idem, mas o atacante TEM a chave
MODOS = (SEM_HMAC, HMAC, HMAC_CHAVE_VAZADA)

MAC_ATACANTE = "02:00:00:00:00:66"     # MAC próprio do atacante ingênuo (C2)
INSTANTE_INICIAL = 1_700_000_000.0     # época arbitrária do relógio virtual
HEARTBEATS_DE_AQUECIMENTO = 5          # frames legítimos antes de qualquer ataque
INTERVALO_HEARTBEAT_S = 1.0            # heartbeat GOOSE a 1 Hz


@dataclass(frozen=True)
class ItemTrafego:
    gap_s: float      # tempo desde o frame anterior (0 para o primeiro)
    raw: bytes        # frame Ethernet completo
    is_attack: bool


def _carregar_molde():
    return gf.parse_ethernet_goose(bytes(rdpcap(str(MOLDE_PCAP))[0]))


class GeradorDeTrafego:
    """Monta uma linha do tempo de frames de um IED legítimo e de um atacante."""

    def __init__(self, modo):
        molde = _carregar_molde()
        self._dst_mac = molde["dst_mac"]
        self._appid = molde["appid"]
        self.mac_do_ied = molde["src_mac"]
        self.estado = dict(molde["fields"])  # estado corrente do IED legítimo
        self._assinante_do_ied = GooseAuthenticator() if modo != SEM_HMAC else None
        self._assinante_do_atacante = (GooseAuthenticator()
                                       if modo == HMAC_CHAVE_VAZADA else None)
        self.itens = []
        self._agora = INSTANTE_INICIAL

    def _emitir(self, gap_s, campos, mac, assinante, is_attack):
        self._agora += gap_s
        campos["t"] = gf.make_utctime(self._agora)
        tag = assinante.sign(campos) if assinante else None
        raw = bytes(gf.build_ethernet_goose_frame(
            self._dst_mac, mac, self._appid, campos, auth_tag=tag))
        self.itens.append(ItemTrafego(gap_s, raw, is_attack))

    # --- tráfego legítimo -------------------------------------------------

    def heartbeat(self, gap_s):
        self.estado["sqNum"] += 1
        self._emitir(gap_s, self.estado, self.mac_do_ied,
                     self._assinante_do_ied, is_attack=False)

    def mudanca_de_estado(self, gap_s):
        """Transição real: inverte um booleano, stNum+1, sqNum reinicia."""
        self.estado["allData"], *_ = gf.flip_boolean_in_data(self.estado["allData"])
        self.estado["stNum"] += 1
        self.estado["sqNum"] = 0
        self._emitir(gap_s, self.estado, self.mac_do_ied,
                     self._assinante_do_ied, is_attack=False)

    def aquecimento(self):
        for i in range(HEARTBEATS_DE_AQUECIMENTO):
            self.heartbeat(0.0 if i == 0 else INTERVALO_HEARTBEAT_S)

    # --- ataques (espelham atacante/goose_attack.py) -----------------------

    def _emitir_ataque(self, gap_s, campos, mac=None):
        self._emitir(gap_s, campos, mac or self.mac_do_ied,
                     self._assinante_do_atacante, is_attack=True)

    def ataque_flood(self, pps, duracao_s):
        """Teste A: stNum fixo, sqNum crescente, mesmo MAC, em taxa `pps`."""
        campos = dict(self.estado)
        for _ in range(int(pps * duracao_s)):
            campos["sqNum"] += 1
            self._emitir_ataque(1.0 / pps, campos)

    def ataque_replay(self, frame_capturado, gap_s):
        """Teste B: reenvia bytes idênticos de um frame legítimo antigo
        (inclusive o HMAC original, que continua válido)."""
        self.itens.append(ItemTrafego(gap_s, frame_capturado, True))

    def ataque_masquerade(self, mac_proprio):
        """Testes C1 (mac_proprio=False, MAC clonado) e C2 (MAC distinto)."""
        campos = dict(self.estado)
        campos["allData"], *_ = gf.flip_boolean_in_data(campos["allData"])
        campos["stNum"] += 1
        campos["sqNum"] = 0
        self._emitir_ataque(INTERVALO_HEARTBEAT_S, campos,
                            MAC_ATACANTE if mac_proprio else None)

    def ataque_supressao(self, salto_stnum):
        """Teste D: stNum muito à frente do estado real."""
        campos = dict(self.estado)
        campos["stNum"] += salto_stnum
        campos["sqNum"] = 0
        self._emitir_ataque(INTERVALO_HEARTBEAT_S, campos)


# --- cenários memoizados (conteúdo determinístico) -------------------------

@lru_cache(maxsize=None)
def trafego_baseline(modo, rajada_pps=5, rajada_s=2.0, duracao_s=60,
                     instantes_de_rajada=(20, 40)):
    """T0: heartbeat 1 Hz + rajadas legítimas (mudança de estado seguida de
    retransmissões rápidas) em `rajada_pps`. Nenhum frame é ataque."""
    eventos = []  # (instante, tipo)
    for segundo in range(duracao_s + 1):
        dentro_de_rajada = any(i <= segundo < i + rajada_s for i in instantes_de_rajada)
        if not dentro_de_rajada:
            eventos.append((float(segundo), "heartbeat"))
    for inicio in instantes_de_rajada:
        eventos.append((float(inicio), "mudanca"))
        for k in range(1, int(rajada_pps * rajada_s)):
            eventos.append((inicio + k / rajada_pps, "heartbeat"))
    eventos.sort(key=lambda e: e[0])

    gerador = GeradorDeTrafego(modo)
    anterior = eventos[0][0]
    for instante, tipo in eventos:
        gap = instante - anterior
        anterior = instante
        if tipo == "mudanca":
            gerador.mudanca_de_estado(gap)
        else:
            gerador.heartbeat(gap)
    return tuple(gerador.itens)


@lru_cache(maxsize=None)
def trafego_flood(modo, pps, duracao_s=3.0):
    gerador = GeradorDeTrafego(modo)
    gerador.aquecimento()
    gerador.ataque_flood(pps, duracao_s)
    return tuple(gerador.itens)


@lru_cache(maxsize=None)
def _trafego_replay(modo, heartbeats_extras):
    gerador = GeradorDeTrafego(modo)
    gerador.aquecimento()
    frame_antigo = gerador.itens[0].raw
    for _ in range(heartbeats_extras):
        gerador.heartbeat(INTERVALO_HEARTBEAT_S)
    gerador.ataque_replay(frame_antigo, gap_s=0.0)
    return tuple(gerador.itens)


def trafego_replay(modo, delta_t_s):
    """Teste B: o replay chega `delta_t_s` depois do fim do aquecimento (nesse
    intervalo o IED legítimo segue com heartbeats a 1 Hz)."""
    heartbeats_extras = int(delta_t_s)
    itens = list(_trafego_replay(modo, heartbeats_extras))
    itens[-1] = replace(itens[-1], gap_s=delta_t_s - heartbeats_extras)
    return tuple(itens)


@lru_cache(maxsize=None)
def trafego_masquerade(modo, mac_proprio):
    gerador = GeradorDeTrafego(modo)
    gerador.aquecimento()
    gerador.ataque_masquerade(mac_proprio)
    return tuple(gerador.itens)


@lru_cache(maxsize=None)
def trafego_supressao(modo, salto_stnum):
    gerador = GeradorDeTrafego(modo)
    gerador.aquecimento()
    gerador.ataque_supressao(salto_stnum)
    return tuple(gerador.itens)
