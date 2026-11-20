"""
autenticador_core.py — núcleo (sem I/O de rede) do autenticador 802.1X.

Três responsabilidades, todas testáveis sem hostapd/nftables:

1. `InterpretadorLogHostapd`: transforma o log de depuração do hostapd
   (v2.10, `-d`) em eventos de acesso. O log é a ÚNICA fonte do
   certificado apresentado: o `hostapd_cli sta` só mostra a identidade
   EAP *declarada* pelo cliente (`dot1xAuthSessionUserName`), que não é
   verificada contra o certificado; já a linha `authsrv: peer
   certificate: depth=0 ... subject=...` traz o subject validado pelo TLS.
2. `Inventario`: vínculo CN do certificado -> MACs permitidos.
3. `ControladorAcesso`: decide (aceitar/rejeitar), libera/revoga o par
   porta+MAC no firewall e registra cada decisão em JSON lines.

Os motivos de rejeição são os do enunciado do cenário: sem certificado,
certificado inválido, revogado, CN fora do inventário, MAC divergente.
"""
import json
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone

MOTIVO_SEM_CERTIFICADO = "sem_certificado"
MOTIVO_CERTIFICADO_INVALIDO = "certificado_invalido"
MOTIVO_CERTIFICADO_REVOGADO = "certificado_revogado"
MOTIVO_CN_FORA_DO_INVENTARIO = "cn_fora_do_inventario"
MOTIVO_MAC_DIVERGENTE = "mac_divergente"
MOTIVO_FALHA_EAP = "falha_eap"

# Códigos X509_V_ERR_* do OpenSSL que significam "revogado" (23).
CODIGO_OPENSSL_REVOGADO = 23

_MAC = r"(?P<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})"
_RE_PACOTE_EAP = re.compile(
    rf"(?P<iface>[\w.\-]+): STA {_MAC} IEEE 802\.1X: received EAP packet .*"
    r"EAP Response-(?P<resposta>.+)$")
_RE_PROCESSAMENTO = re.compile(
    rf"IEEE 802\.1X: {_MAC} BE_AUTH entering state RESPONSE")
_RE_CERT_PAR = re.compile(
    r"authsrv: peer certificate: depth=0 serial_num=(?P<serial>\S+) subject=(?P<subject>.*)$")
_RE_ERRO_TLS = re.compile(
    r"TLS: Certificate verification failed, error (?P<codigo>\d+) \((?P<descricao>.*?)\) "
    r"depth \d+ for '(?P<subject>.*)'")
_RE_EVENTO = re.compile(
    rf"(?P<iface>[\w.\-]+): (?P<evento>CTRL-EVENT-EAP-STARTED|CTRL-EVENT-EAP-SUCCESS|"
    rf"CTRL-EVENT-EAP-FAILURE|AP-STA-DISCONNECTED) {_MAC}")
_RE_CN = re.compile(r"/CN=([^/]*)")
_RESPOSTAS_NAK = ("unknown (3)", "Nak", "NAK")


def extrair_cn(subject):
    """CN de um subject no formato `/O=.../CN=nome` do OpenSSL (ou None)."""
    achados = _RE_CN.findall(subject or "")
    return achados[-1] if achados else None


def normalizar_mac(mac):
    return mac.strip().lower().replace("-", ":")


@dataclass(frozen=True)
class EventoAcesso:
    """`tipo` ∈ {inicio, sucesso, falha, desconexao}."""
    tipo: str
    iface: str
    mac: str
    cn: str = None
    serial: str = None
    motivo: str = None
    detalhe: str = None


@dataclass
class _SessaoEap:
    cn: str = None
    serial: str = None
    erro_tls: tuple = None   # (codigo, descricao)
    nak: bool = False


class InterpretadorLogHostapd:
    """Máquina de estados linha-a-linha sobre o log `hostapd -d`.

    O hostapd recebe o pacote EAP e processa a resposta DEPOIS (callback do
    eloop), então com várias estações o log intercala as duas etapas:
        received EAP packet A / received EAP packet B / ...processa A / ...processa B
    A linha `IEEE 802.1X: <mac> BE_AUTH entering state RESPONSE` marca o início
    do processamento de uma estação; as linhas de TLS seguintes (certificado,
    erros) pertencem a ela. Use UMA instância por processo hostapd (por
    porta): a linha de processamento e as de TLS não trazem a interface, então
    com o MAC repetido em portas diferentes (clonagem) a atribuição só é
    inequívoca se cada porta tiver o seu próprio log.
    """

    def __init__(self):
        self._sessoes = {}
        self._recebidos = OrderedDict()
        self._atual = None

    def processar(self, linha):
        """Devolve a lista (possivelmente vazia) de EventoAcesso da linha."""
        linha = linha.rstrip("\n")
        pacote = _RE_PACOTE_EAP.search(linha)
        if pacote:
            self._registrar_pacote(pacote["iface"], pacote["mac"], pacote["resposta"].strip())
            return []
        processamento = _RE_PROCESSAMENTO.search(linha)
        if processamento:
            self._atual = self._proximo_recebido(processamento["mac"])
            return []
        cert = _RE_CERT_PAR.search(linha)
        if cert and self._atual:
            sessao = self._sessao(self._atual)
            sessao.cn, sessao.serial = extrair_cn(cert["subject"]), cert["serial"]
            return []
        erro = _RE_ERRO_TLS.search(linha)
        if erro and self._atual:
            sessao = self._sessao(self._atual)
            sessao.erro_tls = (int(erro["codigo"]), erro["descricao"])
            sessao.cn = sessao.cn or extrair_cn(erro["subject"])
            return []
        evento = _RE_EVENTO.search(linha)
        if evento:
            return self._evento(evento["evento"], evento["iface"], evento["mac"])
        return []

    def _registrar_pacote(self, iface, mac, resposta):
        chave = (iface, mac)
        self._recebidos.pop(chave, None)
        self._recebidos[chave] = True
        if resposta in _RESPOSTAS_NAK:
            self._sessao(chave).nak = True

    def _proximo_recebido(self, mac):
        for chave in self._recebidos:
            if chave[1] == mac:
                del self._recebidos[chave]
                return chave
        return None

    def _sessao(self, chave):
        return self._sessoes.setdefault(chave, _SessaoEap())

    def _evento(self, nome, iface, mac):
        chave = (iface, mac)
        if nome == "CTRL-EVENT-EAP-STARTED":
            self._sessoes[chave] = _SessaoEap()
            return [EventoAcesso("inicio", iface, mac)]
        if nome == "AP-STA-DISCONNECTED":
            self._sessoes.pop(chave, None)
            return [EventoAcesso("desconexao", iface, mac)]
        sessao = self._sessoes.pop(chave, _SessaoEap())
        if nome == "CTRL-EVENT-EAP-SUCCESS":
            return [EventoAcesso("sucesso", iface, mac, cn=sessao.cn, serial=sessao.serial)]
        motivo, detalhe = self._motivo_da_falha(sessao)
        return [EventoAcesso("falha", iface, mac, cn=sessao.cn, serial=sessao.serial,
                             motivo=motivo, detalhe=detalhe)]

    @staticmethod
    def _motivo_da_falha(sessao):
        if sessao.erro_tls:
            codigo, descricao = sessao.erro_tls
            if codigo == CODIGO_OPENSSL_REVOGADO:
                return MOTIVO_CERTIFICADO_REVOGADO, descricao
            return MOTIVO_CERTIFICADO_INVALIDO, descricao
        if sessao.nak:
            return MOTIVO_SEM_CERTIFICADO, "cliente recusou EAP-TLS (sem credencial configurada)"
        return MOTIVO_FALHA_EAP, "EAP terminou em falha sem erro de certificado"


class Inventario:
    """CN do certificado -> conjunto de MACs autorizados a usá-lo."""

    def __init__(self, dispositivos):
        self._macs_por_cn = {
            cn: frozenset(normalizar_mac(m) for m in info["macs"])
            for cn, info in dispositivos.items()
        }

    @classmethod
    def de_arquivo(cls, caminho):
        with open(caminho, encoding="utf-8") as f:
            dados = json.load(f)
        return cls(dados["dispositivos"])

    def avaliar(self, cn, mac):
        """(aceito, motivo). `motivo` é None quando aceito."""
        if cn not in self._macs_por_cn:
            return False, MOTIVO_CN_FORA_DO_INVENTARIO
        if normalizar_mac(mac) not in self._macs_por_cn[cn]:
            return False, MOTIVO_MAC_DIVERGENTE
        return True, None

    def macs_de(self, cn):
        return sorted(self._macs_por_cn.get(cn, ()))


class RegistroJsonl:
    """Grava um objeto JSON por linha (eventos de autenticação)."""

    def __init__(self, arquivo, relogio=None):
        self._arquivo = arquivo
        self._relogio = relogio or (lambda: datetime.now(timezone.utc))
        self._trava = threading.Lock()

    @classmethod
    def em_arquivo(cls, caminho):
        return cls(open(caminho, "a", encoding="utf-8", buffering=1))

    def emitir(self, evento, **campos):
        registro = {"ts": self._relogio().isoformat(timespec="milliseconds"), "evento": evento}
        registro.update({k: v for k, v in campos.items() if v is not None})
        with self._trava:
            self._arquivo.write(json.dumps(registro, ensure_ascii=False) + "\n")


class ControladorAcesso:
    """Aplica as decisões de acesso.

    Colaboradores (injetados): `firewall` (autorizar/revogar/revogar_porta),
    `registro` (emitir), `desautenticar(iface, mac)` e `inventario`.
    """

    def __init__(self, inventario, firewall, registro, desautenticar):
        self._inventario = inventario
        self._firewall = firewall
        self._registro = registro
        self._desautenticar = desautenticar
        self._contagem_descartes = {}

    def tratar(self, evento):
        if evento.tipo == "sucesso":
            self._tratar_sucesso(evento)
        elif evento.tipo == "falha":
            self._tratar_falha(evento)
        elif evento.tipo == "desconexao":
            self._encerrar_sessao(evento.iface, evento.mac)

    def _tratar_sucesso(self, evento):
        aceito, motivo = self._inventario.avaliar(evento.cn, evento.mac)
        if not aceito:
            self._rejeitar(evento, motivo, self._detalhe_vinculo(evento, motivo))
            return
        self._firewall.autorizar(evento.iface, evento.mac)
        self._registro.emitir("auth_aceita", iface=evento.iface, mac=evento.mac,
                              cn=evento.cn, serial=evento.serial)

    def _detalhe_vinculo(self, evento, motivo):
        if motivo == MOTIVO_MAC_DIVERGENTE:
            esperados = ",".join(self._inventario.macs_de(evento.cn))
            return f"MAC {evento.mac} não pertence a {evento.cn} (esperado: {esperados})"
        return f"CN {evento.cn!r} ausente do inventário"

    def _tratar_falha(self, evento):
        self._rejeitar(evento, evento.motivo, evento.detalhe, desautenticar=False)

    def _rejeitar(self, evento, motivo, detalhe, desautenticar=True):
        self._firewall.revogar(evento.iface, evento.mac)
        if desautenticar:
            self._desautenticar(evento.iface, evento.mac)
        self._registro.emitir("auth_rejeitada", iface=evento.iface, mac=evento.mac,
                              cn=evento.cn, serial=evento.serial, motivo=motivo, detalhe=detalhe)

    def _encerrar_sessao(self, iface, mac):
        if self._firewall.revogar(iface, mac):
            self._registro.emitir("sessao_encerrada", iface=iface, mac=mac)

    def porta_caiu(self, iface):
        """Link da porta caiu: nada que estava autorizado nela continua válido."""
        for mac in self._firewall.revogar_porta(iface):
            self._desautenticar(iface, mac)
            self._registro.emitir("sessao_encerrada", iface=iface, mac=mac, motivo="link_down")

    def reportar_descartes(self, descartes):
        """`descartes`: iterável de (iface, mac, pacotes). Emite só o que mudou."""
        for iface, mac, pacotes in descartes:
            if self._contagem_descartes.get((iface, mac)) != pacotes:
                self._contagem_descartes[(iface, mac)] = pacotes
                self._registro.emitir("quadro_descartado", iface=iface, mac=mac, pacotes=pacotes,
                                      motivo="origem_nao_autorizada")
