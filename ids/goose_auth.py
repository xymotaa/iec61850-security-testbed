"""
goose_auth.py — SIMULAÇÃO da ideia de autenticação da IEC 62351-6 (opt-in).

ATENÇÃO: isto NÃO é uma implementação conforme da IEC 62351-6. A norma
prevê assinatura/HMAC com gestão de chaves (IEC 62351-9), codificação
própria da extensão e protocolo de distribuição de chaves. Aqui há só o
essencial para estudar o efeito da ideia sobre um IDS:

  * HMAC-SHA256 por frame, com uma chave por gocbRef (derivada de uma
    chave-mestra de TESTE; nunca use chave real neste código);
  * calculado sobre gocbRef, stNum, sqNum, t (timestamp) e allData;
  * anexado como trailer após o APDU (ver goose_frame.AUTH_TRAILER_TAG),
    em vez de usar o mecanismo de extensão normativo;
  * verificação com hmac.compare_digest (tempo constante).

Não há proteção contra replay por si só: um frame legítimo reenviado
continua com HMAC válido (o replay é pego pela checagem de (stNum, sqNum)
do ids_core). E quem possui a chave forja frames válidos.

Cópia idêntica em ids/ e atacante/ (mesma convenção do goose_frame.py:
cada pasta é um contexto Docker independente).
"""
import hashlib
import hmac
import os

KEY_ENV_VAR = "GOOSE_HMAC_KEY"
# Chave-mestra PÚBLICA, só para testes e para o benchmark offline.
TEST_MASTER_KEY = b"chave-de-teste-iec62351-6-simulada"
TAG_SIZE = hashlib.sha256().digest_size

_LENGTH_PREFIX_BYTES = 4
_COUNTER_BYTES = 8


def _length_prefixed(data):
    """Prefixa o tamanho para que a concatenação seja não ambígua
    (evita que bytes migrem de um campo para outro sem mudar o HMAC)."""
    return len(data).to_bytes(_LENGTH_PREFIX_BYTES, "big") + data


def signed_bytes(fields):
    """Serialização canônica dos campos protegidos pelo HMAC."""
    parts = (
        fields["gocbRef"].encode("ascii"),
        fields["stNum"].to_bytes(_COUNTER_BYTES, "big"),
        fields["sqNum"].to_bytes(_COUNTER_BYTES, "big"),
        fields["t"],
        fields["allData"],
    )
    return b"".join(_length_prefixed(p) for p in parts)


class GooseAuthenticator:
    """Assina e verifica frames GOOSE com uma chave HMAC por gocbRef."""

    def __init__(self, master_key=TEST_MASTER_KEY):
        self._master_key = master_key
        self._flow_keys = {}  # gocbRef -> chave derivada (cache)

    @classmethod
    def from_env(cls):
        """Lê a chave-mestra de GOOSE_HMAC_KEY; sem a variável, usa a
        chave de teste pública (e o chamador deve avisar o operador)."""
        value = os.environ.get(KEY_ENV_VAR)
        return cls(value.encode() if value else TEST_MASTER_KEY)

    @staticmethod
    def uses_test_key():
        return not os.environ.get(KEY_ENV_VAR)

    def _flow_key(self, gocb_ref):
        key = self._flow_keys.get(gocb_ref)
        if key is None:
            key = hmac.new(self._master_key, b"gocbRef:" + gocb_ref.encode("ascii"),
                           hashlib.sha256).digest()
            self._flow_keys[gocb_ref] = key
        return key

    def sign(self, fields):
        """Retorna o HMAC-SHA256 (32 bytes) dos campos protegidos."""
        return hmac.new(self._flow_key(fields["gocbRef"]), signed_bytes(fields),
                        hashlib.sha256).digest()

    def verify(self, fields, tag):
        """True só se tag existe e confere. Frame sem tag é inválido."""
        if tag is None:
            return False
        try:
            expected = self.sign(fields)
        except (KeyError, UnicodeEncodeError, OverflowError):
            return False  # campos ausentes/malformados: não autenticável
        return hmac.compare_digest(expected, tag)
