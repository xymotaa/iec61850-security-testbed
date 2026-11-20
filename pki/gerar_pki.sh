#!/usr/bin/env bash
# gerar_pki.sh — PKI de TESTE (laboratório) para o cenário 802.1X EAP-TLS.
#
# Cria uma CA raiz de teste, o certificado de servidor do autenticador,
# um certificado de cliente por dispositivo e uma CRL (com um cliente
# revogado). As chaves privadas NÃO são versionadas (ver .gitignore):
# gere sob demanda com este script.
#
# Uso:
#   ./gerar_pki.sh [--out DIR] [--force] [--ieds N]   cria a PKI do zero
#   ./gerar_pki.sh [--out DIR] --revogar CN           revoga nos/CN e atualiza a CRL
#
#   --ieds N   nº de certificados ubuntu-ied-1..N (padrão 5)
#
# Saída (padrão: pki/saida/):
#   ca/ca.crt  ca/ca.key  ca/crl.pem            CA de teste e CRL
#   nos/<nome>/                                  pasta pronta p/ copiar em /etc/8021x
#     ca.pem cert.pem key.pem                    (clientes)
#     ca.pem cert.pem key.pem crl.pem            (autenticador-8021x)
#
# NUNCA use estas chaves fora do laboratório.
set -euo pipefail

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAIDA="$AQUI/saida"
FORCAR=0
NUM_IEDS=5
REVOGAR_CN=""
DIAS_VALIDADE=825
BITS_RSA=2048

# Certificados VÁLIDOS além dos ubuntu-ied-N (CN = nome do nó no GNS3).
# atacante-comprometido: certificado legítimo de um nó invadido (cenário de
# limite do 802.1X). fora-do-inventario-1: válido, mas o CN não consta no
# inventário.
DISPOSITIVOS_FIXOS=(ids-1 oraculo-1 publicador-1 atacante-comprometido fora-do-inventario-1)
DISPOSITIVOS_REVOGADOS=(revogado-1)
NOME_AUTENTICADOR="autenticador-8021x"

uso() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
erro() { echo "[!] $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) SAIDA="$2"; shift 2 ;;
        --force) FORCAR=1; shift ;;
        --ieds) NUM_IEDS="$2"; shift 2 ;;
        --revogar) REVOGAR_CN="$2"; shift 2 ;;
        -h|--help) uso; exit 0 ;;
        *) echo "[!] opção desconhecida: $1" >&2; exit 2 ;;
    esac
done
[[ "$NUM_IEDS" =~ ^[0-9]+$ ]] || erro "--ieds exige um número"
command -v openssl >/dev/null || erro "openssl não encontrado"
umask 077

# Configuração do openssl (CA com banco de dados, para emitir e revogar).
# Reescrita a cada execução para que os caminhos absolutos acompanhem a pasta.
escrever_openssl_cnf() {
    cat > "$CONF" <<CNF
[ ca ]
default_ca = CA_teste

[ CA_teste ]
dir              = $SAIDA/ca
database         = \$dir/index.txt
new_certs_dir    = \$dir/novos
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
certificate      = \$dir/ca.crt
private_key      = \$dir/ca.key
default_md       = sha256
default_days     = $DIAS_VALIDADE
default_crl_days = 3650
policy           = politica
unique_subject   = no
copy_extensions  = none

[ politica ]
organizationName = optional
commonName       = supplied

[ req ]
distinguished_name = dn
prompt             = no

[ dn ]
CN = placeholder

[ ext_ca ]
basicConstraints     = critical, CA:TRUE, pathlen:0
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ ext_servidor ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = DNS:$NOME_AUTENTICADOR
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid

[ ext_cliente ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
CNF
}

# emitir_certificado <cn> <extensão>  -> tmp/<cn>.{key,crt}
emitir_certificado() {
    local cn="$1" extensao="$2"
    openssl req -new -newkey rsa:"$BITS_RSA" -nodes -sha256 \
        -subj "/O=Testbed IEC61850 (LAB)/CN=$cn" \
        -keyout "$SAIDA/tmp/$cn.key" -out "$SAIDA/tmp/$cn.csr" -config "$CONF" 2>/dev/null
    openssl ca -batch -config "$CONF" -extensions "$extensao" \
        -in "$SAIDA/tmp/$cn.csr" -out "$SAIDA/tmp/$cn.crt" -notext 2>/dev/null
}

# montar_no <cn>  -> nos/<cn>/{ca.pem,cert.pem,key.pem}
montar_no() {
    local cn="$1" destino="$SAIDA/nos/$1"
    mkdir -p "$destino"
    cp "$SAIDA/ca/ca.crt" "$destino/ca.pem"
    cp "$SAIDA/tmp/$cn.crt" "$destino/cert.pem"
    cp "$SAIDA/tmp/$cn.key" "$destino/key.pem"
}

gerar_crl() {
    openssl ca -batch -config "$CONF" -gencrl -out "$SAIDA/ca/crl.pem" 2>/dev/null
    cp "$SAIDA/ca/crl.pem" "$SAIDA/nos/$NOME_AUTENTICADOR/crl.pem"
}

criar_pki() {
    if [ -e "$SAIDA/ca/ca.crt" ] && [ "$FORCAR" -ne 1 ]; then
        erro "$SAIDA já contém uma PKI. Use --force para recriar (invalida os certificados atuais)."
    fi
    rm -rf "$SAIDA"
    mkdir -p "$SAIDA/ca/novos" "$SAIDA/nos" "$SAIDA/tmp"
    SAIDA="$(cd "$SAIDA" && pwd)"
    CONF="$SAIDA/ca/openssl.cnf"
    : > "$SAIDA/ca/index.txt"
    echo 1000 > "$SAIDA/ca/serial"
    echo 1000 > "$SAIDA/ca/crlnumber"
    escrever_openssl_cnf

    openssl req -x509 -newkey rsa:"$BITS_RSA" -nodes -sha256 -days 3650 \
        -subj "/O=Testbed IEC61850 (LAB)/CN=CA Raiz de TESTE 802.1X" \
        -keyout "$SAIDA/ca/ca.key" -out "$SAIDA/ca/ca.crt" \
        -config "$CONF" -extensions ext_ca 2>/dev/null

    local validos=() i cn
    for ((i = 1; i <= NUM_IEDS; i++)); do validos+=("ubuntu-ied-$i"); done
    validos+=("${DISPOSITIVOS_FIXOS[@]}")

    emitir_certificado "$NOME_AUTENTICADOR" ext_servidor
    montar_no "$NOME_AUTENTICADOR"
    for cn in "${validos[@]}" "${DISPOSITIVOS_REVOGADOS[@]}"; do
        emitir_certificado "$cn" ext_cliente
        montar_no "$cn"
    done
    for cn in "${DISPOSITIVOS_REVOGADOS[@]}"; do
        openssl ca -batch -config "$CONF" -revoke "$SAIDA/tmp/$cn.crt" -crl_reason keyCompromise 2>/dev/null
    done
    gerar_crl
    rm -rf "$SAIDA/tmp"

    verificar_pki "${validos[@]}"
    echo "[+] PKI de teste gerada em $SAIDA"
    echo "    CA: ca/ca.crt | autenticador: nos/$NOME_AUTENTICADOR | válidos: ${#validos[@]} | revogados: ${#DISPOSITIVOS_REVOGADOS[@]}"
    echo "[!] Chaves privadas de LABORATÓRIO — não versionar, não reutilizar."
}

verificar_pki() {
    local cn
    for cn in "$@"; do
        openssl verify -CAfile "$SAIDA/ca/ca.crt" -purpose sslclient "$SAIDA/nos/$cn/cert.pem" >/dev/null
    done
    for cn in "${DISPOSITIVOS_REVOGADOS[@]}"; do
        if openssl verify -crl_check -CAfile "$SAIDA/ca/ca.crt" -CRLfile "$SAIDA/ca/crl.pem" \
            "$SAIDA/nos/$cn/cert.pem" >/dev/null 2>&1; then
            erro "$cn deveria estar revogado"
        fi
    done
}

revogar_dispositivo() {
    local cn="$1"
    [ -e "$SAIDA/ca/ca.crt" ] || erro "nenhuma PKI em $SAIDA (rode sem --revogar primeiro)"
    [ -r "$SAIDA/nos/$cn/cert.pem" ] || erro "dispositivo desconhecido: $cn"
    SAIDA="$(cd "$SAIDA" && pwd)"
    CONF="$SAIDA/ca/openssl.cnf"
    escrever_openssl_cnf
    openssl ca -batch -config "$CONF" -revoke "$SAIDA/nos/$cn/cert.pem" -crl_reason keyCompromise 2>/dev/null \
        || erro "não foi possível revogar $cn (já revogado?)"
    gerar_crl
    echo "[+] $cn revogado. Nova CRL em $SAIDA/nos/$NOME_AUTENTICADOR/crl.pem"
    echo "    Copie-a para /etc/8021x do autenticador e rode no console dele: autenticador-ctl recarregar-crl"
}

if [ -n "$REVOGAR_CN" ]; then revogar_dispositivo "$REVOGAR_CN"; else criar_pki; fi
