#!/bin/sh
# medir_versao_tls.sh — mede a versão de TLS negociada no EAP-TLS.
#
# AMBIENTE DE DEPURAÇÃO — NÃO É O GNS3.
# Roda DENTRO de um contêiner Docker privilegiado (imagem autenticador-8021x:teste):
#   hostapd (driver wired) na interface `vh` e wpa_supplicant (driver wired) em um
#   network namespace (`cli`, interface `vc`), ligados por um par veth. A
#   configuração reproduz a do projeto (autenticador-8021x/hostapd.conf.tmpl e
#   supplicant/supplicant_8021x.sh): EAP-TLS, CA com CRL, check_crl=1, sem fixar
#   versão de TLS. A PKI é temporária (pki/gerar_pki.sh --out), fora do repositório.
#
# Uso (no host, a partir da raiz do repositório):
#   pki/gerar_pki.sh --out /tmp/pki_tls
#   docker build -q -t autenticador-8021x:latest autenticador-8021x
#   docker build -q -t autenticador-8021x:teste -f autenticador-8021x/Dockerfile.teste autenticador-8021x
#   docker run --rm --privileged \
#       -v "$PWD/autenticador-8021x/evidencias/tls":/t:ro -v /tmp/pki_tls:/pki:ro \
#       autenticador-8021x:teste sh /t/medir_versao_tls.sh            # configuração do projeto
#   ... idem com o argumento `tls13`                                  # TLS 1.3 habilitado nas duas pontas
#
# Só linhas filtradas são impressas; os logs completos de depuração (-dd) não são
# versionados.
set -u
HABILITAR_TLS13=0
[ "${1:-}" = "tls13" ] && HABILITAR_TLS13=1
P=/pki/nos

echo "== medição: $([ $HABILITAR_TLS13 = 1 ] && echo 'TLS 1.3 habilitado nas duas pontas (tls_flags / phase1)' || echo 'configuração do projeto (versão de TLS não fixada)')"
echo "== data (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "== ambiente: contêiner Docker privilegiado, par veth + network namespace; NÃO é o GNS3"
grep -E '^(PRETTY_NAME)=' /etc/os-release
echo "== versões =="
hostapd -v 2>&1 | head -1
wpa_supplicant -v 2>&1 | head -1
dpkg -l 2>/dev/null | awk '$2 ~ /^(libssl3|hostapd|wpasupplicant)/ {print $2, $3}'
echo "== bibliotecas ligadas =="
ldd "$(command -v hostapd)" | grep -i -E "libssl|libcrypto"
ldd "$(command -v wpa_supplicant)" | grep -i -E "libssl|libcrypto"

ip netns add cli
ip link add vh type veth peer name vc
ip link set vc netns cli
ip link set vh up
ip netns exec cli ip link set vc up

cat "$P/autenticador-8021x/ca.pem" "$P/autenticador-8021x/crl.pem" > /tmp/ca_crl.pem
printf '*\tTLS\n' > /tmp/eap_user
mkdir -p /run/hostapd /run/wpa

EXTRA_H=""
EXTRA_W=""
if [ "$HABILITAR_TLS13" = 1 ]; then
    EXTRA_H='tls_flags=[ENABLE_TLSv1_3]'
    EXTRA_W='    phase1="tls_disable_tlsv1_3=0"'
fi

cat > /tmp/h.conf <<CONF
interface=vh
driver=wired
ctrl_interface=/run/hostapd
ieee8021x=1
eap_server=1
eap_user_file=/tmp/eap_user
eap_reauth_period=600
ca_cert=/tmp/ca_crl.pem
check_crl=1
crl_reload_interval=60
server_cert=$P/autenticador-8021x/cert.pem
private_key=$P/autenticador-8021x/key.pem
$EXTRA_H
CONF

cat > /tmp/w.conf <<CONF
ctrl_interface=/run/wpa
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=TLS
    eapol_flags=0
    identity="ubuntu-ied-1"
    ca_cert="$P/ubuntu-ied-1/ca.pem"
    client_cert="$P/ubuntu-ied-1/cert.pem"
    private_key="$P/ubuntu-ied-1/key.pem"
    domain_suffix_match="autenticador-8021x"
$EXTRA_W
}
CONF

hostapd -dd /tmp/h.conf > /tmp/hostapd.log 2>&1 &
sleep 2
ip netns exec cli wpa_supplicant -dd -i vc -D wired -c /tmp/w.conf > /tmp/wpa.log 2>&1 &
sleep 12

echo "== resultado do EAP =="
grep -E "CTRL-EVENT-EAP-SUCCESS|EAP-TLS: Done|Supplicant port status" /tmp/wpa.log | head -4
echo "== wpa_supplicant: versão de TLS e cifra =="
grep -E "SSL: Using TLS version|Server selected cipher suite" /tmp/wpa.log | head -6
echo "== hostapd: erros de configuração (esperado: nenhuma linha abaixo) =="
grep -i -E "unknown configuration item|failed to parse|invalid configuration|Line [0-9]+:" /tmp/hostapd.log | head -4
echo "== fim =="
