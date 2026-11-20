#!/usr/bin/env bash
# teste_netns_interno.sh — roda DENTRO do container privilegiado (ver teste_netns.sh).
#
# Cada cliente vive num network namespace ligado ao autenticador por um par
# veth; o lado do autenticador (pN) entra na ponte br0 do container. Nada
# passa pela ponte do host (ela descartaria o EAPOL).
set -uo pipefail

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI=/pki/nos                    # bundles gerados por pki/gerar_pki.sh
INVENTARIO=/work/inventario.json
SUPPLICANT=/opt/supplicant_8021x.sh
EVIDENCIAS=/evidencias
export CERT_DIR=/work/cert_autenticador LOG_DIR=/var/log/8021x INVENTARIO
export AUTENTICADOR_IFACES="p1 p2 p3 p4 p5 p6 p7 p8 p9"
export AUTENTICADOR_DEBUG=1 REAUTH_PERIODO=600 CRL_RELOAD=2

PASSOU=0; FALHOU=0
verificar() {  # verificar "descrição" comando...
    local descricao="$1"; shift
    if "$@" >/dev/null 2>&1; then echo "  [PASSOU] $descricao"; PASSOU=$((PASSOU + 1))
    else echo "  [FALHOU] $descricao"; FALHOU=$((FALHOU + 1)); fi
}
negar() {  # passa quando o comando FALHA
    local descricao="$1"; shift
    if "$@" >/dev/null 2>&1; then echo "  [FALHOU] $descricao"; FALHOU=$((FALHOU + 1))
    else echo "  [PASSOU] $descricao"; PASSOU=$((PASSOU + 1)); fi
}

mac_de() { python3 -c "import json,sys;print(json.load(open('$INVENTARIO'))['dispositivos'][sys.argv[1]]['macs'][0])" "$1"; }
eventos() { cat "$LOG_DIR/eventos.jsonl"; }
tem_evento() { eventos | grep -q "$1"; }

# criar_cliente <ns> <porta> <mac> <ip>
criar_cliente() {
    local ns="$1" porta="$2" mac="$3" ip="$4"
    ip netns add "$ns"
    ip link add "$porta" type veth peer name eth0 netns "$ns"
    ip netns exec "$ns" ip link set eth0 address "$mac"
    ip netns exec "$ns" ip addr add "$ip/24" dev eth0
    ip netns exec "$ns" ip link set eth0 up
    ip netns exec "$ns" ip link set lo up
    ip link set "$porta" up
}

# iniciar_supplicant <ns> <pasta-de-certificados> [timeout]
iniciar_supplicant() {
    local ns="$1" cert_dir="$2" timeout="${3:-20}"
    ip netns exec "$ns" env AUTH_8021X_CERT_DIR="$cert_dir" AUTH_8021X_TIMEOUT="$timeout" \
        AUTH_8021X_RETRY=8 AUTH_8021X_RUN_DIR="/run/8021x-$ns" AUTH_8021X_LOG_DIR="/var/log/8021x-$ns" \
        "$SUPPLICANT" start
}

ping_ok() { ip netns exec "$1" ping -c 2 -W 2 "$2" >/dev/null 2>&1; }

echo "== Preparação"
mkdir -p "$CERT_DIR" "$LOG_DIR" "$EVIDENCIAS"
cp "$PKI/autenticador-8021x/"*.pem "$CERT_DIR/"
chmod 600 "$CERT_DIR/key.pem"

MAC_IED1=$(mac_de ubuntu-ied-1); MAC_IED2=$(mac_de ubuntu-ied-2)
MAC_ATACANTE=$(mac_de atacante-comprometido)
criar_cliente c1 p1 "$MAC_IED1" 192.168.10.11            # IED legítimo 1
criar_cliente c2 p2 "$MAC_IED2" 192.168.10.12            # IED legítimo 2
criar_cliente c3 p3 "$MAC_IED1" 192.168.10.13            # E1: sem 802.1X, MAC clonado do IED 1
criar_cliente c4 p4 02:00:c0:a8:0a:0e 192.168.10.14   # E2: certificado revogado
criar_cliente c5 p5 "$MAC_IED1" 192.168.10.15            # E3: cert válido de outro dispositivo + MAC do IED 1
criar_cliente c6 p6 "$MAC_ATACANTE" 192.168.10.40        # E4: cert válido e MAC próprio
criar_cliente c7 p7 02:00:c0:a8:0a:11 192.168.10.17   # cert válido fora do inventário
criar_cliente c8 p8 02:00:c0:a8:0a:12 192.168.10.18  # CA falsa
criar_cliente c9 p9 02:00:c0:a8:0a:63 192.168.10.19      # EAP-TLS sem credencial (NAK)

echo "== Subindo o autenticador"
"$AQUI/iniciar_autenticador.sh"
for _ in $(seq 20); do tem_evento autenticador_iniciado && break; sleep 0.5; done
sleep 2
verificar "hostapd e supervisor no ar" pgrep -f autenticador.py

echo "== Referência: antes de autenticar, nada passa"
negar "c1 (ainda não autenticado) não alcança c2" ping_ok c1 192.168.10.12

echo "== Autenticando clientes (em paralelo)"
# CA falsa para c8 e supplicant sem credencial para c9
FALSO=/work/ca_falsa; mkdir -p "$FALSO"
openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=CA Falsa" -keyout "$FALSO/ca.key" \
    -out "$FALSO/ca-falsa.pem" -days 5 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=ubuntu-ied-5" -keyout "$FALSO/key.pem" \
    -out "$FALSO/c.csr" 2>/dev/null
openssl x509 -req -in "$FALSO/c.csr" -CA "$FALSO/ca-falsa.pem" -CAkey "$FALSO/ca.key" \
    -CAcreateserial -out "$FALSO/cert.pem" -days 5 2>/dev/null
cp "$PKI/ubuntu-ied-1/ca.pem" "$FALSO/ca.pem"          # o cliente confia na CA real; o servidor é que rejeita

mkdir -p /run/8021x-c9 /var/log/8021x-c9/ctrl
cat > /run/8021x-c9/sem_cert.conf <<CONF
ctrl_interface=/run/8021x-c9/ctrl
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=TLS
    eapol_flags=0
    identity="sem-credencial"
}
CONF
ip netns exec c9 wpa_supplicant -B -i eth0 -D wired -c /run/8021x-c9/sem_cert.conf \
    -f /var/log/8021x-c9/wpa.log >/dev/null

iniciar_supplicant c1 "$PKI/ubuntu-ied-1" &
iniciar_supplicant c2 "$PKI/ubuntu-ied-2" &
iniciar_supplicant c4 "$PKI/revogado-1" 15 &
iniciar_supplicant c5 "$PKI/atacante-comprometido" 15 &
iniciar_supplicant c6 "$PKI/atacante-comprometido" &
iniciar_supplicant c7 "$PKI/fora-do-inventario-1" 15 &
iniciar_supplicant c8 "$FALSO" 15 &
wait
sleep 2

echo "== Resultados esperados"
verificar "c1 autenticado (ubuntu-ied-1)" tem_evento '"auth_aceita".*"cn": "ubuntu-ied-1"'
verificar "c2 autenticado (ubuntu-ied-2)" tem_evento '"auth_aceita".*"cn": "ubuntu-ied-2"'
verificar "c1 alcança c2 após autenticar" ping_ok c1 192.168.10.12
verificar "c2 alcança c1 após autenticar" ping_ok c2 192.168.10.11

echo "-- E1: sem 802.1X + MAC clonado do IED 1"
negar "c3 não alcança c2" ping_ok c3 192.168.10.12
negar "c2 não alcança c3 (porta não autorizada não recebe)" ping_ok c2 192.168.10.13
verificar "descarte de c3 registrado (quadro_descartado)" tem_evento '"quadro_descartado".*"iface": "p3"'

echo "-- E2: certificado revogado"
verificar "c4 rejeitado: certificado_revogado" tem_evento '"motivo": "certificado_revogado"'
negar "c4 não alcança c2" ping_ok c4 192.168.10.12

echo "-- E3: cert válido de outro dispositivo + MAC do IED 1"
verificar "c5 rejeitado: mac_divergente" tem_evento '"motivo": "mac_divergente"'
negar "c5 não alcança c2" ping_ok c5 192.168.10.12
negar "p5 (MAC clonado) nunca chegou a ser autorizado" tem_evento '"auth_aceita", "iface": "p5"'

echo "-- E4: cert válido + MAC próprio (limite do 802.1X)"
verificar "c6 autenticado (atacante-comprometido)" tem_evento '"auth_aceita".*"cn": "atacante-comprometido"'
verificar "c6 alcança c2" ping_ok c6 192.168.10.12
ip netns exec c6 ip link set eth0 address 02:00:00:00:00:99   # forjar origem DEPOIS de autenticar
negar "c6 com MAC forjado pós-autenticação não alcança c2 (anti-spoof por porta)" ping_ok c6 192.168.10.12
ip netns exec c6 ip link set eth0 address "$MAC_ATACANTE"
verificar "c6 volta a alcançar c2 com o MAC autenticado" ping_ok c6 192.168.10.12

echo "-- Outros motivos"
verificar "c7 rejeitado: cn_fora_do_inventario" tem_evento '"motivo": "cn_fora_do_inventario"'
verificar "c8 rejeitado: certificado_invalido (CA falsa)" tem_evento '"motivo": "certificado_invalido"'
verificar "c9 rejeitado: sem_certificado" tem_evento '"motivo": "sem_certificado"'
negar "c8 não alcança c2" ping_ok c8 192.168.10.12

echo "-- Queda de link revoga a sessão e reautenticação restaura"
ip link set p1 down; sleep 3
verificar "sessão de p1 encerrada ao cair o link" tem_evento '"evento": "sessao_encerrada", "iface": "p1"'
ip link set p1 up
for _ in $(seq 40); do ping_ok c1 192.168.10.12 && break; sleep 1; done
verificar "c1 reautentica sozinho e volta a alcançar c2" ping_ok c1 192.168.10.12

echo "-- CRL: revogar com o autenticador em operação"
mkdir -p /work && cp -r /pki /work/pki_rw
/opt/gerar_pki.sh --out /work/pki_rw --revogar ubuntu-ied-2 >/dev/null
cp /work/pki_rw/nos/autenticador-8021x/crl.pem "$CERT_DIR/crl.pem"
"$AQUI/autenticador_ctl.sh" recarregar-crl >/dev/null
sleep $((CRL_RELOAD + 2))
"$AQUI/autenticador_ctl.sh" reautenticar >/dev/null
sleep 6
verificar "ubuntu-ied-2 revogado em operação: rejeitado na reautenticação" \
    tem_evento '"cn": "ubuntu-ied-2".*"motivo": "certificado_revogado"'
negar "c1 não alcança mais c2 (sessão revogada)" ping_ok c1 192.168.10.12
verificar "c1 (não revogado) segue alcançando c6" ping_ok c1 192.168.10.40

echo "-- E0: sem 802.1X (autenticador-ctl desativar) e reativação"
"$AQUI/autenticador_ctl.sh" desativar >/dev/null
sleep 1
verificar "sem 802.1X: c3 (sem credencial, MAC clonado) alcança c6" ping_ok c3 192.168.10.40
"$AQUI/autenticador_ctl.sh" ativar >/dev/null
sleep 3
negar "reativado: c3 volta a ser bloqueado" ping_ok c3 192.168.10.40
iniciar_supplicant c1 "$PKI/ubuntu-ied-1" 30 >/dev/null &
iniciar_supplicant c6 "$PKI/atacante-comprometido" 30 >/dev/null &
wait
verificar "reativado: c1 e c6 reautenticam (supplicant reiniciado) e c6 alcança c1" ping_ok c6 192.168.10.11

echo
echo "== Estado final do nftables"
nft list ruleset
echo "== Eventos (JSON lines)"
eventos
cp "$LOG_DIR/eventos.jsonl" "$EVIDENCIAS/eventos-teste_netns.jsonl"
nft list ruleset > "$EVIDENCIAS/nftables-teste_netns.txt"
grep -E "peer certificate|CTRL-EVENT-EAP|AP-STA|Certificate verification failed|Response-unknown" \
    "$LOG_DIR/hostapd.log" > "$EVIDENCIAS/hostapd-trecho-teste_netns.log" || true

echo
echo "RESUMO: $PASSOU verificações passaram, $FALHOU falharam"
[ "$FALHOU" -eq 0 ]
