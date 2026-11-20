#!/usr/bin/env bash
# autenticador-ctl — operação do autenticador em execução.
#
#   recarregar-crl   reconstrói ca+CRL a partir de /etc/8021x/{ca,crl}.pem;
#                    o hostapd relê o arquivo em até CRL_RELOAD segundos (60)
#   reautenticar     força nova autenticação EAP de todos os dispositivos
#                    conectados: quem foi revogado cai agora, sem esperar
#                    o REAUTH_PERIODO
#   estado           pares porta+MAC autorizados, portas e últimos eventos
#   desativar        encerra o 802.1X e apaga as regras: a ponte vira um switch
#                    L2 comum (referência "sem 802.1X", cenário E0)
#   ativar           sobe o 802.1X de novo (regras zeradas). Os nós já
#                    autenticados não sabem que o autenticador reiniciou:
#                    rode `8021x-supplicant start` neles
set -euo pipefail

CERT_DIR="${CERT_DIR:-/etc/8021x}"
LOG_DIR="${LOG_DIR:-/var/log/8021x}"
RUN_DIR="${RUN_DIR:-/run/8021x}"
HOSTAPD_CTRL_DIR=/run/hostapd

recarregar_crl() {
    [ -r "$CERT_DIR/crl.pem" ] || { echo "CRL ausente: $CERT_DIR/crl.pem" >&2; exit 1; }
    cat "$CERT_DIR/ca.pem" "$CERT_DIR/crl.pem" > "$RUN_DIR/ca_com_crl.pem.novo"
    mv "$RUN_DIR/ca_com_crl.pem.novo" "$RUN_DIR/ca_com_crl.pem"   # troca atômica
    echo "CRL atualizada; o hostapd a relê em até ${CRL_RELOAD:-60}s"
}

reautenticar() {
    local porta mac
    for socket in "$HOSTAPD_CTRL_DIR"/*; do
        porta="$(basename "$socket")"
        for mac in $(hostapd_cli -p "$HOSTAPD_CTRL_DIR" -i "$porta" all_sta | grep -E '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'); do
            hostapd_cli -p "$HOSTAPD_CTRL_DIR" -i "$porta" raw EAPOL_REAUTH "$mac" >/dev/null
            echo "reautenticação solicitada: $porta $mac"
        done
    done
}

estado() {
    nft list set bridge acesso8021x autorizados
    nft list set bridge acesso8021x portas_autorizadas
    echo "--- últimos eventos (sem descartes)"
    grep -v quadro_descartado "$LOG_DIR/eventos.jsonl" | tail -n 15
}

desativar() {
    if [ -f "$RUN_DIR/supervisor.pid" ]; then
        kill "$(cat "$RUN_DIR/supervisor.pid")" 2>/dev/null || true
        rm -f "$RUN_DIR/supervisor.pid"
    fi
    nft delete table bridge acesso8021x 2>/dev/null || true
    echo "802.1X DESATIVADO: a ponte encaminha tudo (sem controle de acesso)"
}

ativar() {
    desativar >/dev/null
    "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/iniciar_autenticador.sh"
}

case "${1:-}" in
    recarregar-crl) recarregar_crl ;;
    reautenticar) reautenticar ;;
    estado) estado ;;
    desativar) desativar ;;
    ativar) ativar ;;
    *) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
