#!/usr/bin/env bash
# supplicant_8021x.sh — cliente IEEE 802.1X (EAP-TLS) via wpa_supplicant.
#
# Fonte única: autenticador-8021x/supplicant/supplicant_8021x.sh. Cada
# imagem (ubuntu-ied, oraculo, atacante, ids) recebe uma cópia no build
# (instalada como /usr/local/bin/8021x-supplicant); tests/test_supplicant_copias.py
# garante que as cópias não divirjam.
#
# Uso: 8021x-supplicant {start|stop|status}
#
# Variáveis de ambiente (todas opcionais):
#   AUTH_8021X_CERT_DIR  pasta com ca.pem, cert.pem e key.pem   (/etc/8021x)
#   AUTH_8021X_IFACE     interface cabeada                       (eth0)
#   AUTH_8021X_TIMEOUT   segundos esperando a autorização        (60)
#   AUTH_8021X_RETRY     segundos sem autorizar até reiniciar o supplicant (20)
#   AUTH_8021X_RUN_DIR   socket de controle/pid                   (/run/8021x)
#   AUTH_8021X_LOG_DIR   logs                                     (/var/log/8021x)
#   AUTH_8021X_SERVER_NAME  CN esperado no cert do autenticador   (autenticador-8021x)
#
# `start` bloqueia até autorizar ou estourar o timeout (código 0/1); o
# wpa_supplicant continua em background e segue tentando mesmo após o
# timeout. Nas entrypoints a chamada é feita com `&` para não bloquear
# o console. A configuração de IP não é tocada aqui.
set -uo pipefail

CERT_DIR="${AUTH_8021X_CERT_DIR:-/etc/8021x}"
IFACE="${AUTH_8021X_IFACE:-eth0}"
TIMEOUT="${AUTH_8021X_TIMEOUT:-60}"
RETRY="${AUTH_8021X_RETRY:-20}"
RUN_DIR="${AUTH_8021X_RUN_DIR:-/run/8021x}"
LOG_DIR="${AUTH_8021X_LOG_DIR:-/var/log/8021x}"
SERVER_NAME="${AUTH_8021X_SERVER_NAME:-autenticador-8021x}"

CONF="$RUN_DIR/wpa_supplicant-$IFACE.conf"
PIDFILE="$RUN_DIR/wpa_supplicant-$IFACE.pid"
CTRL_DIR="$RUN_DIR/ctrl"
WATCHDOG_PIDFILE="$RUN_DIR/watchdog-$IFACE.pid"

log() { echo "[8021x-supplicant] $*"; }
die() { log "ERRO: $*" >&2; exit 1; }

wpa_cli_iface() { wpa_cli -p "$CTRL_DIR" -i "$IFACE" "$@" 2>/dev/null; }

port_status() { wpa_cli_iface status | sed -n 's/^suppPortStatus=//p'; }

is_authorized() { [ "$(port_status)" = "Authorized" ]; }

certificate_cn() {
    openssl x509 -in "$CERT_DIR/cert.pem" -noout -subject -nameopt RFC2253 \
        | sed -n 's/.*CN=\([^,]*\).*/\1/p'
}

require_credentials() {
    local f
    for f in ca.pem cert.pem key.pem; do
        [ -r "$CERT_DIR/$f" ] || die "arquivo ausente: $CERT_DIR/$f (ver pki/README.md)"
    done
    ip link show "$IFACE" >/dev/null 2>&1 || die "interface $IFACE inexistente"
}

write_config() {
    local identity
    identity="$(certificate_cn)"
    [ -n "$identity" ] || die "CN não encontrado em $CERT_DIR/cert.pem"
    mkdir -p "$RUN_DIR" "$CTRL_DIR" "$LOG_DIR"
    cat > "$CONF" <<CONFIG
ctrl_interface=$CTRL_DIR
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=TLS
    eapol_flags=0
    identity="$identity"
    ca_cert="$CERT_DIR/ca.pem"
    client_cert="$CERT_DIR/cert.pem"
    private_key="$CERT_DIR/key.pem"
    domain_suffix_match="$SERVER_NAME"
}
CONFIG
}

launch_daemon() {
    wpa_supplicant -B -i "$IFACE" -D wired -c "$CONF" -P "$PIDFILE" \
        -f "$LOG_DIR/wpa_supplicant-$IFACE.log" >/dev/null
}

restart_daemon() {
    kill_from_pidfile "$PIDFILE"
    launch_daemon || log "falha ao reiniciar o wpa_supplicant"
}

carrier() { cat "/sys/class/net/$IFACE/carrier" 2>/dev/null; }

# O wpa_supplicant só reenvia o EAPOL-Start a cada 30 s e não percebe a
# queda/volta do link nem que o autenticador esqueceu a sessão. Reiniciá-lo
# força um EAPOL-Start imediato: é o que este laço faz quando o link volta
# ou quando a porta fica RETRY segundos sem autorizar (ex.: autenticador
# que subiu depois do nó).
watch_link_and_authorization() {
    local last_carrier current_carrier unauthorized_for=0
    last_carrier="$(carrier)"
    while sleep 1; do
        current_carrier="$(carrier)"
        if [ "$current_carrier" = 1 ] && [ "$last_carrier" != 1 ]; then
            restart_daemon; unauthorized_for=0
        elif is_authorized; then
            unauthorized_for=0
        else
            unauthorized_for=$((unauthorized_for + 1))
            if [ "$unauthorized_for" -ge "$RETRY" ]; then restart_daemon; unauthorized_for=0; fi
        fi
        last_carrier="$current_carrier"
    done
}

start_watchdog() {
    watch_link_and_authorization >/dev/null 2>&1 &
    echo $! > "$WATCHDOG_PIDFILE"
}

wait_for_authorization() {
    local waited=0
    while [ "$waited" -lt "$TIMEOUT" ]; do
        if is_authorized; then
            log "porta AUTORIZADA em $IFACE (identidade: $(certificate_cn))"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    log "porta NÃO autorizada após ${TIMEOUT}s em $IFACE; o supplicant continua tentando"
    return 1
}

cmd_start() {
    require_credentials
    cmd_stop >/dev/null
    write_config
    launch_daemon || die "falha ao iniciar wpa_supplicant"
    start_watchdog
    log "supplicant iniciado em $IFACE (cert: $CERT_DIR); aguardando autorização"
    wait_for_authorization
}

# Espera o processo MORRER antes de seguir: o wpa_supplicant envia EAPOL-Logoff
# ao encerrar; se o daemon novo já tiver autenticado, o logoff atrasado do
# antigo derruba a sessão no autenticador e o novo continua "Authorized"
# localmente, sem nunca reautenticar.
kill_from_pidfile() {
    local pidfile="$1" pid
    [ -f "$pidfile" ] || return 0
    pid="$(cat "$pidfile")"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    rm -f "$pidfile"
}

cmd_stop() {
    kill_from_pidfile "$WATCHDOG_PIDFILE"
    kill_from_pidfile "$PIDFILE"
    log "supplicant parado em $IFACE"
}

cmd_status() {
    local status
    status="$(wpa_cli_iface status)" || die "supplicant não está rodando em $IFACE"
    echo "$status" | grep -E '^(suppPortStatus|EAP state|selectedMethod|Supplicant PAE state)='
}

case "${1:-}" in
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    *) sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
