#!/usr/bin/env bash
# iniciar_autenticador.sh — monta a ponte br0, as regras nftables e o
# hostapd por porta, e sobe o supervisor (autenticador.py) em background.
#
# Variáveis de ambiente:
#   AUTENTICADOR_MODO       8021x (padrão) | aberto (switch L2 comum: referência E0)
#   AUTENTICADOR_PORTAS     nº de portas eth0..ethN-1 (padrão 9)
#   AUTENTICADOR_IFACES     lista explícita de interfaces (testes; ignora o nº acima)
#   PORTAS_CONFIAVEIS       portas sem 802.1X, ex.: "eth7 eth8" (padrão: nenhuma)
#   REAUTH_PERIODO          segundos entre reautenticações (padrão 600)
#   CRL_RELOAD              segundos entre releituras da CRL (padrão 60)
#   AUTENTICADOR_SEM_CRL=1  desliga a checagem de CRL (NÃO recomendado)
#   AUTENTICADOR_DEBUG=1    grava o log bruto do hostapd em /var/log/8021x/hostapd.log
#   CERT_DIR / INVENTARIO / LOG_DIR / RUN_DIR (padrões: /etc/8021x, $CERT_DIR/inventario.json,
#                                              /var/log/8021x, /run/8021x)
set -euo pipefail

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODO="${AUTENTICADOR_MODO:-8021x}"
CERT_DIR="${CERT_DIR:-/etc/8021x}"
INVENTARIO="${INVENTARIO:-$CERT_DIR/inventario.json}"
LOG_DIR="${LOG_DIR:-/var/log/8021x}"
RUN_DIR="${RUN_DIR:-/run/8021x}"
REAUTH_PERIODO="${REAUTH_PERIODO:-600}"
CRL_RELOAD="${CRL_RELOAD:-60}"
PONTE="br0"

log() { echo "[autenticador] $*"; }
die() { echo "[autenticador] ERRO: $*" >&2; exit 1; }

listar_portas() {
    if [ -n "${AUTENTICADOR_IFACES:-}" ]; then
        echo "$AUTENTICADOR_IFACES"
        return
    fi
    local i portas=()
    for ((i = 0; i < ${AUTENTICADOR_PORTAS:-9}; i++)); do
        if ip link show "eth$i" >/dev/null 2>&1; then
            portas+=("eth$i")
        else
            log "aviso: eth$i inexistente (adapters do nó < AUTENTICADOR_PORTAS)" >&2
        fi
    done
    echo "${portas[*]}"
}

criar_ponte() {
    ip link add "$PONTE" type bridge stp_state 0 2>/dev/null || true
    sysctl -qw "net.ipv6.conf.$PONTE.disable_ipv6=1" 2>/dev/null || true
    ip link set "$PONTE" up
}

adicionar_portas_na_ponte() {
    local porta
    for porta in "$@"; do
        sysctl -qw "net.ipv6.conf.$porta.disable_ipv6=1" 2>/dev/null || true
        ip link set "$porta" up
        ip link set "$porta" master "$PONTE"
    done
}

carregar_regras() {
    nft delete table bridge acesso8021x 2>/dev/null || true
    nft -f "$AQUI/regras.nft"
    local porta
    for porta in ${PORTAS_CONFIAVEIS:-}; do
        nft add element bridge acesso8021x portas_confiaveis "{ \"$porta\" }"
        log "porta $porta marcada como CONFIÁVEL (sem 802.1X)"
    done
}

exigir_credenciais() {
    local f
    for f in ca.pem cert.pem key.pem; do
        [ -r "$CERT_DIR/$f" ] || die "arquivo ausente: $CERT_DIR/$f (ver pki/README.md)"
    done
    [ -r "$INVENTARIO" ] || die "inventário ausente: $INVENTARIO (ver autenticador-8021x/README.md)"
}

preparar_ca_com_crl() {
    local ca_com_crl="$RUN_DIR/ca_com_crl.pem" check_crl=1
    if [ "${AUTENTICADOR_SEM_CRL:-0}" = "1" ]; then
        check_crl=0
        cp "$CERT_DIR/ca.pem" "$ca_com_crl"
        log "AVISO: checagem de CRL DESLIGADA"
    else
        [ -r "$CERT_DIR/crl.pem" ] || die "CRL ausente: $CERT_DIR/crl.pem (ou AUTENTICADOR_SEM_CRL=1)"
        cat "$CERT_DIR/ca.pem" "$CERT_DIR/crl.pem" > "$ca_com_crl"
    fi
    echo "$check_crl"
}

gerar_configs_hostapd() {
    local check_crl="$1"; shift
    local porta
    for porta in "$@"; do
        sed -e "s|@IFACE@|$porta|" \
            -e "s|@EAP_USER_FILE@|$AQUI/eap_user|" \
            -e "s|@REAUTH_PERIODO@|$REAUTH_PERIODO|" \
            -e "s|@CA_COM_CRL@|$RUN_DIR/ca_com_crl.pem|" \
            -e "s|@CHECK_CRL@|$check_crl|" \
            -e "s|@CRL_RELOAD@|$CRL_RELOAD|" \
            -e "s|@CERT_DIR@|$CERT_DIR|" \
            "$AQUI/hostapd.conf.tmpl" > "$RUN_DIR/hostapd-$porta.conf"
    done
}

separar_portas_autenticadas() {
    local porta confiavel c autenticadas=()
    for porta in "$@"; do
        confiavel=0
        for c in ${PORTAS_CONFIAVEIS:-}; do [ "$c" = "$porta" ] && confiavel=1; done
        [ "$confiavel" -eq 1 ] || autenticadas+=("$porta")
    done
    echo "${autenticadas[*]}"
}

iniciar_supervisor() {
    local portas=("$@") confs=() porta
    for porta in "${portas[@]}"; do confs+=("$RUN_DIR/hostapd-$porta.conf"); done
    local extra=()
    [ "${AUTENTICADOR_DEBUG:-0}" = "1" ] && extra+=(--log-hostapd "$LOG_DIR/hostapd.log")
    mkdir -p /run/hostapd
    cd "$AQUI"
    nohup python3 autenticador.py --inventario "$INVENTARIO" --eventos "$LOG_DIR/eventos.jsonl" \
        --portas "${portas[@]}" --hostapd-conf "${confs[@]}" "${extra[@]}" \
        >> "$LOG_DIR/autenticador.log" 2>&1 &
    echo $! > "$RUN_DIR/supervisor.pid"
    log "supervisor iniciado (pid $!); eventos em $LOG_DIR/eventos.jsonl"
}

main() {
    mkdir -p "$LOG_DIR" "$RUN_DIR"
    local portas
    read -r -a portas <<< "$(listar_portas)"
    [ "${#portas[@]}" -gt 0 ] || die "nenhuma porta encontrada"

    criar_ponte
    if [ "$MODO" = "aberto" ]; then
        adicionar_portas_na_ponte "${portas[@]}"
        log "MODO ABERTO: switch L2 sem 802.1X (${portas[*]})"
        return
    fi
    [ "$MODO" = "8021x" ] || die "AUTENTICADOR_MODO inválido: $MODO"

    exigir_credenciais
    carregar_regras                      # antes das portas: fail-closed desde o 1º quadro
    adicionar_portas_na_ponte "${portas[@]}"

    local check_crl autenticadas
    check_crl="$(preparar_ca_com_crl)"
    read -r -a autenticadas <<< "$(separar_portas_autenticadas "${portas[@]}")"
    gerar_configs_hostapd "$check_crl" "${autenticadas[@]}"
    iniciar_supervisor "${autenticadas[@]}"
    log "MODO 802.1X: portas ${autenticadas[*]} | confiáveis: ${PORTAS_CONFIAVEIS:-nenhuma}"
}

main "$@"
