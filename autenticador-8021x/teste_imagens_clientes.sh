#!/usr/bin/env bash
# teste_imagens_clientes.sh — valida o supplicant EMBUTIDO nas 4 imagens
# reais (ubuntu-ied, oraculo, ids, atacante) contra o autenticador-8021x.
#
# Cada imagem roda num container próprio; o autenticador entra no MESMO
# network namespace (--network container:...), onde um par veth liga a porta
# do autenticador (p1, na br0) à eth0 do cliente. Também confere que o
# entrypoint chama o supplicant com AUTH_8021X=1.
#
# Requisitos: docker (--privileged), openssl. Constrói as 5 imagens.
set -euo pipefail

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(cd "$AQUI/.." && pwd)"
TRABALHO="$(mktemp -d)"
LOG="$AQUI/evidencias/teste_imagens_clientes-$(date +%Y%m%d-%H%M%S).log"
CASOS=("ubuntu-ied:ubuntu-ied-1" "oraculo:oraculo-1" "ids:ids-1" "atacante:publicador-1")  # imagem:CN
FALHAS=0

limpar() {
    docker rm -f $(docker ps -aq --filter "label=teste8021x") >/dev/null 2>&1 || true
    rm -rf "$TRABALHO"
}
trap limpar EXIT

passou() { echo "  [PASSOU] $1"; }
falhou() { echo "  [FALHOU] $1"; FALHAS=$((FALHAS + 1)); }

executar() {
    echo "[+] PKI temporária e inventário"
    "$RAIZ/pki/gerar_pki.sh" --out "$TRABALHO/pki" >/dev/null
    python3 "$RAIZ/extracao-scd/inventario_8021x.py" "$RAIZ/extracao-scd/dados.json" \
        --out "$TRABALHO/aut-inventario.json" >/dev/null
    mkdir -p "$TRABALHO/aut"
    cp "$TRABALHO/pki/nos/autenticador-8021x/"*.pem "$TRABALHO/aut/"
    cp "$TRABALHO/aut-inventario.json" "$TRABALHO/aut/inventario.json"

    echo "[+] Construindo imagens"
    for caso in "${CASOS[@]}"; do docker build -q -t "${caso%%:*}:latest" "$RAIZ/${caso%%:*}" >/dev/null; done
    docker build -q -t autenticador-8021x:latest "$AQUI" >/dev/null

    for caso in "${CASOS[@]}"; do testar_imagem "${caso%%:*}" "${caso##*:}"; done
    echo "RESUMO: $FALHAS falha(s)"
    [ "$FALHAS" -eq 0 ]
}

testar_imagem() {
    local imagem="$1" cn="$2"
    local cliente="cli-$imagem" autenticador="aut-$imagem"
    echo "== $imagem (certificado $cn)"
    local mac
    mac=$(python3 -c "import json;print(json.load(open('$TRABALHO/aut-inventario.json'))['dispositivos']['$cn']['macs'][0])")

    # 1) Binários presentes na imagem.
    if docker run --rm --network none --entrypoint bash "$imagem:latest" -c \
        'test -x /usr/local/bin/8021x-supplicant && command -v wpa_supplicant >/dev/null && command -v openssl >/dev/null'; then
        passou "binários presentes (8021x-supplicant, wpa_supplicant, openssl)"
    else falhou "binários ausentes na imagem"; fi

    # 2) AUTH_8021X=1 chama o supplicant a partir do entrypoint (sem eth0 ele reclama da interface).
    docker run -dit --privileged --network none --label teste8021x --name "$cliente" \
        --hostname "$cn" -e AUTH_8021X=1 -v "$TRABALHO/pki/nos/$cn:/etc/8021x:ro" "$imagem:latest" >/dev/null
    sleep 3
    if docker logs "$cliente" 2>&1 | grep -q "8021x-supplicant.*interface eth0 inexistente"; then
        passou "entrypoint com AUTH_8021X=1 invoca o supplicant"
    else falhou "entrypoint não invocou o supplicant: $(docker logs "$cliente" 2>&1 | tail -3)"; fi

    # 3) Autenticador no mesmo netns + veth p1 <-> eth0.
    docker run -dit --privileged --label teste8021x --name "$autenticador" --network "container:$cliente" \
        -v "$TRABALHO/aut:/etc/8021x" autenticador-8021x:latest >/dev/null
    sleep 2
    docker exec "$autenticador" bash -c "
        ip link add p1 type veth peer name eth0 &&
        ip link set eth0 address $mac && ip link set eth0 up &&
        AUTENTICADOR_IFACES=p1 /opt/autenticador/iniciar_autenticador.sh" >/dev/null
    sleep 2
    if docker exec "$cliente" /usr/local/bin/8021x-supplicant start >/dev/null 2>&1; then
        passou "$imagem: porta AUTORIZADA via supplicant da imagem"
    else falhou "$imagem: supplicant não autorizou"; fi
    sleep 1
    if docker exec "$autenticador" grep -q "\"auth_aceita\".*\"cn\": \"$cn\"" /var/log/8021x/eventos.jsonl; then
        passou "$imagem: autenticador registrou auth_aceita para $cn"
    else falhou "$imagem: sem auth_aceita para $cn"; fi
    docker rm -f "$autenticador" "$cliente" >/dev/null
}

executar 2>&1 | tee "$LOG"
exit "${PIPESTATUS[0]}"
