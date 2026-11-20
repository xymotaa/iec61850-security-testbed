#!/usr/bin/env bash
# teste_netns.sh — validação automatizada do autenticador 802.1X (EAP-TLS real)
# sem GNS3: hostapd + wpa_supplicant + nftables dentro de UM container
# privilegiado, com os clientes em network namespaces (par veth direto na
# ponte do container, sem passar pela ponte do host).
#
# Requisitos no host: docker (permissão de --privileged), openssl.
# Uso: ./teste_netns.sh        (gera PKI temporária, constrói imagens, roda, salva evidências)
# Saída: evidencias/teste_netns-<data>.log, eventos-teste_netns.jsonl, nftables-teste_netns.txt
set -euo pipefail

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(cd "$AQUI/.." && pwd)"
TRABALHO="$(mktemp -d)"
trap 'rm -rf "$TRABALHO"' EXIT

echo "[+] PKI temporária (não toca em pki/saida)"
"$RAIZ/pki/gerar_pki.sh" --out "$TRABALHO/pki" >/dev/null
python3 "$RAIZ/extracao-scd/inventario_8021x.py" "$RAIZ/extracao-scd/dados.json" \
    --out "$TRABALHO/inventario.json" >/dev/null

echo "[+] Construindo imagens"
docker build -q -t autenticador-8021x:latest "$AQUI" >/dev/null
docker build -q -t autenticador-8021x:teste -f "$AQUI/Dockerfile.teste" "$AQUI" >/dev/null

mkdir -p "$AQUI/evidencias"
LOG="$AQUI/evidencias/teste_netns-$(date +%Y%m%d-%H%M%S).log"
echo "[+] Executando (log em ${LOG#$RAIZ/})"
set +e
docker run --rm --privileged \
    -v "$TRABALHO/pki:/pki:ro" \
    -v "$TRABALHO/inventario.json:/work/inventario.json:ro" \
    -v "$AQUI/supplicant/supplicant_8021x.sh:/opt/supplicant_8021x.sh:ro" \
    -v "$RAIZ/pki/gerar_pki.sh:/opt/gerar_pki.sh:ro" \
    -v "$AQUI/teste_netns_interno.sh:/opt/autenticador/teste_netns_interno.sh:ro" \
    -v "$AQUI/evidencias:/evidencias" \
    autenticador-8021x:teste bash /opt/autenticador/teste_netns_interno.sh 2>&1 | tee "$LOG"
resultado=${PIPESTATUS[0]}
set -e
echo "[+] código de saída do teste: $resultado"
exit "$resultado"
