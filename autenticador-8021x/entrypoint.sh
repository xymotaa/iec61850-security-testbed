#!/bin/bash
# Sobe o autenticador (ponte + nftables + hostapd + supervisor) e entrega o
# terminal ao console do GNS3. Falha de configuração não derruba o container:
# o console abre e a mensagem de erro fica visível.
cd "$(dirname "$0")"
./iniciar_autenticador.sh || echo "[autenticador] NÃO iniciou — corrija a configuração e rode ./iniciar_autenticador.sh"

exec /bin/bash
