#!/bin/bash
# Só existe uma instância do oraculo na topologia, então IP fixo mesmo
# (sem precisar derivar do hostname como no ubuntu-ied).
ip addr add 192.168.10.20/24 dev eth0 2>/dev/null
ip link set eth0 up 2>/dev/null

# 802.1X (EAP-TLS) opcional: desligado por padrão. Com AUTH_8021X=1 o
# supplicant autentica a porta em background (o IP acima não muda; a rede
# só passa depois de autenticar). Ver autenticador-8021x/README.md.
if [ "${AUTH_8021X:-0}" = "1" ]; then
    /usr/local/bin/8021x-supplicant start &
fi

exec /bin/bash
