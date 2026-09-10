#!/bin/bash
# Sobe o sshd em background (pro Oráculo conseguir conectar).
/usr/sbin/sshd

# Configura o IP automaticamente com base no nome do host, que o GNS3
# já define igual ao nome do nó na topologia (ex: hostname "ubuntu-ied-3"
# -> IP 192.168.10.13). Isso sobrevive a qualquer restart/reload do nó,
# sem precisar configurar IP na mão de novo toda vez.
HOST=$(hostname)
NUM=$(echo "$HOST" | grep -oE '[0-9]+$')
if [ -n "$NUM" ]; then
    ip addr add "192.168.10.1${NUM}/24" dev eth0 2>/dev/null
    ip link set eth0 up 2>/dev/null
fi

# Entrega o terminal pro console do GNS3 (precisa ser um shell interativo,
# não o sshd, ou o console fica "mudo" -- ver README do projeto).
exec /bin/bash
