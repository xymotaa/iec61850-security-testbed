#!/bin/bash
# Só existe uma instância do oraculo na topologia, então IP fixo mesmo
# (sem precisar derivar do hostname como no ubuntu-ied).
ip addr add 192.168.10.20/24 dev eth0 2>/dev/null
ip link set eth0 up 2>/dev/null

exec /bin/bash
