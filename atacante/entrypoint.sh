#!/bin/bash
# Uma única instância do atacante na topologia -> IP fixo.
ip addr add 192.168.10.40/24 dev eth0 2>/dev/null
ip link set eth0 up 2>/dev/null

exec /bin/bash
